use std::{
    collections::{HashMap, HashSet},
    hash::{Hash, Hasher},
    io,
    net::{
        IpAddr, Ipv4Addr, SocketAddr, TcpListener as StdTcpListener, TcpStream as StdTcpStream,
        UdpSocket as StdUdpSocket,
    },
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::Context;
use axiom_config::{DnsBlockResponse, DnsConfig, DnsLocalRecordConfig, DnsRecordType, PolicyMode};
use axiom_core::{DnsAction, DnsProtocol, DnsQueryEvent, RuntimeState};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::RwLock,
    task::JoinSet,
    time::timeout,
};
use tracing::{info, warn};

const DNS_HEADER_LEN: usize = 12;
const DNS_MAX_UDP_PACKET_LEN: usize = 4096;
const DNS_MAX_TCP_PACKET_LEN: usize = 65_535;
const DNS_TYPE_A: u16 = 1;
const DNS_TYPE_AAAA: u16 = 28;
const DNS_TYPE_ANY: u16 = 255;
const DNS_CLASS_IN: u16 = 1;
const DNS_RCODE_NOERROR: u8 = 0;
const DNS_RCODE_FORMERR: u8 = 1;
const DNS_RCODE_REFUSED: u8 = 5;
const DNS_RCODE_NXDOMAIN: u8 = 3;

pub async fn run_dns_gateway(config: DnsConfig, runtime: Arc<RuntimeState>) -> anyhow::Result<()> {
    if !config.enabled {
        return Ok(());
    }

    let udp_socket = Arc::new(bind_udp_socket_to_interface(
        &config.interface,
        config.udp_listen_addr(),
    )?);
    let tcp_listener =
        bind_tcp_listener_to_interface(&config.interface, config.tcp_listen_addr(), 4096)
            .await
            .with_context(|| {
                format!(
                    "failed binding DNS TCP listener on interface '{}' at {}",
                    config.interface,
                    config.tcp_listen_addr()
                )
            })?;

    let state = Arc::new(DnsGatewayState::new(config, runtime));
    state.refresh_threat_feeds().await;

    info!(
        interface = state.config.interface,
        udp_addr = %state.config.udp_listen_addr(),
        tcp_addr = %state.config.tcp_listen_addr(),
        upstreams = ?state.config.upstreams,
        "DNS security gateway started"
    );

    let mut tasks = JoinSet::new();
    tasks.spawn(run_udp_server(Arc::clone(&state), Arc::clone(&udp_socket)));
    tasks.spawn(run_tcp_server(Arc::clone(&state), tcp_listener));
    tasks.spawn(refresh_threat_feeds_periodically(Arc::clone(&state)));

    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                tasks.abort_all();
                return Err(error);
            }
            Err(error) => {
                tasks.abort_all();
                return Err(error.into());
            }
        }
    }

    Ok(())
}

async fn run_udp_server(state: Arc<DnsGatewayState>, socket: Arc<UdpSocket>) -> anyhow::Result<()> {
    let mut buffer = vec![0_u8; DNS_MAX_UDP_PACKET_LEN];

    loop {
        let (bytes_read, client_addr) = socket.recv_from(&mut buffer).await?;
        let query = buffer[..bytes_read].to_vec();
        let state = Arc::clone(&state);
        let socket = Arc::clone(&socket);

        tokio::spawn(async move {
            match handle_dns_query(Arc::clone(&state), DnsProtocol::Udp, client_addr, query).await {
                Ok(response) => {
                    if let Err(error) = socket.send_to(&response, client_addr).await {
                        warn!(?error, %client_addr, "failed sending DNS UDP response");
                    }
                }
                Err(error) => {
                    state.runtime.record_dns_upstream_error();
                    warn!(?error, %client_addr, "failed handling DNS UDP query");
                }
            }
        });
    }
}

async fn run_tcp_server(state: Arc<DnsGatewayState>, listener: TcpListener) -> anyhow::Result<()> {
    loop {
        let (stream, client_addr) = listener.accept().await?;
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            if let Err(error) = handle_tcp_client(state, stream, client_addr).await {
                warn!(?error, %client_addr, "DNS TCP client connection ended");
            }
        });
    }
}

async fn handle_tcp_client(
    state: Arc<DnsGatewayState>,
    mut stream: TcpStream,
    client_addr: SocketAddr,
) -> anyhow::Result<()> {
    loop {
        let packet_len = match stream.read_u16().await {
            Ok(value) => usize::from(value),
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(error) => return Err(error.into()),
        };

        if packet_len == 0 || packet_len > DNS_MAX_TCP_PACKET_LEN {
            return Err(anyhow::anyhow!(
                "invalid DNS TCP packet length {packet_len}"
            ));
        }

        let mut packet = vec![0_u8; packet_len];
        stream.read_exact(&mut packet).await?;

        let response =
            handle_dns_query(Arc::clone(&state), DnsProtocol::Tcp, client_addr, packet).await?;
        stream.write_u16(response.len() as u16).await?;
        stream.write_all(&response).await?;
    }
}

async fn handle_dns_query(
    state: Arc<DnsGatewayState>,
    protocol: DnsProtocol,
    client_addr: SocketAddr,
    query: Vec<u8>,
) -> anyhow::Result<Vec<u8>> {
    let started = Instant::now();
    let question = match parse_dns_question(&query) {
        Ok(question) => question,
        Err(error) => {
            let response = build_error_response(&query, DNS_RCODE_FORMERR)
                .unwrap_or_else(|| minimal_error_response(&query, DNS_RCODE_FORMERR));
            state.runtime.record_dns_query(DnsQueryEvent::now(
                protocol,
                client_addr,
                "<invalid>".to_string(),
                "INVALID".to_string(),
                DnsAction::Error,
                format!("malformed DNS query: {error}"),
                None,
                Some(DNS_RCODE_FORMERR),
                started.elapsed().as_millis() as u64,
                false,
            ));
            return Ok(response);
        }
    };

    let policy = state.runtime.dns_policy_config();
    let decision = state
        .policy_decision(&policy, &question.normalized_name)
        .await;
    if decision.action == DnsAction::Block {
        let response = build_policy_block_response(&query, &question, &policy);
        state.runtime.record_dns_query(DnsQueryEvent::now(
            protocol,
            client_addr,
            question.name,
            dns_type_label(question.qtype),
            DnsAction::Block,
            decision.reason,
            None,
            Some(response_code(&response)),
            started.elapsed().as_millis() as u64,
            false,
        ));
        return Ok(response);
    }

    if let Some(response) = build_local_record_response(&query, &question, &policy) {
        state.runtime.record_dns_query(DnsQueryEvent::now(
            protocol,
            client_addr,
            question.name,
            dns_type_label(question.qtype),
            if decision.action == DnsAction::Monitor {
                DnsAction::Monitor
            } else {
                DnsAction::Allow
            },
            if decision.action == DnsAction::Monitor {
                decision.reason
            } else {
                "answered from Axiom local DNS records".to_string()
            },
            None,
            Some(response_code(&response)),
            started.elapsed().as_millis() as u64,
            false,
        ));
        return Ok(response);
    }

    let cache_key = DnsCacheKey::from_question(&question);
    if let Some(response) = state.cached_response(&cache_key, request_id(&query)) {
        state.runtime.record_dns_query(DnsQueryEvent::now(
            protocol,
            client_addr,
            question.name,
            dns_type_label(question.qtype),
            if decision.action == DnsAction::Monitor {
                DnsAction::Monitor
            } else {
                DnsAction::Allow
            },
            if decision.action == DnsAction::Monitor {
                decision.reason
            } else {
                "cache hit".to_string()
            },
            None,
            Some(response_code(&response)),
            started.elapsed().as_millis() as u64,
            true,
        ));
        return Ok(response);
    }

    let response = state
        .forward_with_failover(protocol, client_addr, &query)
        .await;

    match response {
        Ok((upstream, response)) => {
            state.store_cache(cache_key, response.clone());
            state.runtime.record_dns_query(DnsQueryEvent::now(
                protocol,
                client_addr,
                question.name,
                dns_type_label(question.qtype),
                if decision.action == DnsAction::Monitor {
                    DnsAction::Monitor
                } else {
                    DnsAction::Allow
                },
                decision.reason,
                Some(upstream),
                Some(response_code(&response)),
                started.elapsed().as_millis() as u64,
                false,
            ));
            Ok(response)
        }
        Err(error) => {
            state.runtime.record_dns_upstream_error();
            let response = build_error_response(&query, DNS_RCODE_REFUSED)
                .unwrap_or_else(|| minimal_error_response(&query, DNS_RCODE_REFUSED));
            state.runtime.record_dns_query(DnsQueryEvent::now(
                protocol,
                client_addr,
                question.name,
                dns_type_label(question.qtype),
                DnsAction::Error,
                format!("upstream DNS query failed: {error}"),
                None,
                Some(DNS_RCODE_REFUSED),
                started.elapsed().as_millis() as u64,
                false,
            ));
            Ok(response)
        }
    }
}

async fn refresh_threat_feeds_periodically(state: Arc<DnsGatewayState>) -> anyhow::Result<()> {
    let mut interval = tokio::time::interval(Duration::from_secs(
        state.config.threat_feed_refresh_seconds.max(60),
    ));

    loop {
        interval.tick().await;
        state.refresh_threat_feeds().await;
    }
}

struct DnsGatewayState {
    config: DnsConfig,
    runtime: Arc<RuntimeState>,
    cache: Mutex<HashMap<DnsCacheKey, DnsCacheEntry>>,
    blocked_domains: RwLock<HashSet<String>>,
    upstream_cursor: AtomicUsize,
    http_client: reqwest::Client,
}

impl DnsGatewayState {
    fn new(config: DnsConfig, runtime: Arc<RuntimeState>) -> Self {
        Self {
            config,
            runtime,
            cache: Mutex::new(HashMap::new()),
            blocked_domains: RwLock::new(HashSet::new()),
            upstream_cursor: AtomicUsize::new(0),
            http_client: reqwest::Client::builder()
                .timeout(Duration::from_secs(20))
                .user_agent("AxiomDNS/0.1")
                .build()
                .expect("valid DNS threat feed HTTP client"),
        }
    }

    async fn refresh_threat_feeds(&self) {
        let policy = self.runtime.dns_policy_config();
        if policy.threat_feed_urls.is_empty() {
            *self.blocked_domains.write().await = HashSet::new();
            return;
        }

        let mut refreshed = HashSet::new();

        for url in &policy.threat_feed_urls {
            match self.http_client.get(url).send().await {
                Ok(response) => match response.text().await {
                    Ok(body) => {
                        let mut count = 0_usize;
                        for domain in parse_threat_feed_domains(&body) {
                            if refreshed.insert(domain) {
                                count += 1;
                            }
                        }
                        info!(url, count, "DNS threat feed loaded");
                    }
                    Err(error) => {
                        warn!(url, ?error, "failed reading DNS threat feed body");
                    }
                },
                Err(error) => {
                    warn!(url, ?error, "failed downloading DNS threat feed");
                }
            }
        }

        *self.blocked_domains.write().await = refreshed;
    }

    async fn policy_decision(
        &self,
        policy: &axiom_config::DnsPolicyConfig,
        normalized_name: &str,
    ) -> DnsPolicyDecision {
        let static_blocked_domains = policy
            .blocked_domains
            .iter()
            .filter_map(|domain| normalize_domain(domain))
            .collect::<HashSet<_>>();
        if domain_matches(&static_blocked_domains, normalized_name)
            && policy.blocked_domain_action.is_enabled()
        {
            return DnsPolicyDecision {
                action: policy_mode_to_dns_action(policy.blocked_domain_action),
                reason: format!("domain matched DNS block policy: {normalized_name}"),
            };
        }

        let feed_blocked_domains = self.blocked_domains.read().await;
        if domain_matches(&feed_blocked_domains, normalized_name)
            && policy.blocked_domain_action.is_enabled()
        {
            return DnsPolicyDecision {
                action: policy_mode_to_dns_action(policy.blocked_domain_action),
                reason: format!("domain matched DNS threat feed: {normalized_name}"),
            };
        }
        drop(feed_blocked_domains);

        let static_monitored_domains = policy
            .monitored_domains
            .iter()
            .filter_map(|domain| normalize_domain(domain))
            .collect::<HashSet<_>>();
        if domain_matches(&static_monitored_domains, normalized_name)
            && policy.monitored_domain_action.is_enabled()
        {
            return DnsPolicyDecision {
                action: policy_mode_to_dns_action(policy.monitored_domain_action),
                reason: format!("domain matched DNS monitor policy: {normalized_name}"),
            };
        }

        DnsPolicyDecision {
            action: DnsAction::Allow,
            reason: "allowed by DNS policy".to_string(),
        }
    }

    fn ordered_upstreams(&self) -> Vec<SocketAddr> {
        let upstream_count = self.config.upstreams.len();
        let start = self.upstream_cursor.fetch_add(1, Ordering::Relaxed) % upstream_count;
        (0..upstream_count)
            .map(|offset| self.config.upstreams[(start + offset) % upstream_count])
            .collect()
    }

    fn cached_response(&self, key: &DnsCacheKey, request_id: [u8; 2]) -> Option<Vec<u8>> {
        let mut cache = self.cache.lock().expect("dns cache mutex poisoned");
        let entry = cache.get(key)?;
        if Instant::now() >= entry.expires_at {
            cache.remove(key);
            return None;
        }

        let mut response = entry.response.clone();
        response[0..2].copy_from_slice(&request_id);
        Some(response)
    }

    fn store_cache(&self, key: DnsCacheKey, response: Vec<u8>) {
        if response.len() < DNS_HEADER_LEN {
            return;
        }

        let ttl = response_min_ttl(&response).unwrap_or(self.config.cache_ttl_seconds);
        let ttl = ttl.max(1).min(self.config.cache_ttl_seconds);
        let mut cache = self.cache.lock().expect("dns cache mutex poisoned");

        if cache.len() >= self.config.cache_max_entries
            && let Some(oldest_key) = cache
                .iter()
                .min_by_key(|(_, entry)| entry.expires_at)
                .map(|(entry_key, _)| entry_key.clone())
        {
            cache.remove(&oldest_key);
        }

        cache.insert(
            key,
            DnsCacheEntry {
                response,
                expires_at: Instant::now() + Duration::from_secs(ttl),
            },
        );
    }

    async fn forward_udp(&self, query: &[u8], upstream: SocketAddr) -> anyhow::Result<Vec<u8>> {
        let socket = bind_udp_socket_to_interface(
            self.config.upstream_interface(),
            unspecified_addr_for(upstream),
        )?;
        socket.connect(upstream).await?;
        socket.send(query).await?;

        let mut buffer = vec![0_u8; DNS_MAX_UDP_PACKET_LEN];
        let bytes_read = timeout(
            Duration::from_millis(self.config.query_timeout_millis),
            socket.recv(&mut buffer),
        )
        .await
        .context("DNS UDP upstream query timed out")??;
        buffer.truncate(bytes_read);
        Ok(buffer)
    }

    async fn forward_with_failover(
        &self,
        protocol: DnsProtocol,
        client_addr: SocketAddr,
        query: &[u8],
    ) -> anyhow::Result<(SocketAddr, Vec<u8>)> {
        let mut last_error = None;
        let mut skipped_loop_upstreams = 0_usize;

        for upstream in self.ordered_upstreams() {
            if upstream.ip() == client_addr.ip() || Some(upstream.ip()) == self.config.listen_ip {
                skipped_loop_upstreams += 1;
                warn!(
                    %client_addr,
                    %upstream,
                    "skipping DNS upstream to prevent a resolver forwarding loop"
                );
                continue;
            }

            let result = match protocol {
                DnsProtocol::Udp => self.forward_udp(query, upstream).await,
                DnsProtocol::Tcp => self.forward_tcp(query, upstream).await,
            };

            match result {
                Ok(response) => return Ok((upstream, response)),
                Err(error) => {
                    warn!(%upstream, ?error, "DNS upstream attempt failed; trying next resolver");
                    last_error = Some(error);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            if skipped_loop_upstreams > 0 {
                anyhow::anyhow!(
                    "DNS forwarding loop prevented: every usable upstream matched the client or Axiom listen address"
                )
            } else {
                anyhow::anyhow!("no upstream DNS resolvers configured")
            }
        }))
    }

    async fn forward_tcp(&self, query: &[u8], upstream: SocketAddr) -> anyhow::Result<Vec<u8>> {
        let mut stream = connect_tcp_via_interface(self.config.upstream_interface(), upstream)
            .await
            .with_context(|| format!("failed connecting to DNS upstream {upstream}"))?;
        stream.write_u16(query.len() as u16).await?;
        stream.write_all(query).await?;

        let response_len = timeout(
            Duration::from_millis(self.config.query_timeout_millis),
            stream.read_u16(),
        )
        .await
        .context("DNS TCP upstream length read timed out")?? as usize;
        if response_len == 0 || response_len > DNS_MAX_TCP_PACKET_LEN {
            return Err(anyhow::anyhow!(
                "invalid DNS TCP upstream response length {response_len}"
            ));
        }

        let mut response = vec![0_u8; response_len];
        timeout(
            Duration::from_millis(self.config.query_timeout_millis),
            stream.read_exact(&mut response),
        )
        .await
        .context("DNS TCP upstream response read timed out")??;
        Ok(response)
    }
}

#[derive(Debug)]
struct DnsPolicyDecision {
    action: DnsAction,
    reason: String,
}

#[derive(Debug, Clone, Eq)]
struct DnsCacheKey {
    normalized_name: String,
    qtype: u16,
    qclass: u16,
}

impl DnsCacheKey {
    fn from_question(question: &DnsQuestion) -> Self {
        Self {
            normalized_name: question.normalized_name.clone(),
            qtype: question.qtype,
            qclass: question.qclass,
        }
    }
}

impl PartialEq for DnsCacheKey {
    fn eq(&self, other: &Self) -> bool {
        self.normalized_name == other.normalized_name
            && self.qtype == other.qtype
            && self.qclass == other.qclass
    }
}

impl Hash for DnsCacheKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.normalized_name.hash(state);
        self.qtype.hash(state);
        self.qclass.hash(state);
    }
}

#[derive(Debug)]
struct DnsCacheEntry {
    response: Vec<u8>,
    expires_at: Instant,
}

#[derive(Debug)]
struct DnsQuestion {
    name: String,
    normalized_name: String,
    qtype: u16,
    qclass: u16,
    question_end: usize,
}

fn parse_dns_question(packet: &[u8]) -> anyhow::Result<DnsQuestion> {
    if packet.len() < DNS_HEADER_LEN {
        return Err(anyhow::anyhow!("packet too short"));
    }

    let qdcount = read_u16(packet, 4).unwrap_or(0);
    if qdcount == 0 {
        return Err(anyhow::anyhow!("query contains no questions"));
    }

    let (name, name_end) = parse_dns_name(packet, DNS_HEADER_LEN)?;
    let qtype = read_u16(packet, name_end).context("question type is missing")?;
    let qclass = read_u16(packet, name_end + 2).context("question class is missing")?;
    let normalized_name = normalize_domain(&name).unwrap_or_else(|| name.to_ascii_lowercase());

    Ok(DnsQuestion {
        name,
        normalized_name,
        qtype,
        qclass,
        question_end: name_end + 4,
    })
}

fn parse_dns_name(packet: &[u8], start: usize) -> anyhow::Result<(String, usize)> {
    let mut labels = Vec::new();
    let mut offset = start;
    let mut end_offset = None;
    let mut jumps = 0;

    loop {
        let Some(length) = packet.get(offset).copied() else {
            return Err(anyhow::anyhow!("name offset outside packet"));
        };

        if length & 0xC0 == 0xC0 {
            let Some(next) = packet.get(offset + 1).copied() else {
                return Err(anyhow::anyhow!("truncated compressed name pointer"));
            };
            let pointer = (((length & 0x3f) as usize) << 8) | next as usize;
            if pointer >= packet.len() {
                return Err(anyhow::anyhow!("compressed name pointer outside packet"));
            }
            end_offset.get_or_insert(offset + 2);
            offset = pointer;
            jumps += 1;
            if jumps > 16 {
                return Err(anyhow::anyhow!("too many compressed name jumps"));
            }
            continue;
        }

        if length == 0 {
            let final_offset = end_offset.unwrap_or(offset + 1);
            return Ok((labels.join("."), final_offset));
        }

        if length > 63 {
            return Err(anyhow::anyhow!("invalid DNS label length {length}"));
        }

        let label_start = offset + 1;
        let label_end = label_start + length as usize;
        let Some(label) = packet.get(label_start..label_end) else {
            return Err(anyhow::anyhow!("truncated DNS label"));
        };
        labels.push(String::from_utf8_lossy(label).to_string());
        offset = label_end;
    }
}

fn build_policy_block_response(
    request: &[u8],
    question: &DnsQuestion,
    policy: &axiom_config::DnsPolicyConfig,
) -> Vec<u8> {
    match policy.block_response {
        DnsBlockResponse::Nxdomain => build_error_response(request, DNS_RCODE_NXDOMAIN)
            .unwrap_or_else(|| minimal_error_response(request, DNS_RCODE_NXDOMAIN)),
        DnsBlockResponse::Refused => build_error_response(request, DNS_RCODE_REFUSED)
            .unwrap_or_else(|| minimal_error_response(request, DNS_RCODE_REFUSED)),
        DnsBlockResponse::Sinkhole => {
            build_a_record_response(request, question, policy.sinkhole_ipv4, 60).unwrap_or_else(
                || {
                    build_error_response(request, DNS_RCODE_NXDOMAIN)
                        .unwrap_or_else(|| minimal_error_response(request, DNS_RCODE_NXDOMAIN))
                },
            )
        }
    }
}

fn build_local_record_response(
    request: &[u8],
    question: &DnsQuestion,
    policy: &axiom_config::DnsPolicyConfig,
) -> Option<Vec<u8>> {
    let record = policy.local_records.iter().find(|record| {
        normalize_domain(&record.name).as_deref() == Some(question.normalized_name.as_str())
            && local_record_matches_question(record, question.qtype)
    })?;

    match (record.record_type, record.value) {
        (DnsRecordType::A, IpAddr::V4(address)) => {
            build_a_record_response(request, question, address, u64::from(record.ttl_seconds))
        }
        (DnsRecordType::Aaaa, IpAddr::V6(address)) => {
            build_aaaa_record_response(request, question, address, u64::from(record.ttl_seconds))
        }
        _ => None,
    }
}

fn build_error_response(request: &[u8], rcode: u8) -> Option<Vec<u8>> {
    let question = parse_dns_question(request).ok()?;
    let mut response = Vec::with_capacity(question.question_end);
    response.extend_from_slice(request.get(0..2)?);
    response.extend_from_slice(&response_flags(request, rcode).to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(request.get(DNS_HEADER_LEN..question.question_end)?);
    Some(response)
}

fn minimal_error_response(request: &[u8], rcode: u8) -> Vec<u8> {
    let mut response = vec![0_u8; DNS_HEADER_LEN];
    if request.len() >= 2 {
        response[0..2].copy_from_slice(&request[0..2]);
    }
    response[2..4].copy_from_slice(&response_flags(request, rcode).to_be_bytes());
    response
}

fn build_a_record_response(
    request: &[u8],
    question: &DnsQuestion,
    address: Ipv4Addr,
    ttl: u64,
) -> Option<Vec<u8>> {
    if question.qclass != DNS_CLASS_IN
        || !(question.qtype == DNS_TYPE_A || question.qtype == DNS_TYPE_ANY)
    {
        return None;
    }

    let mut response = Vec::with_capacity(question.question_end + 16);
    response.extend_from_slice(request.get(0..2)?);
    response.extend_from_slice(&response_flags(request, DNS_RCODE_NOERROR).to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(request.get(DNS_HEADER_LEN..question.question_end)?);
    response.extend_from_slice(&[0xC0, 0x0C]);
    response.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
    response.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
    response.extend_from_slice(&(ttl.min(u64::from(u32::MAX)) as u32).to_be_bytes());
    response.extend_from_slice(&4_u16.to_be_bytes());
    response.extend_from_slice(&address.octets());
    Some(response)
}

fn build_aaaa_record_response(
    request: &[u8],
    question: &DnsQuestion,
    address: std::net::Ipv6Addr,
    ttl: u64,
) -> Option<Vec<u8>> {
    if question.qclass != DNS_CLASS_IN
        || !(question.qtype == DNS_TYPE_AAAA || question.qtype == DNS_TYPE_ANY)
    {
        return None;
    }

    let mut response = Vec::with_capacity(question.question_end + 28);
    response.extend_from_slice(request.get(0..2)?);
    response.extend_from_slice(&response_flags(request, DNS_RCODE_NOERROR).to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(request.get(DNS_HEADER_LEN..question.question_end)?);
    response.extend_from_slice(&[0xC0, 0x0C]);
    response.extend_from_slice(&DNS_TYPE_AAAA.to_be_bytes());
    response.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
    response.extend_from_slice(&(ttl.min(u64::from(u32::MAX)) as u32).to_be_bytes());
    response.extend_from_slice(&16_u16.to_be_bytes());
    response.extend_from_slice(&address.octets());
    Some(response)
}

fn local_record_matches_question(record: &DnsLocalRecordConfig, qtype: u16) -> bool {
    matches!(
        (record.record_type, qtype),
        (DnsRecordType::A, DNS_TYPE_A)
            | (DnsRecordType::A, DNS_TYPE_ANY)
            | (DnsRecordType::Aaaa, DNS_TYPE_AAAA)
            | (DnsRecordType::Aaaa, DNS_TYPE_ANY)
    )
}

fn response_flags(request: &[u8], rcode: u8) -> u16 {
    let request_flags = read_u16(request, 2).unwrap_or(0);
    0x8000 | (request_flags & 0x7900) | 0x0080 | u16::from(rcode & 0x0f)
}

fn response_code(packet: &[u8]) -> u8 {
    packet.get(3).copied().unwrap_or(DNS_RCODE_FORMERR) & 0x0f
}

fn request_id(packet: &[u8]) -> [u8; 2] {
    [
        packet.first().copied().unwrap_or(0),
        packet.get(1).copied().unwrap_or(0),
    ]
}

fn response_min_ttl(packet: &[u8]) -> Option<u64> {
    if packet.len() < DNS_HEADER_LEN {
        return None;
    }

    let qdcount = read_u16(packet, 4)? as usize;
    let ancount = read_u16(packet, 6)? as usize;
    let mut offset = DNS_HEADER_LEN;

    for _ in 0..qdcount {
        let (_, name_end) = parse_dns_name(packet, offset).ok()?;
        offset = name_end.checked_add(4)?;
        if offset > packet.len() {
            return None;
        }
    }

    let mut ttl = None;
    for _ in 0..ancount {
        let (_, name_end) = parse_dns_name(packet, offset).ok()?;
        offset = name_end;
        let record_ttl = read_u32(packet, offset + 4)? as u64;
        let rdlen = read_u16(packet, offset + 8)? as usize;
        offset = offset.checked_add(10 + rdlen)?;
        if offset > packet.len() {
            return None;
        }
        ttl = Some(ttl.map_or(record_ttl, |current: u64| current.min(record_ttl)));
    }

    ttl
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let pair = bytes.get(offset..offset + 2)?;
    Some(u16::from_be_bytes([pair[0], pair[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let quad = bytes.get(offset..offset + 4)?;
    Some(u32::from_be_bytes([quad[0], quad[1], quad[2], quad[3]]))
}

fn dns_type_label(qtype: u16) -> String {
    match qtype {
        DNS_TYPE_A => "A".to_string(),
        DNS_TYPE_AAAA => "AAAA".to_string(),
        2 => "NS".to_string(),
        5 => "CNAME".to_string(),
        6 => "SOA".to_string(),
        12 => "PTR".to_string(),
        15 => "MX".to_string(),
        16 => "TXT".to_string(),
        33 => "SRV".to_string(),
        DNS_TYPE_ANY => "ANY".to_string(),
        value => format!("TYPE{value}"),
    }
}

fn policy_mode_to_dns_action(mode: PolicyMode) -> DnsAction {
    match mode {
        PolicyMode::Disabled => DnsAction::Allow,
        PolicyMode::Monitor => DnsAction::Monitor,
        PolicyMode::Block => DnsAction::Block,
    }
}

fn domain_matches(domains: &HashSet<String>, query_name: &str) -> bool {
    domains
        .iter()
        .any(|domain| query_name == domain || query_name.ends_with(&format!(".{domain}")))
}

fn normalize_domain(domain: &str) -> Option<String> {
    let mut value = domain
        .trim()
        .trim_end_matches('.')
        .trim_start_matches("||")
        .trim_start_matches("*.")
        .trim_end_matches('^')
        .trim_end_matches('/')
        .to_ascii_lowercase();

    if value.starts_with("http://") || value.starts_with("https://") {
        value = value
            .split("://")
            .nth(1)?
            .split('/')
            .next()
            .unwrap_or_default()
            .to_string();
    }

    if value.is_empty()
        || value.len() > 253
        || value.contains(':')
        || value.contains('/')
        || value.contains(' ')
    {
        return None;
    }

    let valid = value.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    });

    valid.then_some(value)
}

fn parse_threat_feed_domains(body: &str) -> Vec<String> {
    let mut domains = HashSet::new();

    for line in body.lines() {
        let line = line.trim();
        if line.is_empty()
            || line.starts_with('#')
            || line.starts_with('!')
            || line.starts_with(';')
        {
            continue;
        }

        let candidate = line
            .split('#')
            .next()
            .unwrap_or(line)
            .split_whitespace()
            .last()
            .unwrap_or(line);

        if let Some(domain) = normalize_domain(candidate)
            && !matches!(
                domain.as_str(),
                "localhost" | "localhost.localdomain" | "broadcasthost"
            )
            && !domain.parse::<IpAddr>().is_ok()
        {
            domains.insert(domain);
        }
    }

    domains.into_iter().collect()
}

fn unspecified_addr_for(peer: SocketAddr) -> SocketAddr {
    match peer {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0),
    }
}

fn bind_udp_socket_to_interface(interface: &str, addr: SocketAddr) -> io::Result<UdpSocket> {
    let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    socket.set_reuse_port(true)?;
    bind_socket_to_interface(&socket, interface)?;
    socket.bind(&SockAddr::from(addr))?;
    socket.set_nonblocking(true)?;

    let socket: StdUdpSocket = socket.into();
    UdpSocket::from_std(socket)
}

async fn bind_tcp_listener_to_interface(
    interface: &str,
    addr: SocketAddr,
    backlog: i32,
) -> io::Result<TcpListener> {
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    socket.set_reuse_port(true)?;
    bind_socket_to_interface(&socket, interface)?;
    socket.bind(&SockAddr::from(addr))?;
    socket.listen(backlog)?;
    socket.set_nonblocking(true)?;

    let listener: StdTcpListener = socket.into();
    TcpListener::from_std(listener)
}

async fn connect_tcp_via_interface(
    interface: &str,
    target_addr: SocketAddr,
) -> io::Result<TcpStream> {
    let socket = Socket::new(
        Domain::for_address(target_addr),
        Type::STREAM,
        Some(Protocol::TCP),
    )?;
    bind_socket_to_interface(&socket, interface)?;
    socket.set_nonblocking(true)?;

    match socket.connect(&SockAddr::from(target_addr)) {
        Ok(()) => {}
        Err(error) if connect_is_in_progress(&error) => {}
        Err(error) => return Err(error),
    }

    let stream: StdTcpStream = socket.into();
    stream.set_nonblocking(true)?;
    let stream = TcpStream::from_std(stream)?;
    stream.writable().await?;

    if let Some(error) = stream.take_error()? {
        return Err(error);
    }

    Ok(stream)
}

#[cfg(target_os = "linux")]
fn bind_socket_to_interface(socket: &Socket, interface: &str) -> io::Result<()> {
    if interface.as_bytes().contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "interface name contains a null byte",
        ));
    }

    socket.bind_device(Some(interface.as_bytes()))
}

#[cfg(not(target_os = "linux"))]
fn bind_socket_to_interface(_socket: &Socket, interface: &str) -> io::Result<()> {
    tracing::warn!(
        interface,
        "SO_BINDTODEVICE is only enforced on Linux; this development build is not interface-isolated"
    );
    Ok(())
}

fn connect_is_in_progress(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::WouldBlock || error.raw_os_error() == Some(libc::EINPROGRESS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axiom_config::{DnsPolicyConfig, PolicyConfig};
    use axiom_core::StreamPolicy;

    #[test]
    fn parses_plain_dns_question() {
        let packet = dns_query("Example.COM", DNS_TYPE_A);

        let question = parse_dns_question(&packet).unwrap();

        assert_eq!(question.name, "Example.COM");
        assert_eq!(question.normalized_name, "example.com");
        assert_eq!(question.qtype, DNS_TYPE_A);
    }

    #[test]
    fn builds_nxdomain_response_with_original_question() {
        let packet = dns_query("blocked.example", DNS_TYPE_A);

        let response = build_error_response(&packet, DNS_RCODE_NXDOMAIN).unwrap();

        assert_eq!(&response[0..2], &packet[0..2]);
        assert_eq!(response_code(&response), DNS_RCODE_NXDOMAIN);
        assert_eq!(read_u16(&response, 4), Some(1));
        assert_eq!(read_u16(&response, 6), Some(0));
        assert!(response.ends_with(&packet[DNS_HEADER_LEN..]));
    }

    #[test]
    fn builds_sinkhole_a_response() {
        let packet = dns_query("blocked.example", DNS_TYPE_A);
        let question = parse_dns_question(&packet).unwrap();

        let response =
            build_a_record_response(&packet, &question, Ipv4Addr::new(10, 10, 10, 10), 60).unwrap();

        assert_eq!(response_code(&response), DNS_RCODE_NOERROR);
        assert_eq!(read_u16(&response, 6), Some(1));
        assert_eq!(&response[response.len() - 4..], &[10, 10, 10, 10]);
    }

    #[test]
    fn builds_local_dns_aaaa_response() {
        let packet = dns_query("host.internal", DNS_TYPE_AAAA);
        let question = parse_dns_question(&packet).unwrap();
        let address = "2001:db8::10".parse().unwrap();

        let response = build_aaaa_record_response(&packet, &question, address, 300).unwrap();

        assert_eq!(response_code(&response), DNS_RCODE_NOERROR);
        assert_eq!(read_u16(&response, 6), Some(1));
        assert_eq!(&response[response.len() - 16..], &address.octets());
    }

    #[test]
    fn matches_parent_domain_policy() {
        let domains = HashSet::from(["evil.example".to_string()]);

        assert!(domain_matches(&domains, "sub.evil.example"));
        assert!(domain_matches(&domains, "evil.example"));
        assert!(!domain_matches(&domains, "notevil.example"));
    }

    #[test]
    fn parses_hosts_style_threat_feed() {
        let body = "\n# comment\n0.0.0.0 bad.example\n127.0.0.1 worse.example # inline\n";

        let domains = parse_threat_feed_domains(body);

        assert!(domains.contains(&"bad.example".to_string()));
        assert!(domains.contains(&"worse.example".to_string()));
    }

    #[tokio::test]
    async fn prevents_forwarding_loop_to_client_upstream() {
        let config = DnsConfig {
            enabled: true,
            interface: "lo".to_string(),
            listen_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            upstreams: vec!["192.168.0.10:53".parse().unwrap()],
            ..DnsConfig::default()
        };
        let runtime = Arc::new(RuntimeState::new(
            StreamPolicy::from_config(PolicyConfig::default()),
            DnsPolicyConfig::default(),
        ));
        let state = DnsGatewayState::new(config, runtime);
        let query = dns_query("example.com", DNS_TYPE_A);
        let client_addr: SocketAddr = "192.168.0.10:53333".parse().unwrap();

        let error = state
            .forward_with_failover(DnsProtocol::Udp, client_addr, &query)
            .await
            .unwrap_err();

        assert!(error.to_string().contains("DNS forwarding loop prevented"));
    }

    fn dns_query(name: &str, qtype: u16) -> Vec<u8> {
        let mut packet = Vec::new();
        packet.extend_from_slice(&[0x12, 0x34]);
        packet.extend_from_slice(&0x0100_u16.to_be_bytes());
        packet.extend_from_slice(&1_u16.to_be_bytes());
        packet.extend_from_slice(&0_u16.to_be_bytes());
        packet.extend_from_slice(&0_u16.to_be_bytes());
        packet.extend_from_slice(&0_u16.to_be_bytes());

        for label in name.split('.') {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0);
        packet.extend_from_slice(&qtype.to_be_bytes());
        packet.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        packet
    }
}
