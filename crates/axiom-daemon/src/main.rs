use std::{
    collections::{HashMap, VecDeque},
    env, fs,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::Context;
use axiom_config::{AxiomConfig, ClusterServiceTemplate, DnsConfig, NodeRole, ProxyListenerConfig};
use axiom_control::{
    ControlApplyResponse, ControlPolicyBundle, EncryptedEnvelope, decrypt_payload, encrypt_payload,
};
use axiom_core::{CompletedFileTransfer, RuntimeState, StreamPolicy};
use axiom_reputation::{
    FileReputationReport, KnownBadAction, ReputationLookupResponse, ReputationVerdict,
    cache_expiry_timestamp,
};
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::post,
};
use serde_json::json;
use tokio::task::JoinSet;
use tracing::{error, info, warn};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    install_rustls_crypto_provider();
    init_tracing();

    if env::args().nth(1).as_deref() == Some("--version") {
        println!("{}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    let config_path = env::args()
        .nth(1)
        .unwrap_or_else(|| "config/axiom.toml".to_string());
    let config = AxiomConfig::load_from_path(&config_path)
        .with_context(|| format!("failed loading Axiom config from '{config_path}'"))?;

    let config_path = PathBuf::from(config_path);
    let runtime = Arc::new(RuntimeState::new(
        StreamPolicy::from_config(config.policy.clone()),
        config.dns.policy.clone(),
    ));

    if config.node.role.runs_agent()
        && let Err(error) = bootstrap_node_runtime_config(&config, &runtime).await
    {
        warn!(
            ?error,
            "failed bootstrapping runtime config from management before listeners start; failing open"
        );
    }

    let mut tasks = JoinSet::new();

    if config.node.role.runs_management() {
        let web_config = config.clone();
        let web_runtime = Arc::clone(&runtime);
        tasks.spawn(async move {
            axiom_web::run_management_server(config_path, web_config, web_runtime).await
        });
    }

    if config.node.role.runs_smb_proxy() {
        let reputation_lookup_config = smb_reputation_lookup_config(&config);
        for proxy_listener in config.proxy_listeners.clone() {
            let proxy_runtime = Arc::clone(&runtime);
            let proxy_reputation_lookup_config = reputation_lookup_config.clone();
            tasks.spawn(async move {
                axiom_net::run_proxy_listener(
                    proxy_listener,
                    proxy_runtime,
                    proxy_reputation_lookup_config,
                )
                .await
            });
        }
    }

    if config.node.role.runs_dns() && config.dns.enabled {
        let dns_config = config.dns.clone();
        let dns_runtime = Arc::clone(&runtime);
        tasks.spawn(async move { axiom_dns::run_dns_gateway(dns_config, dns_runtime).await });
    }

    if config.node.role.runs_agent() {
        let control_config = config.clone();
        let control_runtime = Arc::clone(&runtime);
        tasks.spawn(async move { run_node_control_server(control_config, control_runtime).await });

        let agent_config = config.clone();
        let agent_runtime = Arc::clone(&runtime);
        tasks.spawn(async move { run_node_agent(agent_config, agent_runtime).await });
    }

    info!(
        role = config.node.role.as_str(),
        node_id = config.node.node_id,
        management_interface = config.management.interface,
        management_addr = %config.management.listen_addr(),
        proxy_listener_count = if config.node.role.runs_smb_proxy() { config.proxy_listeners.len() } else { 0 },
        dns_enabled = config.node.role.runs_dns() && config.dns.enabled,
        "Axiom daemon started"
    );

    tokio::select! {
        signal = tokio::signal::ctrl_c() => {
            signal.context("failed waiting for Ctrl+C")?;
            info!("shutdown signal received");
        }
        task_result = tasks.join_next() => {
            match task_result {
                Some(Ok(Ok(()))) => {
                    info!("Axiom task exited cleanly");
                }
                Some(Ok(Err(error))) => {
                    error!(?error, "Axiom task failed");
                    tasks.abort_all();
                    return Err(error);
                }
                Some(Err(error)) => {
                    error!(?error, "Axiom task panicked");
                    tasks.abort_all();
                    return Err(error.into());
                }
                None => {
                    info!("all Axiom tasks exited");
                }
            }
        }
    }

    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    info!("Axiom daemon stopped");
    Ok(())
}

fn install_rustls_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

struct NodeControlState {
    runtime: Arc<RuntimeState>,
    node_id: String,
    role: NodeRole,
    shared_secret: String,
    seen_commands: Mutex<VecDeque<String>>,
}

async fn run_node_control_server(
    config: AxiomConfig,
    runtime: Arc<RuntimeState>,
) -> anyhow::Result<()> {
    let control = config.node.control.clone();
    if !control.enabled {
        return Err(anyhow::anyhow!(
            "node control listener is disabled for agent role"
        ));
    }

    let shared_secret = config
        .node
        .enrollment_token
        .clone()
        .context("node.enrollment_token is required for node control")?;
    let listener =
        axiom_net::bind_tcp_listener_to_interface(&control.interface, control.listen_addr(), 1024)
            .await
            .with_context(|| {
                format!(
                    "failed binding node control listener to interface '{}' at {}",
                    control.interface,
                    control.listen_addr()
                )
            })?;
    let state = Arc::new(NodeControlState {
        runtime,
        node_id: config.node.node_id.clone(),
        role: config.node.role,
        shared_secret,
        seen_commands: Mutex::new(VecDeque::new()),
    });
    let app = Router::new()
        .route("/api/control/policies", post(api_apply_control_policy))
        .with_state(state);

    info!(
        node_id = config.node.node_id,
        role = config.node.role.as_str(),
        interface = control.interface,
        listen_addr = %control.listen_addr(),
        "Axiom node control listener started"
    );

    axum::serve(listener, app).await?;
    Ok(())
}

async fn api_apply_control_policy(
    headers: HeaderMap,
    State(state): State<Arc<NodeControlState>>,
    Json(envelope): Json<EncryptedEnvelope>,
) -> Response {
    if !bearer_token_matches(&headers, &state.shared_secret) {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    if envelope.node_id != state.node_id {
        warn!(
            expected = state.node_id,
            received = envelope.node_id,
            "rejected control payload for a different node"
        );
        return StatusCode::BAD_REQUEST.into_response();
    }

    let command: ControlPolicyBundle = match decrypt_payload(&state.shared_secret, &envelope) {
        Ok(command) => command,
        Err(error) => {
            warn!(?error, "rejected unauthenticated control payload");
            return StatusCode::BAD_REQUEST.into_response();
        }
    };

    if command_seen(&state, &command.command_id) {
        let response = ControlApplyResponse {
            accepted: true,
            message: "duplicate command ignored".to_string(),
            applied_unix_timestamp_seconds: unix_timestamp_seconds(),
            policy_generation: state.runtime.policy_runtime_snapshot().generation,
            dns_policy_generation: state.runtime.dns_policy_runtime_snapshot().generation,
            known_bad_reputation_hash_count: state.runtime.known_bad_reputation_hash_count(),
        };
        return encrypted_control_response(&state, response);
    }

    let command_id = command.command_id.clone();

    if let Some(policy) = command.policy {
        if let Err(error) = policy.validate() {
            warn!(?error, "rejected invalid pushed SMB policy");
            return StatusCode::BAD_REQUEST.into_response();
        }
        state.runtime.update_policy(policy);
    }

    if let Some(dns_policy) = command.dns_policy {
        if let Err(error) = dns_policy.validate() {
            warn!(?error, "rejected invalid pushed DNS policy");
            return StatusCode::BAD_REQUEST.into_response();
        }
        state.runtime.update_dns_policy(dns_policy);
    }

    if let Some(known_bad_hashes) = command.known_bad_reputation_hashes {
        state
            .runtime
            .update_known_bad_reputation_hashes(known_bad_hashes);
        info!(
            node_id = state.node_id,
            loaded = state.runtime.known_bad_reputation_hash_count(),
            "applied pushed known bad reputation feed"
        );
    }

    let response = ControlApplyResponse {
        accepted: true,
        message: format!(
            "policy push applied on {}; known_bad_hashes_loaded={}",
            state.role.as_str(),
            state.runtime.known_bad_reputation_hash_count()
        ),
        applied_unix_timestamp_seconds: unix_timestamp_seconds(),
        policy_generation: state.runtime.policy_runtime_snapshot().generation,
        dns_policy_generation: state.runtime.dns_policy_runtime_snapshot().generation,
        known_bad_reputation_hash_count: state.runtime.known_bad_reputation_hash_count(),
    };

    info!(
        node_id = state.node_id,
        command_id, "applied pushed control policy bundle"
    );
    encrypted_control_response(&state, response)
}

fn encrypted_control_response(
    state: &NodeControlState,
    response: ControlApplyResponse,
) -> Response {
    match encrypt_payload(&state.node_id, &state.shared_secret, &response) {
        Ok(envelope) => Json(envelope).into_response(),
        Err(error) => {
            warn!(?error, "failed encrypting control response");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

fn command_seen(state: &NodeControlState, command_id: &str) -> bool {
    let mut seen_commands = state
        .seen_commands
        .lock()
        .expect("node control command cache mutex poisoned");

    if seen_commands.iter().any(|seen| seen == command_id) {
        return true;
    }

    if seen_commands.len() >= 256 {
        seen_commands.pop_front();
    }
    seen_commands.push_back(command_id.to_string());
    false
}

fn bearer_token_matches(headers: &HeaderMap, expected_token: &str) -> bool {
    if let Some(header_value) = headers.get(header::AUTHORIZATION)
        && let Ok(value) = header_value.to_str()
        && let Some(token) = value.strip_prefix("Bearer ")
    {
        return constant_time_eq(token.as_bytes(), expected_token.as_bytes());
    }

    false
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }

    let mut diff = 0_u8;
    for (left, right) in left.iter().zip(right.iter()) {
        diff |= left ^ right;
    }

    diff == 0
}

fn unix_timestamp_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs()
}

async fn run_node_agent(config: AxiomConfig, runtime: Arc<RuntimeState>) -> anyhow::Result<()> {
    let management_url = config
        .node
        .management_url
        .as_deref()
        .context("node.management_url is required for agent roles")?
        .trim_end_matches('/')
        .to_string();
    let enrollment_token = config
        .node
        .enrollment_token
        .as_deref()
        .context("node.enrollment_token is required for agent roles")?
        .to_string();
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(6))
        .user_agent("AxiomNodeAgent/0.1")
        .danger_accept_invalid_certs(config.node.allow_invalid_management_tls)
        .build()
        .context("failed building node agent HTTP client")?;
    let mut interval = tokio::time::interval(Duration::from_secs(
        config.node.heartbeat_interval_seconds.max(1),
    ));
    let mut reputation_cache: HashMap<String, CachedReputation> = HashMap::new();

    info!(
        node_id = config.node.node_id,
        role = config.node.role.as_str(),
        management_url,
        "Axiom node agent started"
    );

    loop {
        interval.tick().await;

        if let Err(error) =
            pull_runtime_config(&client, &management_url, &enrollment_token, &runtime).await
        {
            warn!(
                ?error,
                "failed pulling runtime config from management server"
            );
        }

        process_completed_file_reputation(
            &client,
            &management_url,
            &enrollment_token,
            &config,
            &runtime,
            &mut reputation_cache,
        )
        .await;

        if let Err(error) = post_node_report(
            &client,
            &management_url,
            &enrollment_token,
            &config,
            &runtime,
        )
        .await
        {
            warn!(?error, "failed posting node report to management server");
        }
    }
}

async fn bootstrap_node_runtime_config(
    config: &AxiomConfig,
    runtime: &Arc<RuntimeState>,
) -> anyhow::Result<()> {
    let management_url = config
        .node
        .management_url
        .as_deref()
        .context("node.management_url is required for agent roles")?
        .trim_end_matches('/')
        .to_string();
    let enrollment_token = config
        .node
        .enrollment_token
        .as_deref()
        .context("node.enrollment_token is required for agent roles")?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(6))
        .user_agent("AxiomNodeBootstrap/0.1")
        .danger_accept_invalid_certs(config.node.allow_invalid_management_tls)
        .build()
        .context("failed building node bootstrap HTTP client")?;

    pull_runtime_config(&client, &management_url, enrollment_token, runtime).await?;
    info!(
        node_id = config.node.node_id,
        role = config.node.role.as_str(),
        loaded = runtime.known_bad_reputation_hash_count(),
        "bootstrapped runtime config from management"
    );

    Ok(())
}

fn smb_reputation_lookup_config(config: &AxiomConfig) -> Option<axiom_net::ReputationLookupConfig> {
    if !config.node.role.runs_agent() {
        return None;
    }

    let management_url = config.node.management_url.as_deref()?.trim();
    let enrollment_token = config.node.enrollment_token.as_deref()?.trim();
    if management_url.is_empty() || enrollment_token.is_empty() {
        return None;
    }

    Some(axiom_net::ReputationLookupConfig {
        management_url: management_url.to_string(),
        enrollment_token: enrollment_token.to_string(),
        allow_invalid_tls: config.node.allow_invalid_management_tls,
        max_inline_lookup_bytes: 1024 * 1024,
    })
}

#[derive(Debug, Clone)]
struct CachedReputation {
    verdict: ReputationVerdict,
    expires_at_unix_timestamp_seconds: u64,
    hit_count: u64,
    last_seen_unix_timestamp_seconds: u64,
}

async fn process_completed_file_reputation(
    client: &reqwest::Client,
    management_url: &str,
    enrollment_token: &str,
    config: &AxiomConfig,
    runtime: &RuntimeState,
    cache: &mut HashMap<String, CachedReputation>,
) {
    let policy = runtime.policy_config().reputation;
    if !policy.enabled {
        return;
    }

    let transfers = runtime.drain_completed_file_transfers(64);
    if transfers.is_empty() {
        return;
    }

    for transfer in transfers {
        let verdict = match cached_or_lookup_reputation(
            client,
            management_url,
            enrollment_token,
            &transfer.sha256,
            policy.cache_ttl_seconds,
            cache,
        )
        .await
        {
            Ok(verdict) => verdict,
            Err(error) => {
                warn!(
                    sha256 = transfer.sha256,
                    ?error,
                    "management reputation lookup failed; failing open"
                );
                ReputationVerdict::Unknown
            }
        };

        if let Err(error) =
            post_file_reputation_report(client, management_url, enrollment_token, config, &transfer)
                .await
        {
            warn!(
                sha256 = transfer.sha256,
                ?error,
                "failed posting SMB file reputation report"
            );
        }

        let action = if verdict == ReputationVerdict::KnownBad {
            if runtime.add_known_bad_reputation_hash(&transfer.sha256) {
                info!(
                    sha256 = transfer.sha256,
                    loaded = runtime.known_bad_reputation_hash_count(),
                    "learned known bad reputation hash from management lookup"
                );
            }
            policy.known_bad_action
        } else {
            KnownBadAction::Allow
        };
        let reason = match verdict {
            ReputationVerdict::KnownGood => {
                format!("reputation known_good for {}", transfer.sha256)
            }
            ReputationVerdict::KnownBad => format!(
                "reputation known_bad for {}; configured action {:?}",
                transfer.sha256, action
            ),
            ReputationVerdict::Unknown => {
                format!(
                    "reputation unknown for {}; queued for async scan",
                    transfer.sha256
                )
            }
        };
        runtime.record_reputation_verdict(&transfer, verdict, action, reason);
    }
}

async fn cached_or_lookup_reputation(
    client: &reqwest::Client,
    management_url: &str,
    enrollment_token: &str,
    sha256: &str,
    ttl_seconds: u64,
    cache: &mut HashMap<String, CachedReputation>,
) -> anyhow::Result<ReputationVerdict> {
    let now = unix_timestamp_seconds();
    if let Some(entry) = cache.get_mut(sha256)
        && entry.expires_at_unix_timestamp_seconds > now
    {
        entry.hit_count = entry.hit_count.saturating_add(1);
        entry.last_seen_unix_timestamp_seconds = now;
        return Ok(entry.verdict);
    }

    let response = client
        .get(format!("{management_url}/api/reputation/lookup/{sha256}"))
        .bearer_auth(enrollment_token)
        .send()
        .await
        .context("reputation lookup request failed")?;

    if !response.status().is_success() {
        return Err(anyhow::anyhow!(
            "management returned HTTP {} for reputation lookup",
            response.status()
        ));
    }

    let payload: ReputationLookupResponse = response
        .json()
        .await
        .context("failed decoding reputation lookup response")?;
    cache.insert(
        sha256.to_string(),
        CachedReputation {
            verdict: payload.verdict,
            expires_at_unix_timestamp_seconds: cache_expiry_timestamp(ttl_seconds),
            hit_count: 1,
            last_seen_unix_timestamp_seconds: now,
        },
    );

    Ok(payload.verdict)
}

async fn post_file_reputation_report(
    client: &reqwest::Client,
    management_url: &str,
    enrollment_token: &str,
    config: &AxiomConfig,
    transfer: &CompletedFileTransfer,
) -> anyhow::Result<()> {
    let report = FileReputationReport {
        node_id: config.node.node_id.clone(),
        route_name: transfer.route_name.clone(),
        interface: transfer.interface.clone(),
        direction: format!("{:?}", transfer.direction).to_ascii_lowercase(),
        source_ip: transfer.peer_addr.ip().to_string(),
        target_addr: transfer.target_addr.to_string(),
        destination_share: transfer.destination_share.clone(),
        source_user: transfer.source_user.clone(),
        file_name: transfer.file_name.clone(),
        extension: transfer.extension.clone(),
        mime_type: transfer.mime_type.clone(),
        file_size: transfer.file_size,
        creation_time: transfer.creation_time,
        upload_timestamp: transfer.upload_timestamp,
        sha256: transfer.sha256.clone(),
        md5: transfer.md5.clone(),
    };

    let response = client
        .post(format!("{management_url}/api/reputation/files"))
        .bearer_auth(enrollment_token)
        .json(&report)
        .send()
        .await
        .context("file reputation report request failed")?;

    if !response.status().is_success() {
        return Err(anyhow::anyhow!(
            "management returned HTTP {} for file reputation report",
            response.status()
        ));
    }

    Ok(())
}

async fn pull_runtime_config(
    client: &reqwest::Client,
    management_url: &str,
    enrollment_token: &str,
    runtime: &RuntimeState,
) -> anyhow::Result<()> {
    let response = client
        .get(format!("{management_url}/api/nodes/runtime-config"))
        .bearer_auth(enrollment_token)
        .send()
        .await
        .context("runtime config request failed")?;

    if !response.status().is_success() {
        return Err(anyhow::anyhow!(
            "management returned HTTP {} for runtime config",
            response.status()
        ));
    }

    let payload: serde_json::Value = response
        .json()
        .await
        .context("failed decoding runtime config response")?;

    if let Some(policy_value) = payload.pointer("/policy_runtime/active_policy") {
        let policy = serde_json::from_value(policy_value.clone())
            .context("failed decoding SMB policy from management")?;
        runtime.update_policy(policy);
    }

    if let Some(dns_policy_value) = payload.pointer("/dns_policy_runtime/active_policy") {
        let dns_policy = serde_json::from_value(dns_policy_value.clone())
            .context("failed decoding DNS policy from management")?;
        runtime.update_dns_policy(dns_policy);
    }

    if let Some(hashes_value) = payload.get("known_bad_reputation_hashes") {
        let hashes = serde_json::from_value(hashes_value.clone())
            .context("failed decoding known bad reputation hashes from management")?;
        runtime.update_known_bad_reputation_hashes(hashes);
        info!(
            loaded = runtime.known_bad_reputation_hash_count(),
            "pulled known bad reputation feed from management"
        );
    }

    Ok(())
}

async fn post_node_report(
    client: &reqwest::Client,
    management_url: &str,
    enrollment_token: &str,
    config: &AxiomConfig,
    runtime: &RuntimeState,
) -> anyhow::Result<()> {
    let report = json!({
        "node_id": config.node.node_id,
        "display_name": config.node.display_name,
        "role": config.node.role,
        "hostname": hostname(),
        "version": env!("CARGO_PKG_VERSION"),
        "management_url": config.node.management_url,
        "control_url": node_control_url(config),
        "cluster_name": config.node.cluster.name,
        "service_template": ClusterServiceTemplate::from_config(config),
        "proxy_listeners": config.proxy_listeners.iter().map(proxy_listener_status).collect::<Vec<_>>(),
        "dns": dns_status(&config.dns),
        "stats": runtime.snapshot(),
    });

    let response = client
        .post(format!("{management_url}/api/nodes/report"))
        .bearer_auth(enrollment_token)
        .json(&report)
        .send()
        .await
        .context("node report request failed")?;

    if !response.status().is_success() {
        return Err(anyhow::anyhow!(
            "management returned HTTP {} for node report",
            response.status()
        ));
    }

    Ok(())
}

fn node_control_url(config: &AxiomConfig) -> Option<String> {
    if !config.node.control.enabled {
        return None;
    }

    let listen_addr = config.node.control.listen_addr();
    Some(format!("http://{listen_addr}"))
}

fn proxy_listener_status(listener: &ProxyListenerConfig) -> serde_json::Value {
    json!({
        "name": listener.name,
        "source_interface": listener.source_interface,
        "client_vlan": listener.client_vlan,
        "listen_addr": listener.listen_addr().to_string(),
        "target_file_server_addr": listener.target_addr().to_string(),
    })
}

fn dns_status(dns: &DnsConfig) -> serde_json::Value {
    json!({
        "enabled": dns.enabled,
        "interface": dns.interface,
        "listen_udp_addr": dns.udp_listen_addr().to_string(),
        "listen_tcp_addr": dns.tcp_listen_addr().to_string(),
        "upstream_interface": dns.upstream_interface(),
        "upstreams": dns.upstreams.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "threat_feed_urls": dns.policy.threat_feed_urls,
        "blocked_domains": dns.policy.blocked_domains.len(),
        "monitored_domains": dns.policy.monitored_domains.len(),
        "local_records": dns.policy.local_records.len(),
        "block_response": format!("{:?}", dns.policy.block_response).to_ascii_lowercase(),
        "deployment_warnings": Vec::<String>::new(),
    })
}

fn hostname() -> String {
    fs::read_to_string("/etc/hostname")
        .map(|value| value.trim().to_string())
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

fn init_tracing() {
    tracing_subscriber::registry()
        .with(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("axiom=info,axiom_daemon=info,axiom_dns=info")),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();
}
