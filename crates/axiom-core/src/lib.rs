use std::{
    collections::{HashMap, HashSet, VecDeque},
    fs::OpenOptions,
    io::Write,
    net::SocketAddr,
    sync::{
        Mutex, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axiom_config::{DnsPolicyConfig, PolicyConfig, PolicyMode};
use axiom_reputation::{KnownBadAction, ReputationVerdict};
use serde::Serialize;

const MAX_RETAINED_THREAT_EVENTS: usize = 128;
const MAX_RETAINED_AUDIT_EVENTS: usize = 512;
const MAX_RETAINED_DNS_EVENTS: usize = 512;
const MAX_RETAINED_FILE_HASH_EVENTS: usize = 512;
const MAX_TRACKED_FILE_ACTIVITIES: usize = 512;
const ARCHIVE_MAX_PATTERN_LEN: usize = 8;
const STREAM_INSPECTION_TAIL_LEN: usize = 4096;
const AUDIT_LOG_PATH: &str = "/var/log/axiom/audit.jsonl";

#[derive(Debug)]
pub struct AppState {
    started_at: SystemTime,
    counters: TrafficCounters,
    policy: RwLock<StreamPolicy>,
    dns_policy: RwLock<DnsPolicyConfig>,
    policy_generation: AtomicU64,
    dns_policy_generation: AtomicU64,
    policy_updated_at_unix_timestamp_seconds: AtomicU64,
    dns_policy_updated_at_unix_timestamp_seconds: AtomicU64,
    route_stats: Mutex<HashMap<String, RouteRuntimeStats>>,
    active_connections: Mutex<HashMap<String, ActiveConnectionStats>>,
    file_activity: Mutex<HashMap<String, FileActivityStats>>,
    recent_threats: Mutex<VecDeque<ThreatEvent>>,
    recent_audit_events: Mutex<VecDeque<AuditEvent>>,
    recent_dns_events: Mutex<VecDeque<DnsQueryEvent>>,
    completed_file_hashes: Mutex<VecDeque<CompletedFileTransfer>>,
    known_bad_reputation_hashes: RwLock<HashSet<String>>,
}

impl AppState {
    pub fn new(policy: StreamPolicy, dns_policy: DnsPolicyConfig) -> Self {
        Self {
            started_at: SystemTime::now(),
            counters: TrafficCounters::default(),
            policy: RwLock::new(policy),
            dns_policy: RwLock::new(dns_policy),
            policy_generation: AtomicU64::new(1),
            dns_policy_generation: AtomicU64::new(1),
            policy_updated_at_unix_timestamp_seconds: AtomicU64::new(unix_timestamp_seconds()),
            dns_policy_updated_at_unix_timestamp_seconds: AtomicU64::new(unix_timestamp_seconds()),
            route_stats: Mutex::new(HashMap::new()),
            active_connections: Mutex::new(HashMap::new()),
            file_activity: Mutex::new(HashMap::new()),
            recent_threats: Mutex::new(VecDeque::with_capacity(MAX_RETAINED_THREAT_EVENTS)),
            recent_audit_events: Mutex::new(VecDeque::with_capacity(MAX_RETAINED_AUDIT_EVENTS)),
            recent_dns_events: Mutex::new(VecDeque::with_capacity(MAX_RETAINED_DNS_EVENTS)),
            completed_file_hashes: Mutex::new(VecDeque::with_capacity(
                MAX_RETAINED_FILE_HASH_EVENTS,
            )),
            known_bad_reputation_hashes: RwLock::new(HashSet::new()),
        }
    }

    pub fn register_route(
        &self,
        route_name: &str,
        interface: &str,
        listen_addr: SocketAddr,
        target_addr: SocketAddr,
    ) {
        let mut route_stats = self.route_stats.lock().expect("route stats mutex poisoned");
        route_stats
            .entry(route_name.to_string())
            .and_modify(|route| {
                route.interface = interface.to_string();
                route.listen_addr = listen_addr.to_string();
                route.target_addr = target_addr.to_string();
                route.listener_ready = true;
                route.last_activity_unix_timestamp_seconds = Some(unix_timestamp_seconds());
            })
            .or_insert_with(|| RouteRuntimeStats {
                route_name: route_name.to_string(),
                interface: interface.to_string(),
                listen_addr: listen_addr.to_string(),
                target_addr: target_addr.to_string(),
                listener_ready: true,
                ..RouteRuntimeStats::default()
            });
    }

    pub fn connection_started(&self) {
        self.counters
            .total_connections
            .fetch_add(1, Ordering::Relaxed);
        self.counters
            .active_connections
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn route_connection_started(&self, route_name: &str, peer_addr: SocketAddr) {
        self.with_route_stats(route_name, |route| {
            route.total_connections += 1;
            route.active_connections += 1;
            route.last_peer_addr = Some(peer_addr.to_string());
        });
    }

    pub fn record_connection_opened(&self, context: &InspectionContext<'_>) {
        self.upsert_active_connection(context, |connection| {
            connection.last_action = "allow".to_string();
            connection.last_reason = "SMB client connection opened".to_string();
        });
        self.push_audit_event(AuditEvent::from_context(
            context,
            AuditEventKind::ConnectionOpened,
            AuditSeverity::Info,
            None,
            "allow".to_string(),
            "SMB client connection opened".to_string(),
            None,
            None,
        ));
    }

    pub fn connection_finished(&self) {
        let _ = self.counters.active_connections.fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |value| Some(value.saturating_sub(1)),
        );
    }

    pub fn route_connection_finished(&self, route_name: &str) {
        self.with_route_stats(route_name, |route| {
            route.active_connections = route.active_connections.saturating_sub(1);
        });
    }

    pub fn record_connection_closed(&self, context: &InspectionContext<'_>) {
        self.remove_active_connection(context);
        self.push_audit_event(AuditEvent::from_context(
            context,
            AuditEventKind::ConnectionClosed,
            AuditSeverity::Info,
            None,
            "close".to_string(),
            "SMB client connection closed".to_string(),
            None,
            None,
        ));
    }

    pub fn record_bytes(&self, direction: TrafficDirection, bytes: u64) {
        match direction {
            TrafficDirection::ClientToServer => self
                .counters
                .bytes_client_to_server
                .fetch_add(bytes, Ordering::Relaxed),
            TrafficDirection::ServerToClient => self
                .counters
                .bytes_server_to_client
                .fetch_add(bytes, Ordering::Relaxed),
        };
    }

    pub fn record_stream_bytes(&self, route_name: &str, direction: TrafficDirection, bytes: u64) {
        match direction {
            TrafficDirection::ClientToServer => self
                .counters
                .stream_bytes_client_to_server
                .fetch_add(bytes, Ordering::Relaxed),
            TrafficDirection::ServerToClient => self
                .counters
                .stream_bytes_server_to_client
                .fetch_add(bytes, Ordering::Relaxed),
        };

        self.with_route_stats(route_name, |route| match direction {
            TrafficDirection::ClientToServer => route.stream_bytes_client_to_server += bytes,
            TrafficDirection::ServerToClient => route.stream_bytes_server_to_client += bytes,
        });
    }

    pub fn record_connection_stream_bytes(&self, context: &InspectionContext<'_>, bytes: u64) {
        self.record_stream_bytes(context.route_name, context.direction, bytes);
        self.upsert_active_connection(context, |connection| {
            match context.direction {
                TrafficDirection::ClientToServer => {
                    connection.stream_bytes_client_to_server += bytes;
                }
                TrafficDirection::ServerToClient => {
                    connection.stream_bytes_server_to_client += bytes;
                }
            }
            connection.last_action = "read".to_string();
            connection.last_reason = "SMB socket bytes read by proxy".to_string();
        });
    }

    pub fn record_route_bytes(&self, route_name: &str, direction: TrafficDirection, bytes: u64) {
        self.with_route_stats(route_name, |route| match direction {
            TrafficDirection::ClientToServer => route.bytes_client_to_server += bytes,
            TrafficDirection::ServerToClient => route.bytes_server_to_client += bytes,
        });
    }

    pub fn record_forwarded_bytes(&self, context: &InspectionContext<'_>, bytes: u64) {
        self.record_bytes(context.direction, bytes);
        self.record_route_bytes(context.route_name, context.direction, bytes);
        self.upsert_active_connection(context, |connection| {
            match context.direction {
                TrafficDirection::ClientToServer => {
                    connection.forwarded_bytes_client_to_server += bytes;
                }
                TrafficDirection::ServerToClient => {
                    connection.forwarded_bytes_server_to_client += bytes;
                }
            }
            connection.last_action = "forward".to_string();
            connection.last_reason = "SMB frame forwarded after inspection".to_string();
            if let Some(file_path) = context.file_path_hint {
                connection.last_file_path = Some(file_path.to_string());
            }
        });
    }

    pub fn record_inspection(&self, bytes: u64) {
        self.counters
            .inspected_chunks
            .fetch_add(1, Ordering::Relaxed);
        self.counters
            .inspected_bytes
            .fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn record_route_inspection(&self, route_name: &str, bytes: u64) {
        self.with_route_stats(route_name, |route| {
            route.inspected_chunks += 1;
            route.inspected_bytes += bytes;
        });
    }

    pub fn record_allowed_chunk(&self) {
        self.counters.allowed_chunks.fetch_add(1, Ordering::Relaxed);
    }

    pub fn update_known_bad_reputation_hashes(&self, hashes: Vec<String>) {
        let normalized_hashes = hashes
            .into_iter()
            .map(|hash| hash.trim().to_ascii_lowercase())
            .filter(|hash| hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .collect();
        *self
            .known_bad_reputation_hashes
            .write()
            .expect("known bad reputation hashes lock poisoned") = normalized_hashes;
    }

    pub fn add_known_bad_reputation_hash(&self, hash: &str) -> bool {
        let normalized = hash.trim().to_ascii_lowercase();
        if normalized.len() != 64 || !normalized.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return false;
        }

        self.known_bad_reputation_hashes
            .write()
            .expect("known bad reputation hashes lock poisoned")
            .insert(normalized)
    }

    pub fn is_known_bad_reputation_hash(&self, sha256: &str) -> bool {
        let normalized = sha256.trim().to_ascii_lowercase();
        self.known_bad_reputation_hashes
            .read()
            .expect("known bad reputation hashes lock poisoned")
            .contains(&normalized)
    }

    pub fn known_bad_reputation_hash_count(&self) -> usize {
        self.known_bad_reputation_hashes
            .read()
            .expect("known bad reputation hashes lock poisoned")
            .len()
    }

    pub fn record_file_observed(
        &self,
        context: &InspectionContext<'_>,
        file_path: String,
        bytes_in_chunk: u64,
    ) {
        self.counters
            .observed_file_events
            .fetch_add(1, Ordering::Relaxed);
        self.record_file_activity(context, file_path.clone(), |activity| {
            activity.observed_events += 1;
            activity.last_action = "observe".to_string();
            activity.last_reason = "SMB file open/create observed".to_string();
            activity.last_rule_name = None;
            activity.last_bytes_in_chunk = Some(bytes_in_chunk);
        });
        self.upsert_active_connection(context, |connection| {
            connection.last_file_path = Some(file_path.clone());
            connection.observed_file_events += 1;
            connection.last_action = "observe".to_string();
            connection.last_reason = "SMB file open/create observed".to_string();
        });
        self.push_audit_event(AuditEvent::from_context(
            context,
            AuditEventKind::FileObserved,
            AuditSeverity::Info,
            Some(file_path),
            "observe".to_string(),
            "SMB file open/create observed".to_string(),
            Some(bytes_in_chunk),
            None,
        ));
    }

    pub fn record_smb_write_payload(&self, route_name: &str, bytes: u64) {
        self.counters
            .smb_write_requests
            .fetch_add(1, Ordering::Relaxed);
        self.counters
            .smb_write_bytes
            .fetch_add(bytes, Ordering::Relaxed);
        self.with_route_stats(route_name, |route| {
            route.smb_write_requests += 1;
            route.smb_write_bytes += bytes;
        });
    }

    pub fn record_smb_write_payload_for_connection(
        &self,
        context: &InspectionContext<'_>,
        bytes: u64,
    ) {
        self.record_smb_write_payload(context.route_name, bytes);
        self.upsert_active_connection(context, |connection| {
            connection.smb_write_requests += 1;
            connection.smb_write_bytes += bytes;
            connection.last_action = "write".to_string();
            connection.last_reason = "SMB WRITE payload observed".to_string();
            if let Some(file_path) = context.file_path_hint {
                connection.last_file_path = Some(file_path.to_string());
            }
        });
    }

    pub fn record_file_write_payload(
        &self,
        context: &InspectionContext<'_>,
        file_path: &str,
        bytes: u64,
    ) {
        self.record_smb_write_payload_for_connection(context, bytes);
        self.record_file_activity(context, file_path.to_string(), |activity| {
            activity.smb_write_requests += 1;
            activity.smb_write_bytes += bytes;
            activity.last_action = "write".to_string();
            activity.last_reason = "SMB WRITE payload observed".to_string();
            activity.last_rule_name = None;
            activity.last_bytes_in_chunk = Some(bytes);
        });
        self.upsert_active_connection(context, |connection| {
            connection.last_file_path = Some(file_path.to_string());
        });
    }

    pub fn record_completed_file_transfer(&self, transfer: CompletedFileTransfer) {
        self.counters
            .completed_file_hashes
            .fetch_add(1, Ordering::Relaxed);
        let context = InspectionContext {
            route_name: &transfer.route_name,
            interface: &transfer.interface,
            direction: transfer.direction,
            peer_addr: transfer.peer_addr,
            target_addr: transfer.target_addr,
            file_path_hint: Some(&transfer.file_name),
        };
        self.push_audit_event(AuditEvent::from_context(
            &context,
            AuditEventKind::FileHashCompleted,
            AuditSeverity::Info,
            Some(transfer.file_name.clone()),
            "hash".to_string(),
            format!(
                "SMB file hash completed sha256={} md5={} size={}",
                transfer.sha256, transfer.md5, transfer.file_size
            ),
            Some(transfer.file_size),
            Some("SMB streaming hash".to_string()),
        ));

        let mut completed = self
            .completed_file_hashes
            .lock()
            .expect("completed file hash mutex poisoned");
        if completed.len() == MAX_RETAINED_FILE_HASH_EVENTS {
            completed.pop_front();
        }
        completed.push_back(transfer);
    }

    pub fn drain_completed_file_transfers(&self, max_items: usize) -> Vec<CompletedFileTransfer> {
        let mut completed = self
            .completed_file_hashes
            .lock()
            .expect("completed file hash mutex poisoned");
        let mut drained = Vec::new();
        for _ in 0..max_items {
            let Some(item) = completed.pop_front() else {
                break;
            };
            drained.push(item);
        }
        drained
    }

    pub fn record_reputation_verdict(
        &self,
        transfer: &CompletedFileTransfer,
        verdict: ReputationVerdict,
        action: KnownBadAction,
        reason: String,
    ) {
        match verdict {
            ReputationVerdict::KnownBad => {
                self.counters
                    .known_bad_reputation_events
                    .fetch_add(1, Ordering::Relaxed);
            }
            ReputationVerdict::KnownGood => {
                self.counters
                    .known_good_reputation_events
                    .fetch_add(1, Ordering::Relaxed);
            }
            ReputationVerdict::Unknown => {
                self.counters
                    .unknown_reputation_events
                    .fetch_add(1, Ordering::Relaxed);
            }
        }

        let context = InspectionContext {
            route_name: &transfer.route_name,
            interface: &transfer.interface,
            direction: transfer.direction,
            peer_addr: transfer.peer_addr,
            target_addr: transfer.target_addr,
            file_path_hint: Some(&transfer.file_name),
        };
        let severity = match verdict {
            ReputationVerdict::KnownBad => AuditSeverity::Critical,
            ReputationVerdict::Unknown => AuditSeverity::Warning,
            ReputationVerdict::KnownGood => AuditSeverity::Info,
        };
        self.push_audit_event(AuditEvent::from_context(
            &context,
            AuditEventKind::ReputationVerdict,
            severity,
            Some(transfer.file_name.clone()),
            format!("{action:?}").to_ascii_lowercase(),
            reason,
            Some(transfer.file_size),
            Some(format!("{verdict:?}")),
        ));
    }

    pub fn record_server_side_copy_requested(&self, context: &InspectionContext<'_>) {
        self.counters
            .server_side_copy_requests
            .fetch_add(1, Ordering::Relaxed);
        self.push_audit_event(AuditEvent::from_context(
            context,
            AuditEventKind::ServerSideCopyRequested,
            AuditSeverity::Warning,
            None,
            "observe".to_string(),
            "SMB server-side copy request observed; file bytes may not cross the proxy".to_string(),
            None,
            Some("SMB2 IOCTL copychunk".to_string()),
        ));
        self.upsert_active_connection(context, |connection| {
            connection.server_side_copy_requests += 1;
            connection.last_action = "observe".to_string();
            connection.last_reason =
                "SMB server-side copy request observed; file bytes may not cross the proxy"
                    .to_string();
        });
    }

    pub fn record_smb_multichannel_blocked(&self, context: &InspectionContext<'_>, bytes: u64) {
        let event = ThreatEvent::now(
            context,
            PolicyMode::Block,
            "SMB multichannel bypass protection".to_string(),
            "SMB multichannel interface discovery was blocked so clients stay on the Axiom proxy path"
                .to_string(),
            bytes as usize,
            0.0,
        );
        self.record_blocked_threat(event);
    }

    pub fn record_monitored_threat(&self, event: ThreatEvent) {
        self.counters
            .monitored_chunks
            .fetch_add(1, Ordering::Relaxed);
        self.counters
            .monitored_threats
            .fetch_add(1, Ordering::Relaxed);
        self.with_route_stats(&event.route_name, |route| {
            route.monitored_events += 1;
        });
        self.record_file_activity_for_threat(&event);
        self.record_active_connection_threat(&event);
        self.push_audit_event(AuditEvent::from_threat(
            &event,
            AuditEventKind::PolicyDetection,
            AuditSeverity::Warning,
        ));
        self.push_recent_event(event);
    }

    pub fn record_blocked_threat(&self, event: ThreatEvent) {
        self.counters.blocked_chunks.fetch_add(1, Ordering::Relaxed);
        self.counters
            .blocked_threats
            .fetch_add(1, Ordering::Relaxed);
        self.with_route_stats(&event.route_name, |route| {
            route.blocked_events += 1;
        });
        self.record_file_activity_for_threat(&event);
        self.record_active_connection_threat(&event);
        self.push_audit_event(AuditEvent::from_threat(
            &event,
            AuditEventKind::PolicyBlocked,
            AuditSeverity::Critical,
        ));
        self.push_recent_event(event);
    }

    pub fn record_dns_query(&self, event: DnsQueryEvent) {
        self.counters.dns_queries.fetch_add(1, Ordering::Relaxed);

        match event.protocol {
            DnsProtocol::Udp => {
                self.counters
                    .dns_udp_queries
                    .fetch_add(1, Ordering::Relaxed);
            }
            DnsProtocol::Tcp => {
                self.counters
                    .dns_tcp_queries
                    .fetch_add(1, Ordering::Relaxed);
            }
        }

        match event.action {
            DnsAction::Allow => {}
            DnsAction::Monitor => {
                self.counters
                    .dns_monitored_queries
                    .fetch_add(1, Ordering::Relaxed);
            }
            DnsAction::Block => {
                self.counters
                    .dns_blocked_queries
                    .fetch_add(1, Ordering::Relaxed);
            }
            DnsAction::Error => {}
        }

        if event.cache_hit {
            self.counters.dns_cache_hits.fetch_add(1, Ordering::Relaxed);
        }

        let mut events = self
            .recent_dns_events
            .lock()
            .expect("recent dns event mutex poisoned");

        if events.len() == MAX_RETAINED_DNS_EVENTS {
            events.pop_front();
        }
        events.push_back(event);
    }

    pub fn record_dns_upstream_error(&self) {
        self.counters
            .dns_upstream_errors
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inspect_chunk(&self, context: &InspectionContext<'_>, chunk: &[u8]) -> InspectionResult {
        self.policy
            .read()
            .expect("stream policy lock poisoned")
            .inspect_chunk(context, chunk)
    }

    pub fn policy_config(&self) -> PolicyConfig {
        self.policy
            .read()
            .expect("stream policy lock poisoned")
            .config()
            .clone()
    }

    pub fn update_policy(&self, policy: PolicyConfig) -> PolicyRuntimeSnapshot {
        {
            let mut guard = self.policy.write().expect("stream policy lock poisoned");
            *guard = StreamPolicy::from_config(policy);
        }

        let updated_at = unix_timestamp_seconds();
        self.policy_updated_at_unix_timestamp_seconds
            .store(updated_at, Ordering::Relaxed);
        self.policy_generation.fetch_add(1, Ordering::Relaxed);
        self.policy_runtime_snapshot()
    }

    pub fn dns_policy_config(&self) -> DnsPolicyConfig {
        self.dns_policy
            .read()
            .expect("dns policy lock poisoned")
            .clone()
    }

    pub fn update_dns_policy(&self, policy: DnsPolicyConfig) -> DnsPolicyRuntimeSnapshot {
        {
            let mut guard = self.dns_policy.write().expect("dns policy lock poisoned");
            *guard = policy;
        }

        let updated_at = unix_timestamp_seconds();
        self.dns_policy_updated_at_unix_timestamp_seconds
            .store(updated_at, Ordering::Relaxed);
        self.dns_policy_generation.fetch_add(1, Ordering::Relaxed);
        self.dns_policy_runtime_snapshot()
    }

    pub fn dns_policy_runtime_snapshot(&self) -> DnsPolicyRuntimeSnapshot {
        DnsPolicyRuntimeSnapshot {
            generation: self.dns_policy_generation.load(Ordering::Relaxed),
            last_updated_unix_timestamp_seconds: self
                .dns_policy_updated_at_unix_timestamp_seconds
                .load(Ordering::Relaxed),
            active_policy: self.dns_policy_config(),
        }
    }

    pub fn max_pattern_len(&self) -> usize {
        let policy_len = self
            .policy
            .read()
            .expect("stream policy lock poisoned")
            .max_pattern_len();

        policy_len.max(STREAM_INSPECTION_TAIL_LEN)
    }

    pub fn policy_runtime_snapshot(&self) -> PolicyRuntimeSnapshot {
        let policy = self.policy_config();
        PolicyRuntimeSnapshot {
            generation: self.policy_generation.load(Ordering::Relaxed),
            last_updated_unix_timestamp_seconds: self
                .policy_updated_at_unix_timestamp_seconds
                .load(Ordering::Relaxed),
            blocking_rules: blocking_rules(&policy),
            monitoring_rules: monitoring_rules(&policy),
            active_policy: policy,
        }
    }

    pub fn snapshot(&self) -> StatusSnapshot {
        let recent_threats = self
            .recent_threats
            .lock()
            .expect("recent threat event mutex poisoned")
            .iter()
            .cloned()
            .collect();
        let recent_audit_events = self
            .recent_audit_events
            .lock()
            .expect("recent audit event mutex poisoned")
            .iter()
            .cloned()
            .collect();
        let recent_dns_events = self
            .recent_dns_events
            .lock()
            .expect("recent dns event mutex poisoned")
            .iter()
            .cloned()
            .collect();

        StatusSnapshot {
            uptime_seconds: self
                .started_at
                .elapsed()
                .unwrap_or_else(|_| Duration::from_secs(0))
                .as_secs(),
            total_connections: self.counters.total_connections.load(Ordering::Relaxed),
            active_connections: self.counters.active_connections.load(Ordering::Relaxed),
            inspected_chunks: self.counters.inspected_chunks.load(Ordering::Relaxed),
            inspected_bytes: self.counters.inspected_bytes.load(Ordering::Relaxed),
            allowed_chunks: self.counters.allowed_chunks.load(Ordering::Relaxed),
            monitored_chunks: self.counters.monitored_chunks.load(Ordering::Relaxed),
            blocked_chunks: self.counters.blocked_chunks.load(Ordering::Relaxed),
            observed_file_events: self.counters.observed_file_events.load(Ordering::Relaxed),
            audit_events: self.counters.audit_events.load(Ordering::Relaxed),
            stream_bytes_client_to_server: self
                .counters
                .stream_bytes_client_to_server
                .load(Ordering::Relaxed),
            stream_bytes_server_to_client: self
                .counters
                .stream_bytes_server_to_client
                .load(Ordering::Relaxed),
            bytes_client_to_server: self.counters.bytes_client_to_server.load(Ordering::Relaxed),
            bytes_server_to_client: self.counters.bytes_server_to_client.load(Ordering::Relaxed),
            smb_write_requests: self.counters.smb_write_requests.load(Ordering::Relaxed),
            smb_write_bytes: self.counters.smb_write_bytes.load(Ordering::Relaxed),
            server_side_copy_requests: self
                .counters
                .server_side_copy_requests
                .load(Ordering::Relaxed),
            completed_file_hashes: self.counters.completed_file_hashes.load(Ordering::Relaxed),
            known_good_reputation_events: self
                .counters
                .known_good_reputation_events
                .load(Ordering::Relaxed),
            known_bad_reputation_events: self
                .counters
                .known_bad_reputation_events
                .load(Ordering::Relaxed),
            unknown_reputation_events: self
                .counters
                .unknown_reputation_events
                .load(Ordering::Relaxed),
            known_bad_reputation_hashes_loaded: self.known_bad_reputation_hash_count(),
            dns_queries: self.counters.dns_queries.load(Ordering::Relaxed),
            dns_udp_queries: self.counters.dns_udp_queries.load(Ordering::Relaxed),
            dns_tcp_queries: self.counters.dns_tcp_queries.load(Ordering::Relaxed),
            dns_blocked_queries: self.counters.dns_blocked_queries.load(Ordering::Relaxed),
            dns_monitored_queries: self.counters.dns_monitored_queries.load(Ordering::Relaxed),
            dns_cache_hits: self.counters.dns_cache_hits.load(Ordering::Relaxed),
            dns_upstream_errors: self.counters.dns_upstream_errors.load(Ordering::Relaxed),
            monitored_threats: self.counters.monitored_threats.load(Ordering::Relaxed),
            blocked_threats: self.counters.blocked_threats.load(Ordering::Relaxed),
            policy_runtime: self.policy_runtime_snapshot(),
            dns_policy_runtime: self.dns_policy_runtime_snapshot(),
            audit_log_path: AUDIT_LOG_PATH.to_string(),
            route_stats: self.route_snapshots(),
            active_connection_details: self.active_connection_snapshots(),
            file_activity: self.file_activity_snapshots(),
            recent_threats,
            recent_audit_events,
            recent_dns_events,
        }
    }

    fn push_recent_event(&self, event: ThreatEvent) {
        let mut recent_threats = self
            .recent_threats
            .lock()
            .expect("recent threat event mutex poisoned");

        if recent_threats.len() == MAX_RETAINED_THREAT_EVENTS {
            recent_threats.pop_front();
        }
        recent_threats.push_back(event);
    }

    fn push_audit_event(&self, event: AuditEvent) {
        self.counters.audit_events.fetch_add(1, Ordering::Relaxed);
        append_audit_event_to_disk(&event);

        let mut audit_events = self
            .recent_audit_events
            .lock()
            .expect("recent audit event mutex poisoned");

        if audit_events.len() == MAX_RETAINED_AUDIT_EVENTS {
            audit_events.pop_front();
        }
        audit_events.push_back(event);
    }

    fn with_route_stats(&self, route_name: &str, update: impl FnOnce(&mut RouteRuntimeStats)) {
        let mut route_stats = self.route_stats.lock().expect("route stats mutex poisoned");
        let route = route_stats
            .entry(route_name.to_string())
            .or_insert_with(|| RouteRuntimeStats {
                route_name: route_name.to_string(),
                ..RouteRuntimeStats::default()
            });

        update(route);
        route.last_activity_unix_timestamp_seconds = Some(unix_timestamp_seconds());
    }

    fn record_file_activity(
        &self,
        context: &InspectionContext<'_>,
        file_path: String,
        update: impl FnOnce(&mut FileActivityStats),
    ) {
        let key = file_activity_key(context.route_name, context.peer_addr, &file_path);
        let mut file_activity = self
            .file_activity
            .lock()
            .expect("file activity mutex poisoned");

        if !file_activity.contains_key(&key)
            && file_activity.len() >= MAX_TRACKED_FILE_ACTIVITIES
            && let Some(oldest_key) = file_activity
                .iter()
                .min_by_key(|(_, activity)| activity.last_activity_unix_timestamp_seconds)
                .map(|(activity_key, _)| activity_key.clone())
        {
            file_activity.remove(&oldest_key);
        }

        let now = unix_timestamp_seconds();
        let activity = file_activity
            .entry(key)
            .and_modify(|activity| {
                activity.route_name = context.route_name.to_string();
                activity.interface = context.interface.to_string();
                activity.peer_addr = context.peer_addr;
                activity.target_addr = context.target_addr;
                activity.file_path = file_path.clone();
            })
            .or_insert_with(|| FileActivityStats {
                file_path: file_path.clone(),
                route_name: context.route_name.to_string(),
                interface: context.interface.to_string(),
                peer_addr: context.peer_addr,
                target_addr: context.target_addr,
                observed_events: 0,
                blocked_events: 0,
                monitored_events: 0,
                smb_write_requests: 0,
                smb_write_bytes: 0,
                last_action: "observe".to_string(),
                last_reason: String::new(),
                last_rule_name: None,
                last_bytes_in_chunk: None,
                last_activity_unix_timestamp_seconds: now,
            });

        update(activity);
        activity.last_activity_unix_timestamp_seconds = now;
    }

    fn record_file_activity_for_threat(&self, event: &ThreatEvent) {
        let Some(file_path) = event
            .file_path
            .clone()
            .or_else(|| extract_file_path_hint(&event.reason))
        else {
            return;
        };
        let file_path_hint = file_path.clone();
        let context = InspectionContext {
            route_name: &event.route_name,
            interface: &event.interface,
            direction: event.direction,
            peer_addr: event.peer_addr,
            target_addr: event.target_addr,
            file_path_hint: Some(&file_path_hint),
        };
        self.record_file_activity(&context, file_path, |activity| {
            match event.action {
                PolicyMode::Block => activity.blocked_events += 1,
                PolicyMode::Monitor => activity.monitored_events += 1,
                PolicyMode::Disabled => {}
            }
            activity.last_action = policy_mode_label(event.action).to_string();
            activity.last_reason = event.reason.clone();
            activity.last_rule_name = Some(event.rule_name.clone());
            activity.last_bytes_in_chunk = Some(event.bytes_in_chunk as u64);
        });
    }

    fn upsert_active_connection(
        &self,
        context: &InspectionContext<'_>,
        update: impl FnOnce(&mut ActiveConnectionStats),
    ) {
        let key = active_connection_key(context.route_name, context.peer_addr, context.target_addr);
        let now = unix_timestamp_seconds();
        let mut active_connections = self
            .active_connections
            .lock()
            .expect("active connections mutex poisoned");
        let connection = active_connections
            .entry(key.clone())
            .and_modify(|connection| {
                connection.route_name = context.route_name.to_string();
                connection.interface = context.interface.to_string();
                connection.peer_addr = context.peer_addr;
                connection.target_addr = context.target_addr;
                if let Some(file_path) = context.file_path_hint {
                    connection.last_file_path = Some(file_path.to_string());
                }
            })
            .or_insert_with(|| ActiveConnectionStats {
                connection_key: key,
                route_name: context.route_name.to_string(),
                interface: context.interface.to_string(),
                peer_addr: context.peer_addr,
                target_addr: context.target_addr,
                opened_unix_timestamp_seconds: now,
                last_activity_unix_timestamp_seconds: now,
                stream_bytes_client_to_server: 0,
                stream_bytes_server_to_client: 0,
                forwarded_bytes_client_to_server: 0,
                forwarded_bytes_server_to_client: 0,
                smb_write_requests: 0,
                smb_write_bytes: 0,
                observed_file_events: 0,
                server_side_copy_requests: 0,
                monitored_events: 0,
                blocked_events: 0,
                last_file_path: context.file_path_hint.map(ToString::to_string),
                last_action: "allow".to_string(),
                last_reason: "SMB client connection opened".to_string(),
            });

        update(connection);
        connection.last_activity_unix_timestamp_seconds = now;
    }

    fn remove_active_connection(&self, context: &InspectionContext<'_>) {
        self.active_connections
            .lock()
            .expect("active connections mutex poisoned")
            .remove(&active_connection_key(
                context.route_name,
                context.peer_addr,
                context.target_addr,
            ));
    }

    fn record_active_connection_threat(&self, event: &ThreatEvent) {
        let context = InspectionContext {
            route_name: &event.route_name,
            interface: &event.interface,
            direction: event.direction,
            peer_addr: event.peer_addr,
            target_addr: event.target_addr,
            file_path_hint: event.file_path.as_deref(),
        };
        self.upsert_active_connection(&context, |connection| {
            match event.action {
                PolicyMode::Block => connection.blocked_events += 1,
                PolicyMode::Monitor => connection.monitored_events += 1,
                PolicyMode::Disabled => {}
            }
            connection.last_action = policy_mode_label(event.action).to_string();
            connection.last_reason = event.reason.clone();
            if let Some(file_path) = &event.file_path {
                connection.last_file_path = Some(file_path.clone());
            }
        });
    }

    fn route_snapshots(&self) -> Vec<RouteStatsSnapshot> {
        let mut snapshots: Vec<_> = self
            .route_stats
            .lock()
            .expect("route stats mutex poisoned")
            .values()
            .map(RouteStatsSnapshot::from)
            .collect();

        snapshots.sort_by(|left, right| left.route_name.cmp(&right.route_name));
        snapshots
    }

    fn active_connection_snapshots(&self) -> Vec<ActiveConnectionStats> {
        let mut snapshots: Vec<_> = self
            .active_connections
            .lock()
            .expect("active connections mutex poisoned")
            .values()
            .cloned()
            .collect();

        snapshots.sort_by(|left, right| {
            right
                .last_activity_unix_timestamp_seconds
                .cmp(&left.last_activity_unix_timestamp_seconds)
                .then_with(|| left.peer_addr.cmp(&right.peer_addr))
        });
        snapshots
    }

    fn file_activity_snapshots(&self) -> Vec<FileActivityStats> {
        let mut snapshots: Vec<_> = self
            .file_activity
            .lock()
            .expect("file activity mutex poisoned")
            .values()
            .cloned()
            .collect();

        snapshots.sort_by(|left, right| {
            right
                .last_activity_unix_timestamp_seconds
                .cmp(&left.last_activity_unix_timestamp_seconds)
                .then_with(|| left.file_path.cmp(&right.file_path))
        });
        snapshots
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new(StreamPolicy::default(), DnsPolicyConfig::default())
    }
}

pub type RuntimeState = AppState;

#[derive(Debug, Default)]
struct TrafficCounters {
    total_connections: AtomicU64,
    active_connections: AtomicU64,
    inspected_chunks: AtomicU64,
    inspected_bytes: AtomicU64,
    allowed_chunks: AtomicU64,
    monitored_chunks: AtomicU64,
    blocked_chunks: AtomicU64,
    observed_file_events: AtomicU64,
    audit_events: AtomicU64,
    stream_bytes_client_to_server: AtomicU64,
    stream_bytes_server_to_client: AtomicU64,
    bytes_client_to_server: AtomicU64,
    bytes_server_to_client: AtomicU64,
    smb_write_requests: AtomicU64,
    smb_write_bytes: AtomicU64,
    server_side_copy_requests: AtomicU64,
    completed_file_hashes: AtomicU64,
    known_good_reputation_events: AtomicU64,
    known_bad_reputation_events: AtomicU64,
    unknown_reputation_events: AtomicU64,
    dns_queries: AtomicU64,
    dns_udp_queries: AtomicU64,
    dns_tcp_queries: AtomicU64,
    dns_blocked_queries: AtomicU64,
    dns_monitored_queries: AtomicU64,
    dns_cache_hits: AtomicU64,
    dns_upstream_errors: AtomicU64,
    monitored_threats: AtomicU64,
    blocked_threats: AtomicU64,
}

#[derive(Debug, Clone, Serialize)]
pub struct StatusSnapshot {
    pub uptime_seconds: u64,
    pub total_connections: u64,
    pub active_connections: u64,
    pub inspected_chunks: u64,
    pub inspected_bytes: u64,
    pub allowed_chunks: u64,
    pub monitored_chunks: u64,
    pub blocked_chunks: u64,
    pub observed_file_events: u64,
    pub audit_events: u64,
    pub stream_bytes_client_to_server: u64,
    pub stream_bytes_server_to_client: u64,
    pub bytes_client_to_server: u64,
    pub bytes_server_to_client: u64,
    pub smb_write_requests: u64,
    pub smb_write_bytes: u64,
    pub server_side_copy_requests: u64,
    pub completed_file_hashes: u64,
    pub known_good_reputation_events: u64,
    pub known_bad_reputation_events: u64,
    pub unknown_reputation_events: u64,
    pub known_bad_reputation_hashes_loaded: usize,
    pub dns_queries: u64,
    pub dns_udp_queries: u64,
    pub dns_tcp_queries: u64,
    pub dns_blocked_queries: u64,
    pub dns_monitored_queries: u64,
    pub dns_cache_hits: u64,
    pub dns_upstream_errors: u64,
    pub monitored_threats: u64,
    pub blocked_threats: u64,
    pub policy_runtime: PolicyRuntimeSnapshot,
    pub dns_policy_runtime: DnsPolicyRuntimeSnapshot,
    pub audit_log_path: String,
    pub route_stats: Vec<RouteStatsSnapshot>,
    pub active_connection_details: Vec<ActiveConnectionStats>,
    pub file_activity: Vec<FileActivityStats>,
    pub recent_threats: Vec<ThreatEvent>,
    pub recent_audit_events: Vec<AuditEvent>,
    pub recent_dns_events: Vec<DnsQueryEvent>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DnsQueryEvent {
    pub unix_timestamp_seconds: u64,
    pub protocol: DnsProtocol,
    pub client_addr: SocketAddr,
    pub query_name: String,
    pub query_type: String,
    pub action: DnsAction,
    pub reason: String,
    pub upstream_addr: Option<SocketAddr>,
    pub response_code: Option<u8>,
    pub latency_millis: u64,
    pub cache_hit: bool,
}

impl DnsQueryEvent {
    pub fn now(
        protocol: DnsProtocol,
        client_addr: SocketAddr,
        query_name: String,
        query_type: String,
        action: DnsAction,
        reason: String,
        upstream_addr: Option<SocketAddr>,
        response_code: Option<u8>,
        latency_millis: u64,
        cache_hit: bool,
    ) -> Self {
        Self {
            unix_timestamp_seconds: unix_timestamp_seconds(),
            protocol,
            client_addr,
            query_name,
            query_type,
            action,
            reason,
            upstream_addr,
            response_code,
            latency_millis,
            cache_hit,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DnsProtocol {
    Udp,
    Tcp,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DnsAction {
    Allow,
    Monitor,
    Block,
    Error,
}

#[derive(Debug, Clone, Serialize)]
pub struct DnsPolicyRuntimeSnapshot {
    pub generation: u64,
    pub last_updated_unix_timestamp_seconds: u64,
    pub active_policy: DnsPolicyConfig,
}

#[derive(Debug, Clone, Serialize)]
pub struct ActiveConnectionStats {
    pub connection_key: String,
    pub route_name: String,
    pub interface: String,
    pub peer_addr: SocketAddr,
    pub target_addr: SocketAddr,
    pub opened_unix_timestamp_seconds: u64,
    pub last_activity_unix_timestamp_seconds: u64,
    pub stream_bytes_client_to_server: u64,
    pub stream_bytes_server_to_client: u64,
    pub forwarded_bytes_client_to_server: u64,
    pub forwarded_bytes_server_to_client: u64,
    pub smb_write_requests: u64,
    pub smb_write_bytes: u64,
    pub observed_file_events: u64,
    pub server_side_copy_requests: u64,
    pub monitored_events: u64,
    pub blocked_events: u64,
    pub last_file_path: Option<String>,
    pub last_action: String,
    pub last_reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct FileActivityStats {
    pub file_path: String,
    pub route_name: String,
    pub interface: String,
    pub peer_addr: SocketAddr,
    pub target_addr: SocketAddr,
    pub observed_events: u64,
    pub blocked_events: u64,
    pub monitored_events: u64,
    pub smb_write_requests: u64,
    pub smb_write_bytes: u64,
    pub last_action: String,
    pub last_reason: String,
    pub last_rule_name: Option<String>,
    pub last_bytes_in_chunk: Option<u64>,
    pub last_activity_unix_timestamp_seconds: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct CompletedFileTransfer {
    pub route_name: String,
    pub interface: String,
    pub direction: TrafficDirection,
    pub peer_addr: SocketAddr,
    pub target_addr: SocketAddr,
    pub destination_share: Option<String>,
    pub source_user: Option<String>,
    pub file_name: String,
    pub extension: Option<String>,
    pub mime_type: Option<String>,
    pub file_size: u64,
    pub creation_time: Option<u64>,
    pub upload_timestamp: u64,
    pub sha256: String,
    pub md5: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PolicyRuntimeSnapshot {
    pub generation: u64,
    pub last_updated_unix_timestamp_seconds: u64,
    pub blocking_rules: Vec<String>,
    pub monitoring_rules: Vec<String>,
    pub active_policy: PolicyConfig,
}

#[derive(Debug, Default)]
struct RouteRuntimeStats {
    route_name: String,
    interface: String,
    listen_addr: String,
    target_addr: String,
    listener_ready: bool,
    total_connections: u64,
    active_connections: u64,
    inspected_chunks: u64,
    inspected_bytes: u64,
    stream_bytes_client_to_server: u64,
    stream_bytes_server_to_client: u64,
    bytes_client_to_server: u64,
    bytes_server_to_client: u64,
    smb_write_requests: u64,
    smb_write_bytes: u64,
    server_side_copy_requests: u64,
    monitored_events: u64,
    blocked_events: u64,
    last_peer_addr: Option<String>,
    last_activity_unix_timestamp_seconds: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RouteStatsSnapshot {
    pub route_name: String,
    pub interface: String,
    pub listen_addr: String,
    pub target_addr: String,
    pub listener_ready: bool,
    pub total_connections: u64,
    pub active_connections: u64,
    pub inspected_chunks: u64,
    pub inspected_bytes: u64,
    pub stream_bytes_client_to_server: u64,
    pub stream_bytes_server_to_client: u64,
    pub bytes_client_to_server: u64,
    pub bytes_server_to_client: u64,
    pub smb_write_requests: u64,
    pub smb_write_bytes: u64,
    pub server_side_copy_requests: u64,
    pub monitored_events: u64,
    pub blocked_events: u64,
    pub last_peer_addr: Option<String>,
    pub last_activity_unix_timestamp_seconds: Option<u64>,
}

impl From<&RouteRuntimeStats> for RouteStatsSnapshot {
    fn from(value: &RouteRuntimeStats) -> Self {
        Self {
            route_name: value.route_name.clone(),
            interface: value.interface.clone(),
            listen_addr: value.listen_addr.clone(),
            target_addr: value.target_addr.clone(),
            listener_ready: value.listener_ready,
            total_connections: value.total_connections,
            active_connections: value.active_connections,
            inspected_chunks: value.inspected_chunks,
            inspected_bytes: value.inspected_bytes,
            stream_bytes_client_to_server: value.stream_bytes_client_to_server,
            stream_bytes_server_to_client: value.stream_bytes_server_to_client,
            bytes_client_to_server: value.bytes_client_to_server,
            bytes_server_to_client: value.bytes_server_to_client,
            smb_write_requests: value.smb_write_requests,
            smb_write_bytes: value.smb_write_bytes,
            server_side_copy_requests: value.server_side_copy_requests,
            monitored_events: value.monitored_events,
            blocked_events: value.blocked_events,
            last_peer_addr: value.last_peer_addr.clone(),
            last_activity_unix_timestamp_seconds: value.last_activity_unix_timestamp_seconds,
        }
    }
}

pub type TrafficSnapshot = StatusSnapshot;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TrafficDirection {
    ClientToServer,
    ServerToClient,
}

#[derive(Debug, Clone, Serialize)]
pub struct ThreatEvent {
    pub unix_timestamp_seconds: u64,
    pub action: PolicyMode,
    pub rule_name: String,
    pub route_name: String,
    pub interface: String,
    pub direction: TrafficDirection,
    pub peer_addr: SocketAddr,
    pub target_addr: SocketAddr,
    pub file_path: Option<String>,
    pub reason: String,
    pub bytes_in_chunk: usize,
    pub entropy: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditEvent {
    pub unix_timestamp_seconds: u64,
    pub severity: AuditSeverity,
    pub kind: AuditEventKind,
    pub route_name: String,
    pub interface: String,
    pub direction: TrafficDirection,
    pub peer_addr: SocketAddr,
    pub target_addr: SocketAddr,
    pub file_path: Option<String>,
    pub action: String,
    pub reason: String,
    pub bytes_in_chunk: Option<u64>,
    pub rule_name: Option<String>,
}

impl AuditEvent {
    fn from_context(
        context: &InspectionContext<'_>,
        kind: AuditEventKind,
        severity: AuditSeverity,
        file_path: Option<String>,
        action: String,
        reason: String,
        bytes_in_chunk: Option<u64>,
        rule_name: Option<String>,
    ) -> Self {
        Self {
            unix_timestamp_seconds: unix_timestamp_seconds(),
            severity,
            kind,
            route_name: context.route_name.to_string(),
            interface: context.interface.to_string(),
            direction: context.direction,
            peer_addr: context.peer_addr,
            target_addr: context.target_addr,
            file_path,
            action,
            reason,
            bytes_in_chunk,
            rule_name,
        }
    }

    fn from_threat(event: &ThreatEvent, kind: AuditEventKind, severity: AuditSeverity) -> Self {
        Self {
            unix_timestamp_seconds: event.unix_timestamp_seconds,
            severity,
            kind,
            route_name: event.route_name.clone(),
            interface: event.interface.clone(),
            direction: event.direction,
            peer_addr: event.peer_addr,
            target_addr: event.target_addr,
            file_path: event
                .file_path
                .clone()
                .or_else(|| extract_file_path_hint(&event.reason)),
            action: policy_mode_label(event.action).to_string(),
            reason: event.reason.clone(),
            bytes_in_chunk: Some(event.bytes_in_chunk as u64),
            rule_name: Some(event.rule_name.clone()),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditSeverity {
    Info,
    Warning,
    Critical,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventKind {
    ConnectionOpened,
    ConnectionClosed,
    FileObserved,
    FileHashCompleted,
    PolicyDetection,
    PolicyBlocked,
    ReputationVerdict,
    ServerSideCopyRequested,
}

impl ThreatEvent {
    pub fn now(
        context: &InspectionContext<'_>,
        action: PolicyMode,
        rule_name: String,
        reason: String,
        bytes_in_chunk: usize,
        entropy: f64,
    ) -> Self {
        Self {
            unix_timestamp_seconds: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_else(|_| Duration::from_secs(0))
                .as_secs(),
            action,
            rule_name,
            route_name: context.route_name.to_string(),
            interface: context.interface.to_string(),
            direction: context.direction,
            peer_addr: context.peer_addr,
            target_addr: context.target_addr,
            file_path: context.file_path_hint.map(ToString::to_string),
            reason,
            bytes_in_chunk,
            entropy,
        }
    }
}

#[derive(Debug, Clone)]
pub struct StreamPolicy {
    config: PolicyConfig,
    signatures: Vec<RuntimeSignature>,
}

impl StreamPolicy {
    pub fn from_config(config: PolicyConfig) -> Self {
        let signatures = config
            .signatures
            .iter()
            .map(RuntimeSignature::from)
            .collect();

        Self { config, signatures }
    }

    pub fn config(&self) -> &PolicyConfig {
        &self.config
    }

    pub fn inspect_chunk(&self, context: &InspectionContext<'_>, chunk: &[u8]) -> InspectionResult {
        let entropy = calculate_shannon_entropy(chunk);

        if let Some(detection) = self.detect_smb_policy_violation(chunk) {
            return detection.into_result(context, chunk.len(), entropy);
        }

        if let Some(detection) = self.detect_archive_policy_violation(context, chunk) {
            return detection.into_result(context, chunk.len(), entropy);
        }

        if let Some(signature) = self.match_signature(chunk) {
            return PolicyDetection {
                action: signature.mode,
                rule_name: signature.name.clone(),
                reason: format!("signature '{}' matched", signature.name),
            }
            .into_result(context, chunk.len(), entropy);
        }

        if chunk.len() >= self.config.entropy.minimum_chunk_size
            && self.config.entropy.mode.is_enabled()
            && entropy >= self.config.entropy.threshold
            && !looks_like_smb_negotiate_or_session_setup(chunk)
        {
            return PolicyDetection {
                action: self.config.entropy.mode,
                rule_name: "High entropy payload".to_string(),
                reason: format!(
                    "entropy {:.3} exceeded threshold {:.3}",
                    entropy, self.config.entropy.threshold
                ),
            }
            .into_result(context, chunk.len(), entropy);
        }

        InspectionResult::Allow { entropy }
    }

    pub fn max_pattern_len(&self) -> usize {
        let signature_len = self
            .signatures
            .iter()
            .flat_map(|signature| signature.patterns.iter().map(Vec::len))
            .max()
            .unwrap_or(0);

        signature_len.max(ARCHIVE_MAX_PATTERN_LEN)
    }

    fn detect_smb_policy_violation(&self, chunk: &[u8]) -> Option<PolicyDetection> {
        if contains_smb_encrypted_transform_header(chunk)
            && self.config.smb.encrypted_payload.is_enabled()
        {
            return Some(PolicyDetection {
                action: self.config.smb.encrypted_payload,
                rule_name: "SMB encrypted payload".to_string(),
                reason: "SMB3 encrypted payload detected; file content cannot be inspected"
                    .to_string(),
            });
        }

        None
    }

    fn match_signature<'a>(&'a self, chunk: &[u8]) -> Option<&'a RuntimeSignature> {
        self.signatures
            .iter()
            .find(|signature| signature.mode.is_enabled() && signature.matches(chunk))
    }

    fn detect_archive_policy_violation(
        &self,
        context: &InspectionContext<'_>,
        chunk: &[u8],
    ) -> Option<PolicyDetection> {
        if context.direction == TrafficDirection::ClientToServer {
            if let Some(file_path) = context.file_path_hint
                && let Some(detection) = self.archive_policy_detection_for_file_path(file_path)
            {
                return Some(detection);
            }

            for file_path in extract_smb_file_paths(chunk) {
                if let Some(detection) = self.archive_policy_detection_for_file_path(&file_path) {
                    return Some(detection);
                }
            }

            if contains_ascii_or_utf16le_case_insensitive(chunk, ".rar")
                && self.config.archive.rar.is_enabled()
            {
                return Some(PolicyDetection {
                    action: self.config.archive.rar,
                    rule_name: "RAR archive".to_string(),
                    reason: "RAR filename extension detected in SMB create/write flow".to_string(),
                });
            }

            if (contains_ascii_or_utf16le_case_insensitive(chunk, ".7z")
                || contains_ascii_or_utf16le_case_insensitive(chunk, ".7zip"))
                && self.config.archive.seven_zip.is_enabled()
            {
                return Some(PolicyDetection {
                    action: self.config.archive.seven_zip,
                    rule_name: "7z archive".to_string(),
                    reason: "7z filename extension detected in SMB create/write flow".to_string(),
                });
            }

            if contains_ascii_or_utf16le_case_insensitive(chunk, ".zip")
                && self.config.archive.zip.is_enabled()
            {
                return Some(PolicyDetection {
                    action: self.config.archive.zip,
                    rule_name: "ZIP archive".to_string(),
                    reason: "ZIP filename extension detected in SMB create/write flow".to_string(),
                });
            }
        }

        if let Some(mode) = encrypted_zip_mode(chunk, self.config.archive.encrypted_zip)
            && mode.is_enabled()
        {
            return Some(PolicyDetection {
                action: mode,
                rule_name: "Encrypted ZIP archive".to_string(),
                reason: "encrypted ZIP transfer detected".to_string(),
            });
        }

        if contains_bytes(chunk, b"Rar!\x1A\x07\x00") && self.config.archive.rar.is_enabled() {
            return Some(PolicyDetection {
                action: self.config.archive.rar,
                rule_name: "RAR archive".to_string(),
                reason: "RAR4 archive transfer detected".to_string(),
            });
        }

        if contains_bytes(chunk, b"Rar!\x1A\x07\x01\x00") && self.config.archive.rar.is_enabled() {
            return Some(PolicyDetection {
                action: self.config.archive.rar,
                rule_name: "RAR archive".to_string(),
                reason: "RAR5 archive transfer detected".to_string(),
            });
        }

        if contains_bytes(chunk, b"7z\xBC\xAF\x27\x1C")
            && self.config.archive.seven_zip.is_enabled()
        {
            return Some(PolicyDetection {
                action: self.config.archive.seven_zip,
                rule_name: "7z archive".to_string(),
                reason: "7z archive transfer detected".to_string(),
            });
        }

        if contains_bytes(chunk, b"PK\x03\x04") && self.config.archive.zip.is_enabled() {
            return Some(PolicyDetection {
                action: self.config.archive.zip,
                rule_name: "ZIP archive".to_string(),
                reason: "ZIP archive transfer detected".to_string(),
            });
        }

        None
    }

    fn archive_policy_detection_for_file_path(&self, file_path: &str) -> Option<PolicyDetection> {
        let lower_file_path = file_path.to_ascii_lowercase();
        if lower_file_path.ends_with(".rar") && self.config.archive.rar.is_enabled() {
            return Some(PolicyDetection {
                action: self.config.archive.rar,
                rule_name: "RAR archive".to_string(),
                reason: format!(
                    "RAR filename extension detected in SMB create/write flow: '{file_path}'"
                ),
            });
        }

        if (lower_file_path.ends_with(".7z") || lower_file_path.ends_with(".7zip"))
            && self.config.archive.seven_zip.is_enabled()
        {
            return Some(PolicyDetection {
                action: self.config.archive.seven_zip,
                rule_name: "7z archive".to_string(),
                reason: format!(
                    "7z filename extension detected in SMB create/write flow: '{file_path}'"
                ),
            });
        }

        if lower_file_path.ends_with(".zip") && self.config.archive.zip.is_enabled() {
            return Some(PolicyDetection {
                action: self.config.archive.zip,
                rule_name: "ZIP archive".to_string(),
                reason: format!(
                    "ZIP filename extension detected in SMB create/write flow: '{file_path}'"
                ),
            });
        }

        None
    }
}

impl Default for StreamPolicy {
    fn default() -> Self {
        Self::from_config(PolicyConfig::default())
    }
}

impl From<PolicyConfig> for StreamPolicy {
    fn from(config: PolicyConfig) -> Self {
        Self::from_config(config)
    }
}

#[derive(Debug, Clone)]
struct RuntimeSignature {
    name: String,
    patterns: Vec<Vec<u8>>,
    mode: PolicyMode,
}

impl RuntimeSignature {
    fn matches(&self, chunk: &[u8]) -> bool {
        self.patterns
            .iter()
            .any(|pattern| contains_bytes(chunk, pattern))
    }
}

impl From<&axiom_config::SignaturePolicyConfig> for RuntimeSignature {
    fn from(value: &axiom_config::SignaturePolicyConfig) -> Self {
        let raw_pattern = value.pattern.as_bytes().to_vec();
        let mut patterns = vec![raw_pattern];

        if value.pattern.is_ascii() {
            let utf16le_pattern = utf16le_bytes(&value.pattern);
            if !patterns.iter().any(|pattern| pattern == &utf16le_pattern) {
                patterns.push(utf16le_pattern);
            }
        }

        Self {
            name: value.name.clone(),
            patterns,
            mode: value.mode,
        }
    }
}

#[derive(Debug)]
struct PolicyDetection {
    action: PolicyMode,
    rule_name: String,
    reason: String,
}

impl PolicyDetection {
    fn into_result(
        self,
        context: &InspectionContext<'_>,
        bytes_in_chunk: usize,
        entropy: f64,
    ) -> InspectionResult {
        let event = ThreatEvent::now(
            context,
            self.action,
            self.rule_name,
            self.reason,
            bytes_in_chunk,
            entropy,
        );

        match self.action {
            PolicyMode::Disabled => InspectionResult::Allow { entropy },
            PolicyMode::Monitor => InspectionResult::Monitor { event },
            PolicyMode::Block => InspectionResult::Block { event },
        }
    }
}

#[derive(Debug)]
pub struct InspectionContext<'a> {
    pub route_name: &'a str,
    pub interface: &'a str,
    pub direction: TrafficDirection,
    pub peer_addr: SocketAddr,
    pub target_addr: SocketAddr,
    pub file_path_hint: Option<&'a str>,
}

pub type InspectContext<'a> = InspectionContext<'a>;

#[derive(Debug)]
pub enum InspectionResult {
    Allow { entropy: f64 },
    Monitor { event: ThreatEvent },
    Block { event: ThreatEvent },
}

pub type InspectOutcome = InspectionResult;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Smb2CreateRequest {
    pub message_id: u64,
    pub file_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Smb2CreateResponse {
    pub message_id: u64,
    pub file_id: [u8; 16],
    pub creation_time_unix_timestamp_seconds: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Smb2WriteRequest {
    pub file_id: [u8; 16],
    pub length: u32,
    pub data_range: Option<(usize, usize)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Smb2ReadRequest {
    pub message_id: u64,
    pub file_id: [u8; 16],
    pub length: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Smb2ReadResponse {
    pub message_id: u64,
    pub length: u32,
    pub data_range: Option<(usize, usize)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Smb2CloseRequest {
    pub file_id: [u8; 16],
}

pub fn calculate_shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }

    let mut frequencies = [0_u32; 256];
    for byte in bytes {
        frequencies[*byte as usize] += 1;
    }

    let length = bytes.len() as f64;
    frequencies
        .iter()
        .filter(|count| **count > 0)
        .map(|count| {
            let probability = *count as f64 / length;
            -probability * probability.log2()
        })
        .sum()
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

pub fn extract_smb_file_paths(chunk: &[u8]) -> Vec<String> {
    let mut paths = Vec::new();

    for request in extract_smb2_create_requests(chunk) {
        if !paths.iter().any(|existing| existing == &request.file_path) {
            paths.push(request.file_path);
        }
    }

    paths
}

pub fn extract_smb2_create_requests(chunk: &[u8]) -> Vec<Smb2CreateRequest> {
    let mut requests = Vec::new();

    for header_offset in smb2_header_offsets(chunk) {
        let Some(command) = read_u16_le(chunk, header_offset + 12) else {
            continue;
        };
        if command != 5 {
            continue;
        }

        let Some(message_id) = read_u64_le(chunk, header_offset + 24) else {
            continue;
        };

        let body_offset = header_offset + 64;
        let Some(structure_size) = read_u16_le(chunk, body_offset) else {
            continue;
        };
        if structure_size != 57 {
            continue;
        }

        let Some(name_offset) = read_u16_le(chunk, body_offset + 44).map(usize::from) else {
            continue;
        };
        let Some(name_length) = read_u16_le(chunk, body_offset + 46).map(usize::from) else {
            continue;
        };
        if name_offset < 64 || name_length == 0 || name_length > 4096 {
            continue;
        }

        let absolute_name_offset = header_offset + name_offset;
        let Some(name_bytes) =
            chunk.get(absolute_name_offset..absolute_name_offset.saturating_add(name_length))
        else {
            continue;
        };

        if let Some(path) = decode_utf16le_path(name_bytes)
            && !requests
                .iter()
                .any(|existing: &Smb2CreateRequest| existing.message_id == message_id)
        {
            requests.push(Smb2CreateRequest {
                message_id,
                file_path: path,
            });
        }
    }

    requests
}

pub fn extract_smb2_create_responses(chunk: &[u8]) -> Vec<Smb2CreateResponse> {
    let mut responses = Vec::new();

    for header_offset in smb2_header_offsets(chunk) {
        let Some(command) = read_u16_le(chunk, header_offset + 12) else {
            continue;
        };
        if command != 5 {
            continue;
        }

        let Some(status) = read_u32_le(chunk, header_offset + 8) else {
            continue;
        };
        if status != 0 {
            continue;
        }

        let Some(message_id) = read_u64_le(chunk, header_offset + 24) else {
            continue;
        };

        let body_offset = header_offset + 64;
        let Some(structure_size) = read_u16_le(chunk, body_offset) else {
            continue;
        };
        if structure_size != 89 {
            continue;
        }

        let Some(file_id_bytes) = chunk.get(body_offset + 64..body_offset + 80) else {
            continue;
        };
        let Ok(file_id) = <[u8; 16]>::try_from(file_id_bytes) else {
            continue;
        };

        let creation_time_unix_timestamp_seconds = read_u64_le(chunk, body_offset + 8)
            .and_then(windows_filetime_to_unix_timestamp_seconds);

        responses.push(Smb2CreateResponse {
            message_id,
            file_id,
            creation_time_unix_timestamp_seconds,
        });
    }

    responses
}

pub fn extract_smb2_write_lengths(chunk: &[u8]) -> Vec<u32> {
    extract_smb2_write_requests(chunk)
        .into_iter()
        .map(|request| request.length)
        .collect()
}

pub fn extract_smb2_write_requests(chunk: &[u8]) -> Vec<Smb2WriteRequest> {
    let mut requests = Vec::new();

    for header_offset in smb2_header_offsets(chunk) {
        let Some(command) = read_u16_le(chunk, header_offset + 12) else {
            continue;
        };
        if command != 9 {
            continue;
        }

        let body_offset = header_offset + 64;
        let Some(structure_size) = read_u16_le(chunk, body_offset) else {
            continue;
        };
        if structure_size != 49 {
            continue;
        }

        let Some(length) = read_u32_le(chunk, body_offset + 4) else {
            continue;
        };
        if length == 0 {
            continue;
        }

        let data_offset = read_u16_le(chunk, body_offset + 2).map(usize::from);
        let Some(file_id_bytes) = chunk.get(body_offset + 16..body_offset + 32) else {
            continue;
        };
        let Ok(file_id) = <[u8; 16]>::try_from(file_id_bytes) else {
            continue;
        };

        let data_range = data_offset.and_then(|offset| {
            let start = header_offset.saturating_add(offset);
            let end = start.saturating_add(length as usize);
            (start < end && end <= chunk.len()).then_some((start, end))
        });

        requests.push(Smb2WriteRequest {
            file_id,
            length,
            data_range,
        });
    }

    requests
}

pub fn extract_smb2_read_requests(chunk: &[u8]) -> Vec<Smb2ReadRequest> {
    let mut requests = Vec::new();

    for header_offset in smb2_header_offsets(chunk) {
        let Some(command) = read_u16_le(chunk, header_offset + 12) else {
            continue;
        };
        if command != 8 {
            continue;
        }

        let Some(message_id) = read_u64_le(chunk, header_offset + 24) else {
            continue;
        };

        let body_offset = header_offset + 64;
        let Some(structure_size) = read_u16_le(chunk, body_offset) else {
            continue;
        };
        if structure_size != 49 {
            continue;
        }

        let Some(length) = read_u32_le(chunk, body_offset + 4) else {
            continue;
        };
        let Some(file_id_bytes) = chunk.get(body_offset + 16..body_offset + 32) else {
            continue;
        };
        let Ok(file_id) = <[u8; 16]>::try_from(file_id_bytes) else {
            continue;
        };

        requests.push(Smb2ReadRequest {
            message_id,
            file_id,
            length,
        });
    }

    requests
}

pub fn extract_smb2_read_responses(chunk: &[u8]) -> Vec<Smb2ReadResponse> {
    let mut responses = Vec::new();

    for header_offset in smb2_header_offsets(chunk) {
        let Some(command) = read_u16_le(chunk, header_offset + 12) else {
            continue;
        };
        if command != 8 {
            continue;
        }

        let Some(status) = read_u32_le(chunk, header_offset + 8) else {
            continue;
        };
        if status != 0 {
            continue;
        }

        let Some(message_id) = read_u64_le(chunk, header_offset + 24) else {
            continue;
        };

        let body_offset = header_offset + 64;
        let Some(structure_size) = read_u16_le(chunk, body_offset) else {
            continue;
        };
        if structure_size != 17 {
            continue;
        }

        let Some(data_offset) = read_u8(chunk, body_offset + 2).map(usize::from) else {
            continue;
        };
        let Some(length) = read_u32_le(chunk, body_offset + 4) else {
            continue;
        };
        if length == 0 {
            continue;
        }

        let data_range = {
            let start = header_offset.saturating_add(data_offset);
            let end = start.saturating_add(length as usize);
            (start < end && end <= chunk.len()).then_some((start, end))
        };

        responses.push(Smb2ReadResponse {
            message_id,
            length,
            data_range,
        });
    }

    responses
}

pub fn extract_smb2_close_requests(chunk: &[u8]) -> Vec<Smb2CloseRequest> {
    let mut requests = Vec::new();

    for header_offset in smb2_header_offsets(chunk) {
        let Some(command) = read_u16_le(chunk, header_offset + 12) else {
            continue;
        };
        if command != 6 {
            continue;
        }

        let body_offset = header_offset + 64;
        let Some(structure_size) = read_u16_le(chunk, body_offset) else {
            continue;
        };
        if structure_size != 24 {
            continue;
        }

        let Some(file_id_bytes) = chunk.get(body_offset + 8..body_offset + 24) else {
            continue;
        };
        let Ok(file_id) = <[u8; 16]>::try_from(file_id_bytes) else {
            continue;
        };

        requests.push(Smb2CloseRequest { file_id });
    }

    requests
}

pub fn contains_smb2_server_side_copy_request(chunk: &[u8]) -> bool {
    for header_offset in smb2_header_offsets(chunk) {
        let Some(command) = read_u16_le(chunk, header_offset + 12) else {
            continue;
        };
        if command != 11 {
            continue;
        }

        let body_offset = header_offset + 64;
        let Some(structure_size) = read_u16_le(chunk, body_offset) else {
            continue;
        };
        if structure_size != 57 {
            continue;
        }

        let Some(control_code) = read_u32_le(chunk, body_offset + 4) else {
            continue;
        };
        if control_code == 0x0014_40F2 || control_code == 0x0014_80F2 {
            return true;
        }
    }

    false
}

pub fn contains_smb2_network_interface_info_request(chunk: &[u8]) -> bool {
    contains_smb2_ioctl_control_code(chunk, 0x0014_01FC)
}

fn contains_smb2_ioctl_control_code(chunk: &[u8], expected_control_code: u32) -> bool {
    for header_offset in smb2_header_offsets(chunk) {
        let Some(command) = read_u16_le(chunk, header_offset + 12) else {
            continue;
        };
        if command != 11 {
            continue;
        }

        let body_offset = header_offset + 64;
        let Some(structure_size) = read_u16_le(chunk, body_offset) else {
            continue;
        };
        if structure_size != 57 {
            continue;
        }

        let Some(control_code) = read_u32_le(chunk, body_offset + 4) else {
            continue;
        };
        if control_code == expected_control_code {
            return true;
        }
    }

    false
}

fn smb2_header_offsets(chunk: &[u8]) -> Vec<usize> {
    let Some(first_offset) = first_smb2_header_offset(chunk) else {
        return Vec::new();
    };

    let mut offsets = Vec::new();
    let mut header_offset = first_offset;

    loop {
        if chunk.get(header_offset..header_offset + 4) != Some(b"\xFESMB") {
            break;
        }
        offsets.push(header_offset);

        let Some(next_command) = read_u32_le(chunk, header_offset + 20).map(usize::try_from) else {
            break;
        };
        let Ok(next_command) = next_command else {
            break;
        };
        if next_command == 0 {
            break;
        }

        let next_offset = header_offset.saturating_add(next_command);
        if next_offset <= header_offset || next_offset + 64 > chunk.len() {
            break;
        }
        header_offset = next_offset;
    }

    offsets
}

fn first_smb2_header_offset(chunk: &[u8]) -> Option<usize> {
    if chunk.get(4..8) == Some(b"\xFESMB") || chunk.get(4..8) == Some(b"\xFDSMB") {
        return (chunk.get(4..8) == Some(b"\xFESMB")).then_some(4);
    }

    chunk.windows(4).position(|window| window == b"\xFESMB")
}

fn read_u8(bytes: &[u8], offset: usize) -> Option<u8> {
    bytes.get(offset).copied()
}

fn read_u16_le(bytes: &[u8], offset: usize) -> Option<u16> {
    let pair = bytes.get(offset..offset + 2)?;
    Some(u16::from_le_bytes([pair[0], pair[1]]))
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Option<u32> {
    let quad = bytes.get(offset..offset + 4)?;
    Some(u32::from_le_bytes([quad[0], quad[1], quad[2], quad[3]]))
}

fn read_u64_le(bytes: &[u8], offset: usize) -> Option<u64> {
    let octet = bytes.get(offset..offset + 8)?;
    Some(u64::from_le_bytes([
        octet[0], octet[1], octet[2], octet[3], octet[4], octet[5], octet[6], octet[7],
    ]))
}

fn windows_filetime_to_unix_timestamp_seconds(filetime: u64) -> Option<u64> {
    if filetime == 0 {
        return None;
    }

    const WINDOWS_TO_UNIX_EPOCH_SECONDS: u64 = 11_644_473_600;
    let seconds = filetime / 10_000_000;
    seconds.checked_sub(WINDOWS_TO_UNIX_EPOCH_SECONDS)
}

fn decode_utf16le_path(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 2 || !bytes.len().is_multiple_of(2) {
        return None;
    }

    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect();
    let path = String::from_utf16_lossy(&units)
        .trim_matches('\0')
        .trim()
        .to_string();

    if path.is_empty()
        || path
            .chars()
            .any(|character| character.is_control() && character != '\t')
    {
        return None;
    }

    Some(path)
}

fn contains_ascii_or_utf16le_case_insensitive(haystack: &[u8], needle: &str) -> bool {
    contains_ascii_case_insensitive(haystack, needle.as_bytes())
        || contains_utf16le_ascii_case_insensitive(haystack, needle.as_bytes())
}

fn extract_file_path_hint(reason: &str) -> Option<String> {
    let start = reason.find('\'')?;
    let end = reason[start + 1..].find('\'')?;
    Some(reason[start + 1..start + 1 + end].to_string())
}

fn file_activity_key(route_name: &str, peer_addr: SocketAddr, file_path: &str) -> String {
    format!("{route_name}|{}|{file_path}", peer_addr.ip())
}

fn active_connection_key(
    route_name: &str,
    peer_addr: SocketAddr,
    target_addr: SocketAddr,
) -> String {
    format!("{route_name}|{peer_addr}|{target_addr}")
}

fn policy_mode_label(mode: PolicyMode) -> &'static str {
    match mode {
        PolicyMode::Disabled => "disabled",
        PolicyMode::Monitor => "monitor",
        PolicyMode::Block => "block",
    }
}

fn append_audit_event_to_disk(event: &AuditEvent) {
    let Ok(serialized) = serde_json::to_string(event) else {
        return;
    };
    let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(AUDIT_LOG_PATH)
    else {
        return;
    };

    let _ = writeln!(file, "{serialized}");
}

fn contains_ascii_case_insensitive(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack.windows(needle.len()).any(|window| {
            window
                .iter()
                .zip(needle.iter())
                .all(|(left, right)| left.eq_ignore_ascii_case(right))
        })
}

fn utf16le_bytes(value: &str) -> Vec<u8> {
    value
        .encode_utf16()
        .flat_map(|unit| unit.to_le_bytes())
        .collect()
}

fn contains_utf16le_ascii_case_insensitive(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return false;
    }

    let encoded_len = needle.len() * 2;
    if haystack.len() < encoded_len {
        return false;
    }

    (0..=haystack.len() - encoded_len).any(|start| {
        needle.iter().enumerate().all(|(index, expected)| {
            let byte_index = start + index * 2;
            haystack[byte_index + 1] == 0 && haystack[byte_index].eq_ignore_ascii_case(expected)
        })
    })
}

fn contains_smb_encrypted_transform_header(chunk: &[u8]) -> bool {
    contains_bytes(chunk, b"\xFDSMB")
}

fn unix_timestamp_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs()
}

fn encrypted_zip_mode(chunk: &[u8], mode: PolicyMode) -> Option<PolicyMode> {
    let signature = b"PK\x03\x04";

    chunk
        .windows(8)
        .any(|window| {
            window.starts_with(signature)
                && u16::from_le_bytes([window[6], window[7]]) & 0x0001 != 0
        })
        .then_some(mode)
}

fn looks_like_smb_negotiate_or_session_setup(chunk: &[u8]) -> bool {
    if chunk.len() < 8 {
        return false;
    }

    let protocol_offset = if chunk.starts_with(&[0x00]) && chunk.len() >= 5 {
        4
    } else {
        0
    };

    let smb2_header = chunk
        .get(protocol_offset..protocol_offset + 4)
        .is_some_and(|prefix| prefix == b"\xFESMB");

    if !smb2_header {
        return false;
    }

    let Some(command_bytes) = chunk.get(protocol_offset + 12..protocol_offset + 14) else {
        return false;
    };
    let command = u16::from_le_bytes([command_bytes[0], command_bytes[1]]);

    command == 0 || command == 1
}

fn blocking_rules(policy: &PolicyConfig) -> Vec<String> {
    summarize_rules(policy, PolicyMode::Block)
}

fn monitoring_rules(policy: &PolicyConfig) -> Vec<String> {
    summarize_rules(policy, PolicyMode::Monitor)
}

fn summarize_rules(policy: &PolicyConfig, mode: PolicyMode) -> Vec<String> {
    let mut rules = Vec::new();

    if policy.smb.encrypted_payload == mode {
        rules.push("SMB encrypted payload".to_string());
    }
    if policy.archive.rar == mode {
        rules.push("RAR archives".to_string());
    }
    if policy.archive.seven_zip == mode {
        rules.push("7z archives".to_string());
    }
    if policy.archive.zip == mode {
        rules.push("ZIP archives".to_string());
    }
    if policy.archive.encrypted_zip == mode {
        rules.push("Encrypted ZIP archives".to_string());
    }
    if policy.entropy.mode == mode {
        rules.push("High entropy payloads".to_string());
    }

    rules.extend(
        policy
            .signatures
            .iter()
            .filter(|signature| signature.mode == mode)
            .map(|signature| format!("Signature: {}", signature.name)),
    );

    rules
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use axiom_config::{ArchivePolicyConfig, EntropyPolicyConfig, SmbPolicyConfig};

    use super::*;

    #[test]
    fn blocks_rar5_archive_marker_inside_smb_payload() {
        let policy = StreamPolicy::default();
        let context = test_context();
        let chunk = b"\x00\x00\x00\x40\xfeSMBmetadata-padding-Rar!\x1A\x07\x01\x00payload";

        let result = policy.inspect_chunk(&context, chunk);

        assert!(matches!(result, InspectionResult::Block { .. }));
    }

    #[test]
    fn monitors_zip_when_zip_policy_is_monitor() {
        let policy = StreamPolicy::from_config(PolicyConfig {
            archive: ArchivePolicyConfig {
                zip: PolicyMode::Monitor,
                ..ArchivePolicyConfig::default()
            },
            ..PolicyConfig::default()
        });
        let context = test_context();
        let chunk = b"prefixPK\x03\x04\x14\x00\x00\x00plain-zip";

        let result = policy.inspect_chunk(&context, chunk);

        assert!(matches!(result, InspectionResult::Monitor { .. }));
    }

    #[test]
    fn blocks_zip_by_default() {
        let policy = StreamPolicy::default();
        let context = test_context();
        let chunk = b"prefixPK\x03\x04\x14\x00\x00\x00plain-zip";

        let result = policy.inspect_chunk(&context, chunk);

        assert!(matches!(result, InspectionResult::Block { .. }));
    }

    #[test]
    fn blocks_encrypted_zip_local_header() {
        let policy = StreamPolicy::default();
        let context = test_context();
        let chunk = b"prefixPK\x03\x04\x14\x00\x01\x00encrypted";

        let result = policy.inspect_chunk(&context, chunk);

        assert!(matches!(result, InspectionResult::Block { .. }));
    }

    #[test]
    fn monitors_smb_encrypted_payload_by_default() {
        let policy = StreamPolicy::default();
        let context = test_context();
        let chunk = b"\x00\x00\x00\x80\xfdSMB encrypted transform payload";

        let result = policy.inspect_chunk(&context, chunk);

        assert!(matches!(result, InspectionResult::Monitor { .. }));
    }

    #[test]
    fn disabled_archive_policy_allows_rar() {
        let policy = StreamPolicy::from_config(PolicyConfig {
            smb: SmbPolicyConfig {
                encrypted_payload: PolicyMode::Disabled,
            },
            archive: ArchivePolicyConfig {
                rar: PolicyMode::Disabled,
                seven_zip: PolicyMode::Disabled,
                zip: PolicyMode::Disabled,
                encrypted_zip: PolicyMode::Disabled,
            },
            entropy: EntropyPolicyConfig {
                mode: PolicyMode::Disabled,
                threshold: 7.90,
                minimum_chunk_size: 8192,
            },
            reputation: axiom_config::ReputationPolicyConfig::default(),
            signatures: Vec::new(),
        });
        let context = test_context();
        let chunk = b"Rar!\x1A\x07\x01\x00payload";

        let result = policy.inspect_chunk(&context, chunk);

        assert!(matches!(result, InspectionResult::Allow { .. }));
    }

    #[test]
    fn allows_plain_text_chunk() {
        let policy = StreamPolicy::default();
        let context = test_context();
        let chunk = b"normal business text document body";

        let result = policy.inspect_chunk(&context, chunk);

        assert!(matches!(result, InspectionResult::Allow { .. }));
    }

    #[test]
    fn blocks_archive_filename_extension_in_utf16le_smb_create() {
        let policy = StreamPolicy::default();
        let context = test_context();
        let chunk = smb2_create_request("Finance Backup.RaR");

        let result = policy.inspect_chunk(&context, &chunk);

        assert!(matches!(result, InspectionResult::Block { .. }));
    }

    #[test]
    fn blocks_archive_filename_from_active_file_handle_context() {
        let policy = StreamPolicy::default();
        let context = InspectionContext {
            file_path_hint: Some("Exports/zip_sample_file_250MB.zip"),
            ..test_context()
        };
        let chunk = smb2_write_request(262_144);

        let result = policy.inspect_chunk(&context, &chunk);

        assert!(matches!(result, InspectionResult::Block { .. }));
    }

    #[test]
    fn extracts_smb2_create_file_path() {
        let chunk = smb2_create_request(r"Finance\Q2\EicarSample.zip");

        let paths = extract_smb_file_paths(&chunk);

        assert_eq!(paths, vec![r"Finance\Q2\EicarSample.zip"]);
    }

    #[test]
    fn extracts_smb2_write_lengths() {
        let chunk = smb2_write_request(262_144);

        let lengths = extract_smb2_write_lengths(&chunk);

        assert_eq!(lengths, vec![262_144]);
    }

    #[test]
    fn extracts_smb2_write_request_file_id() {
        let chunk = smb2_write_request(65_536);

        let requests = extract_smb2_write_requests(&chunk);

        assert_eq!(
            requests,
            vec![Smb2WriteRequest {
                file_id: test_file_id(),
                length: 65_536,
                data_range: None,
            }]
        );
    }

    #[test]
    fn extracts_smb2_create_response_file_id() {
        let chunk = smb2_create_response(42, test_file_id());

        let responses = extract_smb2_create_responses(&chunk);

        assert_eq!(
            responses,
            vec![Smb2CreateResponse {
                message_id: 42,
                file_id: test_file_id(),
                creation_time_unix_timestamp_seconds: None,
            }]
        );
    }

    #[test]
    fn detects_smb2_server_side_copy_request() {
        let chunk = smb2_ioctl_request(0x0014_40F2);

        assert!(contains_smb2_server_side_copy_request(&chunk));
    }

    #[test]
    fn detects_smb2_multichannel_interface_request() {
        let chunk = smb2_ioctl_request(0x0014_01FC);

        assert!(contains_smb2_network_interface_info_request(&chunk));
    }

    #[test]
    fn blocks_utf16le_signature_variant() {
        let policy = StreamPolicy::default();
        let context = test_context();
        let mut chunk = b"\x00\x00\x00\x90\xfeSMBwrite-request-padding".to_vec();
        chunk.extend_from_slice(&utf16le_bytes("AXIOM_TEST_THREAT"));

        let result = policy.inspect_chunk(&context, &chunk);

        assert!(matches!(result, InspectionResult::Block { .. }));
    }

    #[test]
    fn blocks_plain_eicar_signature() {
        let policy = StreamPolicy::default();
        let context = test_context();
        let chunk = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

        let result = policy.inspect_chunk(&context, chunk);

        assert!(matches!(result, InspectionResult::Block { .. }));
    }

    fn test_context() -> InspectionContext<'static> {
        InspectionContext {
            route_name: "test-route",
            interface: "lo",
            direction: TrafficDirection::ClientToServer,
            peer_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 49152),
            target_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 445),
            file_path_hint: None,
        }
    }

    fn smb2_create_request(path: &str) -> Vec<u8> {
        let name = utf16le_bytes(path);
        let smb_header_offset = 4;
        let body_offset = smb_header_offset + 64;
        let name_offset = 64 + 56;
        let packet_len = body_offset + 56 + name.len();
        let netbios_len = (packet_len - 4) as u32;
        let mut packet = vec![0_u8; packet_len];

        packet[0] = ((netbios_len >> 16) & 0xff) as u8;
        packet[1] = ((netbios_len >> 8) & 0xff) as u8;
        packet[2] = (netbios_len & 0xff) as u8;
        packet[smb_header_offset..smb_header_offset + 4].copy_from_slice(b"\xFESMB");
        packet[smb_header_offset + 12..smb_header_offset + 14]
            .copy_from_slice(&5_u16.to_le_bytes());
        packet[body_offset..body_offset + 2].copy_from_slice(&57_u16.to_le_bytes());
        packet[body_offset + 44..body_offset + 46]
            .copy_from_slice(&(name_offset as u16).to_le_bytes());
        packet[body_offset + 46..body_offset + 48]
            .copy_from_slice(&(name.len() as u16).to_le_bytes());
        packet[smb_header_offset + name_offset..smb_header_offset + name_offset + name.len()]
            .copy_from_slice(&name);

        packet
    }

    fn smb2_write_request(length: u32) -> Vec<u8> {
        let smb_header_offset = 4;
        let body_offset = smb_header_offset + 64;
        let packet_len = body_offset + 48;
        let netbios_len = (packet_len - 4) as u32;
        let mut packet = vec![0_u8; packet_len];

        packet[0] = ((netbios_len >> 16) & 0xff) as u8;
        packet[1] = ((netbios_len >> 8) & 0xff) as u8;
        packet[2] = (netbios_len & 0xff) as u8;
        packet[smb_header_offset..smb_header_offset + 4].copy_from_slice(b"\xFESMB");
        packet[smb_header_offset + 12..smb_header_offset + 14]
            .copy_from_slice(&9_u16.to_le_bytes());
        packet[body_offset..body_offset + 2].copy_from_slice(&49_u16.to_le_bytes());
        packet[body_offset + 4..body_offset + 8].copy_from_slice(&length.to_le_bytes());
        packet[body_offset + 16..body_offset + 32].copy_from_slice(&test_file_id());

        packet
    }

    fn smb2_create_response(message_id: u64, file_id: [u8; 16]) -> Vec<u8> {
        let smb_header_offset = 4;
        let body_offset = smb_header_offset + 64;
        let packet_len = body_offset + 88;
        let netbios_len = (packet_len - 4) as u32;
        let mut packet = vec![0_u8; packet_len];

        packet[0] = ((netbios_len >> 16) & 0xff) as u8;
        packet[1] = ((netbios_len >> 8) & 0xff) as u8;
        packet[2] = (netbios_len & 0xff) as u8;
        packet[smb_header_offset..smb_header_offset + 4].copy_from_slice(b"\xFESMB");
        packet[smb_header_offset + 12..smb_header_offset + 14]
            .copy_from_slice(&5_u16.to_le_bytes());
        packet[smb_header_offset + 24..smb_header_offset + 32]
            .copy_from_slice(&message_id.to_le_bytes());
        packet[body_offset..body_offset + 2].copy_from_slice(&89_u16.to_le_bytes());
        packet[body_offset + 64..body_offset + 80].copy_from_slice(&file_id);

        packet
    }

    fn smb2_ioctl_request(control_code: u32) -> Vec<u8> {
        let smb_header_offset = 4;
        let body_offset = smb_header_offset + 64;
        let packet_len = body_offset + 56;
        let netbios_len = (packet_len - 4) as u32;
        let mut packet = vec![0_u8; packet_len];

        packet[0] = ((netbios_len >> 16) & 0xff) as u8;
        packet[1] = ((netbios_len >> 8) & 0xff) as u8;
        packet[2] = (netbios_len & 0xff) as u8;
        packet[smb_header_offset..smb_header_offset + 4].copy_from_slice(b"\xFESMB");
        packet[smb_header_offset + 12..smb_header_offset + 14]
            .copy_from_slice(&11_u16.to_le_bytes());
        packet[body_offset..body_offset + 2].copy_from_slice(&57_u16.to_le_bytes());
        packet[body_offset + 4..body_offset + 8].copy_from_slice(&control_code.to_le_bytes());

        packet
    }

    fn test_file_id() -> [u8; 16] {
        [
            0x10, 0x11, 0x12, 0x13, 0x20, 0x21, 0x22, 0x23, 0x30, 0x31, 0x32, 0x33, 0x40, 0x41,
            0x42, 0x43,
        ]
    }
}
