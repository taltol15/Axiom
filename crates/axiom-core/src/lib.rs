use std::{
    collections::{HashMap, VecDeque},
    fs::OpenOptions,
    io::Write,
    net::SocketAddr,
    sync::{
        Mutex, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axiom_config::{PolicyConfig, PolicyMode};
use serde::Serialize;

const MAX_RETAINED_THREAT_EVENTS: usize = 128;
const MAX_RETAINED_AUDIT_EVENTS: usize = 512;
const ARCHIVE_MAX_PATTERN_LEN: usize = 8;
const STREAM_INSPECTION_TAIL_LEN: usize = 4096;
const AUDIT_LOG_PATH: &str = "/var/log/axiom/audit.jsonl";

#[derive(Debug)]
pub struct AppState {
    started_at: SystemTime,
    counters: TrafficCounters,
    policy: RwLock<StreamPolicy>,
    policy_generation: AtomicU64,
    policy_updated_at_unix_timestamp_seconds: AtomicU64,
    route_stats: Mutex<HashMap<String, RouteRuntimeStats>>,
    recent_threats: Mutex<VecDeque<ThreatEvent>>,
    recent_audit_events: Mutex<VecDeque<AuditEvent>>,
}

impl AppState {
    pub fn new(policy: StreamPolicy) -> Self {
        Self {
            started_at: SystemTime::now(),
            counters: TrafficCounters::default(),
            policy: RwLock::new(policy),
            policy_generation: AtomicU64::new(1),
            policy_updated_at_unix_timestamp_seconds: AtomicU64::new(unix_timestamp_seconds()),
            route_stats: Mutex::new(HashMap::new()),
            recent_threats: Mutex::new(VecDeque::with_capacity(MAX_RETAINED_THREAT_EVENTS)),
            recent_audit_events: Mutex::new(VecDeque::with_capacity(MAX_RETAINED_AUDIT_EVENTS)),
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

    pub fn record_route_bytes(&self, route_name: &str, direction: TrafficDirection, bytes: u64) {
        self.with_route_stats(route_name, |route| match direction {
            TrafficDirection::ClientToServer => route.bytes_client_to_server += bytes,
            TrafficDirection::ServerToClient => route.bytes_server_to_client += bytes,
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

    pub fn record_file_observed(
        &self,
        context: &InspectionContext<'_>,
        file_path: String,
        bytes_in_chunk: u64,
    ) {
        self.counters
            .observed_file_events
            .fetch_add(1, Ordering::Relaxed);
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
        self.push_audit_event(AuditEvent::from_threat(
            &event,
            AuditEventKind::PolicyBlocked,
            AuditSeverity::Critical,
        ));
        self.push_recent_event(event);
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
            bytes_client_to_server: self.counters.bytes_client_to_server.load(Ordering::Relaxed),
            bytes_server_to_client: self.counters.bytes_server_to_client.load(Ordering::Relaxed),
            monitored_threats: self.counters.monitored_threats.load(Ordering::Relaxed),
            blocked_threats: self.counters.blocked_threats.load(Ordering::Relaxed),
            policy_runtime: self.policy_runtime_snapshot(),
            audit_log_path: AUDIT_LOG_PATH.to_string(),
            route_stats: self.route_snapshots(),
            recent_threats,
            recent_audit_events,
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
}

impl Default for AppState {
    fn default() -> Self {
        Self::new(StreamPolicy::default())
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
    bytes_client_to_server: AtomicU64,
    bytes_server_to_client: AtomicU64,
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
    pub bytes_client_to_server: u64,
    pub bytes_server_to_client: u64,
    pub monitored_threats: u64,
    pub blocked_threats: u64,
    pub policy_runtime: PolicyRuntimeSnapshot,
    pub audit_log_path: String,
    pub route_stats: Vec<RouteStatsSnapshot>,
    pub recent_threats: Vec<ThreatEvent>,
    pub recent_audit_events: Vec<AuditEvent>,
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
    bytes_client_to_server: u64,
    bytes_server_to_client: u64,
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
    pub bytes_client_to_server: u64,
    pub bytes_server_to_client: u64,
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
            bytes_client_to_server: value.bytes_client_to_server,
            bytes_server_to_client: value.bytes_server_to_client,
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
            file_path: extract_file_path_hint(&event.reason),
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
    PolicyDetection,
    PolicyBlocked,
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
            for file_path in extract_smb_file_paths(chunk) {
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
}

pub type InspectContext<'a> = InspectionContext<'a>;

#[derive(Debug)]
pub enum InspectionResult {
    Allow { entropy: f64 },
    Monitor { event: ThreatEvent },
    Block { event: ThreatEvent },
}

pub type InspectOutcome = InspectionResult;

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
    let mut search_start = 0;

    while let Some(relative_offset) = find_bytes(&chunk[search_start..], b"\xFESMB") {
        let header_offset = search_start + relative_offset;
        search_start = header_offset + 4;

        let Some(command) = read_u16_le(chunk, header_offset + 12) else {
            continue;
        };
        if command != 5 {
            continue;
        }

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
            && !paths.iter().any(|existing| existing == &path)
        {
            paths.push(path);
        }
    }

    paths
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    (!needle.is_empty())
        .then(|| {
            haystack
                .windows(needle.len())
                .position(|window| window == needle)
        })
        .flatten()
}

fn read_u16_le(bytes: &[u8], offset: usize) -> Option<u16> {
    let pair = bytes.get(offset..offset + 2)?;
    Some(u16::from_le_bytes([pair[0], pair[1]]))
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
    fn extracts_smb2_create_file_path() {
        let chunk = smb2_create_request(r"Finance\Q2\EicarSample.zip");

        let paths = extract_smb_file_paths(&chunk);

        assert_eq!(paths, vec![r"Finance\Q2\EicarSample.zip"]);
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
}
