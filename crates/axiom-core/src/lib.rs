use std::{
    collections::{HashMap, VecDeque},
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
const ARCHIVE_MAX_PATTERN_LEN: usize = 8;
const STREAM_INSPECTION_TAIL_LEN: usize = 4096;

#[derive(Debug)]
pub struct AppState {
    started_at: SystemTime,
    counters: TrafficCounters,
    policy: RwLock<StreamPolicy>,
    policy_generation: AtomicU64,
    policy_updated_at_unix_timestamp_seconds: AtomicU64,
    route_stats: Mutex<HashMap<String, RouteRuntimeStats>>,
    recent_threats: Mutex<VecDeque<ThreatEvent>>,
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
            bytes_client_to_server: self.counters.bytes_client_to_server.load(Ordering::Relaxed),
            bytes_server_to_client: self.counters.bytes_server_to_client.load(Ordering::Relaxed),
            monitored_threats: self.counters.monitored_threats.load(Ordering::Relaxed),
            blocked_threats: self.counters.blocked_threats.load(Ordering::Relaxed),
            policy_runtime: self.policy_runtime_snapshot(),
            route_stats: self.route_snapshots(),
            recent_threats,
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
    pub bytes_client_to_server: u64,
    pub bytes_server_to_client: u64,
    pub monitored_threats: u64,
    pub blocked_threats: u64,
    pub policy_runtime: PolicyRuntimeSnapshot,
    pub route_stats: Vec<RouteStatsSnapshot>,
    pub recent_threats: Vec<ThreatEvent>,
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

fn contains_ascii_or_utf16le_case_insensitive(haystack: &[u8], needle: &str) -> bool {
    contains_ascii_case_insensitive(haystack, needle.as_bytes())
        || contains_utf16le_ascii_case_insensitive(haystack, needle.as_bytes())
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
        let mut chunk = b"\x00\x00\x00\x90\xfeSMBcreate-request-padding".to_vec();
        chunk.extend_from_slice(&utf16le_bytes("Finance Backup.RaR"));

        let result = policy.inspect_chunk(&context, &chunk);

        assert!(matches!(result, InspectionResult::Block { .. }));
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

    fn test_context() -> InspectionContext<'static> {
        InspectionContext {
            route_name: "test-route",
            interface: "lo",
            direction: TrafficDirection::ClientToServer,
            peer_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 49152),
            target_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 445),
        }
    }
}
