use std::{
    collections::VecDeque,
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

#[derive(Debug)]
pub struct AppState {
    started_at: SystemTime,
    counters: TrafficCounters,
    policy: RwLock<StreamPolicy>,
    recent_threats: Mutex<VecDeque<ThreatEvent>>,
}

impl AppState {
    pub fn new(policy: StreamPolicy) -> Self {
        Self {
            started_at: SystemTime::now(),
            counters: TrafficCounters::default(),
            policy: RwLock::new(policy),
            recent_threats: Mutex::new(VecDeque::with_capacity(MAX_RETAINED_THREAT_EVENTS)),
        }
    }

    pub fn connection_started(&self) {
        self.counters
            .total_connections
            .fetch_add(1, Ordering::Relaxed);
        self.counters
            .active_connections
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn connection_finished(&self) {
        let _ = self.counters.active_connections.fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |value| Some(value.saturating_sub(1)),
        );
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

    pub fn record_inspection(&self, bytes: u64) {
        self.counters
            .inspected_chunks
            .fetch_add(1, Ordering::Relaxed);
        self.counters
            .inspected_bytes
            .fetch_add(bytes, Ordering::Relaxed);
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
        self.push_recent_event(event);
    }

    pub fn record_blocked_threat(&self, event: ThreatEvent) {
        self.counters.blocked_chunks.fetch_add(1, Ordering::Relaxed);
        self.counters
            .blocked_threats
            .fetch_add(1, Ordering::Relaxed);
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

    pub fn update_policy(&self, policy: PolicyConfig) {
        let mut guard = self.policy.write().expect("stream policy lock poisoned");
        *guard = StreamPolicy::from_config(policy);
    }

    pub fn max_pattern_len(&self) -> usize {
        self.policy
            .read()
            .expect("stream policy lock poisoned")
            .max_pattern_len()
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
    pub recent_threats: Vec<ThreatEvent>,
}

pub type TrafficSnapshot = StatusSnapshot;

#[derive(Debug, Clone, Copy, Serialize)]
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

        if let Some(detection) = self.detect_archive_policy_violation(chunk) {
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
            .map(|signature| signature.pattern.len())
            .max()
            .unwrap_or(0);

        signature_len.max(ARCHIVE_MAX_PATTERN_LEN)
    }

    fn match_signature<'a>(&'a self, chunk: &[u8]) -> Option<&'a RuntimeSignature> {
        self.signatures.iter().find(|signature| {
            signature.mode.is_enabled() && contains_bytes(chunk, &signature.pattern)
        })
    }

    fn detect_archive_policy_violation(&self, chunk: &[u8]) -> Option<PolicyDetection> {
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
    pattern: Vec<u8>,
    mode: PolicyMode,
}

impl From<&axiom_config::SignaturePolicyConfig> for RuntimeSignature {
    fn from(value: &axiom_config::SignaturePolicyConfig) -> Self {
        Self {
            name: value.name.clone(),
            pattern: value.pattern.as_bytes().to_vec(),
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

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use axiom_config::{ArchivePolicyConfig, EntropyPolicyConfig};

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
        let policy = StreamPolicy::default();
        let context = test_context();
        let chunk = b"prefixPK\x03\x04\x14\x00\x00\x00plain-zip";

        let result = policy.inspect_chunk(&context, chunk);

        assert!(matches!(result, InspectionResult::Monitor { .. }));
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
    fn disabled_archive_policy_allows_rar() {
        let policy = StreamPolicy::from_config(PolicyConfig {
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
