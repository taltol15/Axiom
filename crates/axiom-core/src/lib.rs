use std::{
    collections::VecDeque,
    net::SocketAddr,
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde::Serialize;

const MAX_RETAINED_THREAT_EVENTS: usize = 128;

#[derive(Debug)]
pub struct AppState {
    started_at: SystemTime,
    counters: TrafficCounters,
    policy: StreamPolicy,
    recent_threats: Mutex<VecDeque<ThreatEvent>>,
}

impl AppState {
    pub fn new(policy: StreamPolicy) -> Self {
        Self {
            started_at: SystemTime::now(),
            counters: TrafficCounters::default(),
            policy,
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

    pub fn record_blocked_threat(&self, event: ThreatEvent) {
        self.counters
            .blocked_threats
            .fetch_add(1, Ordering::Relaxed);

        let mut recent_threats = self
            .recent_threats
            .lock()
            .expect("recent threat event mutex poisoned");

        if recent_threats.len() == MAX_RETAINED_THREAT_EVENTS {
            recent_threats.pop_front();
        }
        recent_threats.push_back(event);
    }

    pub fn policy(&self) -> &StreamPolicy {
        &self.policy
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
            bytes_client_to_server: self.counters.bytes_client_to_server.load(Ordering::Relaxed),
            bytes_server_to_client: self.counters.bytes_server_to_client.load(Ordering::Relaxed),
            blocked_threats: self.counters.blocked_threats.load(Ordering::Relaxed),
            recent_threats,
        }
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
    bytes_client_to_server: AtomicU64,
    bytes_server_to_client: AtomicU64,
    blocked_threats: AtomicU64,
}

#[derive(Debug, Clone, Serialize)]
pub struct StatusSnapshot {
    pub uptime_seconds: u64,
    pub total_connections: u64,
    pub active_connections: u64,
    pub bytes_client_to_server: u64,
    pub bytes_server_to_client: u64,
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
        reason: String,
        bytes_in_chunk: usize,
        entropy: f64,
    ) -> Self {
        Self {
            unix_timestamp_seconds: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_else(|_| Duration::from_secs(0))
                .as_secs(),
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
    signatures: Vec<Vec<u8>>,
    entropy_block_threshold: f64,
    entropy_minimum_chunk_size: usize,
}

impl StreamPolicy {
    pub fn new(
        signatures: Vec<Vec<u8>>,
        entropy_block_threshold: f64,
        entropy_minimum_chunk_size: usize,
    ) -> Self {
        Self {
            signatures,
            entropy_block_threshold,
            entropy_minimum_chunk_size,
        }
    }

    pub fn inspect_chunk(&self, context: &InspectionContext<'_>, chunk: &[u8]) -> InspectionResult {
        let entropy = calculate_shannon_entropy(chunk);

        if let Some(signature) = self.match_signature(chunk) {
            return InspectionResult::Block {
                event: ThreatEvent::now(
                    context,
                    format!(
                        "blocked signature '{}'",
                        String::from_utf8_lossy(signature).escape_default()
                    ),
                    chunk.len(),
                    entropy,
                ),
            };
        }

        if chunk.len() >= self.entropy_minimum_chunk_size
            && entropy >= self.entropy_block_threshold
            && !looks_like_smb_negotiate_or_session_setup(chunk)
        {
            return InspectionResult::Block {
                event: ThreatEvent::now(
                    context,
                    format!("entropy {:.3} exceeded threshold", entropy),
                    chunk.len(),
                    entropy,
                ),
            };
        }

        InspectionResult::Allow { entropy }
    }

    fn match_signature<'a>(&'a self, chunk: &[u8]) -> Option<&'a [u8]> {
        self.signatures
            .iter()
            .find(|signature| contains_bytes(chunk, signature))
            .map(Vec::as_slice)
    }
}

impl Default for StreamPolicy {
    fn default() -> Self {
        Self::new(
            vec![
                b"AXIOM_TEST_THREAT".to_vec(),
                b"WNCRY".to_vec(),
                b"WANACRY!".to_vec(),
            ],
            7.98,
            64 * 1024,
        )
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
