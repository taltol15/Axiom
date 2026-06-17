use std::{
    collections::{HashMap, HashSet},
    io,
    net::SocketAddr,
    sync::{Arc, Mutex as StdMutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::Context;
use axiom_config::{PolicyMode, ProxyListenerConfig};
use axiom_core::{
    CompletedFileTransfer, InspectionContext, InspectionResult, RuntimeState, Smb2CloseRequest,
    Smb2CreateRequest, Smb2CreateResponse, Smb2ReadRequest, Smb2ReadResponse, Smb2WriteRequest,
    ThreatEvent, TrafficDirection, contains_smb2_network_interface_info_request,
    contains_smb2_server_side_copy_request, extract_smb2_close_requests,
    extract_smb2_create_requests, extract_smb2_create_responses, extract_smb2_read_requests,
    extract_smb2_read_responses, extract_smb2_write_requests,
};
use axiom_reputation::{KnownBadAction, ReputationLookupResponse, ReputationVerdict};
use md5::Md5;
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        TcpStream,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
    sync::Mutex as AsyncMutex,
};
use tracing::{debug, info, warn};

use crate::listener::{bind_tcp_listener_to_interface, connect_tcp_via_interface};

const MAX_SMB_TCP_FRAME_LEN: usize = 16 * 1024 * 1024 + 4;
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
const DEFAULT_INLINE_REPUTATION_LOOKUP_MAX_BYTES: u64 = 1024 * 1024;
const INLINE_REPUTATION_CACHE_TTL_SECONDS: u64 = 60;

#[derive(Debug, Clone)]
pub struct ReputationLookupConfig {
    pub management_url: String,
    pub enrollment_token: String,
    pub allow_invalid_tls: bool,
    pub max_inline_lookup_bytes: u64,
}

#[derive(Debug)]
struct ReputationLookupClient {
    client: reqwest::Client,
    management_url: String,
    enrollment_token: String,
    max_inline_lookup_bytes: u64,
    cache: AsyncMutex<HashMap<String, CachedInlineReputation>>,
}

#[derive(Debug, Clone)]
struct CachedInlineReputation {
    verdict: ReputationVerdict,
    expires_at_unix_timestamp_seconds: u64,
}

impl ReputationLookupClient {
    fn new(config: ReputationLookupConfig) -> anyhow::Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(3))
            .user_agent("AxiomSmbInlineReputation/0.1")
            .danger_accept_invalid_certs(config.allow_invalid_tls)
            .build()
            .context("failed building SMB inline reputation client")?;

        Ok(Self {
            client,
            management_url: config.management_url.trim_end_matches('/').to_string(),
            enrollment_token: config.enrollment_token,
            max_inline_lookup_bytes: config
                .max_inline_lookup_bytes
                .max(DEFAULT_INLINE_REPUTATION_LOOKUP_MAX_BYTES),
            cache: AsyncMutex::new(HashMap::new()),
        })
    }

    fn should_lookup(&self, bytes: u64) -> bool {
        bytes > 0 && bytes <= self.max_inline_lookup_bytes
    }

    async fn lookup(&self, sha256: &str) -> anyhow::Result<ReputationVerdict> {
        let now = unix_timestamp_seconds();
        if let Some(entry) = self.cache.lock().await.get(sha256).cloned()
            && entry.expires_at_unix_timestamp_seconds > now
        {
            return Ok(entry.verdict);
        }

        let response = self
            .client
            .get(format!(
                "{}/api/reputation/lookup/{}",
                self.management_url, sha256
            ))
            .bearer_auth(&self.enrollment_token)
            .send()
            .await
            .context("inline reputation lookup request failed")?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!(
                "management returned HTTP {} for inline reputation lookup",
                response.status()
            ));
        }

        let payload: ReputationLookupResponse = response
            .json()
            .await
            .context("failed decoding inline reputation lookup response")?;
        if payload.verdict == ReputationVerdict::KnownBad {
            self.cache.lock().await.insert(
                sha256.to_string(),
                CachedInlineReputation {
                    verdict: payload.verdict,
                    expires_at_unix_timestamp_seconds: now + INLINE_REPUTATION_CACHE_TTL_SECONDS,
                },
            );
        }

        Ok(payload.verdict)
    }
}

pub async fn run_proxy_listener(
    route: ProxyListenerConfig,
    state: Arc<RuntimeState>,
    reputation_lookup_config: Option<ReputationLookupConfig>,
) -> anyhow::Result<()> {
    let reputation_lookup = reputation_lookup_config
        .map(ReputationLookupClient::new)
        .transpose()?
        .map(Arc::new);
    let listener =
        bind_tcp_listener_to_interface(route.interface(), route.listen_addr(), route.backlog)
            .await
            .with_context(|| {
                format!(
                    "failed binding SMB listener '{}' on interface '{}' at {}",
                    route.name,
                    route.interface(),
                    route.listen_addr()
                )
            })?;

    info!(
        route = route.name,
        interface = route.interface(),
        listen_addr = %route.listen_addr(),
        target_addr = %route.target_addr(),
        vlan = ?route.client_vlan,
        "SMB proxy listener started"
    );
    state.register_route(
        &route.name,
        route.interface(),
        route.listen_addr(),
        route.target_addr(),
    );

    loop {
        let (client_stream, peer_addr) = listener.accept().await.with_context(|| {
            format!(
                "failed accepting connection on route '{}' at {}",
                route.name,
                route.listen_addr()
            )
        })?;

        state.connection_started();
        state.route_connection_started(&route.name, peer_addr);
        let connection_context = InspectionContext {
            route_name: &route.name,
            interface: route.interface(),
            direction: TrafficDirection::ClientToServer,
            peer_addr,
            target_addr: route.target_addr(),
            file_path_hint: None,
        };
        state.record_connection_opened(&connection_context);
        let guard = ConnectionGuard::new(
            Arc::clone(&state),
            route.name.clone(),
            route.interface().to_string(),
            peer_addr,
            route.target_addr(),
        );
        let route = Arc::new(route.clone());
        let task_state = Arc::clone(&state);
        let task_reputation_lookup = reputation_lookup.clone();

        tokio::spawn(async move {
            if let Err(error) = handle_connection(
                client_stream,
                peer_addr,
                Arc::clone(&route),
                task_state,
                task_reputation_lookup,
            )
            .await
            {
                warn!(
                    route = route.name,
                    peer = %peer_addr,
                    ?error,
                    "SMB proxy connection terminated"
                );
            }

            drop(guard);
        });
    }
}

async fn handle_connection(
    client_stream: TcpStream,
    peer_addr: SocketAddr,
    route: Arc<ProxyListenerConfig>,
    state: Arc<RuntimeState>,
    reputation_lookup: Option<Arc<ReputationLookupClient>>,
) -> anyhow::Result<()> {
    let target_addr = route.target_addr();
    let server_stream = connect_tcp_via_interface(route.interface(), target_addr)
        .await
        .with_context(|| {
            format!(
                "failed connecting from interface '{}' to target file server {}",
                route.interface(),
                target_addr
            )
        })?;

    debug!(
        route = route.name,
        peer = %peer_addr,
        target = %target_addr,
        "SMB proxy connection established"
    );

    relay_bidirectional(
        client_stream,
        server_stream,
        peer_addr,
        route,
        state,
        reputation_lookup,
    )
    .await
    .map_err(Into::into)
}

async fn relay_bidirectional(
    client_stream: TcpStream,
    server_stream: TcpStream,
    peer_addr: SocketAddr,
    route: Arc<ProxyListenerConfig>,
    state: Arc<RuntimeState>,
    reputation_lookup: Option<Arc<ReputationLookupClient>>,
) -> io::Result<()> {
    let target_addr = route.target_addr();
    let (client_reader, client_writer) = client_stream.into_split();
    let (server_reader, server_writer) = server_stream.into_split();
    let client_writer = Arc::new(AsyncMutex::new(client_writer));
    let server_writer = Arc::new(AsyncMutex::new(server_writer));
    let telemetry = Arc::new(ConnectionTelemetry::default());

    let client_to_server = relay_smb_frame_direction(
        Arc::clone(&route),
        Arc::clone(&state),
        Arc::clone(&telemetry),
        peer_addr,
        target_addr,
        TrafficDirection::ClientToServer,
        client_reader,
        Arc::clone(&server_writer),
        Some(Arc::clone(&client_writer)),
        reputation_lookup,
    );

    let server_to_client = relay_smb_frame_direction(
        route,
        state,
        telemetry,
        peer_addr,
        target_addr,
        TrafficDirection::ServerToClient,
        server_reader,
        client_writer,
        None,
        None,
    );

    tokio::try_join!(client_to_server, server_to_client).map(|_| ())
}

async fn relay_smb_frame_direction(
    route: Arc<ProxyListenerConfig>,
    state: Arc<RuntimeState>,
    telemetry: Arc<ConnectionTelemetry>,
    peer_addr: SocketAddr,
    target_addr: SocketAddr,
    direction: TrafficDirection,
    mut reader: OwnedReadHalf,
    writer: Arc<AsyncMutex<OwnedWriteHalf>>,
    block_response_writer: Option<Arc<AsyncMutex<OwnedWriteHalf>>>,
    reputation_lookup: Option<Arc<ReputationLookupClient>>,
) -> io::Result<()> {
    let mut buffer = vec![0_u8; 128 * 1024];
    let mut framer = SmbTcpFramer::default();
    let mut inspection_window = InspectionWindow::new(state.max_pattern_len());

    loop {
        let bytes_read = reader.read(&mut buffer).await?;
        if bytes_read == 0 {
            writer.lock().await.shutdown().await?;
            return Ok(());
        }

        let read_file_path_hint = telemetry.latest_write_file_path();
        let read_context = InspectionContext {
            route_name: &route.name,
            interface: route.interface(),
            direction,
            peer_addr,
            target_addr,
            file_path_hint: read_file_path_hint.as_deref(),
        };
        state.record_connection_stream_bytes(&read_context, bytes_read as u64);
        let chunk = &buffer[..bytes_read];
        let frames = framer.push(chunk)?;

        for frame in frames {
            inspect_and_forward_frame(
                &route,
                &state,
                &telemetry,
                peer_addr,
                target_addr,
                direction,
                &writer,
                block_response_writer.as_ref(),
                reputation_lookup.as_ref(),
                &mut inspection_window,
                frame,
            )
            .await?;
        }
    }
}

async fn inspect_and_forward_frame(
    route: &ProxyListenerConfig,
    state: &RuntimeState,
    telemetry: &ConnectionTelemetry,
    peer_addr: SocketAddr,
    target_addr: SocketAddr,
    direction: TrafficDirection,
    writer: &Arc<AsyncMutex<OwnedWriteHalf>>,
    block_response_writer: Option<&Arc<AsyncMutex<OwnedWriteHalf>>>,
    reputation_lookup: Option<&Arc<ReputationLookupClient>>,
    inspection_window: &mut InspectionWindow,
    frame: Vec<u8>,
) -> io::Result<()> {
    state.record_inspection(frame.len() as u64);
    state.record_route_inspection(&route.name, frame.len() as u64);

    let inspection_bytes = inspection_window.merge(&frame);
    let create_requests = if direction == TrafficDirection::ClientToServer {
        extract_smb2_create_requests(&frame)
    } else {
        Vec::new()
    };
    let write_requests = if direction == TrafficDirection::ClientToServer {
        extract_smb2_write_requests(&frame)
    } else {
        Vec::new()
    };
    let read_requests = if direction == TrafficDirection::ClientToServer {
        extract_smb2_read_requests(&frame)
    } else {
        Vec::new()
    };
    let close_requests = if direction == TrafficDirection::ClientToServer {
        extract_smb2_close_requests(&frame)
    } else {
        Vec::new()
    };
    let read_responses = if direction == TrafficDirection::ServerToClient {
        extract_smb2_read_responses(&frame)
    } else {
        Vec::new()
    };
    let file_path_hint = if direction == TrafficDirection::ClientToServer {
        create_requests
            .first()
            .map(|request| request.file_path.clone())
            .or_else(|| {
                write_requests
                    .iter()
                    .find_map(|request| telemetry.file_path_for_id(&request.file_id))
            })
            .or_else(|| telemetry.latest_write_file_path())
    } else {
        None
    };

    let context = InspectionContext {
        route_name: &route.name,
        interface: route.interface(),
        direction,
        peer_addr,
        target_addr,
        file_path_hint: file_path_hint.as_deref(),
    };

    let mut known_bad_reputation_match = None;
    if direction == TrafficDirection::ClientToServer {
        for create_request in create_requests {
            telemetry.observe_create_request(state, &context, create_request, frame.len());
        }
        for write_request in write_requests {
            if let Some(hash_progress) =
                telemetry.observe_write_request(state, &context, write_request, &frame)
            {
                if let Some(reputation_match) = known_bad_reputation_match_for_progress(
                    state,
                    reputation_lookup,
                    &hash_progress,
                )
                .await
                {
                    known_bad_reputation_match = Some(reputation_match);
                }
            }
        }
        for read_request in read_requests {
            telemetry.observe_read_request(read_request);
        }
        for close_request in close_requests {
            telemetry.observe_close_request(state, &context, close_request);
        }
        if contains_smb2_network_interface_info_request(&frame) {
            state.record_smb_multichannel_blocked(&context, frame.len() as u64);
            warn!(
                route = route.name,
                interface = route.interface(),
                peer = %peer_addr,
                target = %target_addr,
                "blocked SMB multichannel interface discovery to keep traffic on Axiom"
            );

            if let Some(response_writer) = block_response_writer
                && let Some(response) = build_smb2_error_response(&frame, STATUS_ACCESS_DENIED)
            {
                response_writer.lock().await.write_all(&response).await?;
            }

            return Ok(());
        }
        if contains_smb2_server_side_copy_request(&frame) {
            state.record_server_side_copy_requested(&context);
        }
    } else {
        for create_response in extract_smb2_create_responses(&frame) {
            telemetry.observe_create_response(create_response);
        }
        for read_response in read_responses {
            telemetry.observe_read_response(&context, read_response, &frame);
        }
    }

    if let Some(reputation_match) = known_bad_reputation_match {
        let reputation_policy = state.policy_config().reputation;
        if reputation_policy.enabled
            && matches!(
                reputation_policy.known_bad_action,
                KnownBadAction::Block | KnownBadAction::Quarantine
            )
        {
            let action = match reputation_policy.known_bad_action {
                KnownBadAction::Quarantine => "quarantine",
                _ => "block",
            };
            let event = ThreatEvent::now(
                &context,
                PolicyMode::Block,
                "Known bad reputation hash".to_string(),
                format!(
                    "{action} reputation action triggered for SHA256 {} on '{}'",
                    reputation_match.sha256, reputation_match.file_path
                ),
                frame.len(),
                0.0,
            );
            record_blocked_event(state, event);
            warn!(
                route = route.name,
                interface = route.interface(),
                ?direction,
                peer = %peer_addr,
                target = %target_addr,
                file_path = reputation_match.file_path,
                sha256 = reputation_match.sha256,
                bytes_seen = reputation_match.bytes,
                action,
                "blocked SMB frame by known bad reputation hash"
            );

            if let Some(response_writer) = block_response_writer
                && let Some(response) = build_smb2_error_response(&frame, STATUS_ACCESS_DENIED)
            {
                let mut client_writer = response_writer.lock().await;
                client_writer.write_all(&response).await?;
                client_writer.shutdown().await?;
            }

            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "stream blocked by known bad reputation hash",
            ));
        }
    }

    match state.inspect_chunk(&context, &inspection_bytes) {
        InspectionResult::Allow { entropy } => {
            debug!(
                route = route.name,
                ?direction,
                bytes = frame.len(),
                entropy,
                "forwarding inspected SMB frame"
            );
            writer.lock().await.write_all(&frame).await?;
            inspection_window.remember(&frame);
            state.record_allowed_chunk();
            state.record_forwarded_bytes(&context, frame.len() as u64);
        }
        InspectionResult::Monitor { event } => {
            let reason = event.reason.clone();
            warn!(
                route = route.name,
                interface = route.interface(),
                ?direction,
                peer = %peer_addr,
                target = %target_addr,
                reason,
                "monitored SMB stream policy event"
            );
            state.record_monitored_threat(event);
            writer.lock().await.write_all(&frame).await?;
            inspection_window.remember(&frame);
            state.record_allowed_chunk();
            state.record_forwarded_bytes(&context, frame.len() as u64);
        }
        InspectionResult::Block { event } => {
            let reason = event.reason.clone();
            record_blocked_event(state, event);
            warn!(
                route = route.name,
                interface = route.interface(),
                ?direction,
                peer = %peer_addr,
                target = %target_addr,
                reason,
                "blocked SMB frame"
            );

            if direction == TrafficDirection::ClientToServer
                && let Some(response_writer) = block_response_writer
                && let Some(response) = build_smb2_error_response(&frame, STATUS_ACCESS_DENIED)
            {
                let mut client_writer = response_writer.lock().await;
                client_writer.write_all(&response).await?;
                client_writer.shutdown().await?;
            }

            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "stream blocked by Axiom policy",
            ));
        }
    }

    Ok(())
}

fn record_blocked_event(state: &RuntimeState, event: ThreatEvent) {
    state.record_blocked_threat(event);
}

async fn known_bad_reputation_match_for_progress(
    state: &RuntimeState,
    reputation_lookup: Option<&Arc<ReputationLookupClient>>,
    progress: &FileHashProgress,
) -> Option<KnownBadReputationMatch> {
    let reputation_policy = state.policy_config().reputation;
    if !reputation_policy.enabled
        || !matches!(
            reputation_policy.known_bad_action,
            KnownBadAction::Block | KnownBadAction::Quarantine
        )
    {
        return None;
    }

    if state.is_known_bad_reputation_hash(&progress.sha256) {
        return Some(KnownBadReputationMatch {
            file_path: progress.file_path.clone(),
            sha256: progress.sha256.clone(),
            bytes: progress.bytes,
        });
    }

    let lookup = reputation_lookup?;
    if !lookup.should_lookup(progress.bytes) {
        return None;
    }

    match lookup.lookup(&progress.sha256).await {
        Ok(ReputationVerdict::KnownBad) => {
            state.add_known_bad_reputation_hash(&progress.sha256);
            Some(KnownBadReputationMatch {
                file_path: progress.file_path.clone(),
                sha256: progress.sha256.clone(),
                bytes: progress.bytes,
            })
        }
        Ok(ReputationVerdict::KnownGood | ReputationVerdict::Unknown) => None,
        Err(error) => {
            warn!(
                sha256 = progress.sha256,
                bytes = progress.bytes,
                ?error,
                "inline reputation lookup failed; failing open"
            );
            None
        }
    }
}

#[derive(Debug, Default)]
struct SmbTcpFramer {
    pending: Vec<u8>,
}

impl SmbTcpFramer {
    fn push(&mut self, chunk: &[u8]) -> io::Result<Vec<Vec<u8>>> {
        self.pending.extend_from_slice(chunk);
        let mut frames = Vec::new();

        loop {
            if self.pending.len() < 4 {
                break;
            }

            if self.pending[0] != 0 {
                if let Some(offset) = find_smb_tcp_frame_start(&self.pending) {
                    if offset > 0 {
                        self.pending.drain(..offset);
                    }
                } else if self.pending.len() > 4 {
                    let retained = self.pending.split_off(self.pending.len() - 4);
                    self.pending = retained;
                    break;
                } else {
                    break;
                }
            }

            if self.pending.len() < 4 {
                break;
            }

            let frame_len = ((self.pending[1] as usize) << 16)
                | ((self.pending[2] as usize) << 8)
                | self.pending[3] as usize;
            if frame_len == 0 {
                self.pending.drain(..4);
                continue;
            }

            let total_len = frame_len + 4;
            if total_len > MAX_SMB_TCP_FRAME_LEN {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("SMB frame length {total_len} exceeds supported maximum"),
                ));
            }

            if self.pending.len() < total_len {
                break;
            }

            frames.push(self.pending.drain(..total_len).collect());
        }

        Ok(frames)
    }
}

fn find_smb_tcp_frame_start(bytes: &[u8]) -> Option<usize> {
    bytes.windows(8).position(|window| {
        window[0] == 0
            && (window.get(4..8) == Some(b"\xFESMB") || window.get(4..8) == Some(b"\xFDSMB"))
    })
}

fn build_smb2_error_response(request_frame: &[u8], status: u32) -> Option<Vec<u8>> {
    let header_offset = request_frame
        .windows(4)
        .position(|window| window == b"\xFESMB")?;
    let request_header = request_frame.get(header_offset..header_offset + 64)?;

    let smb_payload_len = 64 + 8;
    let mut response = vec![0_u8; 4 + smb_payload_len];
    response[1] = ((smb_payload_len >> 16) & 0xff) as u8;
    response[2] = ((smb_payload_len >> 8) & 0xff) as u8;
    response[3] = (smb_payload_len & 0xff) as u8;

    let header = &mut response[4..68];
    header[0..4].copy_from_slice(b"\xFESMB");
    header[4..6].copy_from_slice(&64_u16.to_le_bytes());
    header[6..8].copy_from_slice(&request_header[6..8]);
    header[8..12].copy_from_slice(&status.to_le_bytes());
    header[12..14].copy_from_slice(&request_header[12..14]);
    header[14..16].copy_from_slice(&1_u16.to_le_bytes());
    header[16..20].copy_from_slice(&1_u32.to_le_bytes());
    header[24..32].copy_from_slice(&request_header[24..32]);
    header[32..36].copy_from_slice(&request_header[32..36]);
    header[36..40].copy_from_slice(&request_header[36..40]);
    header[40..48].copy_from_slice(&request_header[40..48]);

    let body = &mut response[68..76];
    body[0..2].copy_from_slice(&9_u16.to_le_bytes());
    body[4..8].copy_from_slice(&0_u32.to_le_bytes());

    Some(response)
}

#[derive(Debug, Default)]
struct ConnectionTelemetry {
    pending_create_paths: StdMutex<HashMap<u64, String>>,
    open_file_paths: StdMutex<HashMap<[u8; 16], String>>,
    open_file_creation_times: StdMutex<HashMap<[u8; 16], Option<u64>>>,
    pending_read_file_ids: StdMutex<HashMap<u64, [u8; 16]>>,
    file_hashes: StdMutex<HashMap<[u8; 16], FileHashState>>,
    observed_file_paths: StdMutex<HashSet<String>>,
    latest_write_file_path: StdMutex<Option<String>>,
}

impl ConnectionTelemetry {
    fn observe_create_request(
        &self,
        state: &RuntimeState,
        context: &InspectionContext<'_>,
        request: Smb2CreateRequest,
        bytes_read: usize,
    ) {
        self.pending_create_paths
            .lock()
            .expect("pending create path mutex poisoned")
            .insert(request.message_id, request.file_path.clone());

        let mut observed = self
            .observed_file_paths
            .lock()
            .expect("observed file path mutex poisoned");
        if observed.insert(request.file_path.clone()) {
            state.record_file_observed(context, request.file_path, bytes_read as u64);
        }
    }

    fn observe_create_response(&self, response: Smb2CreateResponse) {
        let Some(file_path) = self
            .pending_create_paths
            .lock()
            .expect("pending create path mutex poisoned")
            .remove(&response.message_id)
        else {
            return;
        };

        self.open_file_paths
            .lock()
            .expect("open file path mutex poisoned")
            .insert(response.file_id, file_path.clone());
        self.open_file_creation_times
            .lock()
            .expect("open file creation time mutex poisoned")
            .insert(
                response.file_id,
                response.creation_time_unix_timestamp_seconds,
            );
        self.file_hashes
            .lock()
            .expect("file hashes mutex poisoned")
            .entry(response.file_id)
            .or_insert_with(|| {
                FileHashState::new(file_path, response.creation_time_unix_timestamp_seconds)
            });
    }

    fn file_path_for_id(&self, file_id: &[u8; 16]) -> Option<String> {
        self.open_file_paths
            .lock()
            .expect("open file path mutex poisoned")
            .get(file_id)
            .cloned()
    }

    fn latest_write_file_path(&self) -> Option<String> {
        self.latest_write_file_path
            .lock()
            .expect("latest write file path mutex poisoned")
            .clone()
    }

    fn observe_write_request(
        &self,
        state: &RuntimeState,
        context: &InspectionContext<'_>,
        request: Smb2WriteRequest,
        frame: &[u8],
    ) -> Option<FileHashProgress> {
        let file_path = self
            .open_file_paths
            .lock()
            .expect("open file path mutex poisoned")
            .get(&request.file_id)
            .cloned();

        if let Some(file_path) = file_path {
            *self
                .latest_write_file_path
                .lock()
                .expect("latest write file path mutex poisoned") = Some(file_path.clone());
            state.record_file_write_payload(context, &file_path, request.length as u64);
            if let Some(payload) = request
                .data_range
                .and_then(|(start, end)| frame.get(start..end))
            {
                let progress = self.update_hash_for_file_id(
                    &request.file_id,
                    &file_path,
                    context.direction,
                    payload,
                );
                if let Some(progress) = progress {
                    return Some(progress);
                }
            }
        } else {
            state.record_smb_write_payload_for_connection(context, request.length as u64);
        }
        None
    }

    fn observe_read_request(&self, request: Smb2ReadRequest) {
        self.pending_read_file_ids
            .lock()
            .expect("pending read file ids mutex poisoned")
            .insert(request.message_id, request.file_id);
    }

    fn observe_read_response(
        &self,
        context: &InspectionContext<'_>,
        response: Smb2ReadResponse,
        frame: &[u8],
    ) {
        let Some(file_id) = self
            .pending_read_file_ids
            .lock()
            .expect("pending read file ids mutex poisoned")
            .remove(&response.message_id)
        else {
            return;
        };

        let Some(file_path) = self.file_path_for_id(&file_id) else {
            return;
        };

        if let Some(payload) = response
            .data_range
            .and_then(|(start, end)| frame.get(start..end))
        {
            let _ = self.update_hash_for_file_id(&file_id, &file_path, context.direction, payload);
        }
    }

    fn observe_close_request(
        &self,
        state: &RuntimeState,
        context: &InspectionContext<'_>,
        request: Smb2CloseRequest,
    ) {
        let transfer = self
            .file_hashes
            .lock()
            .expect("file hashes mutex poisoned")
            .remove(&request.file_id)
            .and_then(|hash_state| hash_state.finish(context));

        self.open_file_paths
            .lock()
            .expect("open file path mutex poisoned")
            .remove(&request.file_id);
        self.open_file_creation_times
            .lock()
            .expect("open file creation time mutex poisoned")
            .remove(&request.file_id);

        if let Some(transfer) = transfer {
            state.record_completed_file_transfer(transfer);
        }
    }

    fn update_hash_for_file_id(
        &self,
        file_id: &[u8; 16],
        file_path: &str,
        direction: TrafficDirection,
        payload: &[u8],
    ) -> Option<FileHashProgress> {
        if payload.is_empty() {
            return None;
        }

        let creation_time = self
            .open_file_creation_times
            .lock()
            .expect("open file creation time mutex poisoned")
            .get(file_id)
            .copied()
            .flatten();

        let mut hashes = self.file_hashes.lock().expect("file hashes mutex poisoned");
        let hash_state = hashes
            .entry(*file_id)
            .or_insert_with(|| FileHashState::new(file_path.to_string(), creation_time));
        hash_state.update(direction, payload);
        Some(hash_state.progress())
    }
}

#[derive(Debug, Clone)]
struct KnownBadReputationMatch {
    file_path: String,
    sha256: String,
    bytes: u64,
}

#[derive(Debug, Clone)]
struct FileHashProgress {
    file_path: String,
    sha256: String,
    bytes: u64,
}

#[derive(Debug)]
struct FileHashState {
    file_path: String,
    creation_time: Option<u64>,
    direction: Option<TrafficDirection>,
    sha256: Sha256,
    md5: Md5,
    bytes: u64,
    first_seen_unix_timestamp_seconds: u64,
    last_seen_unix_timestamp_seconds: u64,
}

impl FileHashState {
    fn new(file_path: String, creation_time: Option<u64>) -> Self {
        let now = unix_timestamp_seconds();
        Self {
            file_path,
            creation_time,
            direction: None,
            sha256: Sha256::new(),
            md5: Md5::new(),
            bytes: 0,
            first_seen_unix_timestamp_seconds: now,
            last_seen_unix_timestamp_seconds: now,
        }
    }

    fn update(&mut self, direction: TrafficDirection, payload: &[u8]) {
        self.direction = Some(direction);
        self.sha256.update(payload);
        self.md5.update(payload);
        self.bytes = self.bytes.saturating_add(payload.len() as u64);
        self.last_seen_unix_timestamp_seconds = unix_timestamp_seconds();
    }

    fn progress(&self) -> FileHashProgress {
        FileHashProgress {
            file_path: self.file_path.clone(),
            sha256: hex_lower(&self.sha256.clone().finalize()),
            bytes: self.bytes,
        }
    }

    fn finish(self, context: &InspectionContext<'_>) -> Option<CompletedFileTransfer> {
        if self.bytes == 0 {
            return None;
        }
        let direction = self.direction.unwrap_or(context.direction);
        let sha256 = hex_lower(&self.sha256.finalize());
        let md5 = hex_lower(&self.md5.finalize());
        let extension = file_extension(&self.file_path);
        let mime_type = extension.as_deref().map(guess_mime_type);

        Some(CompletedFileTransfer {
            route_name: context.route_name.to_string(),
            interface: context.interface.to_string(),
            direction,
            peer_addr: context.peer_addr,
            target_addr: context.target_addr,
            destination_share: Some(context.route_name.to_string()),
            source_user: None,
            file_name: self.file_path,
            extension,
            mime_type,
            file_size: self.bytes,
            creation_time: self.creation_time,
            upload_timestamp: self.first_seen_unix_timestamp_seconds,
            sha256,
            md5,
        })
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn file_extension(file_path: &str) -> Option<String> {
    let name = file_path.rsplit(['\\', '/']).next().unwrap_or(file_path);
    name.rsplit_once('.')
        .map(|(_, extension)| extension.to_ascii_lowercase())
        .filter(|extension| !extension.is_empty())
}

fn guess_mime_type(extension: &str) -> String {
    match extension {
        "txt" | "log" | "csv" => "text/plain",
        "pdf" => "application/pdf",
        "zip" => "application/zip",
        "rar" => "application/vnd.rar",
        "7z" => "application/x-7z-compressed",
        "exe" | "dll" => "application/vnd.microsoft.portable-executable",
        "doc" => "application/msword",
        "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xls" => "application/vnd.ms-excel",
        "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "ppt" => "application/vnd.ms-powerpoint",
        "pptx" => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "gif" => "image/gif",
        _ => "application/octet-stream",
    }
    .to_string()
}

fn unix_timestamp_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| std::time::Duration::from_secs(0))
        .as_secs()
}

struct ConnectionGuard {
    state: Arc<RuntimeState>,
    route_name: String,
    interface: String,
    peer_addr: SocketAddr,
    target_addr: SocketAddr,
}

impl ConnectionGuard {
    fn new(
        state: Arc<RuntimeState>,
        route_name: String,
        interface: String,
        peer_addr: SocketAddr,
        target_addr: SocketAddr,
    ) -> Self {
        Self {
            state,
            route_name,
            interface,
            peer_addr,
            target_addr,
        }
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.state.connection_finished();
        self.state.route_connection_finished(&self.route_name);
        let context = InspectionContext {
            route_name: &self.route_name,
            interface: &self.interface,
            direction: TrafficDirection::ClientToServer,
            peer_addr: self.peer_addr,
            target_addr: self.target_addr,
            file_path_hint: None,
        };
        self.state.record_connection_closed(&context);
    }
}

struct InspectionWindow {
    tail: Vec<u8>,
    max_tail_len: usize,
}

impl InspectionWindow {
    fn new(max_pattern_len: usize) -> Self {
        Self {
            tail: Vec::new(),
            max_tail_len: max_pattern_len.saturating_sub(1),
        }
    }

    fn merge(&self, chunk: &[u8]) -> Vec<u8> {
        if self.tail.is_empty() {
            return chunk.to_vec();
        }

        let mut merged = Vec::with_capacity(self.tail.len() + chunk.len());
        merged.extend_from_slice(&self.tail);
        merged.extend_from_slice(chunk);
        merged
    }

    fn remember(&mut self, chunk: &[u8]) {
        if self.max_tail_len == 0 {
            self.tail.clear();
            return;
        }

        let retained = chunk.len().min(self.max_tail_len);
        self.tail.clear();
        self.tail
            .extend_from_slice(&chunk[chunk.len().saturating_sub(retained)..]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smb_tcp_framer_reassembles_split_frames() {
        let frame = smb2_test_frame(5, 99);
        let split_at = 13;
        let mut framer = SmbTcpFramer::default();

        assert!(framer.push(&frame[..split_at]).unwrap().is_empty());
        let frames = framer.push(&frame[split_at..]).unwrap();

        assert_eq!(frames, vec![frame]);
    }

    #[test]
    fn smb_tcp_framer_extracts_multiple_frames() {
        let first = smb2_test_frame(5, 1);
        let second = smb2_test_frame(9, 2);
        let mut combined = first.clone();
        combined.extend_from_slice(&second);
        let mut framer = SmbTcpFramer::default();

        let frames = framer.push(&combined).unwrap();

        assert_eq!(frames, vec![first, second]);
    }

    #[test]
    fn smb2_error_response_preserves_message_context() {
        let request = smb2_test_frame(5, 42);

        let response = build_smb2_error_response(&request, STATUS_ACCESS_DENIED).unwrap();

        assert_eq!(&response[4..8], b"\xFESMB");
        assert_eq!(
            u32::from_le_bytes(response[12..16].try_into().unwrap()),
            STATUS_ACCESS_DENIED
        );
        assert_eq!(u16::from_le_bytes(response[16..18].try_into().unwrap()), 5);
        assert_eq!(u32::from_le_bytes(response[20..24].try_into().unwrap()), 1);
        assert_eq!(u64::from_le_bytes(response[28..36].try_into().unwrap()), 42);
        assert_eq!(u16::from_le_bytes(response[68..70].try_into().unwrap()), 9);
    }

    #[test]
    fn file_hash_progress_tracks_streamed_sha256() {
        let mut state = FileHashState::new("bad.txt".to_string(), None);
        state.update(TrafficDirection::ClientToServer, b"hello ");
        state.update(TrafficDirection::ClientToServer, b"world");

        let progress = state.progress();

        assert_eq!(
            progress.sha256,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
        assert_eq!(progress.bytes, 11);
    }

    fn smb2_test_frame(command: u16, message_id: u64) -> Vec<u8> {
        let smb_payload_len = 64 + 8;
        let mut frame = vec![0_u8; 4 + smb_payload_len];

        frame[1] = ((smb_payload_len >> 16) & 0xff) as u8;
        frame[2] = ((smb_payload_len >> 8) & 0xff) as u8;
        frame[3] = (smb_payload_len & 0xff) as u8;
        frame[4..8].copy_from_slice(b"\xFESMB");
        frame[8..10].copy_from_slice(&64_u16.to_le_bytes());
        frame[16..18].copy_from_slice(&command.to_le_bytes());
        frame[28..36].copy_from_slice(&message_id.to_le_bytes());
        frame[68..70].copy_from_slice(&9_u16.to_le_bytes());

        frame
    }
}
