use std::{
    collections::{HashMap, HashSet},
    io,
    net::SocketAddr,
    sync::{Arc, Mutex as StdMutex},
};

use anyhow::Context;
use axiom_config::ProxyListenerConfig;
use axiom_core::{
    InspectionContext, InspectionResult, RuntimeState, Smb2CreateRequest, Smb2CreateResponse,
    Smb2WriteRequest, ThreatEvent, TrafficDirection, contains_smb2_server_side_copy_request,
    extract_smb2_create_requests, extract_smb2_create_responses, extract_smb2_write_requests,
};
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

pub async fn run_proxy_listener(
    route: ProxyListenerConfig,
    state: Arc<RuntimeState>,
) -> anyhow::Result<()> {
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

        tokio::spawn(async move {
            if let Err(error) =
                handle_connection(client_stream, peer_addr, Arc::clone(&route), task_state).await
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

    relay_bidirectional(client_stream, server_stream, peer_addr, route, state)
        .await
        .map_err(Into::into)
}

async fn relay_bidirectional(
    client_stream: TcpStream,
    server_stream: TcpStream,
    peer_addr: SocketAddr,
    route: Arc<ProxyListenerConfig>,
    state: Arc<RuntimeState>,
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

        state.record_stream_bytes(&route.name, direction, bytes_read as u64);
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

    if direction == TrafficDirection::ClientToServer {
        for create_request in create_requests {
            telemetry.observe_create_request(state, &context, create_request, frame.len());
        }
        for write_request in write_requests {
            telemetry.observe_write_request(state, &context, write_request);
        }
        if contains_smb2_server_side_copy_request(&frame) {
            state.record_server_side_copy_requested(&context);
        }
    } else {
        for create_response in extract_smb2_create_responses(&frame) {
            telemetry.observe_create_response(create_response);
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
            state.record_bytes(direction, frame.len() as u64);
            state.record_route_bytes(&route.name, direction, frame.len() as u64);
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
            state.record_bytes(direction, frame.len() as u64);
            state.record_route_bytes(&route.name, direction, frame.len() as u64);
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
            .insert(response.file_id, file_path);
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
    ) {
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
        } else {
            state.record_smb_write_payload(context.route_name, request.length as u64);
        }
    }
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
