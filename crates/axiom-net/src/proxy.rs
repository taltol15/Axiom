use std::{
    collections::{HashMap, HashSet},
    io,
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use anyhow::Context;
use axiom_config::ProxyListenerConfig;
use axiom_core::{
    InspectionContext, InspectionResult, RuntimeState, Smb2CreateRequest, Smb2CreateResponse,
    Smb2WriteRequest, ThreatEvent, TrafficDirection, contains_smb2_server_side_copy_request,
    extract_smb2_create_requests, extract_smb2_create_responses, extract_smb2_write_requests,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};
use tracing::{debug, info, warn};

use crate::listener::{bind_tcp_listener_to_interface, connect_tcp_via_interface};

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
    let telemetry = Arc::new(ConnectionTelemetry::default());

    let client_to_server = relay_direction(
        Arc::clone(&route),
        Arc::clone(&state),
        Arc::clone(&telemetry),
        peer_addr,
        target_addr,
        TrafficDirection::ClientToServer,
        client_reader,
        server_writer,
    );

    let server_to_client = relay_direction(
        route,
        state,
        telemetry,
        peer_addr,
        target_addr,
        TrafficDirection::ServerToClient,
        server_reader,
        client_writer,
    );

    tokio::try_join!(client_to_server, server_to_client).map(|_| ())
}

async fn relay_direction<R, W>(
    route: Arc<ProxyListenerConfig>,
    state: Arc<RuntimeState>,
    telemetry: Arc<ConnectionTelemetry>,
    peer_addr: SocketAddr,
    target_addr: SocketAddr,
    direction: TrafficDirection,
    mut reader: R,
    mut writer: W,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = vec![0_u8; 64 * 1024];
    let mut inspection_window = InspectionWindow::new(state.max_pattern_len());

    loop {
        let bytes_read = reader.read(&mut buffer).await?;
        if bytes_read == 0 {
            writer.shutdown().await?;
            return Ok(());
        }

        state.record_inspection(bytes_read as u64);
        state.record_route_inspection(&route.name, bytes_read as u64);
        state.record_stream_bytes(&route.name, direction, bytes_read as u64);
        let chunk = &buffer[..bytes_read];
        let inspection_bytes = inspection_window.merge(chunk);
        let create_requests = if direction == TrafficDirection::ClientToServer {
            extract_smb2_create_requests(chunk)
        } else {
            Vec::new()
        };
        let write_requests = if direction == TrafficDirection::ClientToServer {
            extract_smb2_write_requests(chunk)
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
                telemetry.observe_create_request(&state, &context, create_request, bytes_read);
            }
            for write_request in write_requests {
                telemetry.observe_write_request(&state, &context, write_request);
            }
            if contains_smb2_server_side_copy_request(chunk) {
                state.record_server_side_copy_requested(&context);
            }
        } else {
            for create_response in extract_smb2_create_responses(chunk) {
                telemetry.observe_create_response(create_response);
            }
        }

        match state.inspect_chunk(&context, &inspection_bytes) {
            InspectionResult::Allow { entropy } => {
                debug!(
                    route = route.name,
                    ?direction,
                    bytes = bytes_read,
                    entropy,
                    "forwarding inspected SMB chunk"
                );
                writer.write_all(&buffer[..bytes_read]).await?;
                inspection_window.remember(&buffer[..bytes_read]);
                state.record_allowed_chunk();
                state.record_bytes(direction, bytes_read as u64);
                state.record_route_bytes(&route.name, direction, bytes_read as u64);
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
                writer.write_all(&buffer[..bytes_read]).await?;
                inspection_window.remember(&buffer[..bytes_read]);
                state.record_allowed_chunk();
                state.record_bytes(direction, bytes_read as u64);
                state.record_route_bytes(&route.name, direction, bytes_read as u64);
            }
            InspectionResult::Block { event } => {
                let reason = event.reason.clone();
                record_blocked_event(&state, event);
                warn!(
                    route = route.name,
                    interface = route.interface(),
                    ?direction,
                    peer = %peer_addr,
                    target = %target_addr,
                    reason,
                    "blocked SMB stream"
                );
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "stream blocked by Axiom policy",
                ));
            }
        }
    }
}

fn record_blocked_event(state: &RuntimeState, event: ThreatEvent) {
    state.record_blocked_threat(event);
}

#[derive(Debug, Default)]
struct ConnectionTelemetry {
    pending_create_paths: Mutex<HashMap<u64, String>>,
    open_file_paths: Mutex<HashMap<[u8; 16], String>>,
    observed_file_paths: Mutex<HashSet<String>>,
    latest_write_file_path: Mutex<Option<String>>,
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
