use std::{io, net::SocketAddr, sync::Arc};

use anyhow::Context;
use axiom_config::ProxyListenerConfig;
use axiom_core::{
    InspectionContext, InspectionResult, RuntimeState, ThreatEvent, TrafficDirection,
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

    loop {
        let (client_stream, peer_addr) = listener.accept().await.with_context(|| {
            format!(
                "failed accepting connection on route '{}' at {}",
                route.name,
                route.listen_addr()
            )
        })?;

        state.connection_started();
        let guard = ConnectionGuard::new(Arc::clone(&state));
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

    let client_to_server = relay_direction(
        Arc::clone(&route),
        Arc::clone(&state),
        peer_addr,
        target_addr,
        TrafficDirection::ClientToServer,
        client_reader,
        server_writer,
    );

    let server_to_client = relay_direction(
        route,
        state,
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

    loop {
        let bytes_read = reader.read(&mut buffer).await?;
        if bytes_read == 0 {
            writer.shutdown().await?;
            return Ok(());
        }

        let context = InspectionContext {
            route_name: &route.name,
            interface: route.interface(),
            direction,
            peer_addr,
            target_addr,
        };

        match state
            .policy()
            .inspect_chunk(&context, &buffer[..bytes_read])
        {
            InspectionResult::Allow { entropy } => {
                debug!(
                    route = route.name,
                    ?direction,
                    bytes = bytes_read,
                    entropy,
                    "forwarding inspected SMB chunk"
                );
                writer.write_all(&buffer[..bytes_read]).await?;
                state.record_bytes(direction, bytes_read as u64);
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

struct ConnectionGuard {
    state: Arc<RuntimeState>,
}

impl ConnectionGuard {
    fn new(state: Arc<RuntimeState>) -> Self {
        Self { state }
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.state.connection_finished();
    }
}
