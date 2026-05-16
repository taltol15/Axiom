use std::{
    io,
    net::{SocketAddr, TcpListener as StdTcpListener, TcpStream as StdTcpStream},
};

use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::net::{TcpListener, TcpStream};

pub async fn bind_tcp_listener_to_interface(
    interface: &str,
    addr: SocketAddr,
    backlog: i32,
) -> io::Result<TcpListener> {
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    socket.set_reuse_port(true)?;
    bind_socket_to_interface(&socket, interface)?;
    socket.bind(&SockAddr::from(addr))?;
    socket.listen(backlog)?;
    socket.set_nonblocking(true)?;

    let listener: StdTcpListener = socket.into();
    TcpListener::from_std(listener)
}

pub async fn connect_tcp_via_interface(
    interface: &str,
    target_addr: SocketAddr,
) -> io::Result<TcpStream> {
    let socket = Socket::new(
        Domain::for_address(target_addr),
        Type::STREAM,
        Some(Protocol::TCP),
    )?;
    bind_socket_to_interface(&socket, interface)?;
    socket.set_nonblocking(true)?;

    match socket.connect(&SockAddr::from(target_addr)) {
        Ok(()) => {}
        Err(error) if connect_is_in_progress(&error) => {}
        Err(error) => return Err(error),
    }

    let stream: StdTcpStream = socket.into();
    stream.set_nonblocking(true)?;
    let stream = TcpStream::from_std(stream)?;
    stream.writable().await?;

    if let Some(error) = stream.take_error()? {
        return Err(error);
    }

    Ok(stream)
}

#[cfg(target_os = "linux")]
fn bind_socket_to_interface(socket: &Socket, interface: &str) -> io::Result<()> {
    if interface.as_bytes().contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "interface name contains a null byte",
        ));
    }

    socket.bind_device(Some(interface.as_bytes()))
}

#[cfg(not(target_os = "linux"))]
fn bind_socket_to_interface(_socket: &Socket, interface: &str) -> io::Result<()> {
    tracing::warn!(
        interface,
        "SO_BINDTODEVICE is only enforced on Linux; this development build is not interface-isolated"
    );
    Ok(())
}

fn connect_is_in_progress(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::WouldBlock || error.raw_os_error() == Some(libc::EINPROGRESS)
}
