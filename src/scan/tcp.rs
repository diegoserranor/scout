//! Shared TCP helpers for connect/read/write with bounded timeouts so all probes behave consistently.

use std::net::Ipv4Addr;

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::{Duration, timeout},
};

const IO_TIMEOUT: Duration = Duration::from_secs(3);

pub async fn connect_with_timeout(addr: (Ipv4Addr, u16), deadline: Duration) -> Option<TcpStream> {
    let connect = TcpStream::connect(addr);
    timeout(deadline, connect).await.ok()?.ok()
}

pub async fn write_with_timeout(stream: &mut TcpStream, buf: &[u8]) -> Option<()> {
    let write = stream.write_all(buf);
    timeout(IO_TIMEOUT, write).await.ok()?.ok()
}

pub async fn read_with_timeout(stream: &mut TcpStream, buf: &mut [u8]) -> Option<usize> {
    let read = stream.read(buf);
    timeout(IO_TIMEOUT, read).await.ok()?.ok()
}
