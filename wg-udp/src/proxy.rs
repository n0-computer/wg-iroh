//! A localhost HTTP CONNECT proxy whose upstream connections run through the tunnel.
//!
//! Point HTTP clients at it (iroh's `proxy_url`, or `HTTPS_PROXY` for clients
//! that read the environment) and their TCP connections, including the DNS
//! lookup of the target host, happen inside the tunnel. Only CONNECT is
//! served: TLS runs end to end through it, plain-HTTP proxying is refused.

use std::{io, net::SocketAddr, sync::Arc};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};

use crate::wg::Tunnel;

const HEADER_LIMIT: usize = 8 * 1024;

/// A running proxy. Dropping it stops accepting new connections.
pub struct ConnectProxy {
    addr: SocketAddr,
    accept: JoinHandle<()>,
}

impl Drop for ConnectProxy {
    fn drop(&mut self) {
        self.accept.abort();
    }
}

impl ConnectProxy {
    /// Serves CONNECT requests on `listener`, dialing targets through `tunnel`.
    pub fn serve(listener: TcpListener, tunnel: Arc<Tunnel>) -> io::Result<Self> {
        let addr = listener.local_addr()?;
        let accept = tokio::spawn(async move {
            loop {
                let Ok((client, _)) = listener.accept().await else {
                    break;
                };
                let tunnel = tunnel.clone();
                tokio::spawn(async move {
                    if let Err(err) = serve_connect(client, &tunnel).await {
                        tracing::debug!("connect proxy: {err}");
                    }
                });
            }
        });
        Ok(Self { addr, accept })
    }

    /// The proxy's localhost address.
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// The proxy as an `http://` URL.
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }
}

async fn serve_connect(mut client: TcpStream, tunnel: &Tunnel) -> io::Result<()> {
    let (header, early) = read_header(&mut client).await?;
    let (host, port) = match parse_connect(&header) {
        Ok(target) => target,
        Err(status) => return write_status(&mut client, status).await,
    };
    let mut upstream = match tunnel.stack().tcp_connect_host(&host, port).await {
        Ok(stream) => stream,
        Err(err) => {
            tracing::debug!("connect proxy: dial {host}:{port}: {err}");
            return write_status(&mut client, 502).await;
        }
    };
    write_status(&mut client, 200).await?;
    upstream.write_all(&early).await?;
    tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
    Ok(())
}

/// Reads up to the end of the request header; returns it and any bytes after it.
async fn read_header(socket: &mut TcpStream) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let mut buf = Vec::with_capacity(512);
    let mut chunk = [0u8; 1024];
    loop {
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let early = buf.split_off(end + 4);
            return Ok((buf, early));
        }
        if buf.len() > HEADER_LIMIT {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "header too large"));
        }
        let read = socket.read(&mut chunk).await?;
        if read == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        buf.extend_from_slice(&chunk[..read]);
    }
}

/// The target of a `CONNECT host:port` request, or the status to refuse it with.
fn parse_connect(header: &[u8]) -> Result<(String, u16), u16> {
    let text = std::str::from_utf8(header).map_err(|_| 400u16)?;
    let mut parts = text.lines().next().unwrap_or("").split_whitespace();
    let method = parts.next().ok_or(400u16)?;
    if !method.eq_ignore_ascii_case("CONNECT") {
        return Err(405);
    }
    let target = parts.next().ok_or(400u16)?;
    let (host, port) = match target.strip_prefix('[') {
        Some(rest) => rest.split_once("]:").ok_or(400u16)?,
        None => target.rsplit_once(':').ok_or(400u16)?,
    };
    let port = port.parse().map_err(|_| 400u16)?;
    if host.is_empty() || port == 0 {
        return Err(400);
    }
    Ok((host.to_string(), port))
}

async fn write_status(socket: &mut TcpStream, status: u16) -> io::Result<()> {
    let reason = match status {
        200 => "Connection Established",
        400 => "Bad Request",
        405 => "Method Not Allowed",
        _ => "Bad Gateway",
    };
    socket
        .write_all(format!("HTTP/1.1 {status} {reason}\r\n\r\n").as_bytes())
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_connect_targets() {
        assert_eq!(
            parse_connect(b"CONNECT example.com:443 HTTP/1.1\r\nHost: x\r\n\r\n"),
            Ok(("example.com".to_string(), 443))
        );
        assert_eq!(
            parse_connect(b"CONNECT [2001:db8::1]:443 HTTP/1.1\r\n\r\n"),
            Ok(("2001:db8::1".to_string(), 443))
        );
        assert_eq!(parse_connect(b"GET http://x/ HTTP/1.1\r\n\r\n"), Err(405));
        assert_eq!(parse_connect(b"CONNECT example.com HTTP/1.1\r\n\r\n"), Err(400));
    }
}
