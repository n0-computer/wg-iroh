//! Plain UDP through a userspace WireGuard tunnel.
//!
//! Reads a standard wg-quick config, brings up the tunnel in process
//! (boringtun on a smoltcp stack, no TUN device, no root), opens a UDP
//! socket inside it, and sends a mainline DHT `ping` to a few DHT nodes. DHT
//! nodes echo the sender's address back (BEP 42 `ip` field), so each reply
//! shows the public `ip:port` the VPN exit mapped us to.
//!
//! Any provider's WireGuard config works: ProtonVPN and Mullvad offer
//! downloadable `.conf` files, and `nym-wg-register` writes them for NymVPN.
//! Pass a second config with `--exit` to nest a second WireGuard tunnel inside
//! the first, as NymVPN's two-hop mode does.
//!
//! ```sh
//! cargo run -- proton.conf
//! cargo run -- entry.conf --exit exit.conf
//! ```

use std::{
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use clap::Parser;
use wg_udp::{
    conf::{self, WgConfig},
    wg::Tunnel,
};

const REPLY_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Parser, Debug)]
struct Args {
    /// wg-quick config of the (entry) tunnel.
    config: PathBuf,
    /// wg-quick config of an exit tunnel, nested inside the entry tunnel.
    #[arg(long)]
    exit: Option<PathBuf>,
    /// DHT nodes to ping, as host:port. Resolved through the tunnel.
    #[arg(long = "target", default_values_t = [
        "router.bittorrent.com:6881".to_string(),
        "dht.transmissionbt.com:6881".to_string(),
        "dht.libtorrent.org:25401".to_string(),
        "relay.pkarr.org:6881".to_string(),
    ])]
    targets: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();
    let args = Args::parse();

    let entry = WgConfig::load(&args.config).await?;
    let exit = match &args.exit {
        Some(path) => Some(WgConfig::load(path).await?),
        None => None,
    };
    let tunnel = conf::connect(&entry, exit.as_ref()).await?;
    ping_targets(&tunnel, &args.targets).await
}

/// Resolves each target through the tunnel, pings it from one tunnel UDP
/// socket, and prints the replies.
async fn ping_targets(tunnel: &Tunnel, targets: &[String]) -> Result<()> {
    let socket = tunnel
        .stack()
        .udp_socket()
        .await
        .context("tunnel udp socket")?;
    println!("udp socket:     {} (inside the tunnel)", socket.local_addr()?);

    let node_id: [u8; 20] = rand::random();
    let mut sent = Vec::new();
    for (index, target) in targets.iter().enumerate() {
        let addr = match resolve(tunnel, target).await {
            Ok(addr) => addr,
            Err(err) => {
                println!("{target}: {err:#}");
                continue;
            }
        };
        let tid = [b'p', index as u8];
        socket
            .send_to(&ping(&node_id, &tid), addr)
            .await
            .with_context(|| format!("send to {addr}"))?;
        sent.push((target.as_str(), addr, Instant::now()));
    }

    let mut buf = vec![0u8; 2048];
    let mut replied = Vec::new();
    let deadline = tokio::time::Instant::now() + REPLY_TIMEOUT;
    while replied.len() < sent.len() {
        let Ok(received) = tokio::time::timeout_at(deadline, socket.recv_from(&mut buf)).await
        else {
            break;
        };
        let (len, from) = received?;
        let Some((target, _, start)) = sent.iter().find(|(_, addr, _)| *addr == from) else {
            println!("unexpected datagram from {from} ({len} bytes)");
            continue;
        };
        let seen_as = reported_addr(&buf[..len])
            .map(|addr| addr.to_string())
            .unwrap_or_else(|| "no ip field".to_string());
        println!(
            "{target} ({from}): reply in {:?}, sees us as {seen_as}",
            start.elapsed()
        );
        replied.push(from);
    }
    for (target, addr, _) in &sent {
        if !replied.contains(addr) {
            println!("{target} ({addr}): no reply within {REPLY_TIMEOUT:?}");
        }
    }
    Ok(())
}

async fn resolve(tunnel: &Tunnel, target: &str) -> Result<SocketAddr> {
    if let Ok(addr) = target.parse() {
        return Ok(addr);
    }
    let (host, port) = target
        .rsplit_once(':')
        .context("target must be host:port")?;
    let port: u16 = port.parse().context("invalid port")?;
    let ips = tunnel
        .stack()
        .resolve(host)
        .await
        .with_context(|| format!("resolve {host} through the tunnel"))?;
    // The DHT is IPv4 only.
    let ip = ips
        .into_iter()
        .find(|ip| ip.is_ipv4())
        .with_context(|| format!("{host} has no IPv4 address"))?;
    Ok(SocketAddr::new(ip, port))
}

/// A KRPC `ping` query, bencoded with its keys in sorted order.
fn ping(node_id: &[u8; 20], tid: &[u8; 2]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(64);
    msg.extend_from_slice(b"d1:ad2:id20:");
    msg.extend_from_slice(node_id);
    msg.extend_from_slice(b"e1:q4:ping1:t2:");
    msg.extend_from_slice(tid);
    msg.extend_from_slice(b"1:y1:qe");
    msg
}

/// The BEP 42 `ip` field of a KRPC reply: our address as the node sees it.
///
/// A top-level `2:ip` key followed by a 6-byte compact IPv4 address and port.
/// A substring search is enough for a demo; the key sorts first in the dict.
fn reported_addr(reply: &[u8]) -> Option<SocketAddr> {
    const KEY: &[u8] = b"2:ip6:";
    let at = reply.windows(KEY.len()).position(|w| w == KEY)? + KEY.len();
    let compact: [u8; 6] = reply.get(at..at + 6)?.try_into().ok()?;
    let ip = Ipv4Addr::new(compact[0], compact[1], compact[2], compact[3]);
    let port = u16::from_be_bytes([compact[4], compact[5]]);
    Some(SocketAddr::from((ip, port)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ping_is_valid_bencode_shape() {
        let msg = ping(&[7; 20], b"p0");
        assert!(msg.starts_with(b"d1:ad2:id20:"));
        assert!(msg.ends_with(b"1:t2:p01:y1:qe"));
        assert_eq!(msg.len(), 12 + 20 + 15 + 2 + 7);
    }

    #[test]
    fn parses_reported_addr() {
        let reply = b"d2:ip6:\x01\x02\x03\x04\x1a\xe11:rd2:id20:aaaaaaaaaaaaaaaaaaaae1:t2:p01:y1:re";
        assert_eq!(reported_addr(reply), Some("1.2.3.4:6881".parse().unwrap()));
        assert_eq!(
            reported_addr(b"d1:rd2:id20:aaaaaaaaaaaaaaaaaaaae1:y1:re"),
            None
        );
    }
}
