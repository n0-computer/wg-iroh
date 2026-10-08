//! An iroh endpoint inside a userspace WireGuard tunnel.
//!
//! `accept` runs a stock iroh endpoint that echoes whatever it receives.
//! `connect` brings up a WireGuard tunnel from wg-quick files and runs an
//! iroh endpoint whose traffic all goes through it:
//!
//! - **UDP:** iroh's IP transport binds through netwatch. A netwatch bind
//!   hook hands it a UDP socket inside the tunnel instead of an OS socket, so
//!   QUIC, address discovery and hole punching all run from the VPN exit.
//! - **HTTPS:** a localhost CONNECT proxy opens its upstream connections
//!   inside the tunnel. iroh sends relay connections, relay probes and pkarr
//!   publish/resolve through it (`proxy_url`).
//! - **DNS:** iroh's own lookups, such as the relay hostnames for QUIC
//!   address discovery, resolve through the tunnel too.
//!
//! The endpoint publishes itself via pkarr and resolves peers the same way,
//! so it is dialable by id. The peer sees an ordinary iroh endpoint behind
//! the VPN exit's NAT. netwatch carries the UDP hook.
//!
//! ```sh
//! cargo run -- accept
//! cargo run -- connect nym-entry.conf <endpoint-id>
//! ```

use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::PathBuf,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::{Duration, Instant},
};

use anyhow::{Context as _, Result};
use clap::{Parser, Subcommand};
use iroh::{
    Endpoint, EndpointAddr, EndpointId, RelayMode, RelayUrl,
    dns::{BoxIter, DnsError, DnsResolver, Resolver, TxtRecordData},
    address_lookup::{PkarrPublisher, PkarrResolver},
    endpoint::{Connection, NetReportConfig, PortmapperConfig, presets},
};
use n0_future::boxed::BoxFuture;
use netwatch::CustomUdpSocket;
use wg_udp::{
    conf::{self, WgConfig},
    proxy::ConnectProxy,
    wg::Tunnel,
};

const ALPN: &[u8] = b"wg-iroh/echo/0";

#[derive(Parser, Debug)]
struct Args {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Run a stock iroh endpoint that echoes streams.
    Accept,
    /// Connect to an `accept` endpoint from inside a WireGuard tunnel.
    Connect {
        /// wg-quick config of the (entry) tunnel.
        config: PathBuf,
        /// The `accept` endpoint's id.
        id: EndpointId,
        /// The `accept` endpoint's home relay, to skip the pkarr lookup.
        #[arg(long)]
        relay: Option<RelayUrl>,
        /// wg-quick config of an exit tunnel, nested inside the entry tunnel.
        #[arg(long)]
        exit: Option<PathBuf>,
        /// How many echo round trips to do, one per second.
        #[arg(long, default_value_t = 30)]
        rounds: u32,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "warn".into()),
        )
        .init();
    match Args::parse().cmd {
        Cmd::Accept => accept().await,
        Cmd::Connect {
            config,
            id,
            relay,
            exit,
            rounds,
        } => connect(config, exit, id, relay, rounds).await,
    }
}

async fn accept() -> Result<()> {
    let endpoint = Endpoint::builder(presets::N0)
        .alpns(vec![ALPN.to_vec()])
        .bind()
        .await?;
    endpoint.online().await;
    let relay = endpoint
        .addr()
        .relay_urls()
        .next()
        .cloned()
        .context("no home relay")?;
    println!("listening, connect with:");
    println!("  cargo run -- connect <config> {} {relay}", endpoint.id());
    while let Some(incoming) = endpoint.accept().await {
        tokio::spawn(async move {
            let result = async {
                let conn = incoming.await?;
                println!("connection from {}", conn.remote_id());
                loop {
                    let (mut send, mut recv) = conn.accept_bi().await?;
                    let data = recv.read_to_end(1024).await?;
                    send.write_all(&data).await?;
                    send.finish()?;
                    println!(
                        "{}: peer is at {}",
                        String::from_utf8_lossy(&data),
                        selected_path(&conn)
                    );
                }
                #[allow(unreachable_code)]
                anyhow::Ok(())
            }
            .await;
            if let Err(err) = result {
                println!("connection ended: {err:#}");
            }
        });
    }
    Ok(())
}

async fn connect(
    config: PathBuf,
    exit: Option<PathBuf>,
    id: EndpointId,
    relay: Option<RelayUrl>,
    rounds: u32,
) -> Result<()> {
    let entry = WgConfig::load(&config).await?;
    let exit = match &exit {
        Some(path) => Some(WgConfig::load(path).await?),
        None => None,
    };
    let tunnel = Arc::new(conf::connect(&entry, exit.as_ref()).await?);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let proxy = ConnectProxy::serve(listener, tunnel.clone())?;
    let endpoint = tunneled_endpoint(&tunnel, &proxy).await?;
    endpoint.online().await;
    println!("our endpoint: {} (home relay up)", endpoint.id());

    let mut addr = EndpointAddr::new(id);
    if let Some(relay) = relay {
        addr = addr.with_relay_url(relay);
    }
    let conn = endpoint.connect(addr, ALPN).await.context("connect")?;
    println!("connected to {}", conn.remote_id());
    for round in 1..=rounds {
        let start = Instant::now();
        let (mut send, mut recv) = conn.open_bi().await?;
        let msg = format!("round {round}");
        send.write_all(msg.as_bytes()).await?;
        send.finish()?;
        let echo = recv.read_to_end(1024).await?;
        anyhow::ensure!(echo == msg.as_bytes(), "bad echo");
        println!("{msg}: {:?} over {}", start.elapsed(), selected_path(&conn));
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    conn.close(0u32.into(), b"done");
    endpoint.close().await;
    Ok(())
}

/// An endpoint whose UDP socket and TCP connections all live inside `tunnel`.
async fn tunneled_endpoint(tunnel: &Arc<Tunnel>, proxy: &ConnectProxy) -> Result<Endpoint> {
    // Hand iroh's IPv4 bind the tunnel socket, once. The hook is
    // process-wide, so it is only installed for the duration of the bind.
    let socket: Arc<dyn CustomUdpSocket> =
        Arc::new(TunnelUdp(tunnel.stack().udp_socket().await?));
    let slot = Mutex::new(Some(socket));
    netwatch::set_bind_hook(move |addr| {
        addr.is_ipv4().then(|| {
            slot.lock()
                .expect("poisoned")
                .take()
                .ok_or_else(|| io::Error::other("the tunnel socket is already in use"))
        })
    });

    // The captive portal check is a plain-HTTP GET, which a CONNECT proxy
    // cannot carry. The HTTPS relay probes go through it fine.
    let mut net_report = NetReportConfig::minimal();
    net_report.https_probes = true;
    let endpoint = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Default)
        .dns_resolver(DnsResolver::custom(TunnelResolver(tunnel.clone())))
        .proxy_url(proxy.url().parse()?)
        .net_report_config(net_report)
        // pkarr over HTTPS, through the proxy like the relay; no DNS-based
        // lookup, which would query the system resolver for every peer id.
        .address_lookup(PkarrPublisher::n0_dns())
        .address_lookup(PkarrResolver::n0_dns())
        // Only the IPv4 tunnel socket, no OS sockets.
        .clear_ip_transports()
        .bind_addr("0.0.0.0:0")?
        .portmapper_config(PortmapperConfig::Disabled)
        .bind()
        .await;
    netwatch::clear_bind_hook();
    Ok(endpoint?)
}

/// The tunnel's UDP socket as a netwatch socket.
struct TunnelUdp(nym_smol_core::UdpSocket);

impl std::fmt::Debug for TunnelUdp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("TunnelUdp")
            .field(&self.0.local_addr().ok())
            .finish()
    }
}

impl CustomUdpSocket for TunnelUdp {
    fn poll_send_to(
        &self,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: SocketAddr,
    ) -> Poll<io::Result<()>> {
        self.0.poll_send_to(cx, buf, target).map_ok(|_| ())
    }

    fn poll_recv_from(
        &self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>> {
        self.0.poll_recv_from(cx, buf)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.0.local_addr()
    }
}

/// iroh's DNS lookups, answered through the tunnel.
///
/// The tunnel stack is IPv4-only, so IPv6 lookups come back empty. TXT
/// records are only needed for DNS-based address lookup, which is not used.
///
/// This should not need a custom resolver. iroh's resolver can do DNS over
/// HTTPS, but opens its own TCP connections and ignores `proxy_url`. If its
/// TCP-based transports went through the proxy like everything else, a DoH
/// nameserver plus `proxy_url` would cover DNS too.
#[derive(Debug, Clone)]
struct TunnelResolver(Arc<Tunnel>);

impl Resolver for TunnelResolver {
    fn lookup_ipv4(&self, host: String) -> BoxFuture<Result<BoxIter<Ipv4Addr>, DnsError>> {
        let tunnel = self.0.clone();
        Box::pin(async move {
            let ips = tunnel
                .stack()
                .resolve(&host)
                .await
                .map_err(|err| DnsError::from(n0_error::AnyError::from_std(err)))?;
            let ipv4 = ips.into_iter().filter_map(|ip| match ip {
                IpAddr::V4(ip) => Some(ip),
                IpAddr::V6(_) => None,
            });
            Ok(Box::new(ipv4.collect::<Vec<_>>().into_iter()) as BoxIter<Ipv4Addr>)
        })
    }

    fn lookup_ipv6(&self, _host: String) -> BoxFuture<Result<BoxIter<Ipv6Addr>, DnsError>> {
        Box::pin(async { Ok(Box::new(std::iter::empty()) as BoxIter<Ipv6Addr>) })
    }

    fn lookup_txt(&self, host: String) -> BoxFuture<Result<BoxIter<TxtRecordData>, DnsError>> {
        Box::pin(async move {
            Err(DnsError::from(n0_error::AnyError::from_display(format!(
                "TXT lookup of {host} is not supported through the tunnel"
            ))))
        })
    }

    fn clear_cache(&self) {}

    fn reset(&self) -> Box<dyn Resolver> {
        Box::new(self.clone())
    }
}

fn selected_path(conn: &Connection) -> String {
    let paths = conn.paths();
    let Some(path) = paths.iter().find(|path| path.is_selected()) else {
        return "no selected path".to_string();
    };
    let kind = if path.is_relay() { "relay" } else { "direct" };
    format!("{kind} {:?} (rtt {:?})", path.remote_addr(), path.rtt())
}
