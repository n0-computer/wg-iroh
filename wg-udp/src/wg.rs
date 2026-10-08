//! A userspace WireGuard client tunnel, one or two hops.
//!
//! boringtun does the WireGuard protocol, `nym-smol-core` provides the
//! smoltcp TCP/IP stack with tokio sockets and DNS on top. The only OS socket
//! is one UDP socket to the entry endpoint.
//!
//! Two hops nest the exit tunnel inside the entry tunnel: exit-hop WireGuard
//! datagrams are wrapped in IPv4/UDP packets to the exit endpoint and sent
//! through the entry tunnel. The entry peer forwards them like any other
//! traffic, so this works with any two WireGuard servers that allow it.
//!
//! The engine follows `nym-smoldvpn`'s (Apache-2.0), without its bandwidth
//! top-up, QUIC bridge and HTTP connectors.

use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    time::Duration,
};

use anyhow::{Context, Result, bail};
use boringtun::noise::{Tunn, TunnResult};
use futures::{StreamExt, channel::mpsc};
use nym_smol_core::{ChannelDevice, DnsConfig, Stack, StackConfig};
use smoltcp::{
    phy::ChecksumCapabilities,
    wire::{IpAddress, IpProtocol, Ipv4Packet, Ipv4Repr, UdpPacket, UdpRepr},
};
use tokio::{net::UdpSocket, sync::watch, task::JoinHandle};

/// Space for one WireGuard datagram plus headroom.
const SCRATCH_LEN: usize = 65535;
/// boringtun wants its timers driven roughly this often.
const TIMER_TICK: Duration = Duration::from_millis(100);
/// WireGuard per-hop overhead, IPv6 worst case.
pub const OVERHEAD_PER_HOP: usize = 80;
/// Interface MTU when the config does not set one (wg-quick's default).
pub const DEFAULT_MTU: usize = 1420;
/// Source port of the inner UDP flow carrying the exit hop through the entry
/// tunnel. Any port works; this is the one NymVPN uses.
const EXIT_CARRIER_PORT: u16 = 54001;

/// One WireGuard peer: our key and address, the peer's key and endpoint.
#[derive(Clone)]
pub struct Peer {
    pub private_key: [u8; 32],
    pub address_v4: Ipv4Addr,
    pub public_key: [u8; 32],
    pub preshared_key: Option<[u8; 32]>,
    pub endpoint: SocketAddr,
    pub persistent_keepalive: Option<u16>,
}

/// A running tunnel. Dropping it stops the datapath.
pub struct Tunnel {
    stack: Stack,
    established: watch::Receiver<bool>,
    task: JoinHandle<()>,
}

impl std::fmt::Debug for Tunnel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tunnel")
            .field("established", &*self.established.borrow())
            .finish_non_exhaustive()
    }
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Tunnel {
    /// Starts the datapath and the handshakes. See [`Self::established`].
    ///
    /// `mtu` is the interface MTU of the innermost tunnel, the one the stack
    /// sends into. `dns` is the resolver to query through the tunnel.
    pub async fn connect(
        entry: &Peer,
        exit: Option<&Peer>,
        mtu: usize,
        dns: Option<SocketAddr>,
    ) -> Result<Self> {
        let bind: SocketAddr = match entry.endpoint {
            SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
            SocketAddr::V6(_) => (std::net::Ipv6Addr::UNSPECIFIED, 0).into(),
        };
        let socket = UdpSocket::bind(bind).await.context("bind udp socket")?;
        socket
            .connect(entry.endpoint)
            .await
            .context("connect udp socket")?;

        let engine = match exit {
            None => Engine::single_hop(entry),
            Some(exit) => {
                let SocketAddr::V4(exit_endpoint) = exit.endpoint else {
                    bail!("two hops need an IPv4 exit endpoint");
                };
                let carrier_src = SocketAddrV4::new(entry.address_v4, EXIT_CARRIER_PORT);
                Engine::two_hop(entry, exit, carrier_src, exit_endpoint)
            }
        };
        let inner = exit.unwrap_or(entry);

        let (to_stack, stack_in) = mpsc::unbounded();
        let (stack_out, from_stack) = mpsc::unbounded();
        let device = ChannelDevice::new(stack_in, stack_out, Some(mtu));
        let mut stack = Stack::new(device, StackConfig::new(inner.address_v4));
        if let Some(server) = dns {
            stack = stack.with_dns_config(DnsConfig {
                server,
                ..DnsConfig::default()
            });
        }

        let (established_tx, established) = watch::channel(false);
        let task = tokio::spawn(run(engine, socket, to_stack, from_stack, established_tx));
        Ok(Self {
            stack,
            established,
            task,
        })
    }

    /// Waits until every hop has completed a handshake.
    pub async fn established(&self, timeout: Duration) -> Result<()> {
        let mut rx = self.established.clone();
        tokio::time::timeout(timeout, rx.wait_for(|up| *up))
            .await
            .context("no wireguard handshake")?
            .context("tunnel stopped")?;
        Ok(())
    }

    /// The TCP/IP stack inside the tunnel.
    pub fn stack(&self) -> &Stack {
        &self.stack
    }
}

/// Moves packets between the OS socket, boringtun and the stack.
async fn run(
    mut engine: Engine,
    socket: UdpSocket,
    to_stack: mpsc::UnboundedSender<Vec<u8>>,
    mut from_stack: mpsc::UnboundedReceiver<Vec<u8>>,
    established: watch::Sender<bool>,
) {
    let mut buf = vec![0u8; SCRATCH_LEN];
    let mut timers = tokio::time::interval(TIMER_TICK);
    let mut out = engine.initiate_handshakes();
    loop {
        for packet in out.to_network.drain(..) {
            if let Err(err) = socket.send(&packet).await {
                tracing::debug!("send to entry endpoint: {err}");
            }
        }
        for packet in out.to_stack.drain(..) {
            if to_stack.unbounded_send(packet).is_err() {
                return;
            }
        }
        if !*established.borrow() && engine.established() {
            tracing::info!("wireguard tunnel established");
            established.send_replace(true);
        }
        out = tokio::select! {
            received = socket.recv(&mut buf) => match received {
                Ok(len) => engine.decapsulate(&buf[..len]),
                Err(err) => {
                    tracing::debug!("recv from entry endpoint: {err}");
                    continue;
                }
            },
            packet = from_stack.next() => match packet {
                Some(packet) => engine.encapsulate(&packet),
                None => return,
            },
            _ = timers.tick() => engine.update_timers(),
        };
    }
}

#[derive(Default)]
struct Output {
    /// WireGuard datagrams for the entry endpoint.
    to_network: Vec<Vec<u8>>,
    /// Decrypted IP packets for the stack.
    to_stack: Vec<Vec<u8>>,
}

// One per tunnel, so the size difference does not matter.
#[allow(clippy::large_enum_variant)]
enum Hops {
    Single(Tunn),
    Double {
        entry: Tunn,
        exit: Tunn,
        /// Our end of the inner UDP flow that carries the exit hop.
        carrier_src: SocketAddrV4,
        exit_endpoint: SocketAddrV4,
    },
}

struct Engine {
    hops: Hops,
    scratch: Box<[u8]>,
}

impl Engine {
    fn single_hop(peer: &Peer) -> Self {
        Self::new(Hops::Single(tunn(peer, 0)))
    }

    fn two_hop(
        entry: &Peer,
        exit: &Peer,
        carrier_src: SocketAddrV4,
        exit_endpoint: SocketAddrV4,
    ) -> Self {
        Self::new(Hops::Double {
            entry: tunn(entry, 0),
            exit: tunn(exit, 1),
            carrier_src,
            exit_endpoint,
        })
    }

    fn new(hops: Hops) -> Self {
        Self {
            hops,
            scratch: vec![0; SCRATCH_LEN].into_boxed_slice(),
        }
    }

    fn established(&self) -> bool {
        let up = |tunn: &Tunn| tunn.stats().0.is_some();
        match &self.hops {
            Hops::Single(tunn) => up(tunn),
            Hops::Double { entry, exit, .. } => up(entry) && up(exit),
        }
    }

    fn initiate_handshakes(&mut self) -> Output {
        self.for_each_hop(|tunn, scratch| match tunn.format_handshake_initiation(scratch, false) {
            TunnResult::WriteToNetwork(packet) => Some(packet.to_vec()),
            _ => None,
        })
    }

    fn update_timers(&mut self) -> Output {
        self.for_each_hop(|tunn, scratch| match tunn.update_timers(scratch) {
            TunnResult::WriteToNetwork(packet) => Some(packet.to_vec()),
            _ => None,
        })
    }

    /// Runs `op` on every hop, wrapping exit-hop output for the entry hop.
    fn for_each_hop(
        &mut self,
        mut op: impl FnMut(&mut Tunn, &mut [u8]) -> Option<Vec<u8>>,
    ) -> Output {
        let mut out = Output::default();
        let Self { hops, scratch } = self;
        match hops {
            Hops::Single(tunn) => out.to_network.extend(op(tunn, scratch)),
            Hops::Double {
                entry,
                exit,
                carrier_src,
                exit_endpoint,
            } => {
                out.to_network.extend(op(entry, scratch));
                if let Some(packet) = op(exit, scratch) {
                    let carrier = ipv4_udp(*carrier_src, *exit_endpoint, &packet);
                    out.to_network.extend(encapsulate(entry, scratch, &carrier));
                }
            }
        }
        out
    }

    /// An IP packet from the stack, on its way out.
    fn encapsulate(&mut self, packet: &[u8]) -> Output {
        let mut out = Output::default();
        let Self { hops, scratch } = self;
        match hops {
            Hops::Single(tunn) => out.to_network.extend(encapsulate(tunn, scratch, packet)),
            Hops::Double {
                entry,
                exit,
                carrier_src,
                exit_endpoint,
            } => {
                if let Some(inner) = encapsulate(exit, scratch, packet) {
                    let carrier = ipv4_udp(*carrier_src, *exit_endpoint, &inner);
                    out.to_network.extend(encapsulate(entry, scratch, &carrier));
                }
            }
        }
        out
    }

    /// A WireGuard datagram from the entry endpoint, on its way in.
    fn decapsulate(&mut self, datagram: &[u8]) -> Output {
        let mut out = Output::default();
        let Self { hops, scratch } = self;
        match hops {
            Hops::Single(tunn) => decapsulate(tunn, scratch, datagram, &mut out),
            Hops::Double {
                entry,
                exit,
                carrier_src,
                exit_endpoint,
            } => {
                let mut carriers = Output::default();
                decapsulate(entry, scratch, datagram, &mut carriers);
                out.to_network = carriers.to_network;
                for carrier in carriers.to_stack {
                    let Some((src, payload)) = parse_ipv4_udp(&carrier) else {
                        continue;
                    };
                    if src != *exit_endpoint {
                        continue;
                    }
                    let mut inner = Output::default();
                    decapsulate(exit, scratch, &payload, &mut inner);
                    out.to_stack.extend(inner.to_stack);
                    for packet in inner.to_network {
                        let carrier = ipv4_udp(*carrier_src, *exit_endpoint, &packet);
                        out.to_network.extend(encapsulate(entry, scratch, &carrier));
                    }
                }
            }
        }
        out
    }
}

fn tunn(peer: &Peer, index: u32) -> Tunn {
    Tunn::new(
        x25519_dalek::StaticSecret::from(peer.private_key),
        x25519_dalek::PublicKey::from(peer.public_key),
        peer.preshared_key,
        peer.persistent_keepalive,
        index,
        None,
    )
}

fn encapsulate(tunn: &mut Tunn, scratch: &mut [u8], packet: &[u8]) -> Option<Vec<u8>> {
    match tunn.encapsulate(packet, scratch) {
        TunnResult::WriteToNetwork(datagram) => Some(datagram.to_vec()),
        TunnResult::Err(err) => {
            tracing::debug!("wireguard encapsulate: {err:?}");
            None
        }
        // Done: queued until the handshake completes.
        _ => None,
    }
}

fn decapsulate(tunn: &mut Tunn, scratch: &mut [u8], datagram: &[u8], out: &mut Output) {
    match tunn.decapsulate(None, datagram, scratch) {
        TunnResult::WriteToTunnelV4(packet, _) | TunnResult::WriteToTunnelV6(packet, _) => {
            out.to_stack.push(packet.to_vec());
        }
        TunnResult::WriteToNetwork(datagram) => {
            out.to_network.push(datagram.to_vec());
            // A completed handshake releases packets queued before it.
            while let TunnResult::WriteToNetwork(datagram) = tunn.decapsulate(None, &[], scratch) {
                out.to_network.push(datagram.to_vec());
            }
        }
        TunnResult::Err(err) => tracing::debug!("wireguard decapsulate: {err:?}"),
        TunnResult::Done => {}
    }
}

/// An IPv4/UDP packet carrying `payload`.
fn ipv4_udp(src: SocketAddrV4, dst: SocketAddrV4, payload: &[u8]) -> Vec<u8> {
    let udp = UdpRepr {
        src_port: src.port(),
        dst_port: dst.port(),
    };
    let ip = Ipv4Repr {
        src_addr: *src.ip(),
        dst_addr: *dst.ip(),
        next_header: IpProtocol::Udp,
        payload_len: udp.header_len() + payload.len(),
        hop_limit: 64,
    };
    let checksums = ChecksumCapabilities::default();
    let mut buf = vec![0; ip.buffer_len() + ip.payload_len];
    let mut ip_packet = Ipv4Packet::new_unchecked(&mut buf);
    ip.emit(&mut ip_packet, &checksums);
    udp.emit(
        &mut UdpPacket::new_unchecked(ip_packet.payload_mut()),
        &IpAddress::Ipv4(*src.ip()),
        &IpAddress::Ipv4(*dst.ip()),
        payload.len(),
        |b| b.copy_from_slice(payload),
        &checksums,
    );
    buf
}

/// The source and payload of an IPv4/UDP packet.
fn parse_ipv4_udp(bytes: &[u8]) -> Option<(SocketAddrV4, Vec<u8>)> {
    let ip = Ipv4Packet::new_checked(bytes).ok()?;
    if ip.next_header() != IpProtocol::Udp {
        return None;
    }
    let udp = UdpPacket::new_checked(ip.payload()).ok()?;
    Some((
        SocketAddrV4::new(ip.src_addr(), udp.src_port()),
        udp.payload().to_vec(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_udp_roundtrip() {
        let src = "10.1.0.2:54001".parse().unwrap();
        let dst = "203.0.113.7:51822".parse().unwrap();
        let packet = ipv4_udp(src, dst, b"hello");
        assert_eq!(parse_ipv4_udp(&packet), Some((src, b"hello".to_vec())));
    }

    /// Two in-process boringtun peers complete a handshake through the engine.
    #[test]
    fn single_hop_handshake() {
        let client_key = [1u8; 32];
        let server_key = x25519_dalek::StaticSecret::from([2u8; 32]);
        let peer = Peer {
            private_key: client_key,
            address_v4: Ipv4Addr::new(10, 0, 0, 2),
            public_key: x25519_dalek::PublicKey::from(&server_key).to_bytes(),
            preshared_key: None,
            endpoint: "127.0.0.1:1".parse().unwrap(),
            persistent_keepalive: None,
        };
        let mut client = Engine::single_hop(&peer);
        let mut server = Tunn::new(
            server_key,
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(client_key)),
            None,
            None,
            7,
            None,
        );
        let mut scratch = vec![0u8; SCRATCH_LEN];

        let init = client.initiate_handshakes().to_network;
        assert_eq!(init.len(), 1);
        let mut reply = Output::default();
        decapsulate(&mut server, &mut scratch, &init[0], &mut reply);
        assert_eq!(reply.to_network.len(), 1, "server answers the handshake");
        let out = client.decapsulate(&reply.to_network[0]);
        assert!(client.established());
        // The client confirms with a keepalive, which completes the server side.
        for datagram in out.to_network {
            decapsulate(&mut server, &mut scratch, &datagram, &mut Output::default());
        }

        let ping = ipv4_udp(
            "10.0.0.2:1000".parse().unwrap(),
            "1.2.3.4:2000".parse().unwrap(),
            b"ping",
        );
        let sent = client.encapsulate(&ping).to_network;
        let mut delivered = Output::default();
        decapsulate(&mut server, &mut scratch, &sent[0], &mut delivered);
        assert_eq!(delivered.to_stack, vec![ping]);
    }
}
