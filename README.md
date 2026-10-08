# wg-iroh

Experiment: run an [iroh] endpoint entirely inside a userspace WireGuard
tunnel, so that peers, relays and pkarr only ever see the VPN exit's IP.
No TUN device, no root, no OS-wide VPN.

Tested through NymVPN one-hop gateways: the endpoint connects via the relay,
then hole punches to a direct path, and the peer sees the Nym gateway's
address, never the real one.

## How it works

| Traffic | Route |
|---|---|
| QUIC, QUIC address discovery, hole punching | iroh's IP transport binds through netwatch; a bind hook hands it a UDP socket inside the tunnel |
| Relay connection, HTTPS relay probes, pkarr publish and resolve | `Builder::proxy_url` → a localhost HTTP CONNECT proxy whose upstream TCP connections run inside the tunnel |
| iroh's own DNS lookups | `DnsResolver::custom` with a resolver that queries through the tunnel |

The only socket the process opens to the outside is the WireGuard UDP flow
to the entry endpoint.

It depends on two branches:

- [netwatch `rklaehn/custom-udp`][netwatch branch]: `CustomUdpSocket` and a
  process-wide bind hook. This is the hack; a real integration would pass the
  socket to the endpoint builder explicitly.
- [iroh `rklaehn/pkarr-proxy-url`][iroh PR]: pkarr follows the endpoint's
  `proxy_url`. Without it, pkarr only picks up a proxy from `HTTPS_PROXY`.

## Crates

- `wg-udp`: the tunnel. A small WireGuard engine on [boringtun] (one hop,
  or two hops nested), a smoltcp TCP/IP stack from [nym-smol-core], a
  wg-quick config parser and the CONNECT proxy. Its binary pings mainline
  DHT nodes through the tunnel as a plain UDP check.
- `wg-iroh`: the iroh demo.

## Usage

Any wg-quick config works, for example a ProtonVPN or Mullvad download.

```sh
# anywhere, stock iroh
cargo run -p wg-iroh -- accept

# inside the tunnel, dialing by endpoint id (resolved via pkarr)
cargo run -p wg-iroh -- connect my.conf <endpoint-id>

# two hops: nest a second WireGuard tunnel inside the first
cargo run -p wg-iroh -- connect entry.conf <endpoint-id> --exit exit.conf
```

## Known gaps

- The netwatch bind hook is process-wide; the demo installs it only for the
  duration of `Endpoint::bind`.
- IPv4 only, since the tunnel stack is IPv4 only.
- The tunnel resolver does not support TXT records, so DNS-based address
  lookup is not used; pkarr over HTTPS is.
- Two hops are implemented but not tested against real gateways yet.
- VPN exits may restrict ports. NymVPN's exit policy blocks 6881, for
  example, which the standard mainline DHT bootstrap nodes use.

[iroh]: https://docs.rs/iroh
[boringtun]: https://docs.rs/boringtun
[nym-smol-core]: https://docs.rs/nym-smol-core
[netwatch branch]: https://github.com/n0-computer/net-tools/tree/rklaehn/custom-udp
[iroh PR]: https://github.com/n0-computer/iroh/pull/4595
