//! wg-quick configs, and bringing up a tunnel from them.

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::Path,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};

use crate::wg::{self, Tunnel};

const ESTABLISH_TIMEOUT: Duration = Duration::from_secs(15);

/// Brings up a tunnel from an entry config and an optional nested exit config.
pub async fn connect(entry: &WgConfig, exit: Option<&WgConfig>) -> Result<Tunnel> {
    // The innermost tunnel carries the application traffic, so its config
    // decides the DNS server and the stack's MTU. A nested hop loses one
    // hop's overhead unless its config says otherwise.
    let entry_mtu = entry.mtu.unwrap_or(wg::DEFAULT_MTU);
    let (inner, mtu) = match exit {
        None => (entry, entry_mtu),
        Some(exit) => (
            exit,
            exit.mtu.unwrap_or(entry_mtu - wg::OVERHEAD_PER_HOP),
        ),
    };
    println!("entry endpoint: {}", entry.endpoint);
    if let Some(exit) = exit {
        println!("exit endpoint:  {}", exit.endpoint);
    }
    let dns = inner.dns.map(|ip| SocketAddr::new(ip, 53));
    let tunnel = Tunnel::connect(&entry.peer(), exit.map(WgConfig::peer).as_ref(), mtu, dns).await?;
    tunnel.established(ESTABLISH_TIMEOUT).await?;
    println!("tunnel up, mtu {mtu}");
    Ok(tunnel)
}

/// The parts of a wg-quick config a single-peer client tunnel needs.
///
/// `AllowedIPs` is ignored: everything the application sends goes through
/// the tunnel. Lines this does not know, such as `PostUp`, are ignored too.
#[derive(Debug)]
pub struct WgConfig {
    private_key: [u8; 32],
    address_v4: Ipv4Addr,
    dns: Option<IpAddr>,
    mtu: Option<usize>,
    peer_public_key: [u8; 32],
    preshared_key: Option<[u8; 32]>,
    persistent_keepalive: Option<u16>,
    /// The resolved peer endpoint.
    pub endpoint: SocketAddr,
}

impl WgConfig {
    pub async fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("read {}", path.display()))?;
        let parsed = Parsed::parse(&text).with_context(|| format!("parse {}", path.display()))?;
        // The endpoint is resolved outside the tunnel, necessarily: it is how
        // we reach the tunnel. Providers usually give an IP literal anyway.
        let endpoint = match parsed.endpoint.parse() {
            Ok(addr) => addr,
            Err(_) => tokio::net::lookup_host(&parsed.endpoint)
                .await
                .with_context(|| format!("resolve endpoint {}", parsed.endpoint))?
                .next()
                .with_context(|| format!("endpoint {} has no address", parsed.endpoint))?,
        };
        Ok(Self {
            private_key: parsed.private_key,
            address_v4: parsed.address_v4,
            dns: parsed.dns,
            mtu: parsed.mtu,
            peer_public_key: parsed.peer_public_key,
            preshared_key: parsed.preshared_key,
            persistent_keepalive: parsed.persistent_keepalive,
            endpoint,
        })
    }

    pub fn peer(&self) -> wg::Peer {
        wg::Peer {
            private_key: self.private_key,
            address_v4: self.address_v4,
            public_key: self.peer_public_key,
            preshared_key: self.preshared_key,
            endpoint: self.endpoint,
            persistent_keepalive: self.persistent_keepalive,
        }
    }
}

/// A wg-quick config as parsed, before the endpoint is resolved.
#[derive(Debug, PartialEq)]
struct Parsed {
    private_key: [u8; 32],
    address_v4: Ipv4Addr,
    address_v6: Option<Ipv6Addr>,
    dns: Option<IpAddr>,
    mtu: Option<usize>,
    peer_public_key: [u8; 32],
    preshared_key: Option<[u8; 32]>,
    persistent_keepalive: Option<u16>,
    endpoint: String,
}

impl Parsed {
    fn parse(text: &str) -> Result<Self> {
        let mut section = "";
        let mut peers = 0;
        let mut private_key = None;
        let (mut address_v4, mut address_v6) = (None, None);
        let (mut dns, mut mtu) = (None, None);
        let (mut peer_public_key, mut preshared_key, mut endpoint) = (None, None, None);
        let mut persistent_keepalive = None;
        for line in text.lines() {
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            if line.starts_with('[') {
                section = line;
                if section.eq_ignore_ascii_case("[Peer]") {
                    peers += 1;
                }
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                bail!("not a key = value line: {line}");
            };
            let (key, value) = (key.trim().to_ascii_lowercase(), value.trim());
            match (section.to_ascii_lowercase().as_str(), key.as_str()) {
                ("[interface]", "privatekey") => private_key = Some(key32(value)?),
                ("[interface]", "address") => {
                    for addr in value.split(',') {
                        let ip = addr.trim().split('/').next().unwrap_or("");
                        match ip.parse::<IpAddr>().with_context(|| format!("address {ip}"))? {
                            IpAddr::V4(ip) => address_v4 = address_v4.or(Some(ip)),
                            IpAddr::V6(ip) => address_v6 = address_v6.or(Some(ip)),
                        }
                    }
                }
                ("[interface]", "dns") => {
                    // DNS may also list search domains; take the first IP.
                    dns = value.split(',').find_map(|s| s.trim().parse().ok());
                }
                ("[interface]", "mtu") => mtu = Some(value.parse().context("mtu")?),
                ("[peer]", "publickey") => peer_public_key = Some(key32(value)?),
                ("[peer]", "presharedkey") => preshared_key = Some(key32(value)?),
                ("[peer]", "endpoint") => endpoint = Some(value.to_string()),
                ("[peer]", "persistentkeepalive") => {
                    // wg-quick allows "off" for no keepalive.
                    persistent_keepalive = value.parse().ok().filter(|secs| *secs > 0);
                }
                _ => {}
            }
        }
        if peers != 1 {
            bail!("expected exactly one [Peer], found {peers}");
        }
        Ok(Self {
            private_key: private_key.context("missing PrivateKey")?,
            address_v4: address_v4.context("missing IPv4 Address")?,
            address_v6,
            dns,
            mtu,
            peer_public_key: peer_public_key.context("missing PublicKey")?,
            preshared_key,
            persistent_keepalive,
            endpoint: endpoint.context("missing Endpoint")?,
        })
    }
}

fn key32(value: &str) -> Result<[u8; 32]> {
    let bytes = BASE64.decode(value).context("key is not base64")?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("key is not 32 bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shape of a ProtonVPN download (keys are made up).
    #[test]
    fn parses_wg_quick_config() {
        let key = BASE64.encode([1u8; 32]);
        let peer = BASE64.encode([2u8; 32]);
        let text = format!(
            "[Interface]\n\
             # Key for demo\n\
             # Bouncing = 3\n\
             # NetShield = 1\n\
             PrivateKey = {key}\n\
             Address = 10.2.0.2/32, 2a07:b944::2:2/128\n\
             DNS = 10.2.0.1\n\
             \n\
             [Peer]\n\
             # DE#1\n\
             PublicKey = {peer}\n\
             AllowedIPs = 0.0.0.0/0, ::/0\n\
             Endpoint = 185.159.157.1:51820\n"
        );
        let parsed = Parsed::parse(&text).unwrap();
        assert_eq!(
            parsed,
            Parsed {
                private_key: [1; 32],
                address_v4: "10.2.0.2".parse().unwrap(),
                address_v6: Some("2a07:b944::2:2".parse().unwrap()),
                dns: Some("10.2.0.1".parse().unwrap()),
                mtu: None,
                peer_public_key: [2; 32],
                preshared_key: None,
                persistent_keepalive: None,
                endpoint: "185.159.157.1:51820".to_string(),
            }
        );
    }

    #[test]
    fn rejects_multiple_peers() {
        let key = BASE64.encode([1u8; 32]);
        let text = format!(
            "[Interface]\nPrivateKey = {key}\nAddress = 10.0.0.2/32\n\
             [Peer]\nPublicKey = {key}\nEndpoint = 1.2.3.4:51820\n\
             [Peer]\nPublicKey = {key}\nEndpoint = 1.2.3.5:51820\n"
        );
        assert!(Parsed::parse(&text).is_err());
    }
}
