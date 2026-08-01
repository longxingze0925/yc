use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};

use get_if_addrs::{get_if_addrs, IfAddr};
use rand::Rng;
use rcgen::generate_simple_self_signed;
use remote_crypto::sha256;
use remote_protocol::{
    CandidateSource, CandidateTokenRequest, ConnectionCandidateDto, SessionRole, TransportPath,
};
use remote_transport::{candidate_id, local_interface_claim_hash, LocalNetwork};
use rustls::{
    pki_types::{CertificateDer, PrivatePkcs8KeyDer},
    ServerConfig,
};
use tokio::net::UdpSocket;

use crate::identity::DeviceIdentity;

const CANDIDATE_TOKEN_TTL_MILLIS: u32 = 30_000;
const LAN_BIND_ATTEMPTS: usize = 128;

#[derive(Debug)]
pub enum LanDirectError {
    InterfaceDiscovery,
    NoPrivateInterface,
    Bind,
    InvalidInterface,
    Candidate(remote_transport::BindingError),
    Certificate,
}

impl fmt::Display for LanDirectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InterfaceDiscovery => formatter.write_str("LAN interface discovery failed"),
            Self::NoPrivateInterface => {
                formatter.write_str("no routable private LAN interface is available")
            }
            Self::Bind => formatter.write_str("failed to bind a LAN UDP socket"),
            Self::InvalidInterface => formatter.write_str("LAN interface metadata is invalid"),
            Self::Candidate(error) => write!(formatter, "LAN candidate binding failed: {error:?}"),
            Self::Certificate => {
                formatter.write_str("failed to generate an ephemeral QUIC certificate")
            }
        }
    }
}

impl std::error::Error for LanDirectError {}

impl From<remote_transport::BindingError> for LanDirectError {
    fn from(value: remote_transport::BindingError) -> Self {
        Self::Candidate(value)
    }
}

#[derive(Clone)]
pub struct EphemeralQuicIdentity {
    tls_config: Arc<ServerConfig>,
    certificate_der: Vec<u8>,
    certificate_sha256: [u8; 32],
    server_name: String,
}

impl fmt::Debug for EphemeralQuicIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EphemeralQuicIdentity")
            .field("certificate_sha256", &self.certificate_sha256)
            .finish()
    }
}

impl EphemeralQuicIdentity {
    pub fn generate(session_id: &str) -> Result<Self, LanDirectError> {
        let server_name = format!("rctl-{session_id}.invalid");
        let certified = generate_simple_self_signed(vec![server_name.clone()])
            .map_err(|_| LanDirectError::Certificate)?;
        let certificate_der = certified.cert.der().as_ref().to_vec();
        let key_der = certified.key_pair.serialize_der();
        let tls_config =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .map_err(|_| LanDirectError::Certificate)?
                .with_no_client_auth()
                .with_single_cert(
                    vec![CertificateDer::from(certificate_der.clone())],
                    PrivatePkcs8KeyDer::from(key_der).into(),
                )
                .map_err(|_| LanDirectError::Certificate)?;
        Ok(Self {
            tls_config: Arc::new(tls_config),
            certificate_sha256: sha256(&certificate_der),
            certificate_der,
            server_name,
        })
    }

    pub fn tls_config(&self) -> Arc<ServerConfig> {
        Arc::clone(&self.tls_config)
    }

    pub fn certificate_der(&self) -> &[u8] {
        &self.certificate_der
    }

    pub const fn certificate_sha256(&self) -> [u8; 32] {
        self.certificate_sha256
    }

    pub fn server_name(&self) -> &str {
        &self.server_name
    }
}

pub struct LanDirectCandidate {
    pub socket: UdpSocket,
    pub candidate: ConnectionCandidateDto,
    pub token_request: CandidateTokenRequest,
    pub local_networks: Vec<LocalNetwork>,
    pub quic_identity: EphemeralQuicIdentity,
}

impl fmt::Debug for LanDirectCandidate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LanDirectCandidate")
            .field("candidate", &self.candidate)
            .field("local_network_count", &self.local_networks.len())
            .field("quic_identity", &self.quic_identity)
            .finish()
    }
}

impl LanDirectCandidate {
    pub async fn gather(
        session_id: u128,
        device_id: &str,
        identity: &DeviceIdentity,
        now_epoch_millis: u64,
    ) -> Result<Self, LanDirectError> {
        let interface = discover_private_interface()?;
        let socket = bind_lan_socket(interface.address).await?;
        let endpoint = socket.local_addr().map_err(|_| LanDirectError::Bind)?;
        let mut candidate = ConnectionCandidateDto {
            candidate_id: 0,
            session_id,
            device_id: device_id.to_owned(),
            role: SessionRole::Controlled,
            kind: TransportPath::LanDirect,
            endpoint: endpoint.to_string(),
            source: CandidateSource::LocalInterface,
            observe_result_id: None,
            priority: 0,
            rtt_ms: None,
            loss_ppm: None,
            jitter_ms: None,
            relay_node_id: None,
        };
        candidate.candidate_id = candidate_id(&candidate)?;
        let mut socket_nonce = [0_u8; 32];
        rand::rng().fill(&mut socket_nonce);
        let mut request = CandidateTokenRequest {
            session_id,
            device_id: device_id.to_owned(),
            role: SessionRole::Controlled,
            candidate_id: candidate.candidate_id,
            kind: TransportPath::LanDirect,
            endpoint: candidate.endpoint.clone(),
            source: CandidateSource::LocalInterface,
            relay_node_id: None,
            observe_result_id: None,
            observe_result_binding_hash: None,
            local_interface_claim_hash: None,
            local_interface_signature: None,
            interface_name_hash: Some(sha256(interface.name.as_bytes())),
            interface_index_hash: Some(sha256(interface.index.to_string().as_bytes())),
            local_socket_nonce: Some(socket_nonce),
            timestamp_epoch_millis: Some(now_epoch_millis),
            requested_ttl_millis: CANDIDATE_TOKEN_TTL_MILLIS,
        };
        let claim = local_interface_claim_hash(&request)?;
        request.local_interface_claim_hash = Some(claim);
        request.local_interface_signature = Some(identity.sign_digest(&claim).to_vec());
        Ok(Self {
            socket,
            candidate,
            token_request: request,
            local_networks: vec![interface.network],
            quic_identity: EphemeralQuicIdentity::generate(&session_id.to_string())?,
        })
    }
}

struct PrivateInterface {
    name: String,
    index: u32,
    address: IpAddr,
    network: LocalNetwork,
}

fn discover_private_interface() -> Result<PrivateInterface, LanDirectError> {
    let interfaces = get_if_addrs().map_err(|_| LanDirectError::InterfaceDiscovery)?;
    let default_interface = std::fs::read_to_string("/proc/net/route")
        .ok()
        .and_then(|routes| parse_default_route_interface(&routes));
    let mut candidates = interfaces
        .into_iter()
        .filter_map(|interface| {
            let IfAddr::V4(address) = interface.addr else {
                return None;
            };
            if is_virtual_lan_interface(&interface.name)
                || !is_private_unicast(address.ip)
                || !is_contiguous_netmask(address.netmask)
            {
                return None;
            }
            let prefix = u32::from(address.netmask).leading_ones() as u8;
            let network = LocalNetwork::new(IpAddr::V4(address.ip), prefix).ok()?;
            let index =
                std::fs::read_to_string(format!("/sys/class/net/{}/ifindex", interface.name))
                    .ok()?
                    .trim()
                    .parse()
                    .ok()?;
            Some(PrivateInterface {
                name: interface.name,
                index,
                address: IpAddr::V4(address.ip),
                network,
            })
        })
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| {
        let left_default = default_interface.as_deref() == Some(left.name.as_str());
        let right_default = default_interface.as_deref() == Some(right.name.as_str());
        right_default
            .cmp(&left_default)
            .then_with(|| left.name.cmp(&right.name))
            .then_with(|| left.address.to_string().cmp(&right.address.to_string()))
    });
    candidates
        .into_iter()
        .next()
        .ok_or(LanDirectError::NoPrivateInterface)
}

async fn bind_lan_socket(address: IpAddr) -> Result<UdpSocket, LanDirectError> {
    let minimum = remote_transport::LAN_EPHEMERAL_PORT_MIN;
    let port_count = u32::from(u16::MAX) - u32::from(minimum) + 1;
    let start = rand::rng().random_range(0..port_count);
    for offset in 0..LAN_BIND_ATTEMPTS as u32 {
        let port = minimum + ((start + offset) % port_count) as u16;
        if let Ok(socket) = UdpSocket::bind(SocketAddr::new(address, port)).await {
            return Ok(socket);
        }
    }
    Err(LanDirectError::Bind)
}

fn parse_default_route_interface(routes: &str) -> Option<String> {
    routes
        .lines()
        .skip(1)
        .filter_map(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            if fields.len() < 8 || fields[1] != "00000000" || fields[7] != "00000000" {
                return None;
            }
            let flags = u16::from_str_radix(fields[3], 16).ok()?;
            if flags & 0x1 == 0 {
                return None;
            }
            let metric = fields[6].parse::<u32>().ok()?;
            Some((metric, fields[0].to_owned()))
        })
        .min_by_key(|(metric, _)| *metric)
        .map(|(_, interface)| interface)
}

fn is_virtual_lan_interface(name: &str) -> bool {
    [
        "br-", "cni", "docker", "flannel", "podman", "veth", "virbr", "vnet", "vboxnet", "vmnet",
    ]
    .iter()
    .any(|prefix| name.starts_with(prefix))
}

fn is_private_unicast(address: Ipv4Addr) -> bool {
    address.is_private()
        && !address.is_loopback()
        && !address.is_link_local()
        && !address.is_broadcast()
        && !address.is_documentation()
        && address.octets()[3] != 0
        && address.octets()[3] != 255
}

fn is_contiguous_netmask(mask: Ipv4Addr) -> bool {
    let value = u32::from(mask);
    let ones = value.leading_ones();
    value
        == if ones == 0 {
            0
        } else {
            u32::MAX << (32 - ones)
        }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_loopback_and_non_contiguous_interface_claims() {
        assert!(!is_private_unicast(Ipv4Addr::LOCALHOST));
        assert!(!is_contiguous_netmask(Ipv4Addr::new(255, 0, 255, 0)));
        assert!(is_contiguous_netmask(Ipv4Addr::new(255, 255, 255, 0)));
    }

    #[test]
    fn selects_the_lowest_metric_default_route_and_rejects_virtual_bridges() {
        let routes = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n\
wlo1\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\n\
enp5s0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\n";
        assert_eq!(
            parse_default_route_interface(routes).as_deref(),
            Some("enp5s0")
        );
        assert!(is_virtual_lan_interface("docker0"));
        assert!(is_virtual_lan_interface("br-0123456789ab"));
        assert!(is_virtual_lan_interface("veth1234"));
        assert!(!is_virtual_lan_interface("wlo1"));
        assert!(!is_virtual_lan_interface("enp5s0"));
    }

    #[tokio::test]
    async fn explicit_lan_bind_never_returns_a_low_ephemeral_port() {
        for _ in 0..32 {
            let socket = bind_lan_socket(IpAddr::V4(Ipv4Addr::LOCALHOST))
                .await
                .expect("bind high LAN port");
            assert!(
                socket.local_addr().expect("local endpoint").port()
                    >= remote_transport::LAN_EPHEMERAL_PORT_MIN
            );
        }
    }

    #[test]
    fn ephemeral_identity_exposes_only_public_certificate_metadata() {
        let identity = EphemeralQuicIdentity::generate("session-1").expect("identity");
        assert!(!identity.certificate_der().is_empty());
        assert_ne!(identity.certificate_sha256(), [0; 32]);
    }
}
