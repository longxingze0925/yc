use std::sync::Arc;

use rustls::{
    pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer},
    ClientConfig, RootCertStore, ServerConfig,
};

const CERTIFICATE_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIDSTCCAjGgAwIBAgIUHO+49BfK06g0AP7o93L8jN4BKa0wDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDcyMTA1MzE1MloXDTM2MDcx
ODA1MzE1MlowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAoVDwYHk5BNUuvB6j/aly9zqdEBDI+U8fd2kxA6pZIaC7
K1eVGtdpp32bhgBzMoo8AptUKtIk/QaugEWr9F3vrzWrZufkGlBj8Z1pUZliLPLz
0Yh+BvX1mqH69b7gXIqxbhAhhYwvDIEz+X9aim51GPyg60dDJsBMyGVG26b3TgyR
uCf2/YD2QZ6eJTPMaKxW36OQNy8D0q75WDloTxihNmpNRqZkZBPihU0OpCZjyWsY
g+VqqfrGzlAEMJN5W4N6xI1ofC/G9tgalUusDj+FSYkueSz4vX/KBuH+5RXuhMYn
toxK+2uFYdscNd4R0Vap4jdVS9wbhF0t9B7Yo6EMDQIDAQABo4GSMIGPMB0GA1Ud
DgQWBBQHSC9T7B09au+bun1Y2gIbpaKqGTAfBgNVHSMEGDAWgBQHSC9T7B09au+b
un1Y2gIbpaKqGTAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIFoDATBgNVHSUE
DDAKBggrBgEFBQcDATAaBgNVHREEEzARgglsb2NhbGhvc3SHBH8AAAEwDQYJKoZI
hvcNAQELBQADggEBAHxGmvEj5NyrToBpaq75mK2uIKOPwNhZWX5BwiAiXPmwv6It
GydKvocIVgOntiBIivKVSXIcViRiwKQ8wH0YIlfBPLxJE08Z1mHHn693lV9tRVXa
YeeaEo0UaXkg7T8onpuHvhtvJatb/BhXqDs6Xw8fmPdT3QW5iF1fh+abphf8hatA
9lvJ85ID0MkVui1NwZ27F2YEiVVLb6ktvvDkg1BVKMsqVUQy49qjmIBkrAsDHQqm
pfa1oFh3bgg8OGl0BHDp5Qd/Rgk+sIJcM9KEBYn6yTypJx78zH02QblLYHsKFEqs
6MR5LGICNiqe6UzJmZNPXcBGZgZVEFnh/lAVW4A=
-----END CERTIFICATE-----"#;

const PRIVATE_KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQChUPBgeTkE1S68
HqP9qXL3Op0QEMj5Tx93aTEDqlkhoLsrV5Ua12mnfZuGAHMyijwCm1Qq0iT9Bq6A
Rav0Xe+vNatm5+QaUGPxnWlRmWIs8vPRiH4G9fWaofr1vuBcirFuECGFjC8MgTP5
f1qKbnUY/KDrR0MmwEzIZUbbpvdODJG4J/b9gPZBnp4lM8xorFbfo5A3LwPSrvlY
OWhPGKE2ak1GpmRkE+KFTQ6kJmPJaxiD5Wqp+sbOUAQwk3lbg3rEjWh8L8b22BqV
S6wOP4VJiS55LPi9f8oG4f7lFe6Exie2jEr7a4Vh2xw13hHRVqniN1VL3BuEXS30
HtijoQwNAgMBAAECggEAEETa8UfYfcnIPFW0wUThINjq9S9ULXyS1laoCFAaTB9r
MPxUv8/AypEK6dFKzOqPEc47h1QJQfF2EN618F+26As4HZk+cn7wDXKMKBwZgCIC
f/vNhgMxQWabqkQVWY/tRAXhc5gHOLIhHUUASxzHt3zm98OInLRhKga4xjdJErhd
zGXzDiwdyt3p/DdEdQSYOn318OplV4LOo5y3wBp6VXk0NucbnIZEq9aDMMiixyLR
SdTd/TIjq858vm4Q5c7pGMtXScr2ldJdbmhiNN+BXemykPS8CIrACNyPODqm1PaJ
GjisPgYPaImzcMHQFKQU33qnMA9TuMAwdGwT4fWcQQKBgQDPQtTlRB375P4GRYjj
quHYmBOJKvpdMiJ4bLpLvWxAUOT53EanN/QhZyxBsuLEIoPVp7UWnfuL37vLiqZ0
Wh1tQ76343HUceUnjSpbtjIGMzgv3FTq4lq/dnZThO1iWbcJShg5nBxi/3/1N7mo
HFehDfGs9lzcHjlnTPO1L0T4IQKBgQDHQDaQbn3NJIkC2MhqlGxOexGqozqCQuOH
ZCwJWHATM6lR8IeTC8mRW1tD/lfM+jZk0onYX2vIOpWr+eyA2zdYcR+PL1yKb2CN
LNEOc166T8/N66IA/HtpM6dLXeq6i6SLe73ucpr5dby9Hr6wc/pi1x4u3J0Pe/z1
XBDO5p6mbQKBgQDNmcp/tFbaLosfxZLJ5hYsOpAGni/Gi5lORO15fOsJ0jWS90TP
VN5E1Ig+lCoHzwVgyQEG8qk6VDOC8oO1ID/YyD9FQ8cDrAhad9rxJ4fwRpcSQ0up
xemnzOgMaezih4TfHjVx0L8IJdTVePYfIh57kc2QesQbR5BCPT/1GHMegQKBgAKB
VC5MtVg29WILx7lPVG1ILtiuZLXukV3KbKNRcVdMdvyIwaufolEpjOQ19nSlULnD
y+fkiz5hPjCDW+3i07dQ9MygE9HJxLUBsz8zRCWji0FTjR3mDscr1xajf6gIyXDX
hXPSDRDF4jGeiVc+ng9QFRkRvQfMz0lmdu+jBquhAoGBAJX6vgqO/3ky0m/D74cC
IlmcrNEsZ6M478xn23L4xavw3FMs5JyvuAzGchvAUKTDNDDwU/TEjxykXU5ElPw0
YpKbB680DaRvyS+gXxli1ATksintNNdW245nuygAXjWT6A/W1QRThjI6VsWVOZBD
c9yG/DZS1gtJma0D/t+aLJy5
-----END PRIVATE KEY-----"#;

pub fn client_config() -> Arc<ClientConfig> {
    let certificate = certificate();
    let mut roots = RootCertStore::empty();
    roots.add(certificate).expect("test certificate root");
    Arc::new(
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("test protocol versions")
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

pub fn server_config() -> Arc<ServerConfig> {
    Arc::new(
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("test protocol versions")
            .with_no_client_auth()
            .with_single_cert(vec![certificate()], private_key())
            .expect("test certificate and key"),
    )
}

fn certificate() -> CertificateDer<'static> {
    CertificateDer::from_pem_slice(CERTIFICATE_PEM.as_bytes()).expect("test certificate pem")
}

fn private_key() -> PrivateKeyDer<'static> {
    PrivateKeyDer::from_pem_slice(PRIVATE_KEY_PEM.as_bytes()).expect("test private key pem")
}
