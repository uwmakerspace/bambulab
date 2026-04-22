//! TLS configuration for Bambu MQTT (LAN custom CA + optional hostname skip; cloud webpki roots).

use std::sync::Arc;

#[cfg(feature = "verify-tls")]
use tracing::{debug, info, trace, warn};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
#[cfg(feature = "verify-tls")]
use rustls::client::verify_server_cert_signed_by_trust_anchor;
use rustls::crypto::CryptoProvider;
#[cfg(feature = "verify-tls")]
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
#[cfg(feature = "verify-tls")]
use rustls::server::ParsedCertificate;
use rustls::RootCertStore;
use rustls::{ClientConfig, DigitallySignedStruct, Error, SignatureScheme};

fn ensure_crypto_provider() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

#[cfg(feature = "verify-tls")]
fn crypto_supported_algs() -> WebPkiSupportedAlgorithms {
    ensure_crypto_provider();
    CryptoProvider::get_default()
        .expect("rustls CryptoProvider")
        .signature_verification_algorithms
}

/// BBL CA root and `application_root.bambulab.com` intermediate (see `certs/extracted/README.md`).
#[cfg(feature = "verify-tls")]
const BBL_LAN_TRUST_PEMS: &[&[u8]] = &[
    include_bytes!("certs/extracted/cert_5.pem"),
    include_bytes!("certs/extracted/cert_8.pem"),
];

#[cfg(feature = "verify-tls")]
fn bbl_root_store() -> Result<Arc<RootCertStore>, Box<dyn std::error::Error>> {
    let mut roots = RootCertStore::empty();
    for (i, pem) in BBL_LAN_TRUST_PEMS.iter().enumerate() {
        let mut reader = std::io::BufReader::new(std::io::Cursor::new(*pem));
        let mut certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| {
                warn!(index = i, error = %e, "bambulab tls: failed to parse BBL LAN trust PEM");
                format!("parse BBL LAN trust PEM: {e}")
            })?;
        let c = match certs.len() {
            1 => certs.remove(0),
            n => {
                warn!(
                    index = i,
                    cert_count = n,
                    "bambulab tls: expected 1 cert per PEM"
                );
                return Err(format!("expected 1 certificate per PEM file, got {n}").into());
            }
        };
        roots.add(c).map_err(|e| {
            warn!(index = i, error = %e, "bambulab tls: add BBL trust anchor failed");
            format!("add BBL trust anchor: {e}")
        })?;
    }
    let n = roots.len();
    debug!(
        trust_anchors = n,
        "bambulab tls: BBL LAN root store built (verify-tls)"
    );
    Ok(Arc::new(roots))
}

/// Verifies the server chain against BBL trust anchors but does **not** enforce DNS/IP name
/// matching, so LAN connections to a printer by IP still validate the printer certificate.
#[cfg(feature = "verify-tls")]
#[derive(Debug)]
struct BambuLanCertVerifier {
    roots: Arc<RootCertStore>,
    supported: WebPkiSupportedAlgorithms,
}

#[cfg(feature = "verify-tls")]
impl ServerCertVerifier for BambuLanCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let cert = ParsedCertificate::try_from(end_entity).map_err(|e| {
            warn!(error = %e, "bambulab tls: parse end-entity certificate failed (verify-tls)");
            e
        })?;
        verify_server_cert_signed_by_trust_anchor(
            &cert,
            self.roots.as_ref(),
            intermediates,
            now,
            self.supported.all,
        )
        .map_err(|e| {
            warn!(
                error = %e,
                intermediate_count = intermediates.len(),
                "bambulab tls: server cert chain verification failed against BBL trust anchors (verify-tls)"
            );
            e
        })?;
        trace!("bambulab tls: LAN server certificate verified (chain OK, hostname not enforced)");
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls12_signature(message, cert, dss, &self.supported)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(message, cert, dss, &self.supported)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported.supported_schemes()
    }
}

/// No certificate verification (MITM-vulnerable). Used when `verify-tls` is disabled.
#[derive(Debug)]
struct InsecureCertVerifier;

impl ServerCertVerifier for InsecureCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        ensure_crypto_provider();
        CryptoProvider::get_default()
            .expect("rustls CryptoProvider")
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// TLS client config for LAN printers: trust BBL bundle, validate chain, skip hostname check.
#[cfg(feature = "verify-tls")]
pub fn build_lan_tls_config() -> Result<Arc<ClientConfig>, Box<dyn std::error::Error>> {
    info!(
        "bambulab tls: building LAN ClientConfig with verify-tls (BBL anchors, no hostname check)"
    );
    ensure_crypto_provider();
    let roots = bbl_root_store()?;
    let supported = crypto_supported_algs();
    let verifier = Arc::new(BambuLanCertVerifier { roots, supported });
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

#[cfg(not(feature = "verify-tls"))]
pub fn build_lan_tls_config() -> Result<Arc<ClientConfig>, Box<dyn std::error::Error>> {
    build_insecure_tls_config()
}

/// Standard public-PKI verification for `*.mqtt.bambulab.com`.
pub fn build_cloud_tls_config() -> Result<Arc<ClientConfig>, Box<dyn std::error::Error>> {
    ensure_crypto_provider();
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

pub fn build_insecure_tls_config() -> Result<Arc<ClientConfig>, Box<dyn std::error::Error>> {
    ensure_crypto_provider();
    let verifier: Arc<dyn ServerCertVerifier> = Arc::new(InsecureCertVerifier);
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    Ok(Arc::new(config))
}
