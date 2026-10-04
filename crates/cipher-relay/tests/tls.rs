#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
//! Transport hardening: the relay's TLS configuration is 1.3-only and refuses
//! downgrade. (TLS is not the E2EE boundary; this only protects metadata/transport.)
use rustls::pki_types::ServerName;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

fn client_config(
    cert_der: rustls::pki_types::CertificateDer<'static>,
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> rustls::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der).unwrap();
    rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_protocol_versions(versions)
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth()
}

#[test]
fn server_negotiates_tls13_and_refuses_tls12_and_untrusted_certs() {
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let cert_pem = ck.cert.pem();
    let key_pem = ck.signing_key.serialize_pem();
    let cert_der = ck.cert.der().clone();
    let server_cfg = Arc::new(cipher_relay::tls::server_config(cert_pem.as_bytes(), key_pem.as_bytes()).unwrap());

    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    rt.block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let acceptor = TlsAcceptor::from(server_cfg);
        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else { return };
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    if let Ok(mut tls) = acceptor.accept(tcp).await {
                        let mut buf = [0u8; 4];
                        if tls.read_exact(&mut buf).await.is_ok() {
                            let _ = tls.write_all(b"pong").await;
                            let _ = tls.shutdown().await;
                        }
                    }
                });
            }
        });
        let name = ServerName::try_from("localhost").unwrap();

        // TLS 1.3 client: works, and the negotiated version really is 1.3.
        let c = TlsConnector::from(Arc::new(client_config(cert_der.clone(), &[&rustls::version::TLS13])));
        let mut s = c.connect(name.clone(), TcpStream::connect(addr).await.unwrap()).await.unwrap();
        assert_eq!(s.get_ref().1.protocol_version(), Some(rustls::ProtocolVersion::TLSv1_3));
        s.write_all(b"ping").await.unwrap();
        let mut out = [0u8; 4];
        s.read_exact(&mut out).await.unwrap();
        assert_eq!(&out, b"pong");

        // TLS 1.2-only client (downgrade attempt): handshake must fail.
        let c12 = TlsConnector::from(Arc::new(client_config(cert_der.clone(), &[&rustls::version::TLS12])));
        assert!(c12.connect(name.clone(), TcpStream::connect(addr).await.unwrap()).await.is_err(), "TLS 1.2 must be refused");

        // Client that does not trust the server certificate (MITM with a different cert): must fail closed.
        let other = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let cm = TlsConnector::from(Arc::new(client_config(other.cert.der().clone(), &[&rustls::version::TLS13])));
        assert!(cm.connect(name, TcpStream::connect(addr).await.unwrap()).await.is_err(), "untrusted certificate must be refused");
    });
}

#[test]
fn invalid_tls_material_is_rejected() {
    assert!(cipher_relay::tls::server_config(b"", b"").is_err());
    assert!(cipher_relay::tls::server_config(b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n", b"nope").is_err());
}
