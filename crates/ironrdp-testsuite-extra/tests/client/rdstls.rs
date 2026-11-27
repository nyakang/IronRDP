use std::sync::Arc;
use std::time::Duration;

use ironrdp_client::config::{ClipboardType, ConfigBuilder, Destination};
use ironrdp_client::output_channel::output_channel;
use ironrdp_client::rdp::{RdpClient, RdpOutputEvent};
use ironrdp_core::{decode, encode_vec};
use ironrdp_pdu::nego::{ConnectionConfirm, ConnectionRequest, ResponseFlags, SecurityProtocol};
use ironrdp_pdu::rdp::capability_sets::MajorPlatformType;
use ironrdp_pdu::rdp::server_redirection::{ServerRedirectionFlags, ServerRedirectionPdu, TargetCertificateContainer};
use ironrdp_pdu::x224::X224;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

// oracle: spec MS-RDPBCGR 2.2.17; independent derivation from field widths and UTF-16LE, with synthetic GUID bytes.
const REQUEST: &[u8] = &[
    1, 0, 2, 0, 1, 0, 4, 0, 0x51, 0, 0, 0, 4, 0, 0x75, 0, 0, 0, 2, 0, 0, 0, 4, 0, 0xde, 0xad, 0xbe, 0xef,
];

struct Observation {
    authentication: Vec<u8>,
    subsequent: Vec<u8>,
    error: String,
}

async fn exchange(matching_certificate: bool, embedder_accepts: bool, result: u32) -> Observation {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let cert_der = certified.cert.der().to_vec();
    let key = tokio_rustls::rustls::pki_types::PrivateKeyDer::Pkcs8(
        tokio_rustls::rustls::pki_types::PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der()),
    );
    let server_config = tokio_rustls::rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certified.cert.der().clone()], key)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut header = [0u8; 4];
        stream.read_exact(&mut header).await.unwrap();
        let size = usize::from(u16::from_be_bytes([header[2], header[3]]));
        let mut request = vec![0; size];
        request[..4].copy_from_slice(&header);
        stream.read_exact(&mut request[4..]).await.unwrap();
        assert_eq!(
            decode::<X224<ConnectionRequest>>(&request).unwrap().0.protocol,
            SecurityProtocol::RDSTLS
        );
        let confirm = encode_vec(&X224(ConnectionConfirm::Response {
            flags: ResponseFlags::empty(),
            protocol: SecurityProtocol::RDSTLS,
        }))
        .unwrap();
        stream.write_all(&confirm).await.unwrap();
        let Ok(mut tls) = acceptor.accept(stream).await else {
            return (Vec::new(), Vec::new());
        };
        // Fragment the fixed-sized capability message across separate TLS writes.
        for part in [&[1, 0, 1][..], &[0, 1, 0, 1, 0][..]] {
            if tls.write_all(part).await.is_err() {
                return (Vec::new(), Vec::new());
            }
        }
        let mut auth = vec![0; REQUEST.len()];
        if tls.read_exact(&mut auth).await.is_err() {
            return (Vec::new(), Vec::new());
        }
        let mut response = vec![1, 0, 4, 0, 1, 0];
        response.extend_from_slice(&result.to_le_bytes());
        tls.write_all(&response).await.unwrap();
        let mut header = [0; 4];
        let following = if tls.read_exact(&mut header).await.is_ok() {
            let size = usize::from(u16::from_be_bytes([header[2], header[3]]));
            assert!(4 <= size);
            let mut pdu = vec![0; size];
            pdu[..4].copy_from_slice(&header);
            tls.read_exact(&mut pdu[4..]).await.unwrap();
            pdu
        } else {
            Vec::new()
        };
        (auth, following)
    });
    let mut config = ConfigBuilder::new()
        .with_destination(Destination::from_parts("127.0.0.1", address.port()))
        .with_username("original-user")
        .with_password("original-password")
        .with_client_build(1)
        .with_client_dir("C:\\")
        .with_client_name("client")
        .with_platform(MajorPlatformType::WINDOWS)
        .with_clipboard(ClipboardType::Disable)
        .with_certificate_validation_callback(Arc::new(move |_, _, _| embedder_accepts))
        .build()
        .unwrap();
    let expected_cert = if matching_certificate {
        cert_der
    } else {
        // Different certificate, identical public key: pin the full DER certificate, not only its key.
        let mut params = rcgen::CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
        params.serial_number = Some(12345u64.into());
        params.self_signed(&certified.signing_key).unwrap().der().to_vec()
    };
    ironrdp_client::__test_apply_server_redirection(
        &mut config,
        &ServerRedirectionPdu {
            flags: ServerRedirectionFlags::PASSWORD_IS_PK_ENCRYPTED,
            target_net_address: Some("127.0.0.1".into()),
            target_fqdn: Some("localhost".into()),
            username: Some("u".into()),
            domain: Some(String::new()),
            password: Some(vec![0xde, 0xad, 0xbe, 0xef]),
            redirection_guid: Some(vec![0x51, 0, 0, 0]),
            target_certificate: Some(TargetCertificateContainer::from_certificate_der(expected_cert)),
            ..ServerRedirectionPdu::default()
        },
    )
    .unwrap();
    let (output, mut events) = output_channel(16);
    let client = RdpClient::new(config, output);
    let error = tokio::task::LocalSet::new()
        .run_until(async move {
            let worker = tokio::task::spawn_local(client.run());
            let error = tokio::time::timeout(Duration::from_secs(15), async {
                loop {
                    match events.recv().await.unwrap() {
                        RdpOutputEvent::ConnectionFailure(error) => break format!("{error:?}"),
                        RdpOutputEvent::Connected => panic!("mock server never completes the RDP connection"),
                        _ => {}
                    }
                }
            })
            .await
            .unwrap();
            worker.abort();
            let _ = worker.await;
            error
        })
        .await;
    let (authentication, subsequent) = tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap();
    Observation {
        authentication,
        subsequent,
        error,
    }
}

#[tokio::test]
async fn rdstls_tls_exchange_reaches_mcs_only_after_authentication_success() {
    // oracle: spec MS-RDPBCGR 5.4.5.3.1, TLS -> RDSTLS -> MCS sequence.
    let observed = exchange(true, true, 0).await;
    assert_eq!(observed.authentication, REQUEST);
    let data = decode::<X224<ironrdp_pdu::x224::X224Data<'_>>>(&observed.subsequent).unwrap();
    decode::<ironrdp_pdu::mcs::ConnectInitial>(&data.0.data)
        .expect("successful RDSTLS must resume with MCS Connect Initial");
}

#[tokio::test]
async fn rdstls_failed_authentication_closes_tls_without_mcs() {
    // oracle: spec MS-RDPBCGR 2.2.17.4 and 5.4.5.3.1.
    let observed = exchange(true, true, 0x52e).await;
    assert_eq!(observed.authentication, REQUEST);
    assert!(observed.subsequent.is_empty());
    assert!(observed.error.contains("0000052e"));
}

#[tokio::test]
async fn rdstls_certificate_mismatch_overrides_embedder_acceptance() {
    // oracle: spec MS-RDPBCGR 5.4.5.3.1 requires certificate equality before sending credentials.
    let observed = exchange(false, true, 0).await;
    assert!(observed.authentication.is_empty());
    assert!(observed.subsequent.is_empty());
}

#[tokio::test]
async fn rdstls_matching_certificate_preserves_embedder_rejection() {
    // oracle: NyaTerm certificate approval remains authoritative after redirection.
    let observed = exchange(true, false, 0).await;
    assert!(observed.authentication.is_empty());
    assert!(observed.subsequent.is_empty());
}
