use std::sync::{Arc, Mutex};

use ironrdp_client::config::{ClipboardType, ConfigBuilder, Destination, RedirectionRoute};
use ironrdp_pdu::rdp::capability_sets::MajorPlatformType;
use ironrdp_pdu::rdp::server_redirection::ServerRedirectionPdu;

fn builder() -> ConfigBuilder {
    ConfigBuilder::new()
        .with_destination(Destination::from_parts("broker.example", 3389))
        .with_username("user")
        .with_password("password")
        .with_client_build(1)
        .with_client_dir("C:\\")
        .with_client_name("client")
        .with_platform(MajorPlatformType::WINDOWS)
        .with_clipboard(ClipboardType::Disable)
}

fn redirect() -> ServerRedirectionPdu {
    ServerRedirectionPdu {
        session_id: 42,
        target_fqdn: Some("target.example".into()),
        target_net_address: Some("192.0.2.1".into()),
        load_balance_info: Some(b"private-routing-token".to_vec()),
        ..ServerRedirectionPdu::default()
    }
}

#[tokio::test]
async fn redirected_relay_requires_a_new_route_and_retains_target_identity() {
    // oracle: approved connection-route contract: target TLS identity differs from network address.
    let observed = Arc::new(Mutex::new(None));
    let captured = observed.clone();
    let config = builder()
        .with_direct_tcp_proxy("127.0.0.1:1234".parse().unwrap(), b"old-token".to_vec())
        .with_redirection_handler(Arc::new(move |target| {
            *captured.lock().unwrap() = Some(target);
            Box::pin(async {
                Ok(RedirectionRoute::Relay {
                    address: "127.0.0.1:5678".parse().unwrap(),
                    authentication: b"new-token".to_vec(),
                })
            })
        }))
        .build()
        .unwrap();
    let (prepared, _) = ironrdp_client::__test_prepare_server_redirection(&config, &redirect(), 1)
        .await
        .unwrap();
    assert_eq!(config.destination().name(), "broker.example");
    assert_eq!(prepared.destination().name(), "target.example");
    let target = observed.lock().unwrap().take().unwrap();
    assert_eq!(target.host, "target.example");
    assert!(target.connect_hosts.iter().any(|host| host == "192.0.2.1"));
    assert_eq!(target.hop, 1);
}

#[tokio::test]
async fn redirected_relay_cannot_fall_back_to_direct_tcp() {
    // oracle: approved connection-route contract prohibits bypassing the original proxy or SSH route.
    let config = builder()
        .with_direct_tcp_proxy("127.0.0.1:1234".parse().unwrap(), Vec::new())
        .with_redirection_handler(Arc::new(|_| Box::pin(async { Ok(RedirectionRoute::Direct) })))
        .build()
        .unwrap();
    let error = ironrdp_client::__test_prepare_server_redirection(&config, &redirect(), 1)
        .await
        .err()
        .unwrap();
    assert!(error.to_string().contains("cannot fall back"));
    assert_eq!(config.destination().name(), "broker.example");
}

#[tokio::test]
async fn relay_without_coordination_keeps_rejecting_redirection() {
    // oracle: existing embedder relay contract binds one remote target.
    let config = builder()
        .with_direct_tcp_proxy("127.0.0.1:1234".parse().unwrap(), Vec::new())
        .build()
        .unwrap();
    assert!(
        ironrdp_client::__test_prepare_server_redirection(&config, &redirect(), 1)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn redirected_relay_must_remain_loopback() {
    // oracle: existing loopback proxy validation also applies to prepared redirect routes.
    let config = builder()
        .with_redirection_handler(Arc::new(|_| {
            Box::pin(async {
                Ok(RedirectionRoute::Relay {
                    address: "192.0.2.1:3389".parse().unwrap(),
                    authentication: Vec::new(),
                })
            })
        }))
        .build()
        .unwrap();
    assert!(
        ironrdp_client::__test_prepare_server_redirection(&config, &redirect(), 1)
            .await
            .is_err()
    );
}

#[test]
fn server_redirection_debug_redacts_routing_token_and_credentials() {
    // oracle: credentials and opaque routing tokens are secret-bearing protocol fields.
    let pdu = ServerRedirectionPdu {
        username: Some("private-user".into()),
        domain: Some("private-domain".into()),
        ..redirect()
    };
    let debug = format!("{pdu:?}");
    for secret in ["private-user", "private-domain", "private-routing-token"] {
        assert!(!debug.contains(secret));
    }
}

#[tokio::test]
async fn prepared_route_connects_new_relay_and_sends_its_token() {
    // oracle: target-specific relay contract: the broker route must not be reused.
    use tokio::io::AsyncReadExt as _;
    let old = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let new = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let new_address = new.local_addr().unwrap();
    let config = builder()
        .with_direct_tcp_proxy(old.local_addr().unwrap(), b"old-token".to_vec())
        .with_redirection_handler(Arc::new(move |_| {
            Box::pin(async move {
                Ok(RedirectionRoute::Relay {
                    address: new_address,
                    authentication: b"new-token".to_vec(),
                })
            })
        }))
        .build()
        .unwrap();
    let (prepared, _) = ironrdp_client::__test_prepare_server_redirection(&config, &redirect(), 1)
        .await
        .unwrap();
    let _stream = ironrdp_client::rdp::__test_tcp_connect_destination(&prepared)
        .await
        .unwrap();
    let (mut accepted, _) = new.accept().await.unwrap();
    let mut token = [0; 9];
    accepted.read_exact(&mut token).await.unwrap();
    assert_eq!(&token, b"new-token");
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(25), old.accept())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn close_cancels_pending_redirect_preparation() {
    // oracle: closing a client cancels target preparation before opening any connection.
    let started = Arc::new(tokio::sync::Notify::new());
    let entered = started.clone();
    let config = builder()
        .with_redirection_handler(Arc::new(move |_| {
            let entered = entered.clone();
            Box::pin(async move {
                entered.notify_one();
                std::future::pending().await
            })
        }))
        .build()
        .unwrap();
    let (output, _events) = ironrdp_client::output_channel::output_channel(4);
    let mut client = ironrdp_client::rdp::RdpClient::new(config, output);
    let input = client.input_sender();
    let worker = tokio::spawn(async move { client.__test_follow_server_redirection(&redirect()).await });
    started.notified().await;
    input.request_close();
    assert!(
        !tokio::time::timeout(std::time::Duration::from_secs(1), worker)
            .await
            .unwrap()
            .unwrap()
            .unwrap()
    );
}

#[tokio::test]
async fn rejected_preparation_preserves_original_config() {
    // oracle: failure cannot publish an unprepared target or fall back to another route.
    let config = builder()
        .with_redirection_handler(Arc::new(|_| {
            Box::pin(async { Err(ironrdp_connector::reason_err!("Redirect", "route unavailable")) })
        }))
        .build()
        .unwrap();
    let error = ironrdp_client::__test_prepare_server_redirection(&config, &redirect(), 1)
        .await
        .err()
        .unwrap();
    assert!(error.to_string().contains("route unavailable"));
    assert_eq!(config.destination().name(), "broker.example");
}

fn encrypted_redirect() -> ServerRedirectionPdu {
    use ironrdp_pdu::rdp::server_redirection::{ServerRedirectionFlags, TargetCertificateContainer};
    ServerRedirectionPdu {
        flags: ServerRedirectionFlags::PASSWORD_IS_PK_ENCRYPTED,
        username: Some("redirected-user".into()),
        domain: Some(String::new()),
        password: Some(vec![0xde, 0xad, 0xbe, 0xef]),
        redirection_guid: Some(vec![0x51, 0, 0, 0]),
        target_certificate: Some(TargetCertificateContainer::from_certificate_der(vec![1, 2, 3])),
        ..redirect()
    }
}

#[test]
fn gnome_encrypted_redirection_is_prepared_for_rdstls() {
    // oracle: spec MS-RDPBCGR 2.2.13.1 and 5.4.5.3.1 require forwarding the opaque blob via RDSTLS.
    let mut config = builder().build().unwrap();
    ironrdp_client::__test_apply_server_redirection(&mut config, &encrypted_redirect()).unwrap();
    assert_eq!(config.destination().name(), "target.example");
}

#[test]
fn rdstls_hop_preserves_original_nla_policy_for_later_redirections() {
    // oracle: RDSTLS is required for this hop's encrypted password, not a persistent NLA downgrade.
    let mut config = builder().with_tls(false).with_credssp(true).build().unwrap();
    ironrdp_client::__test_apply_server_redirection(&mut config, &encrypted_redirect()).unwrap();
    ironrdp_client::__test_apply_server_redirection(&mut config, &redirect()).unwrap();
    assert!(config.connector().enable_credssp);
    assert!(!config.connector().enable_tls);
}

#[test]
fn incomplete_encrypted_redirection_is_rejected_before_mutating_destination() {
    // oracle: spec MS-RDPBCGR 5.4.5.3.1 requires certificate, GUID, identity and encrypted credentials.
    let mut no_cert = encrypted_redirect();
    no_cert.target_certificate = None;
    let mut no_guid = encrypted_redirect();
    no_guid.redirection_guid = None;
    let mut no_user = encrypted_redirect();
    no_user.username = None;
    let mut no_password = encrypted_redirect();
    no_password.password = None;
    for pdu in [no_cert, no_guid, no_user, no_password] {
        let mut config = builder().build().unwrap();
        assert!(ironrdp_client::__test_apply_server_redirection(&mut config, &pdu).is_err());
        assert_eq!(config.destination().name(), "broker.example");
    }
}
