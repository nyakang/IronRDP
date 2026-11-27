use ironrdp_connector::rdstls::RdstlsCredentials;
use ironrdp_connector::{ClientConnector, ClientConnectorState, Sequence as _};
use ironrdp_core::{WriteBuf, decode, encode_vec};
use ironrdp_pdu::nego::{ConnectionConfirm, ConnectionRequest, ResponseFlags, SecurityProtocol};
use ironrdp_pdu::x224::X224;

// oracle: spec MS-RDPBCGR 2.2.17.1 and 2.2.17.4, derived independently of the implementation.
const CAPS: &[u8] = &[1, 0, 1, 0, 1, 0, 1, 0];
const SUCCESS: &[u8] = &[1, 0, 4, 0, 1, 0, 0, 0, 0, 0];

fn connector() -> ClientConnector {
    // Synthetic GUID bytes exercise opaque forwarding, not Base64 GUID interpretation.
    let credentials = RdstlsCredentials::new(&[0x51, 0, 0, 0], "u", "", &[0xde, 0xad, 0xbe, 0xef]).unwrap();
    ClientConnector::new(super::test_config(), "127.0.0.1:3389".parse().unwrap()).with_rdstls(credentials)
}

fn confirm(protocol: SecurityProtocol) -> Vec<u8> {
    encode_vec(&X224(ConnectionConfirm::Response {
        flags: ResponseFlags::empty(),
        protocol,
    }))
    .unwrap()
}

fn after_tls() -> ClientConnector {
    let mut connector = connector();
    let mut output = WriteBuf::new();
    connector.step_no_input(&mut output).unwrap();
    connector
        .step(&confirm(SecurityProtocol::RDSTLS), None, &mut output)
        .unwrap();
    assert!(connector.should_perform_security_upgrade());
    connector.mark_security_upgrade_as_done();
    assert!(!connector.should_perform_credssp());
    connector
}

#[test]
fn encrypted_credentials_require_rdstls_without_downgrade() {
    // oracle: spec MS-RDPBCGR 2.2.13.1 mandates RDSTLS for LB_PASSWORD_IS_PK_ENCRYPTED.
    let mut connector = connector();
    let mut output = WriteBuf::new();
    assert!(
        connector
            .initiate_with_security_protocol(SecurityProtocol::empty(), &mut output)
            .is_err()
    );
    connector.step_no_input(&mut output).unwrap();
    let request = decode::<X224<ConnectionRequest>>(output.filled()).unwrap().0;
    assert_eq!(request.protocol, SecurityProtocol::RDSTLS);
    for protocol in [
        SecurityProtocol::empty(),
        SecurityProtocol::SSL,
        SecurityProtocol::HYBRID,
        SecurityProtocol::RDSTLS | SecurityProtocol::SSL,
    ] {
        let mut connector = self::connector();
        connector.step_no_input(&mut WriteBuf::new()).unwrap();
        let mut output = WriteBuf::new();
        assert!(connector.step(&confirm(protocol), None, &mut output).is_err());
        assert_eq!(output.filled_len(), 0);
    }
}

#[test]
fn rdstls_authenticates_before_basic_settings_and_preserves_encrypted_bytes() {
    // oracle: independently derived MS-RDPBCGR 2.2.17.2 vector, synthetic GUID pass-through fixture.
    let expected = [
        1, 0, 2, 0, 1, 0, 4, 0, 0x51, 0, 0, 0, 4, 0, 0x75, 0, 0, 0, 2, 0, 0, 0, 4, 0, 0xde, 0xad, 0xbe, 0xef,
    ];
    let mut connector = after_tls();
    let mut output = WriteBuf::new();
    connector.step(CAPS, None, &mut output).unwrap();
    assert_eq!(output.filled(), expected);
    output.clear();
    connector.step(SUCCESS, None, &mut output).unwrap();
    assert_eq!(output.filled_len(), 0);
    assert!(matches!(
        connector.state,
        ClientConnectorState::BasicSettingsExchangeSendInitial {
            selected_protocol: SecurityProtocol::RDSTLS
        }
    ));
    connector.step_no_input(&mut output).unwrap();
    assert!(!output.filled().is_empty());
}

#[test]
fn rdstls_accepts_freerdp_v1_and_v2_advertisement_using_v1() {
    // oracle: reference FreeRDP/FreeRDP@bf217a504e54cc719880c228e82353382cd7d4fa:libfreerdp/core/rdstls.c advertises VERSION_1 | VERSION_2 (0x0003).
    // Its password authentication accepts a version 1 request when that bit is advertised.
    let mut connector = after_tls();
    let mut output = WriteBuf::new();
    connector.step(&[1, 0, 1, 0, 1, 0, 3, 0], None, &mut output).unwrap();
    assert_eq!(&output.filled()[..6], &[1, 0, 2, 0, 1, 0]);
    output.clear();
    connector.step(SUCCESS, None, &mut output).unwrap();
    assert!(matches!(
        connector.state,
        ClientConnectorState::BasicSettingsExchangeSendInitial {
            selected_protocol: SecurityProtocol::RDSTLS
        }
    ));
}

#[test]
fn rdstls_frames_fragments_and_preserves_coalesced_following_data() {
    // oracle: spec MS-RDPBCGR 2.2.17 fixed-size messages are carried directly inside TLS.
    let mut connector = after_tls();
    let hint = connector.next_pdu_hint().unwrap();
    for end in 0..CAPS.len() {
        assert_eq!(hint.find_size(&CAPS[..end]).unwrap(), None);
    }
    assert_eq!(hint.find_size(&[CAPS, SUCCESS].concat()).unwrap(), Some((true, 8)));
    connector.step(CAPS, None, &mut WriteBuf::new()).unwrap();
    let hint = connector.next_pdu_hint().unwrap();
    for end in 0..SUCCESS.len() {
        assert_eq!(hint.find_size(&SUCCESS[..end]).unwrap(), None);
    }
    assert_eq!(
        hint.find_size(&[SUCCESS, &[3, 0, 0, 4]].concat()).unwrap(),
        Some((true, 10))
    );
}

#[test]
fn malformed_capabilities_never_emit_credentials() {
    // oracle: spec MS-RDPBCGR 2.2.17.1 requires the version 1 header and version 1 support.
    let mut invalid: Vec<Vec<u8>> = (0..CAPS.len()).map(|n| CAPS[..n].to_vec()).collect();
    for index in [0, 2, 4, 6] {
        let mut bytes = CAPS.to_vec();
        bytes[index] = 2;
        invalid.push(bytes);
    }
    for unsupported in [0u16, 4, 0x8000, 0xfffe] {
        let mut bytes = CAPS.to_vec();
        bytes[6..].copy_from_slice(&unsupported.to_le_bytes());
        invalid.push(bytes);
    }
    invalid.push([CAPS, &[0]].concat());
    for bytes in invalid {
        let mut connector = after_tls();
        let mut output = WriteBuf::new();
        assert!(connector.step(&bytes, None, &mut output).is_err());
        assert_eq!(output.filled_len(), 0);
    }
}

#[test]
fn rdstls_ignores_unknown_version_bits_when_v1_is_supported() {
    // oracle: reference FreeRDP/FreeRDP@bf217a504e54cc719880c228e82353382cd7d4fa:libfreerdp/core/rdstls.c intersects the advertised version mask.
    let mut connector = after_tls();
    let mut output = WriteBuf::new();
    connector.step(&[1, 0, 1, 0, 1, 0, 1, 0x80], None, &mut output).unwrap();
    assert_eq!(&output.filled()[..6], &[1, 0, 2, 0, 1, 0]);
}

#[test]
fn failed_or_malformed_authentication_never_enters_basic_settings() {
    // oracle: spec MS-RDPBCGR 2.2.17.4 and 5.4.5.3.1 permit continuation only on zero result.
    let mut invalid: Vec<Vec<u8>> = (0..SUCCESS.len()).map(|n| SUCCESS[..n].to_vec()).collect();
    for index in [0, 2, 4] {
        let mut bytes = SUCCESS.to_vec();
        bytes[index] = 2;
        invalid.push(bytes);
    }
    for code in [5u32, 0x52e, 0x530, 0x532, 0x533, 0x773, 0x775, u32::MAX] {
        let mut bytes = SUCCESS.to_vec();
        bytes[6..].copy_from_slice(&code.to_le_bytes());
        invalid.push(bytes);
    }
    for bytes in invalid {
        let mut connector = after_tls();
        connector.step(CAPS, None, &mut WriteBuf::new()).unwrap();
        let mut output = WriteBuf::new();
        assert!(connector.step(&bytes, None, &mut output).is_err());
        assert!(matches!(connector.state, ClientConnectorState::Consumed));
        assert_eq!(output.filled_len(), 0);
    }
}

#[test]
fn credential_lengths_cannot_wrap_and_debug_is_redacted() {
    // oracle: spec MS-RDPBCGR 2.2.17.2 uses byte lengths in u16 fields; NyaTerm forbids credential logs.
    let guid = [0x51, 0, 0, 0];
    assert!(RdstlsCredentials::new(&guid, "u", "", &vec![1; 65536]).is_err());
    assert!(RdstlsCredentials::new(&vec![0; 65536], "u", "", &[1]).is_err());
    assert!(RdstlsCredentials::new(&guid, &"x".repeat(32767), "", &[1]).is_err());
    assert!(RdstlsCredentials::new(&guid, "u", &"x".repeat(32767), &[1]).is_err());
    let credentials = RdstlsCredentials::new(&guid, "secret-user", "secret-domain", b"secret-password").unwrap();
    let debug = format!("{credentials:?}");
    for secret in ["secret-user", "secret-domain", "secret-password"] {
        assert!(!debug.contains(secret));
        let utf16: Vec<u8> = secret.encode_utf16().flat_map(u16::to_le_bytes).collect();
        for bytes in [secret.as_bytes(), utf16.as_slice()] {
            let decimal = bytes.iter().map(u8::to_string).collect::<Vec<_>>().join(", ");
            let hex = bytes
                .iter()
                .map(|byte| format!("{byte:x}"))
                .collect::<Vec<_>>()
                .join(", ");
            assert!(!debug.contains(&decimal));
            assert!(!debug.contains(&hex));
        }
    }
    assert!(!debug.contains("81, 0, 0, 0"));
}

#[test]
fn rdstls_does_not_send_password_or_encrypted_cookie_in_client_info() {
    // oracle: spec MS-RDPBCGR 2.2.13.1 sends the opaque blob using RDSTLS, not Client Info.
    use ironrdp_pdu::mcs::SendDataRequest;
    use ironrdp_pdu::rdp::ClientInfoPdu;
    let mut connector = after_tls().with_redirection_password_cookie(b"must-not-be-sent".to_vec());
    connector.step(CAPS, None, &mut WriteBuf::new()).unwrap();
    connector.step(SUCCESS, None, &mut WriteBuf::new()).unwrap();
    connector.state = ClientConnectorState::SecureSettingsExchange {
        io_channel_id: 1003,
        user_channel_id: 1004,
    };
    let mut output = WriteBuf::new();
    connector.step_no_input(&mut output).unwrap();
    let request = decode::<X224<SendDataRequest<'_>>>(output.filled()).unwrap().0;
    let info = decode::<ClientInfoPdu>(&request.user_data).unwrap();
    assert!(info.client_info.credentials.password.is_empty());
    assert!(info.client_info.password_cookie.is_none());
}

proptest::proptest! {
    // oracle: spec MS-RDPBCGR 2.2.17 has fixed sizes; arbitrary network data must never panic or allocate by wire length.
    // The connector is not part of ironrdp-fuzzing; this exercises both inbound states with malformed bytes.
    #[test]
    fn rdstls_server_messages_are_bounded_for_arbitrary_bytes(input in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..256)) {
        let mut connector = after_tls();
        let _ = connector.next_pdu_hint().unwrap().find_size(&input);
        let _ = connector.step(&input, None, &mut WriteBuf::new());
        let mut connector = after_tls();
        connector.step(CAPS, None, &mut WriteBuf::new()).unwrap();
        let _ = connector.next_pdu_hint().unwrap().find_size(&input);
        let _ = connector.step(&input, None, &mut WriteBuf::new());
    }
}
