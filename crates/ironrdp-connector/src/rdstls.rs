//! RDSTLS password authentication inside an authenticated TLS connection.
//!
//! See [MS-RDPBCGR] 2.2.17, "RDSTLS PDUs", and 5.4.5.3.1, "RDSTLS Connection Sequence".
//! The caller must match the peer certificate against the redirection target certificate before advancing TLS.
//!
//! [MS-RDPBCGR]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/

use core::fmt;

use ironrdp_core::{DecodeResult, WriteBuf};
use ironrdp_pdu::PduHint;
use zeroize::Zeroizing;

use crate::{ConnectorResult, Written, reason_err};

/// Validated credentials received from a Server Redirection Packet.
///
/// INVARIANT: the encrypted password remains opaque, and Debug never reveals credential bytes.
#[derive(Clone)]
pub struct RdstlsCredentials {
    request: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for RdstlsCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RdstlsCredentials { [REDACTED] }")
    }
}

impl RdstlsCredentials {
    /// Validates the length-prefixed fields of [MS-RDPBCGR] 2.2.17.2, "RDSTLS Authentication Request PDU with Password Credentials".
    ///
    /// The GUID and encrypted password are forwarded verbatim; user and domain are encoded as terminated UTF-16LE.
    ///
    /// [MS-RDPBCGR]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/
    pub fn new(guid: &[u8], username: &str, domain: &str, encrypted_password: &[u8]) -> ConnectorResult<Self> {
        if guid.is_empty() || !guid.len().is_multiple_of(2) || username.is_empty() || encrypted_password.is_empty() {
            return Err(reason_err!("RDSTLS", "missing or invalid redirected credentials"));
        }
        if username.contains('\0') || domain.contains('\0') {
            return Err(reason_err!("RDSTLS", "embedded NUL in redirected identity"));
        }
        let username_len = username
            .encode_utf16()
            .count()
            .checked_add(1)
            .and_then(|n| n.checked_mul(2));
        let domain_len = domain
            .encode_utf16()
            .count()
            .checked_add(1)
            .and_then(|n| n.checked_mul(2));
        let lengths = [
            Some(guid.len()),
            username_len,
            domain_len,
            Some(encrypted_password.len()),
        ];
        let mut encoded_lengths = [0u16; 4];
        for (length, encoded) in lengths.into_iter().zip(&mut encoded_lengths) {
            *encoded = length
                .and_then(|n| u16::try_from(n).ok())
                .ok_or_else(|| reason_err!("RDSTLS", "credential field exceeds the 16-bit wire length"))?;
        }
        let mut request = Zeroizing::new(Vec::new());
        request.extend_from_slice(&[1, 0, 2, 0, 1, 0]);
        request.extend_from_slice(&encoded_lengths[0].to_le_bytes());
        request.extend_from_slice(guid);
        for (value, length) in [(username, encoded_lengths[1]), (domain, encoded_lengths[2])] {
            request.extend_from_slice(&length.to_le_bytes());
            for unit in value.encode_utf16().chain(core::iter::once(0)) {
                request.extend_from_slice(&unit.to_le_bytes());
            }
        }
        request.extend_from_slice(&encoded_lengths[3].to_le_bytes());
        request.extend_from_slice(encrypted_password);
        Ok(Self { request })
    }

    pub(crate) fn write_request(&self, output: &mut WriteBuf) -> ConnectorResult<Written> {
        output.write_slice(&self.request);
        Written::from_size(self.request.len())
    }
}

/// RDSTLS server messages have fixed sizes, without TPKT or X.224 headers.
#[derive(Debug)]
pub(crate) struct RdstlsHint(pub(crate) usize);

impl PduHint for RdstlsHint {
    fn find_size(&self, bytes: &[u8]) -> DecodeResult<Option<(bool, usize)>> {
        Ok((self.0 <= bytes.len()).then_some((true, self.0)))
    }
}

const HEADER_SIZE: usize = 2 /* Version */ + 2 /* PduType */ + 2 /* DataType */;
pub(crate) const CAPABILITIES_HINT: RdstlsHint = RdstlsHint(HEADER_SIZE + 2 /* SupportedVersions */);
pub(crate) const RESULT_HINT: RdstlsHint = RdstlsHint(HEADER_SIZE + 4 /* ResultCode */);

pub(crate) fn validate_capabilities(input: &[u8]) -> ConnectorResult<()> {
    if input != [1, 0, 1, 0, 1, 0, 1, 0] {
        return Err(reason_err!("RDSTLS", "invalid capabilities or unsupported version"));
    }
    Ok(())
}

pub(crate) fn validate_result(input: &[u8]) -> ConnectorResult<()> {
    if input.len() != RESULT_HINT.0 || input[..HEADER_SIZE] != [1, 0, 4, 0, 1, 0] {
        return Err(reason_err!("RDSTLS", "invalid authentication response"));
    }
    let code = u32::from_le_bytes([input[6], input[7], input[8], input[9]]);
    if code != 0 {
        return Err(reason_err!("RDSTLS", "authentication failed with result 0x{code:08x}"));
    }
    Ok(())
}
