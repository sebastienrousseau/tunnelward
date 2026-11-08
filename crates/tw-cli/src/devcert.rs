// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Throwaway self-signed certificates for `tunnelward dev`.
//!
//! Each run makes a fresh ECDSA P-256 key and an X.509 v3 certificate
//! for one DNS name, valid for a day, signed by its own key. The peer
//! trusts that exact certificate as its root, so nothing else is
//! accepted. The key never leaves the process. For local development
//! only: production certificates come from the operator's PKI.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
use tunnelward_crypto::Identity;
use tunnelward_crypto::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

/// How long a development certificate is valid.
const LIFETIME: Duration = Duration::from_secs(24 * 3600);
/// How far back its validity starts, to absorb clock differences.
const BACKDATE: Duration = Duration::from_secs(3600);

// Object identifiers, DER-encoded without tag and length.
const ECDSA_WITH_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
const EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const PRIME256V1: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];
const SUBJECT_ALT_NAME: &[u8] = &[0x55, 0x1d, 0x11];
const EXT_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x25];
const SERVER_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
const CLIENT_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02];

/// Why a certificate could not be made.
#[derive(Debug)]
pub(crate) struct DevCertError(&'static str);

impl std::fmt::Display for DevCertError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "cannot make a development certificate: {}", self.0)
    }
}

impl std::error::Error for DevCertError {}

/// One DER element: `tag`, its length, then `content`.
fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let len = content.len();
    let mut out = vec![tag];
    if len < 0x80 {
        out.push(u8::try_from(len).unwrap_or(0));
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|b| **b == 0).count();
        out.push(0x80 | u8::try_from(bytes.len() - skip).unwrap_or(0));
        out.extend_from_slice(&bytes[skip..]);
    }
    out.extend_from_slice(content);
    out
}

fn seq(parts: &[&[u8]]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

fn oid(id: &[u8]) -> Vec<u8> {
    tlv(0x06, id)
}

/// A BIT STRING with no unused bits.
fn bits(content: &[u8]) -> Vec<u8> {
    tlv(0x03, &[&[0][..], content].concat())
}

/// `CN=<name>` as an X.501 Name.
fn name(cn: &str) -> Vec<u8> {
    let attribute = seq(&[&oid(COMMON_NAME), &tlv(0x0c, cn.as_bytes())]);
    seq(&[&tlv(0x31, &attribute)])
}

/// Days since 1970-01-01 to (year, month, day), proleptic Gregorian
/// (Howard Hinnant's `civil_from_days`).
pub(crate) fn civil(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    (year, month, day)
}

/// `at` as an X.509 `UTCTime`, `YYMMDDHHMMSSZ` (years 1950 to 2049).
fn utc_time(at: SystemTime) -> Result<Vec<u8>, DevCertError> {
    let secs = at
        .duration_since(UNIX_EPOCH)
        .map_err(|_| DevCertError("the clock is before 1970"))?
        .as_secs();
    let (year, month, day) = civil(secs / 86_400);
    if !(1950..2050).contains(&year) {
        return Err(DevCertError("the clock is outside 1950 to 2049"));
    }
    let rest = secs % 86_400;
    let (h, m, s) = (rest / 3600, rest / 60 % 60, rest % 60);
    let text = format!("{:02}{month:02}{day:02}{h:02}{m:02}{s:02}Z", year % 100);
    Ok(tlv(0x17, text.as_bytes()))
}

/// The extensions: the DNS name, the SPIFFE ID when given (which makes
/// the certificate an X.509-SVID), and both TLS usages.
fn extensions(dns: &str, spiffe_id: Option<&str>) -> Vec<u8> {
    let uri = spiffe_id
        .map(|id| tlv(0x86, id.as_bytes()))
        .unwrap_or_default();
    let san = seq(&[&tlv(0x82, dns.as_bytes()), &uri]);
    let eku = seq(&[&oid(SERVER_AUTH), &oid(CLIENT_AUTH)]);
    let list = seq(&[
        &seq(&[&oid(SUBJECT_ALT_NAME), &tlv(0x04, &san)]),
        &seq(&[&oid(EXT_KEY_USAGE), &tlv(0x04, &eku)]),
    ]);
    tlv(0xa3, &list)
}

/// The to-be-signed part of a certificate for `dns` (and `spiffe_id`)
/// and `public_key`.
fn tbs(
    (dns, spiffe_id): (&str, Option<&str>),
    public_key: &[u8],
    serial: &[u8],
    now: SystemTime,
) -> Result<Vec<u8>, DevCertError> {
    let algorithm = seq(&[&oid(ECDSA_WITH_SHA256)]);
    let validity = seq(&[&utc_time(now - BACKDATE)?, &utc_time(now + LIFETIME)?]);
    let spki = seq(&[
        &seq(&[&oid(EC_PUBLIC_KEY), &oid(PRIME256V1)]),
        &bits(public_key),
    ]);
    let subject = name(dns);
    Ok(seq(&[
        &tlv(0xa0, &tlv(0x02, &[2])),
        &tlv(0x02, serial),
        &algorithm,
        &subject,
        &validity,
        &subject,
        &spki,
        &extensions(dns, spiffe_id),
    ]))
}

/// A fresh key and a self-signed certificate for `dns`, as a rustls
/// [`Identity`], with the certificate alone for the peer to trust. With
/// `spiffe_id` the certificate is also an X.509-SVID for it.
pub(crate) fn self_signed(
    dns: &str,
    spiffe_id: Option<&str>,
) -> Result<(Identity, CertificateDer<'static>), DevCertError> {
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
        .map_err(|_| DevCertError("key generation failed"))?;
    let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref())
        .map_err(|_| DevCertError("the new key does not load"))?;
    let mut serial = [0_u8; 16];
    rng.fill(&mut serial)
        .map_err(|_| DevCertError("no randomness for the serial"))?;
    serial[0] = (serial[0] & 0x7f) | 0x40; // positive, and no leading zero byte
    let tbs = tbs(
        (dns, spiffe_id),
        key.public_key().as_ref(),
        &serial,
        SystemTime::now(),
    )?;
    let signature = key
        .sign(&rng, &tbs)
        .map_err(|_| DevCertError("signing failed"))?;
    let algorithm = seq(&[&oid(ECDSA_WITH_SHA256)]);
    let cert = CertificateDer::from(seq(&[&tbs, &algorithm, &bits(signature.as_ref())]));
    let identity = Identity {
        chain: vec![cert.clone()],
        key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8.as_ref().to_vec())),
    };
    Ok((identity, cert))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lengths_use_the_short_and_long_forms() {
        assert_eq!(tlv(0x04, &[1, 2]), vec![0x04, 2, 1, 2]);
        let long = tlv(0x04, &[0; 200]);
        assert_eq!(&long[..3], &[0x04, 0x81, 200]);
        let longer = tlv(0x04, &[0; 300]);
        assert_eq!(&longer[..4], &[0x04, 0x82, 0x01, 0x2c]);
    }

    #[test]
    fn civil_dates_match_known_days() {
        assert_eq!(civil(0), (1970, 1, 1));
        assert_eq!(civil(11_016), (2000, 2, 29));
        assert_eq!(civil(20_765), (2026, 11, 8));
    }

    type Conns = (
        tunnelward_crypto::rustls::ClientConnection,
        tunnelward_crypto::rustls::ServerConnection,
    );

    /// One round trip of handshake bytes, client first.
    fn exchange((c, s): &mut Conns) -> Result<(), Box<dyn std::error::Error>> {
        let mut buf = Vec::new();
        c.write_tls(&mut buf)?;
        s.read_tls(&mut buf.as_slice())?;
        s.process_new_packets()?;
        let mut back = Vec::new();
        s.write_tls(&mut back)?;
        c.read_tls(&mut back.as_slice())?;
        c.process_new_packets()?;
        Ok(())
    }

    /// Runs a handshake between `client` and `server` in memory.
    fn handshake(
        client: tunnelward_crypto::rustls::ClientConfig,
        server: tunnelward_crypto::rustls::ServerConfig,
        name: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        use tunnelward_crypto::rustls::pki_types::ServerName;
        use tunnelward_crypto::rustls::{ClientConnection, ServerConnection};
        let name = ServerName::try_from(name.to_owned())?;
        let mut conns = (
            ClientConnection::new(std::sync::Arc::new(client), name)?,
            ServerConnection::new(std::sync::Arc::new(server))?,
        );
        for _ in 0..10 {
            exchange(&mut conns)?;
            if !conns.0.is_handshaking() && !conns.1.is_handshaking() {
                return Ok(());
            }
        }
        Err("the handshake did not finish".into())
    }

    fn roots(
        cert: CertificateDer<'static>,
    ) -> Result<std::sync::Arc<tunnelward_crypto::rustls::RootCertStore>, Box<dyn std::error::Error>>
    {
        let mut roots = tunnelward_crypto::rustls::RootCertStore::empty();
        roots.add(cert)?;
        Ok(std::sync::Arc::new(roots))
    }

    fn configs(
        server: (Identity, CertificateDer<'static>),
        client: (Identity, CertificateDer<'static>),
        client_trusts: CertificateDer<'static>,
    ) -> Result<
        (
            tunnelward_crypto::rustls::ClientConfig,
            tunnelward_crypto::rustls::ServerConfig,
        ),
        Box<dyn std::error::Error>,
    > {
        use tunnelward_crypto::{ClientAuth, KeyExchange, client_config, server_config};
        let alpn: [&[u8]; 1] = [b"tw/1"];
        let server_tls = server_config(
            server.0,
            ClientAuth::Required(roots(client.1)?),
            KeyExchange::default(),
            &alpn,
        )?;
        let client_tls = client_config(
            roots(client_trusts)?,
            Some(client.0),
            KeyExchange::default(),
            &alpn,
        )?;
        Ok((client_tls, server_tls))
    }

    #[test]
    fn two_self_signed_certificates_complete_mutual_tls() -> Result<(), Box<dyn std::error::Error>>
    {
        let server = self_signed("gateway.dev.tunnelward.invalid", None)?;
        let server_cert = server.1.clone();
        let (client_tls, server_tls) = configs(
            server,
            self_signed("connector.dev.tunnelward.invalid", None)?,
            server_cert,
        )?;
        handshake(client_tls, server_tls, "gateway.dev.tunnelward.invalid")
    }

    #[test]
    fn another_certificate_is_not_trusted() -> Result<(), Box<dyn std::error::Error>> {
        let server = self_signed("gateway.dev.tunnelward.invalid", None)?;
        let (stranger, _) = self_signed("gateway.dev.tunnelward.invalid", None)?;
        let (_, other_cert) = self_signed("gateway.dev.tunnelward.invalid", None)?;
        drop(stranger);
        let (client_tls, server_tls) = configs(
            server,
            self_signed("connector.dev.tunnelward.invalid", None)?,
            other_cert,
        )?;
        assert!(handshake(client_tls, server_tls, "gateway.dev.tunnelward.invalid").is_err());
        Ok(())
    }

    #[test]
    fn the_wrong_name_is_not_accepted() -> Result<(), Box<dyn std::error::Error>> {
        let server = self_signed("gateway.dev.tunnelward.invalid", None)?;
        let server_cert = server.1.clone();
        let (client_tls, server_tls) = configs(
            server,
            self_signed("connector.dev.tunnelward.invalid", None)?,
            server_cert,
        )?;
        assert!(handshake(client_tls, server_tls, "elsewhere.invalid").is_err());
        Ok(())
    }

    #[test]
    fn a_spiffe_id_makes_it_an_svid() -> Result<(), Box<dyn std::error::Error>> {
        let id = "spiffe://dev.tunnelward.invalid/connector";
        let (_, svid) = self_signed("connector.dev.tunnelward.invalid", Some(id))?;
        assert_eq!(tunnelward_identity::spiffe_id(svid.as_ref())?, id);
        let (_, plain) = self_signed("gateway.dev.tunnelward.invalid", None)?;
        assert_eq!(
            tunnelward_identity::spiffe_id(plain.as_ref()),
            Err(tunnelward_identity::SvidError::NoSpiffeId)
        );
        Ok(())
    }

    #[test]
    fn utc_time_is_two_digit_years() -> Result<(), DevCertError> {
        let at = UNIX_EPOCH + Duration::from_secs(20_765 * 86_400 + 3_723);
        assert_eq!(utc_time(at)?, tlv(0x17, b"261108010203Z"));
        Ok(())
    }
}
