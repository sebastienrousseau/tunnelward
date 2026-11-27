// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Audit events as RFC 5424 syslog messages over TCP, framed by octet
//! counting (RFC 6587): over TLS (RFC 5425), or plain to a loopback
//! relay only. The message is the OCSF event as JSON.

use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use http::uri::Authority;
use serde_json::Value;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tunnelward_crypto::rustls::ClientConfig;
use tunnelward_crypto::rustls::pki_types::ServerName;

/// Where and how syslog messages go.
#[derive(Clone)]
#[non_exhaustive]
pub struct SyslogSettings {
    /// The receiver, `host:port`.
    pub address: String,
    /// TLS to the receiver; `None` sends plain TCP, which only a
    /// loopback address may take.
    pub tls: Option<Arc<ClientConfig>>,
    /// The APP-NAME field: printable ASCII, at most 48 characters.
    pub app_name: String,
    /// The HOSTNAME field; `None` writes the nil value `-`.
    pub hostname: Option<String>,
    /// The facility, 0 to 23; 13 (log audit) by default.
    pub facility: u8,
    /// Longest a connection or a send may take.
    pub timeout: Duration,
}

impl fmt::Debug for SyslogSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SyslogSettings")
            .field("address", &self.address)
            .field("tls", &self.tls.is_some())
            .field("app_name", &self.app_name)
            .field("hostname", &self.hostname)
            .field("facility", &self.facility)
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl SyslogSettings {
    /// Messages to `address` over `tls` as `tunnelward`, facility 13,
    /// with a 10 s timeout.
    #[must_use]
    pub fn new(address: impl Into<String>, tls: Option<Arc<ClientConfig>>) -> Self {
        Self {
            address: address.into(),
            tls,
            app_name: "tunnelward".into(),
            hostname: None,
            facility: 13,
            timeout: Duration::from_secs(10),
        }
    }

    /// Whether messages may go as these settings say.
    ///
    /// # Errors
    ///
    /// A sentence saying what is wrong.
    pub fn check(&self) -> Result<(), String> {
        self.reachable()?;
        let hostname = self.hostname.as_deref().is_none_or(|h| printable(h, 255));
        if !printable(&self.app_name, 48) || !hostname {
            return Err("syslog: app_name (48) and hostname (255) are printable ASCII".into());
        }
        if self.facility > 23 || self.timeout.is_zero() {
            return Err("syslog: facility is 0 to 23, timeout_ms at least 1".into());
        }
        Ok(())
    }
}

impl SyslogSettings {
    /// Whether `address` is `host:port`, and loopback if plain.
    fn reachable(&self) -> Result<(), String> {
        let host = host(&self.address)?;
        let loopback = host == "localhost" || host.parse::<IpAddr>().is_ok_and(|i| i.is_loopback());
        if self.tls.is_none() && !loopback {
            return Err(format!(
                "syslog {:?}: plain TCP only to a loopback address; give a ca for TLS",
                self.address
            ));
        }
        Ok(())
    }
}

/// Whether `field` is 1 to `max` printable ASCII characters (RFC 5424
/// PRINTUSASCII).
fn printable(field: &str, max: usize) -> bool {
    !field.is_empty() && field.len() <= max && field.bytes().all(|b| (33..=126).contains(&b))
}

/// The host part of `address`, which must be `host:port`.
fn host(address: &str) -> Result<String, String> {
    let authority: Authority = address
        .parse()
        .map_err(|_| format!("syslog {address:?}: give host:port"))?;
    authority
        .port_u16()
        .ok_or_else(|| format!("syslog {address:?}: give host:port"))?;
    Ok(authority.host().trim_matches(['[', ']']).to_owned())
}

trait Stream: AsyncWrite + Unpin + Send + Sync {}
impl<T: AsyncWrite + Unpin + Send + Sync> Stream for T {}

/// One connection to the receiver, opened when needed.
pub(super) struct Client {
    settings: SyslogSettings,
    stream: Option<Box<dyn Stream>>,
}

impl Client {
    pub(super) fn new(settings: SyslogSettings) -> Self {
        Self {
            settings,
            stream: None,
        }
    }

    /// Sends `events`, on the open connection or, if that fails, on a
    /// new one. A message the old connection half wrote may arrive
    /// twice: delivery is at least once.
    pub(super) async fn send(&mut self, events: &[Value]) -> Result<(), String> {
        let bytes: Vec<u8> = events
            .iter()
            .flat_map(|e| frame(&self.settings, e, std::process::id()))
            .collect();
        for _ in 0..2 {
            if self.stream.is_none() {
                self.stream = Some(self.connect().await?);
            }
            if let Some(stream) = &mut self.stream {
                let sent = async {
                    stream.write_all(&bytes).await?;
                    stream.flush().await
                };
                if let Ok(Ok(())) = tokio::time::timeout(self.settings.timeout, sent).await {
                    return Ok(());
                }
            }
            self.stream = None;
        }
        Err(format!("syslog {}: send failed", self.settings.address))
    }

    async fn connect(&self) -> Result<Box<dyn Stream>, String> {
        let address = &self.settings.address;
        let connecting = async {
            let tcp = TcpStream::connect(address.as_str())
                .await
                .map_err(|e| format!("syslog {address}: {e}"))?;
            let Some(tls) = &self.settings.tls else {
                return Ok(Box::new(tcp) as Box<dyn Stream>);
            };
            let name = ServerName::try_from(host(address)?)
                .map_err(|e| format!("syslog {address}: {e}"))?;
            let stream = tokio_rustls::TlsConnector::from(tls.clone())
                .connect(name, tcp)
                .await
                .map_err(|e| format!("syslog {address}: TLS: {e}"))?;
            Ok(Box::new(stream) as Box<dyn Stream>)
        };
        tokio::time::timeout(self.settings.timeout, connecting)
            .await
            .map_err(|_| format!("syslog {address}: connect timed out"))?
    }
}

/// `event` as one octet-counted RFC 5424 message from process `pid`.
fn frame(settings: &SyslogSettings, event: &Value, pid: u32) -> Vec<u8> {
    let severity = if super::is_failure(event) { 4 } else { 6 };
    let pri = u16::from(settings.facility) * 8 + severity;
    let time = event.get("time").and_then(Value::as_u64).unwrap_or(0);
    let class = event.get("class_uid").and_then(Value::as_u64).unwrap_or(0);
    let message = format!(
        "<{pri}>1 {} {} {} {pid} ocsf-{class} - {event}",
        rfc3339(time),
        settings.hostname.as_deref().unwrap_or("-"),
        settings.app_name,
    );
    format!("{} {message}", message.len()).into_bytes()
}

/// Milliseconds since 1970 as an RFC 3339 UTC time, to the millisecond.
fn rfc3339(ms: u64) -> String {
    let (secs, ms) = (ms / 1000, ms % 1000);
    let (days, secs) = (secs / 86_400, secs % 86_400);
    let (year, month, day) = civil(days);
    let (hour, minute, second) = (secs / 3600, secs % 3600 / 60, secs % 60);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{ms:03}Z")
}

/// Days since 1970-01-01 to (year, month, day), proleptic Gregorian
/// (Howard Hinnant's `civil_from_days`).
fn civil(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + u64::from(month <= 2), month, day)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn times_are_rfc3339_utc() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(rfc3339(951_782_400_000), "2000-02-29T00:00:00.000Z");
        assert_eq!(rfc3339(1_795_787_375_042), "2026-11-27T13:49:35.042Z");
    }

    #[test]
    fn a_frame_is_octet_counted_rfc5424_with_the_event_as_message() {
        let mut settings = SyslogSettings::new("127.0.0.1:514", None);
        settings.hostname = Some("gw-1".into());
        let event = json!({"class_uid": 4002, "status_id": 2, "time": 0});
        let frame = String::from_utf8(frame(&settings, &event, 7)).unwrap();
        let (length, message) = frame.split_once(' ').unwrap();
        assert_eq!(length.parse::<usize>().unwrap(), message.len());
        assert_eq!(
            message,
            format!("<108>1 1970-01-01T00:00:00.000Z gw-1 tunnelward 7 ocsf-4002 - {event}")
        );
        let ok = json!({"class_uid": 6003, "status_id": 1, "time": 0});
        let info = String::from_utf8(super::frame(&settings, &ok, 7)).unwrap();
        assert!(
            info.contains(" <110>1 ") && info.contains(" ocsf-6003 "),
            "{info}"
        );
    }

    #[test]
    fn plain_tcp_stays_on_the_machine_and_fields_are_checked() {
        for address in ["127.0.0.1:514", "[::1]:514", "localhost:514"] {
            assert!(
                SyslogSettings::new(address, None).check().is_ok(),
                "{address}"
            );
        }
        for address in ["10.0.0.5:514", "siem.example.org:514", "127.0.0.1", "x y"] {
            assert!(
                SyslogSettings::new(address, None).check().is_err(),
                "{address}"
            );
        }
        let mut bad = SyslogSettings::new("127.0.0.1:514", None);
        bad.app_name = "two words".into();
        assert!(bad.check().is_err());
        let mut bad = SyslogSettings::new("127.0.0.1:514", None);
        bad.facility = 24;
        assert!(bad.check().is_err());
    }
}
