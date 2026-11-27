// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! The control plane end to end (ADR 0012): operators publish with OIDC
//! tokens and the role their group grants; a gateway with `[control]`
//! pulls the signed bundle over mutual TLS and applies it; an unknown
//! client certificate gets nothing; each publish is audited with who
//! made it.

mod common;

use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::mpsc::{Receiver, channel};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tunnelward_audit::b64;
use tunnelward_crypto::rustls::pki_types::ServerName;
use tunnelward_crypto::{KeyExchange, client_config};
use tunnelward_testpki as pki;

use common::{Res, Running, pki_dir, text, tunnelward, write_config};

const ISSUER: &str = "https://login.test";
const RESOURCE: &str = "https://control.test";
const POLICY: &str = "default = \"deny\"\n[[rules]]\neffect = \"permit\"\ntools = [\"read_*\"]\n";

/// An operator's identity provider: one Ed25519 key.
struct Idp(Ed25519KeyPair);

impl Idp {
    fn new() -> Res<Self> {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).map_err(|_| "keygen")?;
        Ok(Self(
            Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).map_err(|_| "key")?,
        ))
    }

    fn jwks(&self) -> String {
        let x = b64::encode(self.0.public_key().as_ref());
        format!(r#"{{"keys":[{{"kty":"OKP","crv":"Ed25519","x":"{x}","kid":"k1"}}]}}"#)
    }

    /// A token for `sub` in `group`, valid for ten minutes.
    fn token(&self, sub: &str, group: &str) -> Res<String> {
        let exp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() + 600;
        let header = b64::encode(br#"{"alg":"EdDSA","kid":"k1","typ":"JWT"}"#);
        let claims = format!(
            r#"{{"iss":"{ISSUER}","aud":"{RESOURCE}","sub":"{sub}","groups":["{group}"],"exp":{exp}}}"#
        );
        let signed = format!("{header}.{}", b64::encode(claims.as_bytes()));
        let sig = self.0.sign(signed.as_bytes());
        Ok(format!("{signed}.{}", b64::encode(sig.as_ref())))
    }

    /// A viewer's, an operator's and an admin's token.
    fn tokens(&self) -> Res<[String; 3]> {
        Ok([
            self.token("ops-v", "v")?,
            self.token("ops-o", "o")?,
            self.token("ops-a", "a")?,
        ])
    }
}

/// One HTTP/1.1 request over TLS to `addr`, trusting the test CA,
/// presenting `client` when given: the status and the body.
async fn call(addr: &str, request: &str, client: Option<pki::Pair>) -> Res<(u16, String)> {
    let config = client_config(
        pki::roots(pki::CA)?,
        client.map(pki::identity),
        KeyExchange::default(),
        &[b"http/1.1"],
    )?;
    let tcp = TcpStream::connect(addr).await?;
    let name = ServerName::try_from("127.0.0.1")?;
    let mut tls = tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(name, tcp)
        .await?;
    tls.write_all(request.as_bytes()).await?;
    let mut answer = Vec::new();
    let _read = tls.read_to_end(&mut answer).await;
    let answer = String::from_utf8_lossy(&answer).into_owned();
    let status = answer
        .get(9..12)
        .and_then(|s| s.parse().ok())
        .ok_or("no status")?;
    let body = answer
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_owned())
        .unwrap_or_default();
    Ok((status, body))
}

/// The status `api` answers `method path` with, sent with `token`.
async fn status(api: &str, method: &str, path: &str, token: Option<&str>, body: &str) -> Res<u16> {
    Ok(call(api, &http(method, path, token, body), None).await?.0)
}

fn http(method: &str, path: &str, token: Option<&str>, body: &str) -> String {
    let auth = token
        .map(|t| format!("Authorization: Bearer {t}\r\n"))
        .unwrap_or_default();
    format!(
        "{method} {path} HTTP/1.1\r\nHost: control.test\r\n{auth}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

/// A running command, and each line it prints, as they come.
fn spawn(args: &[&str]) -> Res<(Running, Receiver<String>)> {
    let mut child = Running(
        Command::new(env!("CARGO_BIN_EXE_tunnelward"))
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?,
    );
    let (send, lines) = channel();
    for out in [
        child
            .0
            .stdout
            .take()
            .map(|o| Box::new(o) as Box<dyn std::io::Read + Send>),
        child
            .0
            .stderr
            .take()
            .map(|e| Box::new(e) as Box<dyn std::io::Read + Send>),
    ]
    .into_iter()
    .flatten()
    {
        let send = send.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(out).lines().map_while(Result::ok) {
                let _gone = send.send(line);
            }
        });
    }
    Ok((child, lines))
}

/// The first line from `lines` containing `want`, within 10 s.
fn wait_for(lines: &Receiver<String>, want: &str) -> Res<String> {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while let Some(left) = deadline.checked_duration_since(std::time::Instant::now()) {
        let line = lines.recv_timeout(left)?;
        if line.contains(want) {
            return Ok(line);
        }
    }
    Err(format!("no line with {want:?}").into())
}

fn after<'a>(line: &'a str, label: &str) -> Res<&'a str> {
    Ok(line
        .split(label)
        .nth(1)
        .and_then(|rest| rest.split([',', ' ']).next())
        .ok_or("no address")?)
}

fn control_file(dir: &Path, idp: &Idp) -> Res<std::path::PathBuf> {
    std::fs::write(dir.join("operators.json"), idp.jwks())?;
    let path = dir.join("control.toml");
    std::fs::write(
        &path,
        format!(
            "[listen]\napi = \"127.0.0.1:0\"\nfleet = \"127.0.0.1:0\"\n\
             [tls]\ncert = \"gateway.crt\"\nkey = \"gateway.key\"\ngateway_ca = \"ca.crt\"\n\
             gateways = [\"spiffe://example.org/connector\"]\n\
             [operators]\nresource = \"{RESOURCE}\"\n\
             [[operators.issuers]]\nissuer = \"{ISSUER}\"\njwks = \"operators.json\"\n\
             [roles]\nviewer = [\"v\"]\noperator = [\"o\"]\nadmin = [\"a\"]\n\
             [store]\ndir = \"control-data\"\nkey = \"bundle.key\"\n\
             [audit]\npath = \"control-audit.jsonl\"\nkey = \"audit.key\"\n"
        ),
    )?;
    Ok(path)
}

/// A running control, its addresses, its directory, and three tokens:
/// a viewer's, an operator's and an admin's.
struct Setup {
    _control: Running,
    api: String,
    fleet: String,
    dir: std::path::PathBuf,
    viewer: String,
    operator: String,
    admin: String,
}

/// Writes the bundle key and the audit key into `dir`.
fn keygens(dir: &Path) -> Res<()> {
    for (what, file) in [("control", "bundle.key"), ("audit", "audit.key")] {
        let out = dir.join(file).to_string_lossy().into_owned();
        assert!(
            tunnelward(&[what, "keygen", "--out", &out])?
                .status
                .success()
        );
    }
    Ok(())
}

fn start(name: &str) -> Res<Setup> {
    let dir = pki_dir(name)?;
    let idp = Idp::new()?;
    keygens(&dir)?;
    let path = control_file(&dir, &idp)?;
    let (control, lines) = spawn(&["control", "--config", &path.to_string_lossy()])?;
    let started = wait_for(&lines, "operators on")?;
    let [viewer, operator, admin] = idp.tokens()?;
    Ok(Setup {
        _control: control,
        api: after(&started, "operators on ")?.to_owned(),
        fleet: after(&started, "gateways on ")?.to_owned(),
        dir,
        viewer,
        operator,
        admin,
    })
}

/// A gateway file whose policy comes from the control at `fleet`.
fn pulling(dir: &Path, fleet: &str) -> Res<std::path::PathBuf> {
    let pull = format!(
        "[control]\nurl = \"https://{fleet}/v1/bundle\"\nca = \"ca.crt\"\ncert = \"connector.crt\"\n\
         key = \"connector.key\"\npublic_key = \"bundle.key.pub\"\nevery_secs = 1\n"
    );
    write_config(dir, &pull)
}

#[tokio::test(flavor = "multi_thread")]
async fn each_role_may_do_what_it_allows_and_each_change_is_audited() -> Res<()> {
    let s = start("control-roles")?;
    let api = s.api.as_str();
    assert_eq!(status(api, "GET", "/v1/bundles", None, "").await?, 401);
    let listed = call(api, &http("GET", "/v1/bundles", Some(&s.viewer), ""), None).await?;
    assert_eq!(listed, (200, "[]".into()));
    let viewer = Some(s.viewer.as_str());
    assert_eq!(
        status(api, "POST", "/v1/policy", viewer, POLICY).await?,
        403
    );
    let bad = "default = \"maybe\"\n";
    let operator = Some(s.operator.as_str());
    let refused = status(api, "POST", "/v1/policy", operator, bad).await?;
    assert_eq!(refused, 400, "a policy a gateway would refuse");
    let (code, made) = call(
        api,
        &http("POST", "/v1/policy", Some(&s.operator), POLICY),
        None,
    )
    .await?;
    assert_eq!(code, 201, "{made}");
    assert!(
        made.contains(r#""version":1"#) && made.contains("ops-o"),
        "{made}"
    );
    let back = |token: &str| http("POST", "/v1/rollback?to=1", Some(token), "");
    assert_eq!(
        call(api, &back(&s.operator), None).await?.0,
        403,
        "rollback is an admin's"
    );
    assert_eq!(call(api, &back(&s.admin), None).await?.0, 201);
    let log = std::fs::read_to_string(s.dir.join("control-audit.jsonl"))?;
    for (entry, actor) in [
        (
            r#""action":"publish","target":"bundle=1""#,
            r#""actor":"ops-o""#,
        ),
        (
            r#""action":"rollback","target":"bundle=2""#,
            r#""actor":"ops-a""#,
        ),
    ] {
        assert!(log.contains(entry) && log.contains(actor), "{log}");
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_gateway_applies_each_newer_signed_bundle_and_strangers_get_none() -> Res<()> {
    let s = start("control-pull")?;
    let publish = http("POST", "/v1/policy", Some(&s.operator), POLICY);
    assert_eq!(call(&s.api, &publish, None).await?.0, 201);
    let gateway_file = pulling(&s.dir, &s.fleet)?;
    let (_gateway, lines) = spawn(&["gateway", "--config", &gateway_file.to_string_lossy()])?;
    wait_for(&lines, "policy bundle 1 from ops-o applied")?;
    let rollback = http("POST", "/v1/rollback?to=1", Some(&s.admin), "");
    assert_eq!(call(&s.api, &rollback, None).await?.0, 201);
    wait_for(&lines, "policy bundle 2 from ops-a applied")?;
    let (_, fleet) = call(&s.api, &http("GET", "/v1/fleet", Some(&s.viewer), ""), None).await?;
    assert!(fleet.contains("spiffe://example.org/connector"), "{fleet}");
    for (pair, why) in [
        (pki::PLAIN, "no SPIFFE ID"),
        (pki::RIVAL, "an ID not listed"),
    ] {
        let refused = call(&s.fleet, &http("GET", "/v1/bundle", None, ""), Some(pair)).await;
        assert!(
            refused.is_err() || refused.is_ok_and(|(s, _)| s != 200),
            "{why}: no bundle"
        );
    }
    Ok(())
}

/// The status of a plain GET to the gateway's ingress at `addr`.
fn ingress_status(addr: &str) -> Res<u16> {
    use std::io::{Read, Write};
    let mut tcp = std::net::TcpStream::connect(addr)?;
    tcp.write_all(b"GET /tools/x HTTP/1.1\r\nHost: mcp.test\r\nConnection: close\r\n\r\n")?;
    let mut answer = String::new();
    tcp.read_to_string(&mut answer)?;
    Ok(answer
        .get(9..12)
        .and_then(|s| s.parse().ok())
        .ok_or("no status")?)
}

#[test]
fn a_gateway_denies_every_call_until_its_first_bundle() -> Res<()> {
    let dir = pki_dir("control-closed")?;
    let key = dir.join("bundle.key").to_string_lossy().into_owned();
    assert!(
        tunnelward(&["control", "keygen", "--out", &key])?
            .status
            .success()
    );
    // Nothing listens on port 1: no bundle can arrive.
    let (_gateway, agents) = common::spawn_gateway(&pulling(&dir, "127.0.0.1:1")?)?;
    assert_eq!(ingress_status(&agents)?, 403, "denied by the policy");
    let open = pki_dir("control-open")?;
    let (_open, agents) = common::spawn_gateway(&write_config(&open, "")?)?;
    assert_eq!(ingress_status(&agents)?, 404, "without [control]: no route");
    Ok(())
}

#[test]
fn a_gateway_file_with_control_and_policy_is_refused() -> Res<()> {
    let dir = pki_dir("control-and-policy")?;
    std::fs::write(dir.join("policy.toml"), "default = \"deny\"\n")?;
    let (key, pubkey) = (dir.join("bundle.key"), "bundle.key.pub");
    assert!(
        tunnelward(&["control", "keygen", "--out", &key.to_string_lossy()])?
            .status
            .success()
    );
    let both = format!(
        "[policy]\nfile = \"policy.toml\"\n[control]\nurl = \"https://127.0.0.1:1/v1/bundle\"\n\
         ca = \"ca.crt\"\ncert = \"connector.crt\"\nkey = \"connector.key\"\npublic_key = \"{pubkey}\"\n"
    );
    let path = write_config(&dir, &both)?;
    let out = tunnelward(&["config", "check", &path.to_string_lossy()])?;
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stderr).contains("[control] and [policy]"),
        "{}",
        text(&out.stderr)
    );
    Ok(())
}
