// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! The `config check`, `doctor` and `dev` commands, run as a user would.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::Duration;

use tunnelward_testpki as pki;

type Res<T> = Result<T, Box<dyn std::error::Error>>;

fn tunnelward(args: &[&str]) -> std::io::Result<Output> {
    Command::new(env!("CARGO_BIN_EXE_tunnelward"))
        .args(args)
        .output()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Standard base64, as PEM needs it.
fn base64(bytes: &[u8]) -> String {
    const ABC: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n =
            chunk.iter().fold(0_u32, |acc, b| acc << 8 | u32::from(*b)) << (8 * (3 - chunk.len()));
        for i in 0..4 {
            let sextet = (n >> (18 - 6 * i)) & 63;
            out.push(if i <= chunk.len() {
                char::from(ABC[sextet as usize])
            } else {
                '='
            });
        }
    }
    out
}

fn pem(label: &str, der: &[u8]) -> String {
    let body = base64(der);
    let lines: Vec<&str> = body
        .as_bytes()
        .chunks(64)
        .filter_map(|c| std::str::from_utf8(c).ok())
        .collect();
    format!(
        "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
        lines.join("\n")
    )
}

/// A fresh directory holding the test PKI as PEM files.
fn pki_dir(name: &str) -> Res<PathBuf> {
    let dir = std::env::temp_dir().join(format!("tunnelward-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    std::fs::write(dir.join("gateway.crt"), pem("CERTIFICATE", pki::GATEWAY.0))?;
    std::fs::write(dir.join("gateway.key"), pem("PRIVATE KEY", pki::GATEWAY.1))?;
    std::fs::write(dir.join("ca.crt"), pem("CERTIFICATE", pki::CA))?;
    std::fs::write(
        dir.join("connector.crt"),
        pem("CERTIFICATE", pki::CONNECTOR.0),
    )?;
    std::fs::write(
        dir.join("connector.key"),
        pem("PRIVATE KEY", pki::CONNECTOR.1),
    )?;
    Ok(dir)
}

fn write_config(dir: &Path, extra: &str) -> Res<PathBuf> {
    let path = dir.join("tunnelward.toml");
    std::fs::write(
        &path,
        format!(
            "[listen]\nconnectors = \"127.0.0.1:0\"\ningress = \"127.0.0.1:0\"\n\n\
             [tls]\ncert = \"gateway.crt\"\nkey = \"gateway.key\"\nclient_ca = \"ca.crt\"\n{extra}"
        ),
    )?;
    Ok(path)
}

#[test]
fn a_good_config_checks_ok() -> Res<()> {
    let dir = pki_dir("good")?;
    let owners = "[[connectors.owners]]\nroute = \"mcp\"\n\
                  identities = [\"spiffe://example.org/connector\"]\n";
    let path = write_config(&dir, owners)?;
    let out = tunnelward(&["config", "check", &path.to_string_lossy()])?;
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(text(&out.stdout).ends_with(": ok\n"));
    Ok(std::fs::remove_dir_all(dir)?)
}

#[test]
fn a_bad_config_lists_every_problem() -> Res<()> {
    let dir = pki_dir("bad")?;
    let extra = "[ingress]\ncert = \"gateway.crt\"\ntrusted_proxies = [\"10.0.0.0/33\"]\n\
                 [[ingress.cors]]\npath = \"mcp\"\norigins = [\"https://app.example/x\"]\n\
                 [connectors]\nallow = [\"nonsense\"]\n\
                 [[connectors.owners]]\nroute = \"/bad/\"\nidentities = [\"nobody\"]\n\
                 [[connectors.owners]]\nroute = \"/bad/\"\nidentities = []\n";
    let path = write_config(&dir, extra)?;
    let out = tunnelward(&["config", "check", &path.to_string_lossy()])?;
    assert_eq!(out.status.code(), Some(1));
    let errors = text(&out.stderr);
    for expected in [
        "give both cert and key",
        "10.0.0.0/33",
        "nonsense",
        "start it with /",
        "give scheme://host",
        "[[connectors.owners]] route \"/bad/\" is not a route",
        "\"nobody\" is not a SPIFFE ID",
        "\"/bad/\" is listed twice",
        "name at least one identity",
    ] {
        assert!(
            errors.contains(expected),
            "{expected} missing from: {errors}"
        );
    }
    Ok(std::fs::remove_dir_all(dir)?)
}

#[test]
fn agent_auth_checks_ok_or_lists_its_problems() -> Res<()> {
    let dir = pki_dir("agents")?;
    std::fs::write(dir.join("keys.json"), r#"{"keys":[]}"#)?;
    let good = "[agents]\nresource = \"https://mcp.example.org\"\nscopes = [\"mcp\"]\n\
                [[agents.issuers]]\nissuer = \"https://as.example.org\"\njwks = \"keys.json\"\n";
    let path = write_config(&dir, good)?;
    let out = tunnelward(&["config", "check", &path.to_string_lossy()])?;
    assert!(out.status.success(), "{}", text(&out.stderr));
    let bad = "[agents]\nresource = \"mcp.example.org\"\n\
               [[agents.issuers]]\nissuer = \"https://a\"\n\
               [[agents.issuers]]\nissuer = \"https://b\"\njwks = \"keys.json\"\n\
               jwks_uri = \"https://b/jwks\"\n\
               [[agents.issuers]]\nissuer = \"https://c\"\njwks_uri = \"http://c/jwks\"\n";
    let path = write_config(&dir, bad)?;
    let out = tunnelward(&["config", "check", &path.to_string_lossy()])?;
    let errors = text(&out.stderr);
    assert_eq!(out.status.code(), Some(1));
    for expected in [
        "[agents] resource \"mcp.example.org\": give the https:// URL agents use",
        "issuer \"https://a\": give jwks_uri or jwks",
        "issuer \"https://b\": give jwks_uri or jwks, not both",
        "issuer \"https://c\": jwks_uri",
    ] {
        assert!(
            errors.contains(expected),
            "{expected} missing from: {errors}"
        );
    }
    Ok(std::fs::remove_dir_all(dir)?)
}

#[test]
fn a_signed_provider_snapshot_checks_ok_and_a_tampered_one_does_not() -> Res<()> {
    let dir = pki_dir("providers")?;
    let key = dir.join("signing.key");
    let public = keygen(&key)?;
    let snapshot = dir.join("providers.json");
    write_snapshot(&snapshot, "192.0.2.0/24")?;
    let signed = tunnelward(&[
        "providers",
        "sign",
        "--key",
        &key.to_string_lossy(),
        &snapshot.to_string_lossy(),
    ])?;
    assert!(signed.status.success(), "{}", text(&signed.stderr));
    let section = format!("[providers]\nsnapshot = \"providers.json\"\nkeys = [\"{public}\"]\n");
    let path = write_config(&dir, &section)?;
    let ok = tunnelward(&["config", "check", &path.to_string_lossy()])?;
    assert!(ok.status.success(), "{}", text(&ok.stderr));
    write_snapshot(&snapshot, "0.0.0.0/0")?;
    let tampered = tunnelward(&["config", "check", &path.to_string_lossy()])?;
    assert!(!tampered.status.success());
    let errors = text(&tampered.stderr);
    assert!(errors.contains("no trusted key signed"), "{errors}");
    Ok(std::fs::remove_dir_all(dir)?)
}

/// `tunnelward providers keygen` into `key`; its public key, after
/// checking a second run refuses to overwrite it.
fn keygen(key: &Path) -> Res<String> {
    let out = tunnelward(&["providers", "keygen", "--out", &key.to_string_lossy()])?;
    assert!(out.status.success(), "{}", text(&out.stderr));
    let again = tunnelward(&["providers", "keygen", "--out", &key.to_string_lossy()])?;
    assert!(!again.status.success(), "keygen never overwrites a key");
    let public = text(&out.stdout).trim().to_owned();
    assert_eq!(public.len(), 64, "a hex Ed25519 public key");
    Ok(public)
}

fn write_snapshot(path: &Path, range: &str) -> Res<()> {
    let json = format!(
        r#"{{"version":1,"providers":[{{"provider":"test","agent":"a","ranges":["{range}"]}}]}}"#
    );
    Ok(std::fs::write(path, json)?)
}

#[test]
fn an_unknown_key_names_its_line() -> Res<()> {
    let dir = pki_dir("unknown")?;
    let path = write_config(&dir, "[admin]\ntoken = \"inline\"\n")?;
    let out = tunnelward(&["config", "check", &path.to_string_lossy()])?;
    assert_eq!(out.status.code(), Some(1));
    let errors = text(&out.stderr);
    assert!(
        errors.contains("line 10") && errors.contains("token"),
        "{errors}"
    );
    Ok(std::fs::remove_dir_all(dir)?)
}

#[test]
fn doctor_checks_the_machine_and_the_file() -> Res<()> {
    let dir = pki_dir("doctor")?;
    let path = write_config(&dir, "")?;
    let out = tunnelward(&["doctor", "--config", &path.to_string_lossy()])?;
    let report = text(&out.stdout);
    assert!(out.status.success(), "{report}{}", text(&out.stderr));
    assert!(
        report.contains("ok   TLS offers X25519MLKEM768 first"),
        "{report}"
    );
    assert!(report.contains("passes every check"), "{report}");
    Ok(std::fs::remove_dir_all(dir)?)
}

/// A local service answering every request with `hello`.
fn hello_service() -> Res<String> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?.to_string();
    std::thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            let mut request = [0_u8; 4096];
            let _read = stream.read(&mut request);
            let _sent = stream.write_all(
                b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\nconnection: close\r\n\r\nhello",
            );
        }
    });
    Ok(addr)
}

/// The address after `<label> on ` in a startup line.
fn bound(line: &str, label: &str) -> Res<String> {
    let rest = line
        .split(&format!("{label} on "))
        .nth(1)
        .ok_or_else(|| format!("no {label} address in {line:?}"))?;
    Ok(rest.split([',', ' ']).next().unwrap_or_default().to_owned())
}

/// Stops the child when the test ends, pass or fail.
struct Running(Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _killed = self.0.kill();
        let _reaped = self.0.wait();
    }
}

#[test]
fn dev_puts_a_tunnel_in_front_of_a_local_service() -> Res<()> {
    let service = hello_service()?;
    let to = format!("http://{service}");
    let mut child = Running(
        Command::new(env!("CARGO_BIN_EXE_tunnelward"))
            .args(["dev", "--to", &to, "--listen", "127.0.0.1:0"])
            .stdout(Stdio::piped())
            .spawn()?,
    );
    let stdout = child.0.stdout.take().ok_or("no stdout")?;
    let mut line = String::new();
    BufReader::new(stdout).read_line(&mut line)?;
    assert!(line.starts_with("tunnelward dev: ready."), "{line}");
    let listen = line
        .split("http://")
        .nth(1)
        .and_then(|rest| rest.split(' ').next())
        .ok_or("no address in the ready line")?;
    let answer = ask(listen, "/anything")?;
    assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
    assert!(answer.ends_with("hello"), "{answer}");
    Ok(())
}

#[test]
fn dev_refuses_a_public_listener() -> Res<()> {
    let mut child = Running(
        Command::new(env!("CARGO_BIN_EXE_tunnelward"))
            .args(["dev", "--to", "http://127.0.0.1:1", "--listen", "0.0.0.0:0"])
            .stderr(Stdio::piped())
            .spawn()?,
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = child.0.try_wait()? {
            break status;
        }
        if std::time::Instant::now() > deadline {
            return Err("dev kept running on a public address".into());
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let mut errors = String::new();
    child
        .0
        .stderr
        .take()
        .ok_or("no stderr")?
        .read_to_string(&mut errors)?;
    assert_eq!(status.code(), Some(1));
    assert!(errors.contains("loopback only"), "{errors}");
    Ok(())
}

/// Lines a child prints, on a channel, so a test can wait for one.
fn lines(stream: impl Read + Send + 'static) -> std::sync::mpsc::Receiver<String> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stream).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    rx
}

/// Waits for a line containing `wanted`, and returns it.
fn expect(rx: &Lines, wanted: &str) -> Res<String> {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while let Some(left) = deadline.checked_duration_since(std::time::Instant::now()) {
        let line = rx.recv_timeout(left)?;
        if line.contains(wanted) {
            return Ok(line);
        }
    }
    Err(format!("no line containing {wanted:?}").into())
}

type Lines = std::sync::mpsc::Receiver<String>;

/// `tunnelward gateway` on `config`, with its stdout and stderr lines.
fn spawn_gateway(config: &Path) -> Res<(Running, Lines, Lines)> {
    let mut child = Running(
        Command::new(env!("CARGO_BIN_EXE_tunnelward"))
            .args(["gateway", "--config", &config.to_string_lossy()])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?,
    );
    let out = lines(child.0.stdout.take().ok_or("no stdout")?);
    let err = lines(child.0.stderr.take().ok_or("no stderr")?);
    Ok((child, out, err))
}

#[test]
fn the_gateway_reloads_renewed_certificates_and_keeps_good_ones() -> Res<()> {
    let dir = pki_dir("reload")?;
    let path = write_config(&dir, "reload_secs = 1\n")?;
    let (child, out, err) = spawn_gateway(&path)?;
    expect(&out, "tunnelward gateway: connectors on")?;

    std::fs::write(dir.join("gateway.key"), "not a key")?;
    expect(&err, "not reloaded, keeping the running certificates")?;
    std::fs::write(dir.join("gateway.key"), pem("PRIVATE KEY", pki::GATEWAY.1))?;
    expect(&out, "certificates reloaded")?;
    drop(child);
    Ok(std::fs::remove_dir_all(dir)?)
}

fn connector_file(dir: &Path, gateway: &str, target: &str, routes: &str) -> Res<PathBuf> {
    let path = dir.join("connector.toml");
    std::fs::write(
        &path,
        format!(
            "[gateway]\naddress = \"{gateway}\"\nserver_name = \"{}\"\nca = \"ca.crt\"\n\n\
             [identity]\ncert = \"connector.crt\"\nkey = \"connector.key\"\n\
             spiffe_id = \"spiffe://example.org/connector\"\n\n\
             [register]\nroutes = [{routes}]\n\n[target]\nurl = \"{target}\"\n",
            pki::GATEWAY_NAME
        ),
    )?;
    Ok(path)
}

#[test]
fn a_connector_file_checks_ok_or_lists_its_problems() -> Res<()> {
    let dir = pki_dir("connector-check")?;
    let good = connector_file(&dir, "127.0.0.1:7443", "http://127.0.0.1:8080", "\"mcp\"")?;
    let out = tunnelward(&["config", "check", &good.to_string_lossy()])?;
    assert!(out.status.success(), "{}", text(&out.stderr));
    let bad = connector_file(&dir, "nowhere", "ftp://x", "\"/bad/\"")?;
    let out = tunnelward(&["config", "check", &bad.to_string_lossy()])?;
    let errors = text(&out.stderr);
    for expected in ["is not a route", "give host:port", "give http://host:port"] {
        assert!(
            errors.contains(expected),
            "{expected} missing from: {errors}"
        );
    }
    Ok(std::fs::remove_dir_all(dir)?)
}

#[test]
fn a_connector_file_must_claim_its_certificates_identity() -> Res<()> {
    let dir = pki_dir("connector-identity")?;
    let path = connector_file(&dir, "127.0.0.1:7443", "http://127.0.0.1:8080", "\"mcp\"")?;
    let claimed = std::fs::read_to_string(&path)?.replace(
        "spiffe://example.org/connector",
        "spiffe://example.org/someone-else",
    );
    std::fs::write(&path, claimed)?;
    let out = tunnelward(&["config", "check", &path.to_string_lossy()])?;
    let errors = text(&out.stderr);
    assert!(!out.status.success(), "a borrowed identity passed");
    assert!(
        errors.contains("spiffe://example.org/connector"),
        "the certificate's identity missing from: {errors}"
    );
    Ok(std::fs::remove_dir_all(dir)?)
}

fn gateway_file(dir: &Path, connectors: &str, ingress: &str) -> Res<PathBuf> {
    let path = dir.join("tunnelward.toml");
    std::fs::write(
        &path,
        format!(
            "[listen]\nconnectors = \"{connectors}\"\ningress = \"{ingress}\"\n\n\
             [tls]\ncert = \"gateway.crt\"\nkey = \"gateway.key\"\nclient_ca = \"ca.crt\"\n"
        ),
    )?;
    Ok(path)
}

/// `tunnelward connector` on `config`, with its stdout lines.
fn spawn_connector(config: &Path) -> Res<(Running, Lines)> {
    let mut child = Running(
        Command::new(env!("CARGO_BIN_EXE_tunnelward"))
            .args(["connector", "--config", &config.to_string_lossy()])
            .stdout(Stdio::piped())
            .spawn()?,
    );
    let out = lines(child.0.stdout.take().ok_or("no stdout")?);
    Ok((child, out))
}

/// An agent's GET for `path` at `ingress`, and the whole raw answer.
fn ask(ingress: &str, path: &str) -> Res<String> {
    let mut agent = TcpStream::connect(ingress)?;
    agent.set_read_timeout(Some(Duration::from_secs(5)))?;
    write!(
        agent,
        "GET {path} HTTP/1.1\r\nhost: h\r\nconnection: close\r\n\r\n"
    )?;
    let mut answer = String::new();
    agent.read_to_string(&mut answer)?;
    Ok(answer)
}

/// A gateway and a connector from their files in `dir`, in front of a
/// local service; returns both processes and the ingress address once
/// the connector has registered.
fn start_pair(dir: &Path) -> Res<(Running, Running, String)> {
    let service = hello_service()?;
    let (gateway, gateway_out, _) =
        spawn_gateway(&gateway_file(dir, "127.0.0.1:0", "127.0.0.1:0")?)?;
    let started = expect(&gateway_out, "connectors on")?;
    let (connectors, ingress) = (bound(&started, "connectors")?, bound(&started, "agents")?);
    let target = format!("http://{service}");
    let file = connector_file(dir, &connectors, &target, "\"mcp\"")?;
    let (connector, connector_out) = spawn_connector(&file)?;
    expect(&connector_out, "Registered")?;
    Ok((gateway, connector, ingress))
}

#[test]
fn a_gateway_and_a_connector_from_their_files_serve_a_request() -> Res<()> {
    let dir = pki_dir("pair")?;
    let (gateway, connector, ingress) = start_pair(&dir)?;
    let answer = ask(&ingress, "/mcp/x")?;
    assert!(
        answer.starts_with("HTTP/1.1 200") && answer.ends_with("hello"),
        "{answer}"
    );
    drop((connector, gateway));
    Ok(std::fs::remove_dir_all(dir)?)
}
