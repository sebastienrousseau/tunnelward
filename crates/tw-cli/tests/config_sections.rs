// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! The gateway file's optional sections, checked by `config check`:
//! `[agents]`, `[providers]` and `[[providers.signers]]`.

mod common;

use std::path::Path;

use common::{Res, pki_dir, text, tunnelward, write_config};

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

#[test]
fn web_bot_auth_signers_check_ok_or_list_their_problems() -> Res<()> {
    let dir = pki_dir("signers")?;
    let good = "[providers]\non_invalid = \"downgrade\"\nca = \"ca.crt\"\n\
                [[providers.signers]]\nsignature_agent = \"https://chatgpt.com\"\n\
                provider = \"openai\"\nagent = \"chatgpt-agent\"\n";
    let path = write_config(&dir, good)?;
    let out = tunnelward(&["config", "check", &path.to_string_lossy()])?;
    assert!(out.status.success(), "{}", text(&out.stderr));
    let bad = "[providers]\non_invalid = \"ignore\"\nca = \"ca.crt\"\n\
               [[providers.signers]]\nsignature_agent = \"http://agent.test\"\n\
               provider = \"x\"\nagent = \"y\"\n";
    let path = write_config(&dir, bad)?;
    let out = tunnelward(&["config", "check", &path.to_string_lossy()])?;
    let errors = text(&out.stderr);
    for expected in [
        "on_invalid \"ignore\": give reject or downgrade",
        "signature_agent \"http://agent.test\"",
    ] {
        assert!(
            errors.contains(expected),
            "{expected} missing from: {errors}"
        );
    }
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
fn agent_path_rules_check_ok_or_list_their_problems() -> Res<()> {
    let dir = pki_dir("agent-paths")?;
    std::fs::write(dir.join("keys.json"), r#"{"keys":[]}"#)?;
    let base = "[agents]\nresource = \"https://mcp.example.org\"\ndpop_window_secs = 30\n\
                [[agents.issuers]]\nissuer = \"https://as.example.org\"\njwks = \"keys.json\"\n";
    let good = format!(
        "{base}[[agents.paths]]\npath = \"/mcp/pay\"\nsender_constrained = true\nsingle_use = true\n"
    );
    let path = write_config(&dir, &good)?;
    let out = tunnelward(&["config", "check", &path.to_string_lossy()])?;
    assert!(out.status.success(), "{}", text(&out.stderr));
    let bad = format!(
        "{base}[[agents.paths]]\npath = \"mcp\"\nsingle_use = true\n\
         [[agents.paths]]\npath = \"/x\"\n\
         [[agents.paths]]\npath = \"/x/\"\nsingle_use = true\n"
    );
    let path = write_config(&dir, &bad)?;
    let out = tunnelward(&["config", "check", &path.to_string_lossy()])?;
    let errors = text(&out.stderr);
    for expected in [
        "path \"mcp\": start it with /",
        "path \"/x\": demands nothing",
        "path \"/x/\" is listed twice",
    ] {
        assert!(
            errors.contains(expected),
            "{expected} missing from: {errors}"
        );
    }
    Ok(std::fs::remove_dir_all(dir)?)
}

#[test]
fn client_certificates_need_ingress_tls() -> Res<()> {
    let dir = pki_dir("client-certs")?;
    let without = write_config(&dir, "[ingress]\nclient_certificates = true\n")?;
    let out = tunnelward(&["config", "check", &without.to_string_lossy()])?;
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("client_certificates: needs the ingress cert and key"));
    let with = write_config(
        &dir,
        "[ingress]\ncert = \"gateway.crt\"\nkey = \"gateway.key\"\nclient_certificates = true\n",
    )?;
    let out = tunnelward(&["config", "check", &with.to_string_lossy()])?;
    assert!(out.status.success(), "{}", text(&out.stderr));
    Ok(std::fs::remove_dir_all(dir)?)
}
