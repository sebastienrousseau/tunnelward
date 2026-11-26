// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! `tunnelward attest verify`, the gateway file's `[attestation]` and
//! the connector file's `attestation`, against the vectors in
//! tunnelward-attest (ADR 0009).

mod common;

use std::path::{Path, PathBuf};

use common::{Res, pki_dir, text, tunnelward, write_config};

const VECTORS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../tw-attest/tests/vectors");
/// The SHA-256 of passmcp's statement fixture, the payload every vector signs.
const STATEMENT: &str = "68882383ed6e869728cdd01da2e7bb268639565f41e764031904b7292933cce0";

fn vector(name: &str) -> String {
    format!("{VECTORS}/{name}")
}

/// A directory with the test PKI and the cosign key beside a gateway file.
fn dir_with_key(name: &str) -> Res<PathBuf> {
    let dir = pki_dir(name)?;
    std::fs::copy(vector("cosign-p256.pub"), dir.join("passmcp.pub"))?;
    Ok(dir)
}

/// `[attestation]` trusting the cosign key, with `top` added to it, and
/// one route with `rule` added to it.
fn section(top: &str, rule: &str) -> String {
    format!(
        "[attestation]\nkeys = [\"passmcp.pub\"]\n{top}\n[[attestation.routes]]\n\
         route = \"mcp/payments\"\n\
         targets = [{{ transport = \"http\", endpoint = \"https://mcp.example.com/mcp\" }}]\n{rule}"
    )
}

fn check(path: &Path) -> Res<(Option<i32>, String)> {
    let out = tunnelward(&["config", "check", &path.to_string_lossy()])?;
    Ok((out.status.code(), text(&out.stderr)))
}

#[test]
fn verify_with_a_key_prints_the_statement_or_refuses_it() -> Res<()> {
    let bundle = vector("cosign-bundle.json");
    let out = tunnelward(&[
        "attest",
        "verify",
        "--key",
        &vector("cosign-p256.pub"),
        &bundle,
    ])?;
    let said = text(&out.stdout);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(said.contains(&format!("statement {STATEMENT}")), "{said}");
    assert!(said.contains("ran at    2026-09-22T12:00:00Z"), "{said}");
    let out = tunnelward(&["attest", "verify", "--key", &vector("ed25519.pub"), &bundle])?;
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("no signature by a trusted key"));
    let out = tunnelward(&["attest", "verify", &bundle])?;
    assert_eq!(out.status.code(), Some(2), "neither --key nor --config");
    Ok(())
}

#[test]
fn verify_with_a_gateway_file_gives_its_decision() -> Res<()> {
    let dir = dir_with_key("attest-decide")?;
    let decide = |path: &Path| {
        let config = path.to_string_lossy().into_owned();
        let args = [
            "attest",
            "verify",
            "--config",
            &config,
            "--route",
            "mcp/payments",
        ];
        tunnelward(&[&args[..], &[vector("cosign-bundle.json").as_str()]].concat())
    };
    // The fixture ran on 2026-09-22 and failed one check.
    let strict = write_config(&dir, &section("", "max_age_days = 36500\n"))?;
    let out = decide(&strict)?;
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("refused   TW-R007 mcp/payments: the verdicts"));
    let lenient = write_config(&dir, &section("", "max_age_days = 36500\nmax_fail = 1\n"))?;
    let out = decide(&lenient)?;
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(text(&out.stdout).contains("admitted  route mcp/payments"));
    Ok(std::fs::remove_dir_all(dir)?)
}

#[test]
fn the_attestation_section_checks_ok_or_lists_its_problems() -> Res<()> {
    let dir = dir_with_key("attest-section")?;
    std::fs::write(dir.join("revoked.txt"), format!("# by hand\n{STATEMENT}\n"))?;
    let good = section(
        "revoked = \"revoked.txt\"\n",
        "require = [\"protocol.origin\"]\n",
    );
    let (code, errors) = check(&write_config(&dir, &good)?)?;
    assert_eq!(code, Some(0), "{errors}");
    let bad = "[attestation]\nkeys = [\"missing.pub\", \"ca.crt\"]\nrevoked = \"ca.crt\"\n\
               [[attestation.routes]]\nroute = \"/bad\"\ntargets = []\nmax_age_days = 0\n\
               [[attestation.routes]]\nroute = \"mcp/a\"\n\
               targets = [{ transport = \"ftp\", endpoint = \"x\" }]\n\
               [[attestation.routes]]\nroute = \"mcp/a\"\n\
               targets = [{ transport = \"http\", endpoint = \"x\" }]\nmin_score = 101\n";
    let (code, errors) = check(&write_config(&dir, bad)?)?;
    assert_eq!(code, Some(1));
    for expected in [
        "[attestation] keys: ",
        "missing.pub",
        "ca.crt: not a PEM public key",
        "[attestation] revoked: ",
        "route \"/bad\" is not a route",
        "route \"/bad\": name at least one target",
        "route \"mcp/a\": a target needs transport http or stdio",
        "route \"mcp/a\" is listed twice",
        "max_age_days is at least 1, min_score 0 to 100",
    ] {
        assert!(
            errors.contains(expected),
            "{expected} missing from: {errors}"
        );
    }
    Ok(std::fs::remove_dir_all(dir)?)
}

#[test]
fn a_connector_file_names_an_attestation_that_exists() -> Res<()> {
    let dir = pki_dir("attest-connector")?;
    let file = |attestation: &str| -> Res<PathBuf> {
        let path = dir.join("connector.toml");
        std::fs::write(
            &path,
            format!(
                "[gateway]\naddress = \"127.0.0.1:7443\"\nserver_name = \"gateway.test\"\nca = \"ca.crt\"\n\n\
                 [identity]\ncert = \"connector.crt\"\nkey = \"connector.key\"\n\
                 spiffe_id = \"spiffe://example.org/connector\"\n\n\
                 [register]\nroutes = [\"mcp/payments\"]\nattestation = \"{attestation}\"\n\n\
                 [target]\nurl = \"http://127.0.0.1:8080\"\n"
            ),
        )?;
        Ok(path)
    };
    let (code, errors) = check(&file("missing.json")?)?;
    assert_eq!(code, Some(1));
    assert!(errors.contains("[register] attestation: "), "{errors}");
    std::fs::copy(vector("cosign-bundle.json"), dir.join("bundle.json"))?;
    let (code, errors) = check(&file("bundle.json")?)?;
    assert_eq!(code, Some(0), "{errors}");
    Ok(std::fs::remove_dir_all(dir)?)
}
