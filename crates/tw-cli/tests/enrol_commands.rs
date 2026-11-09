// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! `tunnelward enrol ca|token|revoke` and the `[enrolment]` section.

mod common;

use common::{Res, pki_dir, text, tunnelward, write_config};

const ID: &str = "spiffe://example.org/connector";

#[test]
fn a_ca_a_token_and_a_revocation_from_the_command_line() -> Res<()> {
    let dir = pki_dir("enrol-commands")?;
    let (cert, key) = (dir.join("enrol-ca.crt"), dir.join("enrol-ca.key"));
    let _fresh = (std::fs::remove_file(&cert), std::fs::remove_file(&key));
    let made = tunnelward(&[
        "enrol",
        "ca",
        "--cert",
        &cert.to_string_lossy(),
        "--key",
        &key.to_string_lossy(),
    ])?;
    assert!(made.status.success(), "{}", text(&made.stderr));
    let section =
        "[enrolment]\nca_cert = \"enrol-ca.crt\"\nca_key = \"enrol-ca.key\"\ntokens = \"store\"\n";
    let config = write_config(&dir, section)?.to_string_lossy().into_owned();
    let checked = tunnelward(&["config", "check", &config])?;
    assert!(checked.status.success(), "{}", text(&checked.stderr));
    let issued = tunnelward(&["enrol", "token", "--config", &config, "--spiffe-id", ID])?;
    assert!(issued.status.success(), "{}", text(&issued.stderr));
    assert!(text(&issued.stdout).starts_with("twe1_"));
    let refused = tunnelward(&["enrol", "revoke", "--config", &config, "--spiffe-id", ID])?;
    assert_eq!(
        refused.status.code(),
        Some(1),
        "not enrolled until the token is used"
    );
    assert!(text(&refused.stderr).contains("is not enrolled"));
    Ok(std::fs::remove_dir_all(dir)?)
}

#[test]
fn a_gateway_file_without_enrolment_cannot_issue_tokens() -> Res<()> {
    let dir = pki_dir("enrol-none")?;
    let config = write_config(&dir, "")?.to_string_lossy().into_owned();
    let out = tunnelward(&["enrol", "token", "--config", &config, "--spiffe-id", ID])?;
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("no [enrolment] section"));
    Ok(std::fs::remove_dir_all(dir)?)
}
