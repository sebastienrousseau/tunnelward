// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! The tool policy's file: `tunnelward policy test` and the gateway
//! file's `[policy]`.

mod common;

use common::{Res, pki_dir, text, tunnelward, write_config};

const POLICY: &str = r#"
default = "deny"
high_impact = ["transfer"]

[[rules]]
effect = "permit"
agents = ["claude"]
tools = ["read_*", "transfer"]

[[rules]]
effect = "forbid"
tools = ["read_secrets"]

[[rules]]
effect = "forbid"
mismatch = true
"#;

const CASES: &str = r#"
[[case]]
name = "claude reads"
agent = "claude"
path = "/mcp"
method = "tools/call"
tool = "read_balance"
evidence = "declared"
expect = "allow"

[[case]]
name = "a forbid wins"
agent = "claude"
path = "/mcp"
method = "tools/call"
tool = "read_secrets"
evidence = "cryptographic"
expect = "deny"

[[case]]
name = "a claim the evidence does not back is refused"
agent = "claude"
path = "/mcp"
method = "tools/call"
tool = "read_balance"
evidence = "declared"
mismatch = true
expect = "deny"

[[case]]
name = "transfer needs cryptographic evidence"
agent = "claude"
path = "/mcp"
method = "tools/call"
tool = "transfer"
evidence = "network"
expect = "deny"
"#;

fn write(dir: &std::path::Path, name: &str, text: &str) -> Res<String> {
    let path = dir.join(name);
    std::fs::write(&path, text)?;
    Ok(path.to_string_lossy().into_owned())
}

#[test]
fn cases_that_match_the_policy_pass() -> Res<()> {
    let dir = pki_dir("policy-pass")?;
    let (policy, cases) = (
        write(&dir, "policy.toml", POLICY)?,
        write(&dir, "cases.toml", CASES)?,
    );
    let out = tunnelward(&["policy", "test", "--policy", &policy, &cases])?;
    assert!(
        out.status.success(),
        "{}{}",
        text(&out.stdout),
        text(&out.stderr)
    );
    assert!(text(&out.stdout).contains("4 cases, 0 failed"));
    Ok(std::fs::remove_dir_all(dir)?)
}

#[test]
fn a_case_the_policy_decides_otherwise_fails() -> Res<()> {
    let dir = pki_dir("policy-fail")?;
    let policy = write(&dir, "policy.toml", POLICY)?;
    let wrong = CASES.replacen("expect = \"deny\"", "expect = \"allow\"", 1);
    let cases = write(&dir, "cases.toml", &wrong)?;
    let out = tunnelward(&["policy", "test", "--policy", &policy, &cases])?;
    assert_eq!(out.status.code(), Some(1));
    let stdout = text(&out.stdout);
    assert!(
        stdout.contains("FAIL a forbid wins: expected allow, got deny"),
        "{stdout}"
    );
    assert!(stdout.contains("4 cases, 1 failed"), "{stdout}");
    Ok(std::fs::remove_dir_all(dir)?)
}

#[test]
fn the_gateway_file_names_a_policy_that_must_check() -> Res<()> {
    let dir = pki_dir("policy-section")?;
    write(&dir, "policy.toml", POLICY)?;
    let config = write_config(&dir, "[policy]\nfile = \"policy.toml\"\n")?;
    let out = tunnelward(&["config", "check", &config.to_string_lossy()])?;
    assert!(out.status.success(), "{}", text(&out.stderr));
    let bad = "[[rules]]\neffect = \"maybe\"\npaths = [\"mcp\"]\nevidence = \"strong\"\n";
    write(&dir, "policy.toml", bad)?;
    let out = tunnelward(&["config", "check", &config.to_string_lossy()])?;
    let errors = text(&out.stderr);
    assert_eq!(out.status.code(), Some(1));
    for expected in [
        "rule 1: \"maybe\": give permit or forbid",
        "rule 1 paths: \"mcp\": start it with /",
        "rule 1 evidence \"strong\": give declared, network or cryptographic",
    ] {
        assert!(
            errors.contains(expected),
            "{expected} missing from: {errors}"
        );
    }
    Ok(std::fs::remove_dir_all(dir)?)
}
