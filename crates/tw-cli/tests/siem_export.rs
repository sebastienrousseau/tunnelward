// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! `[audit.export]` (ADR 0013): a running gateway sends each audit
//! entry, as an OCSF event, to a syslog receiver and an OTLP collector
//! on loopback; `config check` lists what is wrong with the section.

mod common;

use std::io::{BufRead, BufReader, Read};
use std::net::TcpListener;
use std::path::Path;
use std::sync::mpsc;
use std::time::Duration;

use common::{
    Res, Running, ask, collector, pki_dir, spawn_gateway, text, tunnelward, write_config,
};

/// A syslog receiver on loopback that sends each octet-counted message
/// on, as RFC 6587 frames it.
fn receiver() -> Res<(String, mpsc::Receiver<String>)> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?.to_string();
    let (sent, received) = mpsc::channel();
    std::thread::spawn(move || {
        for tcp in listener.incoming().flatten() {
            let mut reader = BufReader::new(tcp);
            loop {
                let mut length = Vec::new();
                if reader.read_until(b' ', &mut length).unwrap_or(0) == 0 {
                    break;
                }
                let Some(n) = std::str::from_utf8(&length[..length.len() - 1])
                    .ok()
                    .and_then(|n| n.parse().ok())
                else {
                    break;
                };
                let mut message = vec![0; n];
                if reader.read_exact(&mut message).is_err() {
                    break;
                }
                let _sent = sent.send(String::from_utf8_lossy(&message).into_owned());
            }
        }
    });
    Ok((address, received))
}

type Channel = mpsc::Receiver<String>;

fn keygen(dir: &Path) -> Res<()> {
    let key = dir.join("audit.key").to_string_lossy().into_owned();
    let out = tunnelward(&["audit", "keygen", "--out", &key])?;
    assert!(out.status.success(), "{}", text(&out.stderr));
    Ok(())
}

fn syslog_got_the_event(messages: &mpsc::Receiver<String>) -> Res<()> {
    let message = messages.recv_timeout(Duration::from_secs(10))?;
    assert!(
        message.contains(" gw-test tunnelward ") && message.contains(" ocsf-4002 - {"),
        "{message}"
    );
    assert!(message.contains("\"class_uid\":4002") && message.contains("/mcp/siem"));
    Ok(())
}

fn otlp_got_the_event(posts: &mpsc::Receiver<String>) -> Res<()> {
    let post = posts.recv_timeout(Duration::from_secs(10))?;
    assert!(post.starts_with("POST /v1/logs HTTP/1.1"), "{post}");
    assert!(
        post.contains("\"logRecords\"") && post.contains("/mcp/siem"),
        "{post}"
    );
    Ok(())
}

/// A gateway exporting to a syslog receiver and a collector on
/// loopback: the gateway, its ingress, and what each destination gets.
fn start(dir: &Path) -> Res<(Running, String, Channel, Channel)> {
    keygen(dir)?;
    let (syslog, messages) = receiver()?;
    let (endpoint, posts) = collector()?;
    let extra = format!(
        "[audit]\npath = \"audit.jsonl\"\nkey = \"audit.key\"\n\
         [audit.export]\nevery_ms = 50\n\
         [audit.export.syslog]\naddress = \"{syslog}\"\nplain = true\nhostname = \"gw-test\"\n\
         [audit.export.otlp]\nendpoint = \"{endpoint}\"\n"
    );
    let (child, agents) = spawn_gateway(&write_config(dir, &extra)?)?;
    Ok((child, agents, messages, posts))
}

#[test]
fn a_running_gateway_exports_each_entry_to_syslog_and_otlp() -> Res<()> {
    let dir = pki_dir("siem-run")?;
    let (child, agents, messages, posts) = start(&dir)?;
    ask(&agents, "/mcp/siem")?;
    syslog_got_the_event(&messages)?;
    otlp_got_the_event(&posts)?;
    drop(child);
    let log = std::fs::read_to_string(dir.join("audit.jsonl"))?;
    assert!(log.contains("/mcp/siem"), "the file stays the record");
    Ok(std::fs::remove_dir_all(dir)?)
}

#[test]
fn a_bad_export_section_is_refused_with_each_problem() -> Res<()> {
    let dir = pki_dir("siem-check")?;
    keygen(&dir)?;
    let extra = "[audit]\npath = \"audit.jsonl\"\nkey = \"audit.key\"\n\
                 [audit.export]\nbatch = 0\n\
                 [audit.export.syslog]\naddress = \"10.0.0.5:514\"\nplain = true\n";
    let path = write_config(&dir, extra)?;
    let out = tunnelward(&["config", "check", &path.to_string_lossy()])?;
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains("plain TCP only to a loopback address"),
        "{stderr}"
    );
    assert!(
        stderr.contains("queue, batch and every_ms are at least 1"),
        "{stderr}"
    );
    let none = "[audit]\npath = \"audit.jsonl\"\nkey = \"audit.key\"\n[audit.export]\n";
    let out = tunnelward(&[
        "config",
        "check",
        &write_config(&dir, none)?.to_string_lossy(),
    ])?;
    assert!(
        text(&out.stderr).contains("name a syslog or an OTLP destination"),
        "{}",
        text(&out.stderr)
    );
    Ok(std::fs::remove_dir_all(dir)?)
}
