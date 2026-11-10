// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! The log end to end: written by a `Sink`, checked by `verify`, and
//! every kind of tampering caught (FR-15); raw addresses only beside the
//! chain (FR-18).

use std::path::{Path, PathBuf};

use tunnelward_audit::verify::{Report, verify};
use tunnelward_audit::{AdminEntry, Entry, Raw, RequestEntry, Settings, Sink};
use tunnelward_crypto::composite::SigningKey;

fn dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "tw-audit-{name}-{}-{}",
        std::process::id(),
        tunnelward_audit::now_ms()
    ));
    std::fs::create_dir_all(&dir).unwrap_or_else(|e| unreachable!("{e:?}"));
    dir
}

fn key() -> (SigningKey, Vec<u8>) {
    let (key, _) = SigningKey::generate().unwrap_or_else(|e| unreachable!("{e:?}"));
    let public = key.public_key();
    (key, public)
}

fn same_key(public: &[u8], encoded: &[u8]) -> SigningKey {
    let key = SigningKey::from_bytes(encoded).unwrap_or_else(|e| unreachable!("{e:?}"));
    assert_eq!(key.public_key(), public);
    key
}

fn request(sink: &Sink, n: u64) -> Entry {
    let mut entry = RequestEntry::default();
    entry.request_id = format!("R{n}");
    entry.method = "POST".into();
    entry.path = "/mcp".into();
    entry.client = sink.pseudonyms().of("ip", b"192.0.2.7");
    entry.evidence = "declared".into();
    entry.decision = "forwarded".into();
    entry.status = 200;
    Entry::Request(Box::new(entry))
}

fn write(path: &Path, key: SigningKey, entries: u64, every: u64) {
    let mut settings = Settings::new(path.to_owned(), key, [7; 32]);
    settings.checkpoint_every = every;
    let sink = Sink::open(settings).unwrap_or_else(|e| unreachable!("{e:?}"));
    for n in 0..entries {
        sink.record(request(&sink, n), None);
    }
    sink.close();
}

fn check(path: &Path, public: &[u8]) -> Report {
    let file = std::io::BufReader::new(
        std::fs::File::open(path).unwrap_or_else(|e| unreachable!("{e:?}")),
    );
    verify(file, &[public.to_vec()]).unwrap_or_else(|e| unreachable!("{e:?}"))
}

#[test]
fn a_written_log_verifies_and_ends_signed() {
    let dir = dir("ok");
    let path = dir.join("audit.jsonl");
    let (key, public) = key();
    write(&path, key, 25, 10);
    let report = check(&path, &public);
    assert!(report.ok(), "{report:?}");
    assert_eq!(report.entries, 25);
    assert_eq!(
        report.checkpoints, 3,
        "after 10, after 20 more lines, at close"
    );
    assert_eq!(report.unsigned, 0);
    assert_eq!(report.signed_through, Some(report.lines - 1));
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| unreachable!("{e:?}"));
    assert!(!text.contains("192.0.2.7"), "no raw address in the chain");
    std::fs::remove_dir_all(&dir).unwrap_or_else(|e| unreachable!("{e:?}"));
}

#[test]
fn a_restarted_writer_continues_the_chain() {
    let dir = dir("restart");
    let path = dir.join("audit.jsonl");
    let (key, encoded) = SigningKey::generate().unwrap_or_else(|e| unreachable!("{e:?}"));
    let public = key.public_key();
    write(&path, key, 3, 1000);
    write(&path, same_key(&public, &encoded), 4, 1000);
    let report = check(&path, &public);
    assert!(report.ok(), "{report:?}");
    assert_eq!((report.entries, report.checkpoints), (7, 2));
    std::fs::remove_dir_all(&dir).unwrap_or_else(|e| unreachable!("{e:?}"));
}

/// A change to a log's lines.
type Edit = Box<dyn Fn(&mut Vec<String>)>;

/// The log at `path` with `edit` applied to its lines, checked.
fn tampered(path: &Path, public: &[u8], edit: impl Fn(&mut Vec<String>)) -> Report {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| unreachable!("{e:?}"));
    let mut lines: Vec<String> = text.lines().map(str::to_owned).collect();
    edit(&mut lines);
    let copy = path.with_extension("tampered");
    std::fs::write(&copy, lines.join("\n") + "\n").unwrap_or_else(|e| unreachable!("{e:?}"));
    check(&copy, public)
}

#[test]
fn every_kind_of_tampering_is_caught() {
    let dir = dir("tamper");
    let path = dir.join("audit.jsonl");
    let (key, public) = key();
    write(&path, key, 6, 1000);
    let edits: [(&str, Edit, u64); 5] = [
        (
            "a field changed",
            Box::new(|l| l[2] = l[2].replace("\"status\":200", "\"status\":500")),
            4,
        ),
        (
            "a line removed",
            Box::new(|l| {
                l.remove(1);
            }),
            2,
        ),
        ("lines swapped", Box::new(|l| l.swap(1, 2)), 2),
        ("a line added", Box::new(|l| l.insert(3, l[3].clone())), 5),
        (
            "the checkpoint changed",
            Box::new(|l| {
                let n = l.len() - 1;
                l[n] = l[n].replace("\"sig\":\"", "\"sig\":\"A");
            }),
            7,
        ),
    ];
    for (what, edit, line) in edits {
        let report = tampered(&path, &public, edit);
        let problem = report
            .problem
            .unwrap_or_else(|| panic!("{what}: not caught"));
        assert_eq!(problem.line, line, "{what}: {}", problem.what);
    }
    let (_, other) = self::key();
    assert!(!check(&path, &other).ok(), "another key's checkpoint");
    std::fs::remove_dir_all(&dir).unwrap_or_else(|e| unreachable!("{e:?}"));
}

#[test]
fn a_cut_tail_shows_as_unsigned_lines() {
    let dir = dir("tail");
    let path = dir.join("audit.jsonl");
    let (key, public) = key();
    write(&path, key, 6, 4);
    let report = tampered(&path, &public, |l| l.truncate(l.len() - 1));
    assert!(report.ok());
    assert_eq!(report.unsigned, 2, "two entries after the first checkpoint");
    std::fs::remove_dir_all(&dir).unwrap_or_else(|e| unreachable!("{e:?}"));
}

#[test]
fn a_partial_last_line_stops_the_writer_from_starting() {
    let dir = dir("partial");
    let path = dir.join("audit.jsonl");
    let (key, _) = key();
    std::fs::write(&path, "{\"seq\":0,").unwrap_or_else(|e| unreachable!("{e:?}"));
    let error = Sink::open(Settings::new(path, key, [0; 32])).unwrap_err();
    assert!(error.contains("incomplete"), "{error}");
    std::fs::remove_dir_all(&dir).unwrap_or_else(|e| unreachable!("{e:?}"));
}

#[test]
fn a_full_queue_is_recorded_as_a_gap() {
    let dir = dir("gap");
    let path = dir.join("audit.jsonl");
    let (key, public) = key();
    let mut settings = Settings::new(path.clone(), key, [0; 32]);
    settings.queue = 1;
    let sink = Sink::open(settings).unwrap_or_else(|e| unreachable!("{e:?}"));
    for n in 0..5000 {
        sink.record(request(&sink, n), None);
    }
    sink.close();
    sink.record(request(&sink, 0), None);
    let report = check(&path, &public);
    assert!(report.ok(), "{report:?}");
    assert_eq!(report.entries + report.dropped, 5000, "{report:?}");
    std::fs::remove_dir_all(&dir).unwrap_or_else(|e| unreachable!("{e:?}"));
}

#[test]
fn raw_addresses_stay_beside_the_chain_and_only_when_asked() {
    let dir = dir("raw");
    let raw = Raw {
        client: "192.0.2.7".into(),
        client_cert: None,
    };
    for days in [0, 1] {
        let path = dir.join(format!("audit-{days}.jsonl"));
        let (key, public) = key();
        let mut settings = Settings::new(path.clone(), key, [0; 32]);
        settings.raw_days = days;
        let sink = Sink::open(settings).unwrap_or_else(|e| unreachable!("{e:?}"));
        sink.record(request(&sink, 0), Some(raw.clone()));
        let admin = AdminEntry::new("dark", "route=pay".into(), true, "p".into());
        sink.record(Entry::Admin(admin), None);
        sink.close();
        let sidecar = dir.join(format!("audit-{days}.jsonl.raw"));
        assert_eq!(sidecar.exists(), days > 0);
        if days > 0 {
            assert!(
                std::fs::read_to_string(&sidecar)
                    .unwrap_or_else(|e| unreachable!("{e:?}"))
                    .contains("192.0.2.7")
            );
        }
        assert!(
            !std::fs::read_to_string(&path)
                .unwrap_or_else(|e| unreachable!("{e:?}"))
                .contains("192.0.2.7")
        );
        let report = check(&path, &public);
        assert!(report.ok(), "{report:?}");
        assert_eq!(report.entries, 2);
    }
    std::fs::remove_dir_all(&dir).unwrap_or_else(|e| unreachable!("{e:?}"));
}

#[test]
fn raw_days_over_thirty_are_refused() {
    let (key, _) = key();
    let mut settings = Settings::new(std::env::temp_dir().join("never"), key, [0; 32]);
    settings.raw_days = 31;
    assert!(Sink::open(settings).is_err());
}
