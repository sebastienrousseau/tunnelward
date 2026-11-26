// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! The risk score, signal by signal, and FR-16's search-then-export run.

use std::time::{Duration, Instant};

use tunnelward_risk::{Counts, Request, Risk, Scope, Settings, Signal};

fn tools(names: &[&str]) -> Vec<String> {
    names.iter().map(|n| (*n).to_owned()).collect()
}

fn request<'a>(subject: &'a str, tools: &'a [String], body: &'a [u8]) -> Request<'a> {
    Request {
        subject,
        session: Some("session-1"),
        tools,
        body,
    }
}

#[test]
fn each_velocity_limit_crossed_adds_its_weight_once() {
    let risk = Risk::default();
    let calls = tools(&["search", "fetch"]);
    let under = Counts {
        subject: Some(120),
        tools: vec![Some(60), Some(60)],
        prefix: Some(600),
    };
    assert_eq!(risk.assess(&request("a", &calls, b""), &under).score, 0);
    let over = Counts {
        subject: Some(121),
        tools: vec![Some(61), Some(99)],
        prefix: Some(601),
    };
    let a = risk.assess(&request("b", &calls, b""), &over);
    assert_eq!(a.score, 100, "35 + 35 + 35, capped");
    let scopes: Vec<_> = (a.signals.iter())
        .filter_map(|s| match s {
            Signal::Velocity { scope, .. } => Some(*scope),
            _ => None,
        })
        .collect();
    assert_eq!(scopes, [Scope::Subject, Scope::Prefix, Scope::Tool]);
}

#[test]
fn a_count_the_store_could_not_give_is_skipped() {
    let risk = Risk::default();
    let calls = tools(&["search"]);
    let unknown = Counts {
        subject: None,
        tools: vec![None],
        prefix: None,
    };
    assert_eq!(risk.assess(&request("a", &calls, b""), &unknown).score, 0);
}

#[test]
fn a_new_step_after_the_warmup_is_drift() {
    let risk = Risk::new(Settings {
        warmup: 3,
        ..Settings::default()
    });
    let search = tools(&["search"]);
    for _ in 0..4 {
        assert_eq!(
            risk.assess(&request("a", &search, b""), &Counts::default())
                .score,
            0
        );
    }
    let export = tools(&["export"]);
    let a = risk.assess(&request("a", &export, b""), &Counts::default());
    assert_eq!(a.score, 25);
    assert_eq!(a.signals[0].to_string(), "drift:search->export");
    // export -> export is new once; the third export takes no new step,
    // so only the drift staying on the subject can score it.
    let _new_step = risk.assess(&request("a", &export, b""), &Counts::default());
    let known = risk.assess(&request("a", &export, b""), &Counts::default());
    assert_eq!(known.score, 25, "the drift stays for the window");
    let b = risk.assess(&request("b", &export, b""), &Counts::default());
    assert_eq!(b.score, 0, "another subject has its own baseline");
}

#[test]
fn a_canary_scores_100_and_blocks_subject_and_session() {
    let risk = Risk::new(Settings {
        canary_tools: vec!["export_all".into()],
        canary_records: vec!["CANARY-4417".into()],
        block: Duration::from_secs(60),
        ..Settings::default()
    });
    let fine = tools(&["search"]);
    let now = Instant::now();
    assert_eq!(
        risk.assess(&request("a", &fine, b"{}"), &Counts::default())
            .score,
        0
    );
    assert!(!risk.blocked("a", Some("session-1"), now));
    let record = risk.assess(
        &request("a", &fine, br#"{"q":"CANARY-4417"}"#),
        &Counts::default(),
    );
    assert_eq!((record.score, record.canary()), (100, true));
    assert!(risk.blocked("a", None, Instant::now()));
    assert!(risk.blocked("someone-else", Some("session-1"), Instant::now()));
    assert!(!risk.blocked("a", None, Instant::now() + Duration::from_secs(61)));
    let canary = tools(&["export_all"]);
    let tool = risk.assess(&request("b", &canary, b""), &Counts::default());
    assert_eq!(tool.signals, [Signal::CanaryTool("export_all".into())]);
}

/// FR-16's acceptance run: a script searches fast, then bulk-exports.
/// Each call is scored with the counts a store would give.
#[test]
fn a_scripted_search_then_bulk_export_run_crosses_the_alert() {
    let risk = Risk::new(Settings {
        per_subject: 40,
        per_tool: 30,
        ..Settings::default()
    });
    let alert = risk.settings().alert_at;
    let mut highest = 0;
    let (search, export) = (tools(&["search"]), tools(&["export"]));
    for n in 1..=25_u64 {
        let counts = Counts {
            subject: Some(n),
            tools: vec![Some(n)],
            prefix: Some(n),
        };
        let a = risk.assess(&request("script", &search, b""), &counts);
        assert!(a.score < alert, "25 searches alone stay under the alert");
        highest = highest.max(a.score);
    }
    for n in 1..=40_u64 {
        let counts = Counts {
            subject: Some(25 + n),
            tools: vec![Some(n)],
            prefix: Some(25 + n),
        };
        highest = highest.max(risk.assess(&request("script", &export, b""), &counts).score);
    }
    assert!(highest >= alert, "the run peaked at {highest}");
}
