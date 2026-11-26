// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! RED metrics per route (ADR 0010): requests by status class and a
//! duration histogram, each bucket keeping the trace id of its latest
//! request as an `OpenMetrics` exemplar.

use core::fmt::Write as _;
use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use http::StatusCode;

use crate::{ProxyObserver, RequestInfo};

/// Histogram bounds, in seconds.
const BOUNDS: [f64; 12] = [
    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

/// Most route labels; later routes are counted under `_other`.
const MAX_ROUTES: usize = 1024;

/// The label of a request no route served.
const UNROUTED: &str = "_none";

/// One route's counts.
#[derive(Debug, Default)]
struct Route {
    /// Requests by status class, 1xx to 5xx.
    by_class: [u64; 5],
    /// Requests at or under each bound, and over the last one.
    buckets: [u64; BOUNDS.len() + 1],
    /// The latest request in each bucket: its trace id and duration.
    exemplars: [Option<(String, f64)>; BOUNDS.len() + 1],
    sum_seconds: f64,
    count: u64,
}

/// Rate, errors and duration of ingress requests, per route.
#[derive(Debug, Default)]
pub(crate) struct Red {
    routes: Mutex<HashMap<String, Route>>,
}

impl ProxyObserver for Red {
    fn on_response(&self, info: &RequestInfo, status: StatusCode, elapsed: Duration) {
        let mut routes = self.routes.lock().unwrap_or_else(PoisonError::into_inner);
        let mut name = info.route.as_deref().unwrap_or(UNROUTED);
        if !routes.contains_key(name) && routes.len() >= MAX_ROUTES {
            name = "_other";
        }
        let route = routes.entry(name.to_owned()).or_default();
        let class = usize::from(status.as_u16() / 100).clamp(1, 5) - 1;
        route.by_class[class] += 1;
        let seconds = elapsed.as_secs_f64();
        let bucket = BOUNDS
            .iter()
            .position(|b| seconds <= *b)
            .unwrap_or(BOUNDS.len());
        route.buckets[bucket] += 1;
        route.exemplars[bucket] = Some((info.trace.trace_id.clone(), seconds));
        route.sum_seconds += seconds;
        route.count += 1;
    }
}

impl Red {
    /// The metrics in the Prometheus text format, or in `OpenMetrics` with
    /// exemplars.
    pub(crate) fn render(&self, openmetrics: bool) -> String {
        let routes = self.routes.lock().unwrap_or_else(PoisonError::into_inner);
        let mut names: Vec<&String> = routes.keys().collect();
        names.sort();
        let mut out = String::new();
        let family = if openmetrics {
            "tunnelward_requests"
        } else {
            "tunnelward_requests_total"
        };
        let _w = write!(
            out,
            "# HELP {family} Ingress requests by route and status class\n# TYPE {family} counter\n"
        );
        for name in &names {
            requests(&mut out, name, &routes[*name]);
        }
        out.push_str(
            "# HELP tunnelward_request_duration_seconds Ingress request duration, to the response headers\n\
             # TYPE tunnelward_request_duration_seconds histogram\n",
        );
        for name in &names {
            histogram(&mut out, name, &routes[*name], openmetrics);
        }
        out
    }
}

fn requests(out: &mut String, name: &str, route: &Route) {
    let label = escape(name);
    for (i, n) in route.by_class.iter().enumerate().filter(|(_, n)| **n > 0) {
        let _w = writeln!(
            out,
            "tunnelward_requests_total{{route=\"{label}\",code=\"{}xx\"}} {n}",
            i + 1
        );
    }
}

fn histogram(out: &mut String, name: &str, route: &Route, openmetrics: bool) {
    let label = escape(name);
    let mut cumulative = 0;
    for (i, n) in route.buckets.iter().enumerate() {
        cumulative += n;
        let le = BOUNDS
            .get(i)
            .map_or_else(|| "+Inf".to_owned(), ToString::to_string);
        let _w = write!(
            out,
            "tunnelward_request_duration_seconds_bucket{{route=\"{label}\",le=\"{le}\"}} {cumulative}"
        );
        if let (true, Some((trace, seconds))) = (openmetrics, &route.exemplars[i]) {
            let _w = write!(out, " # {{trace_id=\"{trace}\"}} {seconds}");
        }
        out.push('\n');
    }
    let _w = write!(
        out,
        "tunnelward_request_duration_seconds_sum{{route=\"{label}\"}} {}\n\
         tunnelward_request_duration_seconds_count{{route=\"{label}\"}} {}\n",
        route.sum_seconds, route.count
    );
}

/// A label value as the exposition formats quote it.
fn escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}
