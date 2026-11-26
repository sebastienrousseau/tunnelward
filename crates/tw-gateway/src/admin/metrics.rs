// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! `/metrics`: the inventory's gauges, RED metrics per route, and the
//! span exporter's counts, in the Prometheus text format or, when the
//! scraper asks for it, `OpenMetrics` with exemplars (ADR 0010).

use core::fmt::Write as _;

use bytes::Bytes;
use http::header::{ACCEPT, CONTENT_TYPE};
use http::{HeaderMap, HeaderValue, Response};
use http_body_util::Full;

use super::{Answer, Redaction, inventory};
use crate::Gateway;

const PROMETHEUS: &str = "text/plain; version=0.0.4; charset=utf-8";
const OPENMETRICS: &str = "application/openmetrics-text; version=1.0.0; charset=utf-8";

/// Whether the scraper accepts `OpenMetrics`.
pub(super) fn openmetrics(headers: &HeaderMap) -> bool {
    headers
        .get_all(ACCEPT)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|v| v.contains("application/openmetrics-text"))
}

impl Gateway {
    pub(super) fn metrics(&self, openmetrics: bool) -> Answer {
        let mut body = inventory::metrics(&self.inventory(Redaction::Public));
        body.push_str(&self.inner.red.render(openmetrics));
        if let Some(otlp) = &self.inner.config.ingress.otlp {
            spans(&mut body, otlp, openmetrics);
        }
        if openmetrics {
            body.push_str("# EOF\n");
        }
        let mut response = Response::new(Full::new(Bytes::from(body)));
        let kind = if openmetrics { OPENMETRICS } else { PROMETHEUS };
        response
            .headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_static(kind));
        response
    }
}

fn spans(out: &mut String, otlp: &crate::OtlpExporter, openmetrics: bool) {
    let counters = [
        (
            "spans_dropped",
            "Spans dropped because the export queue was full",
            otlp.dropped(),
        ),
        (
            "span_batches_failed",
            "Span batches the collector did not accept",
            otlp.failed(),
        ),
    ];
    for (name, help, value) in counters {
        let family = if openmetrics {
            format!("tunnelward_{name}")
        } else {
            format!("tunnelward_{name}_total")
        };
        let _w = write!(
            out,
            "# HELP {family} {help}\n# TYPE {family} counter\ntunnelward_{name}_total {value}\n"
        );
    }
}
