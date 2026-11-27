// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Telemetry without the OpenTelemetry SDK (ADR 0010): RED metrics per
//! route on `/metrics`, with exemplars in `OpenMetrics`, and a span per
//! ingress request exported as OTLP/HTTP JSON.

mod otlp;
mod red;
mod span;

pub use otlp::{OtlpExporter, OtlpSettings};
pub(crate) use otlp::{post, signal_url};
pub(crate) use red::Red;
