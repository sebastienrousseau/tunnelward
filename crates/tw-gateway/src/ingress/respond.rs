// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! How the ingress answers: a connector's stream with observers and the
//! audit log attached, the gateway's own refusal, and the audit record of
//! an answer the gateway holds whole.

use std::time::Instant;

use bytes::Bytes;
use http::header::{CONTENT_TYPE, RETRY_AFTER, WWW_AUTHENTICATE};
use http::{HeaderValue, Response};
use http_body_util::{BodyExt, Full};

use super::{Ingress, IngressBody, TW_ERROR};
use crate::answers::stamp_request_id;
use crate::audit::Decision;
use crate::observed::{Audited, Observed};
use crate::refusal::Refusal;
use crate::{RequestInfo, ResponseBody};

impl Ingress {
    pub(super) fn observed(
        &self,
        response: Response<ResponseBody>,
        mut info: RequestInfo,
        started: Instant,
    ) -> Response<IngressBody> {
        let observers = self.gateway.inner.config.ingress.observers.clone();
        for o in &observers {
            o.on_response(&info, response.status(), started.elapsed());
        }
        let mut response = response;
        stamp_request_id(response.headers_mut(), &info);
        let audit = self.gateway.inner.config.audit.clone().map(|sink| {
            let status = response.status().as_u16();
            if let Some(value) =
                crate::audit::receipt(&sink, &mut info, status, Decision::Forwarded)
            {
                response.headers_mut().insert(crate::audit::RECEIPT, value);
            }
            Audited::new(sink, status)
        });
        response.map(|body| {
            Observed {
                inner: body,
                observers,
                info,
                started,
                bytes: 0,
                done: false,
                audit,
            }
            .boxed()
        })
    }
    /// Records a whole answer the gateway holds: its receipt, and its
    /// entry with the digest of `body` when it is known.
    pub(super) fn audited(
        &self,
        mut response: Response<IngressBody>,
        info: &RequestInfo,
        decision: Decision,
        body: Option<&[u8]>,
        started: Instant,
    ) -> Response<IngressBody> {
        let sink = self.gateway.inner.config.audit.as_ref();
        if sink.is_some() {
            use hyper::body::Body as _;
            let ended = crate::audit::Ended {
                status: response.status().as_u16(),
                decision,
                bytes: body.map_or_else(|| response.body().size_hint().lower(), |b| b.len() as u64),
                result_digest: body.map(tunnelward_audit::digest),
                started,
            };
            let mut info = info.clone();
            crate::audit::answered(sink, &mut info, response.headers_mut(), ended);
        }
        response
    }
    pub(super) fn refuse(
        &self,
        info: &RequestInfo,
        refusal: &Refusal,
        started: Instant,
    ) -> Response<IngressBody> {
        let observers = &self.gateway.inner.config.ingress.observers;
        for o in observers {
            o.on_failure(info, refusal.status, &refusal.reason);
        }
        for o in observers {
            o.on_response(info, refusal.status, started.elapsed());
        }
        let url = tunnelward_proto::error_url(refusal.id);
        let body = refusal.json.clone().unwrap_or_else(|| {
            let text = format!(
                "{}: {} [{}] {url}\n",
                refusal.status, refusal.reason, refusal.id
            );
            Bytes::from(text)
        });
        let sent = body.clone();
        let mut response = Response::new(Full::new(body).map_err(|e| match e {}).boxed());
        if refusal.json.is_some() {
            let json = HeaderValue::from_static("application/json");
            response.headers_mut().insert(CONTENT_TYPE, json);
        }
        *response.status_mut() = refusal.status;
        response
            .headers_mut()
            .insert(TW_ERROR, HeaderValue::from_static(refusal.id));
        stamp_request_id(response.headers_mut(), info);
        if let Some(value) = refusal
            .challenge
            .as_deref()
            .and_then(|c| HeaderValue::from_str(c).ok())
        {
            response.headers_mut().insert(WWW_AUTHENTICATE, value);
        }
        if let Some(wait) = refusal.retry_after {
            let secs = wait.as_secs() + u64::from(wait.subsec_nanos() > 0);
            response
                .headers_mut()
                .insert(RETRY_AFTER, HeaderValue::from(secs.max(1)));
        }
        let decision = Decision::Refused(refusal.id);
        self.audited(response, info, decision, Some(&sent), started)
    }
}
