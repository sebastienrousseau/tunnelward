// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! The approval page on the ingress (FR-17, ADR 0014): answered by the
//! gateway, rate limited like any request, never forwarded.

use std::sync::Arc;
use std::time::Instant;

use http::Request;
use http_body_util::BodyExt;
use hyper::body::Incoming;

use super::{Ingress, IngressBody};
use crate::answers::stamp_request_id;
use crate::audit::Decision;
use crate::{Approvals, RequestInfo};

impl Ingress {
    /// The approvals, when they are on and `request` is for their page.
    pub(super) fn approvals_for(&self, request: &Request<Incoming>) -> Option<Arc<Approvals>> {
        let approvals = self.gateway.inner.config.ingress.approvals.clone()?;
        crate::approval::is_path(request.uri().path()).then_some(approvals)
    }

    pub(super) async fn approval(
        &self,
        approvals: &Approvals,
        request: Request<Incoming>,
        info: RequestInfo,
        started: Instant,
    ) -> http::Response<IngressBody> {
        let config = &self.gateway.inner.config;
        if let Err(refusal) = self.admit(&request, &info).await {
            return self.refuse(&info, &refusal, started);
        }
        let cx = crate::approval::Context {
            approvals,
            state: config.state.as_ref(),
            audit: config.audit.as_deref(),
            info: &info,
        };
        let response = crate::approval::respond(&cx, request).await;
        let mut response = response.map(|b| b.map_err(|e| match e {}).boxed());
        stamp_request_id(response.headers_mut(), &info);
        self.audited(response, &info, Decision::Answered, None, started)
    }
}
