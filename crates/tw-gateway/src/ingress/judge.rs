// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Judging a buffered request: its risk score (FR-16), then the tool
//! policy (FR-4).

use bytes::Bytes;
use http::Request;
use http_body_util::Full;

use super::Ingress;
use crate::RequestInfo;
use crate::refusal::Refusal;

impl Ingress {
    /// Scores the request (FR-16) and has the policy decide it: whether
    /// a call is to a high-impact tool.
    pub(super) async fn judge(
        &self,
        request: &Request<Full<Bytes>>,
        body: &Bytes,
        info: &mut RequestInfo,
    ) -> Result<bool, Refusal> {
        self.assess(request, body, info).await?;
        self.decide(request, body, info)
    }

    /// The policy's decision on every call in the request, if there is a
    /// policy: whether one is to a high-impact tool.
    fn decide(
        &self,
        request: &Request<Full<Bytes>>,
        body: &Bytes,
        info: &RequestInfo,
    ) -> Result<bool, Refusal> {
        let Some(engine) = self.gateway.policy() else {
            return Ok(false);
        };
        let verdict = crate::policy::decide(engine.as_ref(), request.method(), body, info)?;
        Ok(verdict == crate::policy::Verdict::Forward { high_impact: true })
    }
}
