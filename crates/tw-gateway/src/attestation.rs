// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Admission by passmcp attestation (FR-5, ADR 0009).

use std::sync::{Arc, PoisonError};
use std::time::SystemTime;

use tunnelward_attest::Admission;
use tunnelward_proto::{Register, RejectCode};

use crate::{DrainReport, Gateway};

impl Gateway {
    /// Replaces the attestation rules, keys and revocations for the next
    /// registration; `None` turns admission by attestation off. Every
    /// connection admitted with a statement the new set revokes then
    /// drains, with `drain_grace`; the report says what that did.
    /// Connections admitted under the old rules otherwise keep their
    /// lease (ADR 0009).
    pub async fn set_admission(&self, admission: Option<Arc<Admission>>) -> DrainReport {
        self.inner
            .admission
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .clone_from(&admission);
        let Some(admission) = admission else {
            return DrainReport::default();
        };
        let revoked = self
            .inner
            .registry
            .mark_draining(|e| e.attested.is_some_and(|d| admission.is_revoked(&d)));
        self.finish(&revoked, self.inner.config.drain_grace).await
    }

    pub(crate) fn admission(&self) -> Option<Arc<Admission>> {
        self.inner
            .admission
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The digest of the statement that admits `register`, `None` when
    /// none of its routes needs one, or the refusal to send.
    pub(crate) fn attest(
        &self,
        register: &Register,
    ) -> Result<Option<[u8; 32]>, (RejectCode, String)> {
        let Some(admission) = self.admission() else {
            return Ok(None);
        };
        admission
            .admit(
                &register.routes,
                register.attestation.as_deref(),
                register.mcp.as_ref(),
                SystemTime::now(),
            )
            .map_err(|r| (r.code, r.reason))
    }
}
