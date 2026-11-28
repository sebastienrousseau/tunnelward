// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Stopping on a signal: SIGTERM (Kubernetes, systemd) or SIGINT (Ctrl-C)
//! on Unix, Ctrl-C on Windows. The gateway and the connector then stop
//! taking new work and let what is in flight finish (FR-7, G7).

/// Resolves when the process is asked to stop. If the signal cannot be
/// watched it never resolves, and the process stops as it did before.
pub(crate) async fn stop_asked() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let (Ok(mut term), Ok(mut int)) = (
            signal(SignalKind::terminate()),
            signal(SignalKind::interrupt()),
        ) else {
            return std::future::pending().await;
        };
        tokio::select! {
            _ = term.recv() => {}
            _ = int.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        if tokio::signal::ctrl_c().await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}
