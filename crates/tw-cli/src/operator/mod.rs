// SPDX-FileCopyrightText: 2026 Sebastien Rousseau
// SPDX-License-Identifier: GPL-3.0-only

//! `tunnelward operator`: the Kubernetes operator alpha (ADR 0015). It
//! keeps each `TunnelwardGateway` in its namespace running as its
//! resources, its `ConnectorBinding`s and its `RoutePolicy` say.
//!
//! In a pod it uses its service account; elsewhere, give `--server`,
//! `--token-file` and `--ca`. The manifests are in `deploy/operator`.

mod kube;
mod model;
mod plan;
mod reconcile;
mod render;

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::args::{Args, UsageError};
use crate::{Outcome, runtime};

/// `operator [--namespace <ns>] [--every-secs <n>] [--image <ref>]
/// [--server <url> --token-file <file> --ca <file>]`.
pub(crate) fn command(args: &[String]) -> Result<(), Outcome> {
    let known = [
        "namespace",
        "every-secs",
        "image",
        "server",
        "token-file",
        "ca",
    ];
    let args = Args::parse(args, &known)?;
    let kube = client(&args)?;
    let namespace = match args.get("namespace") {
        Some(ns) => ns.to_owned(),
        None => in_cluster_namespace().map_err(Outcome::Failed)?,
    };
    let image = args.get("image").map_or_else(
        || {
            format!(
                "ghcr.io/sebastienrousseau/tunnelward:{}",
                env!("CARGO_PKG_VERSION")
            )
        },
        str::to_owned,
    );
    let mut operator = reconcile::Operator::new(kube, namespace, image);
    if let Some(secs) = args.parsed::<u64>("every-secs")? {
        operator.every = Duration::from_secs(secs.clamp(1, 3600));
    }
    println!(
        "tunnelward operator: watching namespace {}",
        operator.namespace
    );
    runtime()?.block_on(operator.run());
    Ok(())
}

/// The API server `--server` names, else the cluster this pod runs in.
fn client(args: &Args) -> Result<kube::Kube, Outcome> {
    let Some(server) = args.get("server") else {
        return kube::Kube::in_cluster().map_err(Outcome::Failed);
    };
    let need = |flag: &str| {
        args.get(flag)
            .ok_or_else(|| UsageError(format!("operator --server needs '--{flag} <file>'")))
    };
    let (token, ca) = (need("token-file")?, need("ca")?);
    kube::Kube::new(server, PathBuf::from(token), Path::new(ca)).map_err(Outcome::Failed)
}

/// The namespace the pod runs in.
fn in_cluster_namespace() -> Result<String, String> {
    let file = "/var/run/secrets/kubernetes.io/serviceaccount/namespace";
    std::fs::read_to_string(file)
        .map(|ns| ns.trim().to_owned())
        .map_err(|e| format!("{file}: {e}; give --namespace"))
}
