// SPDX-FileCopyrightText: 2026 Sebastien Rousseau
// SPDX-License-Identifier: GPL-3.0-only

//! The reconcile loop (ADR 0015): list the resources, plan each gateway,
//! apply what changed (everything again every `resync`), and write each
//! resource's status when it changes.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use serde::de::DeserializeOwned;
use serde_json::Value;

use super::kube::Kube;
use super::model::{API_PATH, Binding, Gateway, Resource, RoutePolicy};
use super::plan::{Plan, Status, condition, orphans, path, plan, status};
use super::render::objects;

/// The operator's state between passes.
pub(crate) struct Operator {
    pub(crate) kube: Kube,
    pub(crate) namespace: String,
    /// The image a gateway runs when it names none.
    pub(crate) image: String,
    pub(crate) every: Duration,
    pub(crate) resync: Duration,
    /// The digest last applied, by gateway.
    applied: HashMap<String, String>,
    /// The status last written, by resource path.
    written: HashMap<String, Value>,
    last_full: Option<Instant>,
}

impl Operator {
    pub(crate) fn new(kube: Kube, namespace: String, image: String) -> Self {
        Self {
            kube,
            namespace,
            image,
            every: Duration::from_secs(10),
            resync: Duration::from_secs(300),
            applied: HashMap::new(),
            written: HashMap::new(),
            last_full: None,
        }
    }

    /// Reconciles every `every` until stopped; a failed pass is reported
    /// and the next one tries again.
    pub(crate) async fn run(mut self) {
        loop {
            if let Err(e) = self.pass().await {
                eprintln!("tunnelward operator: {e}");
            }
            tokio::time::sleep(self.every).await;
        }
    }

    /// One pass over the namespace.
    pub(crate) async fn pass(&mut self) -> Result<(), String> {
        let gateways: Vec<Gateway> = self.list("tunnelwardgateways").await?;
        let bindings: Vec<Binding> = self.list("connectorbindings").await?;
        let policies: Vec<RoutePolicy> = self.list("routepolicies").await?;
        let full = self.last_full.is_none_or(|t| t.elapsed() >= self.resync);
        if full {
            self.last_full = Some(Instant::now());
        }
        let mut statuses = orphans(&gateways, &bindings, &policies, &self.namespace);
        for gateway in &gateways {
            let plan = plan(gateway, &bindings, &policies, &self.namespace);
            statuses.push(self.gateway(gateway, &plan, full).await);
            statuses.extend(plan.statuses);
        }
        self.applied
            .retain(|name, _| gateways.iter().any(|g| &g.metadata.name == name));
        for s in statuses {
            self.write(s).await;
        }
        Ok(())
    }

    /// Every resource of kind `plural` in the namespace; one that does not
    /// parse is reported and left out.
    async fn list<S: DeserializeOwned>(&self, plural: &str) -> Result<Vec<Resource<S>>, String> {
        let at = format!("{API_PATH}/namespaces/{}/{plural}", self.namespace);
        let list = self
            .kube
            .get(&at)
            .await?
            .ok_or_else(|| format!("{at}: not found; are the CRDs installed?"))?;
        let items = list
            .get("items")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        Ok(items
            .into_iter()
            .filter_map(|item| {
                serde_json::from_value(item)
                    .map_err(|e| {
                        eprintln!("tunnelward operator: a {plural} item does not parse: {e}");
                    })
                    .ok()
            })
            .collect())
    }

    /// Applies `gateway`'s objects when they changed (or `full`), and its
    /// status: whether its plan was accepted, and whether it is ready.
    async fn gateway(&mut self, gateway: &Gateway, plan: &Plan, full: bool) -> Status {
        let name = &gateway.metadata.name;
        let accepted = match &plan.files {
            Ok(files) => self.apply(gateway, files, full).await,
            Err(why) => Err(why.clone()),
        };
        let accepted = match &accepted {
            Ok(()) => condition(
                "Accepted",
                true,
                "Rendered",
                "the gateway file and its objects are applied",
            ),
            Err(why) => condition("Accepted", false, "Invalid", why),
        };
        Status {
            path: path(&self.namespace, "tunnelwardgateways", name),
            status: status(
                gateway.metadata.generation,
                &[accepted, self.ready(gateway).await],
            ),
        }
    }

    async fn apply(
        &mut self,
        gateway: &Gateway,
        files: &super::render::Files,
        full: bool,
    ) -> Result<(), String> {
        let digest = files.digest();
        if !full && self.applied.get(&gateway.metadata.name) == Some(&digest) {
            return Ok(());
        }
        for (at, object) in objects(gateway, files, &self.namespace, &self.image) {
            self.kube.apply(&at, &object).await?;
        }
        println!(
            "tunnelward operator: applied gateway {} ({})",
            gateway.metadata.name,
            &digest[..12]
        );
        self.applied.insert(gateway.metadata.name.clone(), digest);
        Ok(())
    }

    /// Whether `gateway`'s Deployment has all its replicas ready.
    async fn ready(&self, gateway: &Gateway) -> Value {
        let at = format!(
            "/apis/apps/v1/namespaces/{}/deployments/{}",
            self.namespace, gateway.metadata.name
        );
        let deployment = self.kube.get(&at).await.ok().flatten();
        let count = |key: &str| {
            deployment
                .as_ref()
                .and_then(|d| d["status"][key].as_u64())
                .unwrap_or(0)
        };
        let want = u64::from(gateway.spec.replicas);
        let ready = count("readyReplicas");
        let message = format!("{ready} of {want} replicas ready");
        condition(
            "Ready",
            ready >= want,
            if ready >= want { "Ready" } else { "Waiting" },
            &message,
        )
    }

    /// Writes `status` unless it is what was written last.
    async fn write(&mut self, status: Status) {
        if self.written.get(&status.path) == Some(&status.status) {
            return;
        }
        match self.kube.status(&status.path, &status.status).await {
            Ok(()) => {
                self.written.insert(status.path, status.status);
            }
            Err(e) => eprintln!("tunnelward operator: {e}"),
        }
    }
}
