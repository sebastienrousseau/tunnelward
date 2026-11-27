// SPDX-FileCopyrightText: 2026 Sebastien Rousseau
// SPDX-License-Identifier: GPL-3.0-only

//! The operator's custom resources (ADR 0015), as the API server sends
//! them: `tunnelward.satellion.com/v1alpha1`, namespaced.

use serde::Deserialize;

/// The API group and version of every resource here.
pub(crate) const API_VERSION: &str = "tunnelward.satellion.com/v1alpha1";
/// The group's path on the API server.
pub(crate) const API_PATH: &str = "/apis/tunnelward.satellion.com/v1alpha1";

/// What the operator reads of an object's metadata.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub(crate) struct Meta {
    pub(crate) name: String,
    #[serde(default)]
    pub(crate) uid: String,
    #[serde(default)]
    pub(crate) generation: i64,
}

/// One custom resource: its metadata and spec.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub(crate) struct Resource<S> {
    pub(crate) metadata: Meta,
    pub(crate) spec: S,
}

/// A Secret's key.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub(crate) struct SecretKey {
    pub(crate) name: String,
    #[serde(default = "token")]
    pub(crate) key: String,
}

fn token() -> String {
    "token".to_owned()
}

/// A gateway, rendered as the Helm chart renders one.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GatewaySpec {
    /// The image; the operator's own version by default.
    pub(crate) image: Option<String>,
    #[serde(default = "one")]
    pub(crate) replicas: u32,
    /// A Secret with `tls.crt`, `tls.key` and `ca.crt`: the connector
    /// listener's certificate and the roots connectors chain to.
    pub(crate) tls_secret: String,
    /// A Secret with `tls.crt` and `tls.key` for agents; plain HTTP
    /// without one.
    pub(crate) ingress_tls_secret: Option<String>,
    /// The admin API's token; no admin API without one.
    pub(crate) admin_token_secret: Option<SecretKey>,
    /// The Services' type (`ClusterIP` by default).
    pub(crate) service_type: Option<String>,
    /// More of the gateway file, appended as written.
    pub(crate) config: Option<String>,
}

fn one() -> u32 {
    1
}

/// Routes a connector identity owns on a gateway (FR-3).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub(crate) struct BindingSpec {
    pub(crate) gateway: String,
    pub(crate) identity: String,
    pub(crate) routes: Vec<String>,
}

/// A gateway's tool policy: the policy file, as TOML.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub(crate) struct PolicySpec {
    pub(crate) gateway: String,
    pub(crate) policy: String,
}

pub(crate) type Gateway = Resource<GatewaySpec>;
pub(crate) type Binding = Resource<BindingSpec>;
pub(crate) type RoutePolicy = Resource<PolicySpec>;
