// SPDX-FileCopyrightText: 2026 Sebastien Rousseau
// SPDX-License-Identifier: GPL-3.0-only

//! What a gateway's resources become (ADR 0015): its gateway file and
//! policy file, and the `ConfigMap`, `Deployment` and `Service`s the Helm chart
//! writes for the same gateway, under the same security settings.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use serde_json::{Value, json};

use super::model::{API_VERSION, Gateway};

/// Where the pod mounts the files.
const DIR: &str = "/etc/tunnelward";
const CONNECTORS: u16 = 7443;
const AGENTS: u16 = 8443;
const ADMIN: u16 = 9090;

/// A gateway's two files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Files {
    pub(crate) gateway: String,
    pub(crate) policy: Option<String>,
}

impl Files {
    /// SHA-256 of both, in hex: a change rolls the pods.
    pub(crate) fn digest(&self) -> String {
        let both = format!("{}\0{}", self.gateway, self.policy.as_deref().unwrap_or(""));
        tunnelward_audit::digest(both.as_bytes())
    }
}

/// `text` as a TOML basic string.
fn quoted(text: &str) -> String {
    let mut out = String::from("\"");
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c.is_control() => {
                let _ = write!(out, "\\u{:04X}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// The gateway file: listeners and TLS as the chart writes them, the
/// routes `owners` gives (route to identities), the policy file when
/// there is one, then the resource's own `config`.
pub(crate) fn gateway_file(
    gateway: &Gateway,
    owners: &BTreeMap<String, BTreeSet<String>>,
    policy: bool,
) -> String {
    let spec = &gateway.spec;
    let mut file = format!(
        "[listen]\nconnectors = \"0.0.0.0:{CONNECTORS}\"\ningress = \"0.0.0.0:{AGENTS}\"\n"
    );
    if spec.admin_token_secret.is_some() {
        let _ = writeln!(file, "admin = \"0.0.0.0:{ADMIN}\"");
    }
    let _ = write!(
        file,
        "\n[tls]\ncert = \"{DIR}/tls/tls.crt\"\nkey = \"{DIR}/tls/tls.key\"\nclient_ca = \"{DIR}/tls/ca.crt\"\nreload_secs = 10\n"
    );
    if spec.ingress_tls_secret.is_some() {
        let _ = write!(
            file,
            "\n[ingress]\ncert = \"{DIR}/ingress/tls.crt\"\nkey = \"{DIR}/ingress/tls.key\"\n"
        );
    }
    if spec.admin_token_secret.is_some() {
        file.push_str("\n[admin]\ntoken_env = \"TUNNELWARD_ADMIN_TOKEN\"\n");
    }
    for (route, identities) in owners {
        let identities: Vec<String> = identities.iter().map(|i| quoted(i)).collect();
        let _ = write!(
            file,
            "\n[[connectors.owners]]\nroute = {}\nidentities = [{}]\n",
            quoted(route),
            identities.join(", ")
        );
    }
    if policy {
        let _ = write!(file, "\n[policy]\nfile = \"{DIR}/config/policy.toml\"\n");
    }
    if let Some(config) = &spec.config {
        let _ = write!(file, "\n{}\n", config.trim_end());
    }
    file
}

/// The labels every object of `gateway` carries; the first two select
/// its pods.
fn labels(name: &str) -> Value {
    json!({
        "app.kubernetes.io/name": "tunnelward",
        "app.kubernetes.io/instance": name,
        "app.kubernetes.io/managed-by": "tunnelward-operator",
    })
}

fn selector(name: &str) -> Value {
    json!({ "app.kubernetes.io/name": "tunnelward", "app.kubernetes.io/instance": name })
}

/// Metadata for an object `gateway` owns, so deleting it deletes them.
fn metadata(gateway: &Gateway, name: &str) -> Value {
    json!({
        "name": name,
        "labels": labels(&gateway.metadata.name),
        "ownerReferences": [{
            "apiVersion": API_VERSION,
            "kind": "TunnelwardGateway",
            "name": gateway.metadata.name,
            "uid": gateway.metadata.uid,
            "controller": true,
        }],
    })
}

/// Every object of `gateway` with `files`, by its API path, in the order
/// to apply them: the `ConfigMap` before the `Deployment` that mounts it.
pub(crate) fn objects(
    gateway: &Gateway,
    files: &Files,
    namespace: &str,
    image: &str,
) -> Vec<(String, Value)> {
    let name = &gateway.metadata.name;
    let mut data = json!({ "tunnelward.toml": files.gateway });
    if let Some(policy) = &files.policy {
        data["policy.toml"] = json!(policy);
    }
    let core = format!("/api/v1/namespaces/{namespace}");
    let mut out = vec![(
        format!("{core}/configmaps/{name}-config"),
        json!({ "apiVersion": "v1", "kind": "ConfigMap", "metadata": metadata(gateway, &format!("{name}-config")), "data": data }),
    )];
    out.push((
        format!("/apis/apps/v1/namespaces/{namespace}/deployments/{name}"),
        deployment(gateway, &files.digest(), image),
    ));
    let mut ports = vec![("connectors", CONNECTORS), ("agents", AGENTS)];
    if gateway.spec.admin_token_secret.is_some() {
        ports.push(("admin", ADMIN));
    }
    for (port, number) in ports {
        let service = format!("{name}-{port}");
        out.push((
            format!("{core}/services/{service}"),
            self::service(gateway, &service, port, number),
        ));
    }
    out
}

fn service(gateway: &Gateway, name: &str, port: &str, number: u16) -> Value {
    let kind = match port {
        "admin" => "ClusterIP",
        _ => gateway.spec.service_type.as_deref().unwrap_or("ClusterIP"),
    };
    json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": metadata(gateway, name),
        "spec": {
            "type": kind,
            "selector": selector(&gateway.metadata.name),
            "ports": [{ "name": port, "port": number, "targetPort": port }],
        },
    })
}

fn deployment(gateway: &Gateway, digest: &str, image: &str) -> Value {
    let name = &gateway.metadata.name;
    let spec = &gateway.spec;
    json!({
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": metadata(gateway, name),
        "spec": {
            "replicas": spec.replicas,
            "selector": { "matchLabels": selector(name) },
            "template": {
                "metadata": {
                    "labels": labels(name),
                    "annotations": { "tunnelward.satellion.com/config-digest": digest },
                },
                "spec": {
                    "automountServiceAccountToken": false,
                    "securityContext": {
                        "runAsNonRoot": true, "runAsUser": 65532, "runAsGroup": 65532,
                        "fsGroup": 65532, "seccompProfile": { "type": "RuntimeDefault" },
                    },
                    "containers": [container(gateway, spec.image.as_deref().unwrap_or(image))],
                    "volumes": volumes(gateway),
                },
            },
        },
    })
}

fn container(gateway: &Gateway, image: &str) -> Value {
    let spec = &gateway.spec;
    let mut ports = vec![
        json!({ "name": "connectors", "containerPort": CONNECTORS }),
        json!({ "name": "agents", "containerPort": AGENTS }),
    ];
    let mut env = Vec::new();
    if let Some(secret) = &spec.admin_token_secret {
        ports.push(json!({ "name": "admin", "containerPort": ADMIN }));
        env.push(json!({
            "name": "TUNNELWARD_ADMIN_TOKEN",
            "valueFrom": { "secretKeyRef": { "name": secret.name, "key": secret.key } },
        }));
    }
    let mut mounts = vec![
        json!({ "name": "config", "mountPath": format!("{DIR}/config"), "readOnly": true }),
        json!({ "name": "tls", "mountPath": format!("{DIR}/tls"), "readOnly": true }),
    ];
    if spec.ingress_tls_secret.is_some() {
        mounts.push(json!({ "name": "ingress-tls", "mountPath": format!("{DIR}/ingress"), "readOnly": true }));
    }
    json!({
        "name": "gateway",
        "image": image,
        "args": ["gateway", "--config", format!("{DIR}/config/tunnelward.toml")],
        "ports": ports,
        "env": env,
        // TCP probes: the admin API wants a token a probe cannot carry.
        "startupProbe": { "tcpSocket": { "port": "connectors" }, "periodSeconds": 2, "failureThreshold": 30 },
        "livenessProbe": { "tcpSocket": { "port": "connectors" }, "periodSeconds": 10 },
        "readinessProbe": { "tcpSocket": { "port": "agents" }, "periodSeconds": 5 },
        "resources": { "requests": { "cpu": "100m", "memory": "64Mi" }, "limits": { "memory": "256Mi" } },
        "securityContext": {
            "allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true,
            "capabilities": { "drop": ["ALL"] },
        },
        "volumeMounts": mounts,
    })
}

fn volumes(gateway: &Gateway) -> Value {
    let name = &gateway.metadata.name;
    let mut volumes = vec![
        json!({ "name": "config", "configMap": { "name": format!("{name}-config") } }),
        json!({ "name": "tls", "secret": { "secretName": gateway.spec.tls_secret } }),
    ];
    if let Some(secret) = &gateway.spec.ingress_tls_secret {
        volumes.push(json!({ "name": "ingress-tls", "secret": { "secretName": secret } }));
    }
    Value::Array(volumes)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::operator::model::{GatewaySpec, Meta, Resource, SecretKey};

    pub(crate) fn gateway(admin: bool) -> Gateway {
        Resource {
            metadata: Meta {
                name: "edge".into(),
                uid: "u-1".into(),
                generation: 3,
            },
            spec: GatewaySpec {
                image: None,
                replicas: 2,
                tls_secret: "edge-tls".into(),
                ingress_tls_secret: None,
                admin_token_secret: admin.then(|| SecretKey {
                    name: "edge-admin".into(),
                    key: "token".into(),
                }),
                service_type: None,
                config: Some("[connectors]\nlease_secs = 600".into()),
            },
        }
    }

    #[test]
    fn strings_survive_the_round_trip_through_toml() {
        for text in [
            "plain",
            "a \"quote\" and \\ back",
            "tab\there",
            "é and \u{1}",
        ] {
            let parsed: toml::Table = toml::from_str(&format!("v = {}", quoted(text))).unwrap();
            assert_eq!(parsed["v"].as_str(), Some(text));
        }
    }

    #[test]
    fn the_file_is_a_gateway_file_with_owners_policy_and_extra_config() {
        let owners = BTreeMap::from([(
            "mcp/pay".to_owned(),
            BTreeSet::from(["spiffe://e.org/a".to_owned(), "spiffe://e.org/b".to_owned()]),
        )]);
        let file = gateway_file(&gateway(true), &owners, true);
        let parsed: crate::config::File =
            toml::from_str(&file).unwrap_or_else(|e| panic!("{e}\n{file}"));
        drop(parsed);
        let table: toml::Table = toml::from_str(&file).unwrap();
        let owner = &table["connectors"]["owners"][0];
        assert_eq!(owner["route"].as_str(), Some("mcp/pay"));
        assert_eq!(owner["identities"].as_array().map(Vec::len), Some(2));
        assert_eq!(table["connectors"]["lease_secs"].as_integer(), Some(600));
        assert_eq!(table["listen"]["admin"].as_str(), Some("0.0.0.0:9090"));
        assert!(
            table["policy"]["file"]
                .as_str()
                .unwrap()
                .ends_with("/config/policy.toml")
        );
        assert!(!gateway_file(&gateway(false), &BTreeMap::new(), false).contains("admin"));
    }

    #[test]
    fn the_objects_are_owned_and_a_changed_file_rolls_the_pods() {
        let files = Files {
            gateway: "a".into(),
            policy: Some("default = \"deny\"\n".into()),
        };
        let objects = objects(&gateway(true), &files, "prod", "ghcr.io/x/tunnelward:1");
        let paths: Vec<&str> = objects.iter().map(|(p, _)| p.as_str()).collect();
        assert_eq!(
            paths,
            [
                "/api/v1/namespaces/prod/configmaps/edge-config",
                "/apis/apps/v1/namespaces/prod/deployments/edge",
                "/api/v1/namespaces/prod/services/edge-connectors",
                "/api/v1/namespaces/prod/services/edge-agents",
                "/api/v1/namespaces/prod/services/edge-admin",
            ]
        );
        for (_, object) in &objects {
            assert_eq!(object["metadata"]["ownerReferences"][0]["uid"], "u-1");
        }
        let deployment = &objects[1].1;
        let pod = &deployment["spec"]["template"];
        assert_eq!(deployment["spec"]["replicas"], 2);
        assert_eq!(
            pod["spec"]["containers"][0]["image"],
            "ghcr.io/x/tunnelward:1"
        );
        assert_eq!(
            pod["spec"]["containers"][0]["securityContext"]["readOnlyRootFilesystem"],
            true
        );
        let digest = &pod["metadata"]["annotations"]["tunnelward.satellion.com/config-digest"];
        let changed = Files {
            policy: None,
            ..files
        };
        assert_ne!(digest, &json!(changed.digest()));
        assert_eq!(objects[0].1["data"]["policy.toml"], "default = \"deny\"\n");
    }
}
