// SPDX-FileCopyrightText: 2026 Sebastien Rousseau
// SPDX-License-Identifier: GPL-3.0-only

//! What each gateway gets, or why it gets nothing (ADR 0015): its
//! bindings and its policy checked, its file rendered and parsed as a
//! gateway file. A gateway any of them fails for keeps what it runs; the
//! resource that failed says why in its status.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};

use super::model::{API_PATH, Binding, Gateway, RoutePolicy};
use super::render::{Files, gateway_file};

/// One resource's status, by its API path.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Status {
    pub(crate) path: String,
    pub(crate) status: Value,
}

/// A gateway's files, or why there are none, and the status of each
/// binding and policy naming it.
#[derive(Debug)]
pub(crate) struct Plan {
    pub(crate) files: Result<Files, String>,
    pub(crate) statuses: Vec<Status>,
}

/// A Kubernetes condition.
pub(crate) fn condition(kind: &str, ok: bool, reason: &str, message: &str) -> Value {
    json!({
        "type": kind,
        "status": if ok { "True" } else { "False" },
        "reason": reason,
        "message": message,
    })
}

/// A status with one or more conditions, for `generation`.
pub(crate) fn status(generation: i64, conditions: &[Value]) -> Value {
    json!({ "observedGeneration": generation, "conditions": conditions })
}

pub(crate) fn path(namespace: &str, plural: &str, name: &str) -> String {
    format!("{API_PATH}/namespaces/{namespace}/{plural}/{name}")
}

/// Why `binding` cannot be used, if it cannot.
fn binding_problem(binding: &Binding) -> Option<String> {
    let spec = &binding.spec;
    if !tunnelward_proto::is_spiffe_id(&spec.identity) {
        return Some(format!("identity {:?} is not a SPIFFE ID", spec.identity));
    }
    if spec.routes.is_empty() {
        return Some("name at least one route".into());
    }
    let bad: Vec<&String> = spec
        .routes
        .iter()
        .filter(|r| !tunnelward_proto::is_route(r))
        .collect();
    (!bad.is_empty()).then(|| format!("not routes: {bad:?}"))
}

/// The plan for `gateway`, given every binding and policy in the
/// namespace.
pub(crate) fn plan(
    gateway: &Gateway,
    bindings: &[Binding],
    policies: &[RoutePolicy],
    namespace: &str,
) -> Plan {
    let mut problems = Vec::new();
    let mut statuses = Vec::new();
    let owners = owners(gateway, bindings, namespace, &mut statuses, &mut problems);
    let policy = policy(gateway, policies, namespace, &mut statuses, &mut problems);
    let files = if problems.is_empty() {
        let file = gateway_file(gateway, &owners, policy.is_some());
        toml::from_str::<crate::config::File>(&file)
            .map(|_| Files {
                gateway: file,
                policy,
            })
            .map_err(|e| format!("the gateway file does not parse: {e}"))
    } else {
        Err(problems.join("; "))
    };
    Plan { files, statuses }
}

/// The routes the valid bindings naming `gateway` own, by route;
/// statuses and problems noted.
fn owners(
    gateway: &Gateway,
    bindings: &[Binding],
    namespace: &str,
    statuses: &mut Vec<Status>,
    problems: &mut Vec<String>,
) -> BTreeMap<String, BTreeSet<String>> {
    let name = &gateway.metadata.name;
    let mut owners: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for binding in bindings.iter().filter(|b| &b.spec.gateway == name) {
        let problem = binding_problem(binding);
        let (ok, reason) = if problem.is_none() {
            (true, "Bound")
        } else {
            (false, "Invalid")
        };
        let message = problem
            .clone()
            .unwrap_or_else(|| format!("owns {} routes on {name}", binding.spec.routes.len()));
        statuses.push(Status {
            path: path(namespace, "connectorbindings", &binding.metadata.name),
            status: status(
                binding.metadata.generation,
                &[condition("Bound", ok, reason, &message)],
            ),
        });
        if let Some(p) = problem {
            problems.push(format!("ConnectorBinding {}: {p}", binding.metadata.name));
            continue;
        }
        for route in &binding.spec.routes {
            owners
                .entry(route.clone())
                .or_default()
                .insert(binding.spec.identity.clone());
        }
    }
    owners
}

/// The one policy naming `gateway`, checked; statuses and problems noted.
fn policy(
    gateway: &Gateway,
    policies: &[RoutePolicy],
    namespace: &str,
    statuses: &mut Vec<Status>,
    problems: &mut Vec<String>,
) -> Option<String> {
    let name = &gateway.metadata.name;
    let mine: Vec<&RoutePolicy> = policies
        .iter()
        .filter(|p| &p.spec.gateway == name)
        .collect();
    let several = mine.len() > 1;
    let mut accepted = None;
    for policy in &mine {
        let at = format!("RoutePolicy {}", policy.metadata.name);
        let checked = if several {
            Err(format!(
                "{} RoutePolicies name gateway {name}; keep one",
                mine.len()
            ))
        } else {
            crate::policy::parse(&policy.spec.policy, &at)
                .map(drop)
                .map_err(|p| p.join("; "))
        };
        let (ok, message) = match &checked {
            Ok(()) => (true, format!("applies to {name}")),
            Err(why) => (false, why.clone()),
        };
        statuses.push(Status {
            path: path(namespace, "routepolicies", &policy.metadata.name),
            status: status(
                policy.metadata.generation,
                &[condition(
                    "Accepted",
                    ok,
                    if ok { "Accepted" } else { "Invalid" },
                    &message,
                )],
            ),
        });
        match checked {
            Ok(()) => accepted = Some(policy.spec.policy.clone()),
            Err(why) => problems.push(format!("{at}: {why}")),
        }
    }
    accepted
}

/// The status of each binding and policy that names no gateway here.
pub(crate) fn orphans(
    gateways: &[Gateway],
    bindings: &[Binding],
    policies: &[RoutePolicy],
    namespace: &str,
) -> Vec<Status> {
    let known: BTreeSet<&str> = gateways.iter().map(|g| g.metadata.name.as_str()).collect();
    let missing = |gateway: &str| format!("no TunnelwardGateway {gateway} in {namespace}");
    let bound = bindings
        .iter()
        .filter(|b| !known.contains(b.spec.gateway.as_str()))
        .map(|b| Status {
            path: path(namespace, "connectorbindings", &b.metadata.name),
            status: status(
                b.metadata.generation,
                &[condition(
                    "Bound",
                    false,
                    "NoGateway",
                    &missing(&b.spec.gateway),
                )],
            ),
        });
    let accepted = policies
        .iter()
        .filter(|p| !known.contains(p.spec.gateway.as_str()))
        .map(|p| Status {
            path: path(namespace, "routepolicies", &p.metadata.name),
            status: status(
                p.metadata.generation,
                &[condition(
                    "Accepted",
                    false,
                    "NoGateway",
                    &missing(&p.spec.gateway),
                )],
            ),
        });
    bound.chain(accepted).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operator::model::{BindingSpec, Meta, PolicySpec, Resource};

    fn gateway() -> Gateway {
        crate::operator::render::tests::gateway(false)
    }

    fn binding(name: &str, identity: &str, routes: &[&str]) -> Binding {
        Resource {
            metadata: Meta {
                name: name.into(),
                uid: String::new(),
                generation: 1,
            },
            spec: BindingSpec {
                gateway: "edge".into(),
                identity: identity.into(),
                routes: routes.iter().map(|r| (*r).to_owned()).collect(),
            },
        }
    }

    fn policy(name: &str, text: &str) -> RoutePolicy {
        Resource {
            metadata: Meta {
                name: name.into(),
                uid: String::new(),
                generation: 2,
            },
            spec: PolicySpec {
                gateway: "edge".into(),
                policy: text.into(),
            },
        }
    }

    fn condition_of(plan: &Plan, path_end: &str) -> Value {
        let found = plan.statuses.iter().find(|s| s.path.ends_with(path_end));
        found.map_or(Value::Null, |s| s.status["conditions"][0].clone())
    }

    #[test]
    fn bindings_become_owners_and_the_policy_sits_beside_the_file() {
        let bindings = [
            binding("a", "spiffe://e.org/a", &["mcp/pay"]),
            binding("b", "spiffe://e.org/b", &["mcp/pay", "mcp/read"]),
        ];
        let plan = plan(
            &gateway(),
            &bindings,
            &[policy("p", "default = \"deny\"\n")],
            "prod",
        );
        let files = plan.files.as_ref().unwrap();
        let table: toml::Table = toml::from_str(&files.gateway).unwrap();
        let owners = table["connectors"]["owners"].as_array().unwrap();
        assert_eq!(owners.len(), 2, "one entry per route");
        assert_eq!(owners[0]["identities"].as_array().map(Vec::len), Some(2));
        assert_eq!(files.policy.as_deref(), Some("default = \"deny\"\n"));
        assert_eq!(
            condition_of(&plan, "/connectorbindings/a")["status"],
            "True"
        );
        assert_eq!(condition_of(&plan, "/routepolicies/p")["status"], "True");
    }

    #[test]
    fn a_bad_binding_or_policy_holds_the_gateway_back_and_says_why() {
        let bad_identity = plan(
            &gateway(),
            &[binding("x", "not-spiffe", &["mcp"])],
            &[],
            "prod",
        );
        assert!(bad_identity.files.is_err());
        assert_eq!(
            condition_of(&bad_identity, "/connectorbindings/x")["reason"],
            "Invalid"
        );
        let bad_policy = plan(
            &gateway(),
            &[],
            &[policy("p", "default = \"maybe\"\n")],
            "prod",
        );
        assert!(bad_policy.files.unwrap_err().contains("RoutePolicy p"));
        let two = plan(
            &gateway(),
            &[],
            &[
                policy("p", "default = \"deny\"\n"),
                policy("q", "default = \"deny\"\n"),
            ],
            "prod",
        );
        assert!(two.files.is_err());
        assert!(
            condition_of(&two, "/routepolicies/q")["message"]
                .as_str()
                .unwrap()
                .contains("keep one")
        );
        let mut broken = gateway();
        broken.spec.config = Some("[listen]\nconnectors = 1\n".into());
        assert!(
            plan(&broken, &[], &[], "prod")
                .files
                .unwrap_err()
                .contains("does not parse")
        );
    }

    #[test]
    fn a_binding_or_policy_naming_no_gateway_says_so() {
        let mut stray = binding("s", "spiffe://e.org/s", &["mcp"]);
        stray.spec.gateway = "gone".into();
        let found = orphans(&[gateway()], &[stray], &[], "prod");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].status["conditions"][0]["reason"], "NoGateway");
    }
}
