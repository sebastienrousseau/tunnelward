// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! The operator API (ADR 0012). Every request carries an OIDC bearer
//! token; its role decides what it may do.
//!
//! | Request                        | Role     | Does                              |
//! | :----------------------------- | :------- | :-------------------------------- |
//! | `GET /v1/bundles`              | viewer   | Every bundle's summary            |
//! | `GET /v1/fleet`                | viewer   | Each gateway's version, last seen |
//! | `POST /v1/policy` (TOML body)  | operator | Publishes the policy, if it checks |
//! | `POST /v1/rollback?to=<n>`     | admin    | Publishes bundle n's policy again |

use std::net::SocketAddr;
use std::time::SystemTime;

use http_body_util::{BodyExt, Limited};
use hyper::body::Incoming;
use hyper::{Method, Request, StatusCode};
use tunnelward_audit::{AdminEntry, Entry};
use tunnelward_gateway::Caller;

use super::roles::Role;
use super::server::{Answer, Control, json, text};

/// Longest policy accepted.
const MAX_POLICY: usize = 256 * 1024;

/// What a request asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Action {
    Bundles,
    Fleet,
    Publish,
    Rollback(Option<u64>),
}

/// The action `method` and `path` (with `query`) ask for, and the least
/// role allowed it.
fn route(method: &Method, path: &str, query: Option<&str>) -> Option<(Action, Role)> {
    let to = || {
        query
            .and_then(|q| q.strip_prefix("to="))
            .and_then(|v| v.parse().ok())
    };
    match (method.as_str(), path) {
        ("GET", "/v1/bundles") => Some((Action::Bundles, Role::Viewer)),
        ("GET", "/v1/fleet") => Some((Action::Fleet, Role::Viewer)),
        ("POST", "/v1/policy") => Some((Action::Publish, Role::Operator)),
        ("POST", "/v1/rollback") => Some((Action::Rollback(to()), Role::Admin)),
        _ => None,
    }
}

/// Answers one operator request from `peer`.
pub(crate) async fn answer(
    control: &Control,
    peer: SocketAddr,
    request: Request<Incoming>,
) -> Answer {
    let caller = match control.auth.bearer(request.headers(), SystemTime::now()) {
        Ok(caller) => caller,
        Err(why) => {
            let mut answer = text(StatusCode::UNAUTHORIZED, format!("{why}\n"));
            answer.headers_mut().insert(
                hyper::header::WWW_AUTHENTICATE,
                hyper::header::HeaderValue::from_static("Bearer"),
            );
            return answer;
        }
    };
    let Some((action, needed)) = route(
        request.method(),
        request.uri().path(),
        request.uri().query(),
    ) else {
        return text(StatusCode::NOT_FOUND, "not found\n");
    };
    match control.roles.of(&caller) {
        Some(role) if role >= needed => act(control, (peer, &caller), action, request).await,
        Some(role) => text(
            StatusCode::FORBIDDEN,
            format!(
                "{} needs the {} role; this token has {}\n",
                request.uri().path(),
                needed.name(),
                role.name()
            ),
        ),
        None => text(StatusCode::FORBIDDEN, "this token has no role\n"),
    }
}

async fn act(
    control: &Control,
    (peer, caller): (SocketAddr, &Caller),
    action: Action,
    request: Request<Incoming>,
) -> Answer {
    let actor = actor(caller);
    let (what, published) = match action {
        Action::Bundles => return json(StatusCode::OK, &control.store.history()),
        Action::Fleet => return json(StatusCode::OK, &control.fleet()),
        Action::Rollback(to) => ("rollback", rollback(control, to, &actor)),
        Action::Publish => ("publish", publish_body(control, request, &actor).await),
    };
    match published {
        Ok(summary) => {
            record(control, what, summary.version, peer, actor);
            json(StatusCode::CREATED, &summary)
        }
        Err(why) => text(StatusCode::BAD_REQUEST, format!("{why}\n")),
    }
}

/// Who the audit log names: the token's subject, else its client.
fn actor(caller: &Caller) -> String {
    caller
        .subject
        .clone()
        .or_else(|| caller.client_id.clone())
        .unwrap_or_else(|| "unnamed".to_owned())
}

/// Publishes bundle `to`'s policy again.
fn rollback(
    control: &Control,
    to: Option<u64>,
    actor: &str,
) -> Result<super::store::Summary, String> {
    let to = to.ok_or("name the version: ?to=<n>")?;
    publish(control, control.store.policy(to)?, actor)
}

/// Publishes the policy in `request`'s body.
async fn publish_body(
    control: &Control,
    request: Request<Incoming>,
    actor: &str,
) -> Result<super::store::Summary, String> {
    publish(control, body(request).await?, actor)
}

/// Checks `policy` as a gateway will, then publishes it.
fn publish(
    control: &Control,
    policy: String,
    actor: &str,
) -> Result<super::store::Summary, String> {
    crate::policy::parse(&policy, "policy").map_err(|problems| problems.join("; "))?;
    control.store.publish(policy, actor)
}

/// The request body as text, at most [`MAX_POLICY`] bytes.
async fn body(request: Request<Incoming>) -> Result<String, String> {
    let bytes = Limited::new(request.into_body(), MAX_POLICY)
        .collect()
        .await
        .map_err(|e| format!("body: {e}"))?
        .to_bytes();
    String::from_utf8(bytes.to_vec()).map_err(|_| "the policy is not UTF-8".to_owned())
}

/// An admin entry in the control's audit log, when it has one.
fn record(control: &Control, action: &str, version: u64, peer: SocketAddr, actor: String) {
    let Some(sink) = &control.audit else { return };
    let peer = sink.pseudonyms().of("ip", peer.ip().to_string().as_bytes());
    let entry = AdminEntry::new(action, format!("bundle={version}"), true, peer).by(actor);
    sink.record(Entry::Admin(entry), None);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_request_maps_to_one_action_and_its_least_role() {
        let get = Method::GET;
        let post = Method::POST;
        assert_eq!(
            route(&get, "/v1/bundles", None),
            Some((Action::Bundles, Role::Viewer))
        );
        assert_eq!(
            route(&get, "/v1/fleet", None),
            Some((Action::Fleet, Role::Viewer))
        );
        assert_eq!(
            route(&post, "/v1/policy", None),
            Some((Action::Publish, Role::Operator))
        );
        assert_eq!(
            route(&post, "/v1/rollback", Some("to=3")),
            Some((Action::Rollback(Some(3)), Role::Admin))
        );
        assert_eq!(
            route(&post, "/v1/rollback", Some("to=x")),
            Some((Action::Rollback(None), Role::Admin))
        );
        assert_eq!(route(&get, "/v1/policy", None), None);
        assert_eq!(route(&post, "/v1/bundles", None), None);
    }
}
