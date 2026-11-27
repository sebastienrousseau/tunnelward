// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! An agent with a token from its issuer, bound to its `DPoP` key, as
//! the high-impact tests (FR-13, FR-17) use it: its user is `alice`.

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Request, StatusCode};

use super::Res;
use super::ingress::h1;
use super::jwt::{Signer, now};

pub const ISSUER: &str = "https://as.example.org";
pub const RESOURCE: &str = "https://mcp.example.org";

/// The agent: its issuer and its `DPoP` key.
pub struct Agent {
    pub issuer: Signer,
    pub key: Signer,
}

pub fn agent() -> Res<Agent> {
    Ok(Agent {
        issuer: Signer::es256("as")?,
        key: Signer::eddsa("agent")?,
    })
}

/// A token for the agent, bound to its key when `bound`.
pub fn token(agent: &Agent, bound: bool) -> Res<String> {
    let cnf = if bound {
        format!(r#","cnf":{{"jkt":"{}"}}"#, agent.key.thumbprint())
    } else {
        String::new()
    };
    agent.issuer.token(&format!(
        r#"{{"iss":"{ISSUER}","aud":"{RESOURCE}","exp":{},"client_id":"agent","sub":"alice"{cnf}}}"#,
        now() + 600
    ))
}

/// POSTs a `transfer` of `amount`, with a fresh proof, and `key` when given.
pub async fn transfer(
    ingress: &str,
    agent: &Agent,
    (amount, key): (u32, Option<&str>),
    bound: bool,
) -> Res<(StatusCode, hyper::HeaderMap, String)> {
    let t = token(agent, bound)?;
    let body = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"transfer","arguments":{{"amount":{amount}}}}}}}"#
    );
    let mut request = Request::post("/mcp")
        .header("host", "mcp.example.org")
        .header("content-type", "application/json");
    if bound {
        let jti = format!("{amount}-{}", now_nanos());
        let proof = agent
            .key
            .proof("POST", &format!("{RESOURCE}/mcp"), &t, now(), &jti)?;
        request = request
            .header("authorization", format!("DPoP {t}"))
            .header("dpop", proof);
    } else {
        request = request.header("authorization", format!("Bearer {t}"));
    }
    if let Some(k) = key {
        request = request.header("idempotency-key", k);
    }
    h1(ingress, request.body(Full::new(Bytes::from(body)))?).await
}

pub fn now_nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos())
}
