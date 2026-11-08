// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! CORS per route (G17): allowed origins get their headers, preflights are
//! answered by the gateway, other origins get nothing or a 403.

mod common;

use bytes::Bytes;
use http_body_util::Full;
use hyper::{HeaderMap, Method, Request, StatusCode};
use tunnelward_gateway::CorsRule;

use common::ingress::{h1, ingress_config, start_ingress};
use common::{Res, registration, start_connector};

const APP: &str = "https://app.example.org";

async fn rig(rules: Vec<CorsRule>) -> Res<String> {
    let (_gateway, connectors, ingress) =
        start_ingress(ingress_config(|i| i.cors = rules)?).await?;
    let _c = start_connector(&connectors, "echo", registration(1, &["mcp"], &[])).await?;
    Ok(ingress)
}

fn request(method: Method, path: &str, origin: &str, preflight: bool) -> Res<Request<Full<Bytes>>> {
    let mut r = Request::builder()
        .method(method)
        .uri(path)
        .header("host", "mcp.example.org")
        .header("origin", origin);
    if preflight {
        r = r.header("access-control-request-method", "POST").header(
            "access-control-request-headers",
            "content-type, mcp-session-id",
        );
    }
    Ok(r.body(Full::new(Bytes::new()))?)
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

fn app_rule() -> Vec<CorsRule> {
    vec![CorsRule::new("/mcp", vec![APP.into()])]
}

#[tokio::test]
async fn an_allowed_preflight_is_answered_by_the_gateway() -> Res<()> {
    let ingress = rig(app_rule()).await?;
    let (status, headers, body) =
        h1(&ingress, request(Method::OPTIONS, "/mcp", APP, true)?).await?;
    assert_eq!(
        (status, body.as_str()),
        (StatusCode::NO_CONTENT, ""),
        "not the connector's echo"
    );
    assert_eq!(header(&headers, "access-control-allow-origin"), Some(APP));
    let allowed = header(&headers, "access-control-allow-headers").unwrap_or_default();
    assert!(
        allowed.contains("mcp-session-id") && allowed.contains("authorization"),
        "{allowed}"
    );
    assert_eq!(header(&headers, "access-control-allow-credentials"), None);
    assert!(header(&headers, "tw-request-id").is_some());
    Ok(())
}

#[tokio::test]
async fn a_preflight_from_another_origin_is_refused() -> Res<()> {
    let ingress = rig(app_rule()).await?;
    let evil = request(Method::OPTIONS, "/mcp", "https://evil.example", true)?;
    let (status, headers, _) = h1(&ingress, evil).await?;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(header(&headers, "tw-error"), Some("TW-I007"));
    assert_eq!(header(&headers, "access-control-allow-origin"), None);
    Ok(())
}

#[tokio::test]
async fn an_allowed_origin_can_read_the_answer_and_its_headers() -> Res<()> {
    let ingress = rig(app_rule()).await?;
    let (status, headers, body) = h1(&ingress, request(Method::GET, "/mcp/x", APP, false)?).await?;
    assert_eq!((status, body.as_str()), (StatusCode::OK, "echo GET /mcp/x"));
    assert_eq!(header(&headers, "access-control-allow-origin"), Some(APP));
    assert_eq!(header(&headers, "vary"), Some("origin"));
    let exposed = header(&headers, "access-control-expose-headers").unwrap_or_default();
    assert!(
        exposed.contains("mcp-session-id") && exposed.contains("tw-request-id"),
        "{exposed}"
    );
    Ok(())
}

#[tokio::test]
async fn other_origins_and_other_paths_get_no_cors_headers() -> Res<()> {
    let ingress = rig(app_rule()).await?;
    let evil = request(Method::GET, "/mcp/x", "https://evil.example", false)?;
    let (_, headers, _) = h1(&ingress, evil).await?;
    assert_eq!(header(&headers, "access-control-allow-origin"), None);
    let elsewhere = request(Method::GET, "/mcpx", APP, false)?;
    let (_, headers, _) = h1(&ingress, elsewhere).await?;
    assert_eq!(header(&headers, "access-control-allow-origin"), None);
    Ok(())
}

#[tokio::test]
async fn without_rules_a_preflight_goes_to_the_connector() -> Res<()> {
    let ingress = rig(Vec::new()).await?;
    let (status, headers, body) =
        h1(&ingress, request(Method::OPTIONS, "/mcp", APP, true)?).await?;
    assert_eq!(
        (status, body.as_str()),
        (StatusCode::OK, "echo OPTIONS /mcp")
    );
    assert_eq!(header(&headers, "access-control-allow-origin"), None);
    Ok(())
}
