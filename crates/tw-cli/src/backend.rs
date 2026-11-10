// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! The connector file's `[target]`: the local service it serves, over
//! HTTP, or a stdio MCP server it starts per session (FR-6).
//!
//! ```toml
//! [target]
//! url = "http://127.0.0.1:8080"         # or unix:/path/to/socket
//!
//! # or, instead of url:
//! # stdio = ["npx", "-y", "@modelcontextprotocol/server-everything"]
//! # env = { API_KEY = "..." }          # added to the server's environment
//! # max_sessions = 16                  # one process per MCP session
//! # idle_secs = 600                    # an unused session ends after this
//! ```

use std::collections::BTreeMap;
use std::time::Duration;

use serde::Deserialize;
use tunnelward_connector::{StdioConfig, Target};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TargetPart {
    url: Option<String>,
    stdio: Option<Vec<String>>,
    #[serde(default)]
    env: BTreeMap<String, String>,
    max_sessions: Option<usize>,
    idle_secs: Option<u64>,
}

/// What the connector serves.
#[derive(Debug, Clone)]
pub(crate) enum Backend {
    Http(Target),
    Stdio(StdioConfig),
}

impl Backend {
    /// A line for the log.
    pub(crate) fn describe(&self) -> String {
        match self {
            Self::Http(target) => format!("forwarding to {target:?}"),
            Self::Stdio(config) => format!("bridging to the stdio server {}", config.program),
        }
    }
}

/// `http://host:port` or `unix:/path`.
fn target(url: &str) -> Result<Target, String> {
    if let Some(addr) = url.strip_prefix("http://") {
        let addr = addr.trim_end_matches('/');
        if addr.contains(':') && !addr.contains('/') {
            return Ok(Target::Http {
                addr: addr.to_owned(),
            });
        }
    }
    #[cfg(unix)]
    if let Some(path) = url.strip_prefix("unix:") {
        return Ok(Target::Unix {
            path: std::path::PathBuf::from(path),
        });
    }
    Err(format!(
        "[target] url {url:?}: give http://host:port or unix:/path"
    ))
}

fn stdio(part: &TargetPart, command: &[String]) -> Result<StdioConfig, String> {
    let [program, args @ ..] = command else {
        return Err("[target] stdio: give the command, then its arguments".into());
    };
    let mut config = StdioConfig::new(program.clone(), args.to_vec());
    config.env = part
        .env
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    if let Some(n) = part.max_sessions {
        config.max_sessions = n.max(1);
    }
    if let Some(secs) = part.idle_secs {
        config.idle = Duration::from_secs(secs.max(1));
    }
    Ok(config)
}

/// The `[target]`: `url` or `stdio`, not both.
pub(crate) fn backend(part: &TargetPart) -> Result<Backend, String> {
    let stdio_only = part.env.is_empty() && part.max_sessions.is_none() && part.idle_secs.is_none();
    match (&part.url, &part.stdio) {
        (Some(url), None) if stdio_only => target(url).map(Backend::Http),
        (Some(_), None) => Err("[target]: env, max_sessions and idle_secs go with stdio".into()),
        (None, Some(command)) => stdio(part, command).map(Backend::Stdio),
        _ => Err("[target]: give url or stdio, not both".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn part(text: &str) -> Result<TargetPart, toml::de::Error> {
        toml::from_str(text)
    }

    #[test]
    fn a_target_is_a_url_or_a_stdio_command() -> Result<(), Box<dyn std::error::Error>> {
        assert!(matches!(
            backend(&part("url = \"http://127.0.0.1:8080\"")?)?,
            Backend::Http(_)
        ));
        let stdio = backend(&part("stdio = [\"server\", \"--flag\"]\nidle_secs = 30")?)?;
        let Backend::Stdio(config) = stdio else {
            return Err("not stdio".into());
        };
        assert_eq!(
            (config.program.as_str(), config.args.as_slice()),
            ("server", &["--flag".to_owned()][..])
        );
        assert_eq!(config.idle, Duration::from_secs(30));
        for bad in [
            "",
            "url = \"http://h:1\"\nstdio = [\"x\"]",
            "stdio = []",
            "url = \"http://h:1\"\nidle_secs = 5",
            "url = \"ftp://h\"",
        ] {
            assert!(backend(&part(bad)?).is_err(), "{bad:?}");
        }
        Ok(())
    }
}
