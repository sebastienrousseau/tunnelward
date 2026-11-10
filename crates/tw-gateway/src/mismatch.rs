// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Mismatches between what a request says about itself and what the
//! gateway established (FR-14). A `User-Agent` or an MCP `clientInfo`
//! that names an AI provider is a claim, never identity; when the
//! provider the gateway saw (its published ranges, a verified signature)
//! is another one, or none, the claim does not hold, and that is worth
//! recording: a script dressed as Claude is a common way in.

use tunnelward_mcp::{Envelope, Kind};

use crate::RequestInfo;

/// Where a request's claim came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimSource {
    /// The `User-Agent` header.
    UserAgent,
    /// MCP `clientInfo.name`, from `initialize`.
    ClientInfo,
}

/// A claim the evidence does not back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mismatch {
    /// Where the claim was made.
    pub source: ClaimSource,
    /// The provider the request claims to come from, for example
    /// `anthropic`.
    pub claimed: &'static str,
    /// The provider the gateway saw, if any.
    pub seen: Option<String>,
}

/// The provider a self-description names, by the agent names they
/// publish: Anthropic's `Claude-User`, `ClaudeBot`, `Claude-SearchBot`;
/// `OpenAI`'s `ChatGPT-User`, `GPTBot`, `OAI-SearchBot`.
pub(crate) fn claimed_provider(text: &str) -> Option<&'static str> {
    let text = text.to_ascii_lowercase();
    let has = |words: &[&str]| words.iter().any(|w| text.contains(w));
    if has(&["claude", "anthropic"]) {
        Some("anthropic")
    } else if has(&["chatgpt", "openai", "gptbot", "oai-searchbot"]) {
        Some("openai")
    } else {
        None
    }
}

/// The mismatch of `text`'s claim, if it names a provider the gateway
/// did not see.
fn of(source: ClaimSource, text: &str, info: &RequestInfo) -> Option<Mismatch> {
    let claimed = claimed_provider(text)?;
    let seen = info.provider.as_ref().map(|p| p.provider.clone());
    (seen.as_deref() != Some(claimed)).then_some(Mismatch {
        source,
        claimed,
        seen,
    })
}

/// Records the `User-Agent`'s mismatch, once the provider tag is final.
pub(crate) fn from_user_agent(info: &mut RequestInfo) {
    let found = info
        .user_agent
        .as_deref()
        .and_then(|ua| of(ClaimSource::UserAgent, ua, info));
    info.mismatches.extend(found);
}

/// Records the mismatch of any `clientInfo` in a JSON-RPC `body`.
pub(crate) fn from_body(info: &mut RequestInfo, body: &[u8]) {
    let Ok(Envelope { messages, .. }) = tunnelward_mcp::parse(body) else {
        return;
    };
    let found: Vec<Mismatch> = messages
        .iter()
        .filter(|m| m.kind == Kind::Request)
        .filter_map(|m| m.client.as_ref())
        .filter_map(|c| of(ClaimSource::ClientInfo, &c.name, info))
        .collect();
    info.mismatches.extend(found);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn published_agent_names_name_their_provider() {
        for ua in [
            "Claude-User/1.0",
            "ClaudeBot",
            "Mozilla/5.0 (compatible; Claude-SearchBot)",
        ] {
            assert_eq!(claimed_provider(ua), Some("anthropic"), "{ua}");
        }
        for ua in [
            "ChatGPT-User/1.0",
            "GPTBot/1.1",
            "OAI-SearchBot/1.0",
            "openai-mcp",
        ] {
            assert_eq!(claimed_provider(ua), Some("openai"), "{ua}");
        }
        assert_eq!(claimed_provider("curl/8.7.1"), None);
        assert_eq!(claimed_provider("Mozilla/5.0 Safari"), None);
    }
}
