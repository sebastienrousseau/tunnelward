// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Roles from a token claim (ADR 0012). Each role includes the ones
//! below it: `viewer` reads, `operator` also publishes, `admin` also
//! rolls back.
//!
//! ```toml
//! [roles]
//! claim = "groups"                  # default; a string or a list of strings
//! viewer = ["tw-viewers"]
//! operator = ["tw-operators"]
//! admin = ["tw-admins"]
//! ```

use serde::Deserialize;
use serde_json::Value;
use tunnelward_gateway::Caller;

/// What a caller may do; a higher role may do everything a lower one may.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Role {
    Viewer,
    Operator,
    Admin,
}

impl Role {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Viewer => "viewer",
            Self::Operator => "operator",
            Self::Admin => "admin",
        }
    }
}

/// The control file's `[roles]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Roles {
    #[serde(default = "groups")]
    claim: String,
    #[serde(default)]
    viewer: Vec<String>,
    #[serde(default)]
    operator: Vec<String>,
    #[serde(default)]
    admin: Vec<String>,
}

fn groups() -> String {
    "groups".to_owned()
}

impl Roles {
    /// The highest role `caller`'s claim grants, if any.
    pub(crate) fn of(&self, caller: &Caller) -> Option<Role> {
        let values: Vec<&str> = match caller.claims.get(&self.claim) {
            Some(Value::String(one)) => vec![one.as_str()],
            Some(Value::Array(many)) => many.iter().filter_map(Value::as_str).collect(),
            _ => return None,
        };
        let has = |names: &[String]| names.iter().any(|n| values.contains(&n.as_str()));
        [
            (Role::Admin, &self.admin),
            (Role::Operator, &self.operator),
            (Role::Viewer, &self.viewer),
        ]
        .into_iter()
        .find_map(|(role, names)| has(names).then_some(role))
    }

    /// Why the section is unusable, if it is.
    pub(crate) fn problem(&self) -> Option<String> {
        let none = self.viewer.is_empty() && self.operator.is_empty() && self.admin.is_empty();
        none.then(|| "[roles]: name at least one group for viewer, operator or admin".to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roles() -> Roles {
        toml::from_str("viewer = [\"v\"]\noperator = [\"o\"]\nadmin = [\"a\"]\n").unwrap()
    }

    fn caller(claims: &str) -> Caller {
        let mut caller = Caller::default();
        caller.claims = serde_json::from_str(claims).unwrap();
        caller
    }

    #[test]
    fn the_highest_listed_group_wins() {
        let roles = roles();
        assert_eq!(
            roles.of(&caller(r#"{"groups":["v","a"]}"#)),
            Some(Role::Admin)
        );
        assert_eq!(roles.of(&caller(r#"{"groups":"o"}"#)), Some(Role::Operator));
        assert_eq!(roles.of(&caller(r#"{"groups":["v"]}"#)), Some(Role::Viewer));
        assert_eq!(roles.of(&caller(r#"{"groups":["x"]}"#)), None);
        assert_eq!(
            roles.of(&caller(r#"{"roles":["a"]}"#)),
            None,
            "another claim"
        );
        assert!(Role::Admin > Role::Operator && Role::Operator > Role::Viewer);
    }

    #[test]
    fn the_claim_is_configurable_and_an_empty_section_is_a_problem() {
        let roles: Roles = toml::from_str("claim = \"roles\"\nadmin = [\"a\"]\n").unwrap();
        assert_eq!(roles.of(&caller(r#"{"roles":["a"]}"#)), Some(Role::Admin));
        let empty: Roles = toml::from_str("").unwrap();
        assert!(empty.problem().is_some());
        assert!(roles.problem().is_none());
    }
}
