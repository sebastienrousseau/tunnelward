// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//! The subset of HTTP Structured Fields (RFC 9651) that HTTP message
//! signatures (RFC 9421) need: dictionaries whose members are items or
//! inner lists, with parameters; strings, integers, tokens, booleans and
//! byte sequences. Serialisation is canonical, as RFC 9421 requires for
//! `@signature-params`.

use std::fmt::Write as _;

/// A bare item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Bare {
    Integer(i64),
    String(String),
    Token(String),
    Bytes(Vec<u8>),
    Boolean(bool),
}

/// An item with its parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Item {
    pub(crate) bare: Bare,
    pub(crate) params: Vec<(String, Bare)>,
}

/// A dictionary member's value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Member {
    Item(Item),
    InnerList(Vec<Item>, Vec<(String, Bare)>),
}

/// A dictionary, members in order.
pub(crate) type Dictionary = Vec<(String, Member)>;

struct Parser<'a> {
    s: &'a [u8],
    at: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.s.get(self.at).copied()
    }

    fn eat(&mut self, c: u8) -> bool {
        let hit = self.peek() == Some(c);
        self.at += usize::from(hit);
        hit
    }

    fn spaces(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t')) {
            self.at += 1;
        }
    }

    fn key(&mut self) -> Option<String> {
        let start = self.at;
        if !matches!(self.peek(), Some(b'a'..=b'z' | b'*')) {
            return None;
        }
        while matches!(
            self.peek(),
            Some(b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-' | b'.' | b'*')
        ) {
            self.at += 1;
        }
        Some(String::from_utf8_lossy(&self.s[start..self.at]).into_owned())
    }

    fn bare(&mut self) -> Option<Bare> {
        match self.peek()? {
            b'"' => self.string().map(Bare::String),
            b':' => self.bytes().map(Bare::Bytes),
            b'?' => self.boolean().map(Bare::Boolean),
            b'-' | b'0'..=b'9' => self.integer().map(Bare::Integer),
            c if c.is_ascii_alphabetic() || c == b'*' => Some(Bare::Token(self.token())),
            _ => None,
        }
    }

    fn string(&mut self) -> Option<String> {
        self.at += 1;
        let mut out = String::new();
        loop {
            let c = self.peek()?;
            self.at += 1;
            match c {
                b'"' => return Some(out),
                b'\\' => {
                    let escaped = self.peek().filter(|e| matches!(e, b'"' | b'\\'))?;
                    self.at += 1;
                    out.push(char::from(escaped));
                }
                0x20..=0x7e => out.push(char::from(c)),
                _ => return None,
            }
        }
    }

    fn bytes(&mut self) -> Option<Vec<u8>> {
        self.at += 1;
        let start = self.at;
        while self.peek().is_some_and(|c| c != b':') {
            self.at += 1;
        }
        let text = std::str::from_utf8(&self.s[start..self.at]).ok()?;
        self.eat(b':').then_some(())?;
        crate::auth::b64_standard(text)
    }

    fn boolean(&mut self) -> Option<bool> {
        self.at += 1;
        let value = match self.peek()? {
            b'1' => true,
            b'0' => false,
            _ => return None,
        };
        self.at += 1;
        Some(value)
    }

    fn integer(&mut self) -> Option<i64> {
        let start = self.at;
        self.eat(b'-');
        let digits = self.at;
        while self.peek().is_some_and(|c| c.is_ascii_digit()) {
            self.at += 1;
        }
        if self.at == digits || self.at - digits > 15 {
            return None;
        }
        std::str::from_utf8(&self.s[start..self.at])
            .ok()?
            .parse()
            .ok()
    }

    fn token(&mut self) -> String {
        let start = self.at;
        while self
            .peek()
            .is_some_and(|c| c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~:/".contains(&c))
        {
            self.at += 1;
        }
        String::from_utf8_lossy(&self.s[start..self.at]).into_owned()
    }

    fn params(&mut self) -> Option<Vec<(String, Bare)>> {
        let mut out = Vec::new();
        while self.eat(b';') {
            self.spaces();
            let key = self.key()?;
            let value = if self.eat(b'=') {
                self.bare()?
            } else {
                Bare::Boolean(true)
            };
            out.push((key, value));
        }
        Some(out)
    }

    fn item(&mut self) -> Option<Item> {
        let bare = self.bare()?;
        Some(Item {
            bare,
            params: self.params()?,
        })
    }

    fn inner_list(&mut self) -> Option<Member> {
        self.at += 1;
        let mut items = Vec::new();
        loop {
            self.spaces();
            if self.eat(b')') {
                return Some(Member::InnerList(items, self.params()?));
            }
            items.push(self.item()?);
            if !matches!(self.peek(), Some(b' ' | b')')) {
                return None;
            }
        }
    }

    fn member(&mut self) -> Option<Member> {
        if self.peek() == Some(b'(') {
            self.inner_list()
        } else {
            self.item().map(Member::Item)
        }
    }
}

/// `text` as a dictionary; `None` if it is not one.
pub(crate) fn dictionary(text: &str) -> Option<Dictionary> {
    let mut p = Parser {
        s: text.trim().as_bytes(),
        at: 0,
    };
    let mut out = Dictionary::new();
    while p.peek().is_some() {
        let key = p.key()?;
        let member = if p.eat(b'=') {
            p.member()?
        } else {
            Member::Item(Item {
                bare: Bare::Boolean(true),
                params: p.params()?,
            })
        };
        out.push((key, member));
        p.spaces();
        if p.peek().is_some() {
            p.eat(b',').then_some(())?;
            p.spaces();
        }
    }
    Some(out)
}

/// `text` as one item; `None` if it is not one.
pub(crate) fn item(text: &str) -> Option<Item> {
    let mut p = Parser {
        s: text.trim().as_bytes(),
        at: 0,
    };
    let item = p.item()?;
    (p.peek().is_none()).then_some(item)
}

/// The canonical serialisation of `bare`.
pub(crate) fn bare(value: &Bare) -> String {
    match value {
        Bare::Integer(n) => n.to_string(),
        Bare::String(s) => {
            let escaped = s.replace('\\', "\\\\").replace('"', "\\\"");
            format!("\"{escaped}\"")
        }
        Bare::Token(t) => t.clone(),
        Bare::Bytes(_) => String::new(),
        Bare::Boolean(b) => if *b { "?1" } else { "?0" }.to_owned(),
    }
}

/// The canonical serialisation of `params`.
pub(crate) fn params(params: &[(String, Bare)]) -> String {
    let mut out = String::new();
    for (key, value) in params {
        let _infallible = match value {
            Bare::Boolean(true) => write!(out, ";{key}"),
            _ => write!(out, ";{key}={}", bare(value)),
        };
    }
    out
}

/// The canonical serialisation of an inner list.
pub(crate) fn inner_list(items: &[Item], list_params: &[(String, Bare)]) -> String {
    let inner: Vec<String> = items
        .iter()
        .map(|i| format!("{}{}", bare(&i.bare), params(&i.params)))
        .collect();
    format!("({}){}", inner.join(" "), params(list_params))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_input_parses_and_reserialises_canonically() {
        let text = r#"sig2=("@authority" "signature-agent";key="agent2");created=1735689600;keyid="k";alg="ed25519";tag="web-bot-auth""#;
        let dict = dictionary(text).unwrap_or_default();
        let [(label, Member::InnerList(items, list))] = dict.as_slice() else {
            panic!("{dict:?}");
        };
        assert_eq!(label, "sig2");
        assert_eq!(items.len(), 2);
        assert_eq!(
            inner_list(items, list),
            text.strip_prefix("sig2=").unwrap_or_default()
        );
    }

    #[test]
    fn items_of_each_kind_parse() {
        let dict = dictionary(r#"a=1, b="x\"y", c=tok, d=:aGk=:, e=?0, f"#).unwrap_or_default();
        let bares: Vec<&Bare> = dict
            .iter()
            .filter_map(|(_, m)| match m {
                Member::Item(i) => Some(&i.bare),
                Member::InnerList(..) => None,
            })
            .collect();
        assert_eq!(
            bares,
            [
                &Bare::Integer(1),
                &Bare::String("x\"y".into()),
                &Bare::Token("tok".into()),
                &Bare::Bytes(b"hi".to_vec()),
                &Bare::Boolean(false),
                &Bare::Boolean(true),
            ]
        );
    }

    #[test]
    fn malformed_fields_are_refused() {
        for bad in [
            "A=1",
            "a=",
            "a=(1 2",
            "a=\"open",
            "a=1,,b=2",
            "a=1234567890123456",
            "a=:!!:",
        ] {
            assert_eq!(dictionary(bad), None, "{bad}");
        }
        assert_eq!(item("\"one\" extra"), None);
        assert!(item("\"https://x\"").is_some());
    }
}
