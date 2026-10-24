use super::*;

#[test]
fn a_peer_key_names_the_address_its_node_address_has() {
    let key = PeerKey::any();
    assert_eq!(
        key.address(),
        Ipv6Address::from_node_addr(&NodeAddr::from_pubkey(&key.0))
    );
}

/// Field types a message may carry: integers, flags, strings, bytes, the
/// peer key, and the message types this file defines.
const ALLOWED: &[&str] = &[
    "u8", "u16", "u32", "u64", "i8", "i16", "i32", "i64", "bool", "String", "PeerKey", "Feeds",
    "Attach", "FromMesh",
];

/// The items in the link's source that are not messages: the two link ends,
/// and the peer key, whose inner key is the one opaque field the link allows.
const NOT_MESSAGES: &[&str] = &["MeshLink", "HostLink", "PeerKey"];

/// Whether `ty` is an allowed field type, or an `Option` or `Vec` of one.
fn allowed(ty: &str) -> bool {
    let ty = ty.trim();
    if ty == "Vec<u8>" || ALLOWED.contains(&ty) {
        return true;
    }
    for wrapper in ["Option<", "Vec<"] {
        if let Some(inner) = ty.strip_prefix(wrapper).and_then(|t| t.strip_suffix('>')) {
            return allowed(inner);
        }
    }
    false
}

/// `source` without comments, attributes, or string and char literals, so
/// that only item and field syntax is left to scan. Each literal leaves an
/// empty string in its place.
fn strip(source: &str) -> String {
    let chars: Vec<char> = source.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < chars.len() {
        if let Some(end) = literal_end(&chars, i) {
            out.push_str("\"\"");
            i = end;
            continue;
        }
        let next = chars.get(i + 1).copied();
        match (chars[i], next) {
            ('/', Some('/')) => {
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
            }
            ('/', Some('*')) => {
                while i + 1 < chars.len() && !(chars[i] == '*' && chars[i + 1] == '/') {
                    i += 1;
                }
                i += 2;
            }
            ('#', _) => {
                let mut j = i + 1;
                if chars.get(j) == Some(&'!') {
                    j += 1;
                }
                if chars.get(j) == Some(&'[') {
                    i = close(&chars, j) + 1;
                } else {
                    out.push('#');
                    i += 1;
                }
            }
            (c, _) => {
                out.push(c);
                i += 1;
            }
        }
    }
    out
}

/// Whether `c` can be part of an identifier.
fn ident(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// The index just past the raw string (`r"..."`, `r#"..."#`, or either with
/// a `b` prefix) whose `r` is at `at`, or `None` when none starts there.
fn raw_end(chars: &[char], at: usize) -> Option<usize> {
    if chars[at] != 'r' {
        return None;
    }
    let before = |n: usize| at.checked_sub(n).map(|k| chars[k]);
    let prefixed = before(1) == Some('b') && !before(2).is_some_and(ident);
    if before(1).is_some_and(ident) && !prefixed {
        return None;
    }
    let hashes = chars[at + 1..].iter().take_while(|&&c| c == '#').count();
    let open = at + 1 + hashes;
    if chars.get(open) != Some(&'"') {
        return None;
    }
    let closed = (open + 1..chars.len())
        .find(|&k| chars[k] == '"' && (1..=hashes).all(|n| chars.get(k + n) == Some(&'#')))?;
    Some(closed + 1 + hashes)
}

/// The index just past the char literal whose opening quote is at `at`, or
/// `None` when none starts there: a lifetime such as `'a` opens no literal.
fn char_end(chars: &[char], at: usize) -> Option<usize> {
    if chars[at] != '\'' {
        return None;
    }
    if chars.get(at + 1) == Some(&'\\') {
        // An escape: the quote after the escaped character closes it.
        let closed = (at + 3..chars.len()).find(|&k| chars[k] == '\'')?;
        return Some(closed + 1);
    }
    (chars.get(at + 2) == Some(&'\'')).then_some(at + 3)
}

/// The index just past the string or char literal that starts at `at`, or
/// `None` when none starts there.
///
/// Raw strings and char literals are tried first: either can hold a lone
/// `"`, which the plain-string rule would take for an opening quote and
/// swallow every item after it.
fn literal_end(chars: &[char], at: usize) -> Option<usize> {
    if let Some(end) = raw_end(chars, at).or_else(|| char_end(chars, at)) {
        return Some(end);
    }
    if chars[at] != '"' {
        return None;
    }
    let mut i = at + 1;
    while i < chars.len() && chars[i] != '"' {
        i += if chars[i] == '\\' { 2 } else { 1 };
    }
    Some((i + 1).min(chars.len()))
}

/// The index of the bracket that closes the one at `open`, or the end.
///
/// Brackets inside a literal are not counted: an attribute such as
/// `#[doc = "("]` would otherwise never close, and the attribute would
/// swallow every item after it.
fn close(chars: &[char], open: usize) -> usize {
    let mut depth = 0i32;
    let mut i = open;
    while i < chars.len() {
        if let Some(end) = literal_end(chars, i) {
            i = end;
            continue;
        }
        match chars[i] {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => {
                depth -= 1;
                if depth == 0 {
                    return i;
                }
            }
            _ => {}
        }
        i += 1;
    }
    chars.len()
}

/// `text` split at the commas outside any bracket, each part trimmed, the
/// empty ones dropped.
fn split_top(text: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut depth = 0i32;
    let mut part = String::new();
    let mut prev = ' ';
    for c in text.chars() {
        match c {
            '(' | '[' | '{' | '<' => depth += 1,
            '>' if prev != '-' => depth -= 1,
            ')' | ']' | '}' => depth -= 1,
            ',' if depth == 0 => {
                parts.push(std::mem::take(&mut part));
                prev = c;
                continue;
            }
            _ => {}
        }
        part.push(c);
        prev = c;
    }
    parts.push(part);
    parts
        .into_iter()
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
        .collect()
}

/// `field` without a leading visibility: `pub`, or `pub(..)`.
fn unscoped(field: &str) -> &str {
    let Some(rest) = field.strip_prefix("pub") else {
        return field;
    };
    let rest = rest.trim_start();
    match rest.strip_prefix('(') {
        Some(scoped) => scoped.split_once(')').map_or(rest, |(_, r)| r.trim_start()),
        None => rest,
    }
}

/// The type of each field in a braced field list, named `owner.field`.
fn named_fields(owner: &str, body: &str) -> Vec<(String, String)> {
    split_top(body)
        .iter()
        .map(|field| {
            let field = unscoped(field);
            // The first lone colon, not one of a path's `::`.
            let chars: Vec<char> = field.chars().collect();
            let at = (0..chars.len()).find(|&i| {
                chars[i] == ':' && chars.get(i + 1) != Some(&':') && (i == 0 || chars[i - 1] != ':')
            });
            match at {
                Some(at) => {
                    let name: String = chars[..at].iter().collect();
                    let ty: String = chars[at + 1..].iter().collect();
                    (format!("{owner}.{}", name.trim()), ty.trim().to_string())
                }
                None => (format!("{owner}.?"), field.to_string()),
            }
        })
        .collect()
}

/// The type of each field in a parenthesized field list, named
/// `owner.index`.
fn tuple_fields(owner: &str, body: &str) -> Vec<(String, String)> {
    split_top(body)
        .iter()
        .enumerate()
        .map(|(i, ty)| (format!("{owner}.{i}"), unscoped(ty).to_string()))
        .collect()
}

/// The fields of `body`, which opens with `{` or `(` or is empty.
fn fields_of(owner: &str, body: &str) -> Vec<(String, String)> {
    let body = body.trim();
    if let Some(inner) = body.strip_prefix('{').and_then(|b| b.strip_suffix('}')) {
        named_fields(owner, inner)
    } else if let Some(inner) = body.strip_prefix('(').and_then(|b| b.strip_suffix(')')) {
        tuple_fields(owner, inner)
    } else {
        Vec::new()
    }
}

/// Every `struct`, `enum` and `union` in `source`, whatever its
/// visibility, with the type of every field it or its variants declare:
/// named, tuple, or none. The items of [`NOT_MESSAGES`] are named but their
/// fields are not collected.
fn message_fields(source: &str) -> (Vec<String>, Vec<(String, String)>) {
    let text = strip(source);
    let chars: Vec<char> = text.chars().collect();
    let mut items = Vec::new();
    let mut fields = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let start = i;
        while i < chars.len() && ident(chars[i]) {
            i += 1;
        }
        if i == start {
            i += 1;
            continue;
        }
        let word: String = chars[start..i].iter().collect();
        let keyword = matches!(word.as_str(), "struct" | "enum" | "union")
            && (start == 0 || !ident(chars[start - 1]));
        if !keyword {
            continue;
        }
        while i < chars.len() && chars[i].is_whitespace() {
            i += 1;
        }
        let name_start = i;
        while i < chars.len() && ident(chars[i]) {
            i += 1;
        }
        let name: String = chars[name_start..i].iter().collect();
        // The body is the first bracket after the name and any generics.
        let Some(open) = (i..chars.len()).find(|&j| matches!(chars[j], '{' | '(' | ';')) else {
            break;
        };
        let end = if chars[open] == ';' {
            open
        } else {
            close(&chars, open)
        };
        let body: String = chars[open..=end.min(chars.len() - 1)].iter().collect();
        i = end + 1;
        items.push(name.clone());
        if NOT_MESSAGES.contains(&name.as_str()) {
            continue;
        }
        if word != "enum" {
            fields.extend(fields_of(&name, &body));
            continue;
        }
        let inner = body
            .trim()
            .strip_prefix('{')
            .and_then(|b| b.strip_suffix('}'))
            .unwrap_or("");
        for variant in split_top(inner) {
            let split = variant.find(['{', '(', '=']).unwrap_or(variant.len());
            let (vname, rest) = variant.split_at(split);
            let owner = format!("{name}::{}", vname.trim());
            if !rest.starts_with('=') {
                fields.extend(fields_of(&owner, rest));
            }
        }
    }
    (items, fields)
}

/// The fields of `source`'s messages whose types may not cross the link.
fn refused(source: &str) -> Vec<(String, String)> {
    message_fields(source)
        .1
        .into_iter()
        .filter(|(_, ty)| !allowed(ty) || ty.contains("crate::"))
        .collect()
}

#[test]
fn messages_carry_only_owned_data_of_the_allowed_types() {
    let (items, fields) = message_fields(include_str!("../link.rs"));
    for item in [
        "Feeds", "Attach", "FromMesh", "MeshLink", "HostLink", "PeerKey",
    ] {
        assert!(
            items.iter().any(|i| i == item),
            "the scan must find {item}, found {items:?}"
        );
    }
    assert!(
        fields.len() >= 8,
        "the scan must find the message fields, found {fields:?}"
    );
    assert_eq!(
        refused(include_str!("../link.rs")),
        Vec::new(),
        "message fields that may not cross the link"
    );
}

/// Assert that the scan refuses the `NodeAddr` field of the one forged
/// definition in `source`.
fn assert_refused(source: &str, field: &str) {
    assert_eq!(
        refused(source),
        vec![(field.to_string(), "NodeAddr".to_string())],
        "{source}"
    );
}

#[test]
fn the_allow_list_check_refuses_a_node_address_in_a_named_variant_field() {
    assert_refused(
        "pub(crate) enum FromMesh {\n    Bad {\n        addr: NodeAddr,\n    },\n}\n",
        "FromMesh::Bad.addr",
    );
}

#[test]
fn the_allow_list_check_refuses_a_node_address_in_a_tuple_variant() {
    assert_refused(
        "pub(crate) enum FromMesh {\n    Synced,\n    Bad(NodeAddr),\n}\n",
        "FromMesh::Bad.0",
    );
}

#[test]
fn the_allow_list_check_refuses_a_node_address_in_a_tuple_struct() {
    assert_refused("pub(crate) struct Grant(pub(crate) NodeAddr);\n", "Grant.0");
}

#[test]
fn the_allow_list_check_refuses_a_node_address_in_a_public_item() {
    assert_refused(
        "pub enum ToMesh {\n    Bad { addr: NodeAddr },\n}\n",
        "ToMesh::Bad.addr",
    );
}

#[test]
fn the_allow_list_check_refuses_a_node_address_in_a_private_item_behind_attributes_and_comments() {
    assert_refused(
        "#[derive(Clone)]\n/// A grant.\nstruct Grant {\n    #[serde(skip)]\n    // the address\n    \
         addr: NodeAddr, /* inline */\n}\n",
        "Grant.addr",
    );
}

#[test]
fn the_allow_list_check_refuses_a_node_address_nested_in_a_generic_or_named_by_path() {
    let source = "pub(crate) struct Grant {\n    pairs: Vec<(u8, NodeAddr)>,\n    \
                  addr: crate::NodeAddr,\n}\n";
    assert_eq!(
        refused(source),
        vec![
            ("Grant.pairs".to_string(), "Vec<(u8, NodeAddr)>".to_string()),
            ("Grant.addr".to_string(), "crate::NodeAddr".to_string()),
        ]
    );
}

#[test]
fn the_allow_list_check_refuses_a_node_address_after_a_char_literal_holding_a_quote() {
    assert_refused(
        "const QUOTE: char = '\"';\nstruct Grant {\n    addr: NodeAddr,\n}\n",
        "Grant.addr",
    );
}

#[test]
fn the_allow_list_check_refuses_a_node_address_after_a_raw_string_holding_a_quote() {
    assert_refused(
        "const QUOTED: &str = r#\"a \" b\"#;\nstruct Grant {\n    addr: NodeAddr,\n}\n",
        "Grant.addr",
    );
}

#[test]
fn the_allow_list_check_refuses_a_node_address_after_an_attribute_whose_string_holds_an_unbalanced_bracket()
 {
    for attribute in ["#[doc = \"(\"]", "#[error(\"bad {0\")]", "#[doc = \")\"]"] {
        assert_refused(
            &format!("{attribute}\nstruct Grant {{\n    addr: NodeAddr,\n}}\n"),
            "Grant.addr",
        );
    }
}

#[test]
fn the_allow_list_check_refuses_a_node_address_after_an_attribute_whose_raw_string_or_char_holds_a_bracket()
 {
    for attribute in ["#[sep('(')]", "#[doc = r#\"]\"#]"] {
        assert_refused(
            &format!("{attribute}\nstruct Grant {{\n    addr: NodeAddr,\n}}\n"),
            "Grant.addr",
        );
    }
}
