//! Reading Rust source as text, for the tests that scan the adapter's own
//! files: where an identifier, a string or char literal (raw strings
//! included), or a bracketed group ends.

/// Whether `c` can be part of an identifier.
pub(crate) fn ident(c: char) -> bool {
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
pub(crate) fn literal_end(chars: &[char], at: usize) -> Option<usize> {
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
pub(crate) fn close(chars: &[char], open: usize) -> usize {
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
