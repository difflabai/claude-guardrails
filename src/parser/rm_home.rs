//! AST check for `rm` of the home directory (steward-l8b3, round 3).
//!
//! The `rm-home` and `bash-c-rm-home` regexes are main's, unchanged. This check is OR'd
//! on top: a command is denied if main's regexes deny it or if [`denies`] does. It can
//! only add denials.
//!
//! A regex over raw text loses to the shell's grammar (quotes, escapes, braces,
//! substitutions, redirections with no space before them). This check works on what the
//! shell would run:
//!
//! 1. Parse the command with tree-sitter-bash and visit every `command` node: at top
//!    level, inside backticks, `$(...)`, groups, `if` and functions.
//! 2. Look through wrappers (`\rm`, `/bin/rm`, `command`, `builtin`, `exec`, `sudo`,
//!    `env`, `nohup`, `time`, `noglob`, `xargs`, `find -exec`, ...) to find `rm`.
//!    Parse again the text of `bash|sh|zsh -c '...'`, `eval '...'`, `su -c`, here
//!    documents and here strings.
//! 3. For each operand of `rm` (flags skipped, `--` honoured), decode the word the way
//!    the shell does: plain text, single and double quotes, `$'...'`, escapes, `~`,
//!    `$HOME` and `${HOME}`; expand braces (an empty arm included); normalise `.`, `..`
//!    and repeated slashes.
//! 4. Deny when a word resolves to the home folder or above it (`/`, `/Users`, `/home`,
//!    `/Users/<user>`, `/home/<user>`), or to home plus a glob that can cover its
//!    contents (`*`, `.*`, `.[!.]*`, `?*`, `*(D)`, ...), or when a word that starts with
//!    a home prefix cannot be decoded (`$HOME$x`, `~/$(cmd)`).
//!
//! It never decides that a path is safe to delete; main's regexes still deny what they
//! denied. A path below home that decodes to plain text (`~/proj/build`) is simply not
//! added here.

use tree_sitter::{Node, Parser};

const MAX_DEPTH: usize = 4;
const MAX_ALTERNATIVES: usize = 512;
const SHELLS: &[&str] = &["bash", "sh", "zsh", "dash", "ksh", "ash", "fish", "su"];

/// True when `source` runs `rm` on the home directory, something above it, or a glob
/// that covers its contents.
pub fn denies(source: &str) -> bool {
    scan(source, 0)
}

// ---------------------------------------------------------------------------
// Words
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
enum Piece {
    /// A literal character: unquoted, quoted or escaped.
    Lit(char),
    /// An unquoted `*` or `?`.
    Glob(char),
    /// An unquoted `[...]` (text between the brackets).
    Class(String),
    /// An unquoted `(...)`: a zsh glob qualifier or an extended glob group.
    Qual(String),
    /// Unquoted `{`, `}` and `,`: brace expansion, resolved before the path is read.
    Open,
    Close,
    Comma,
    /// `~`, `~name`, `$HOME` or `${HOME}`.
    Home,
    /// Any other expansion.
    Opaque,
    /// A command substitution or backtick; the text inside.
    Subst(String),
}

type Word = Vec<Piece>;

struct Lexer {
    chars: Vec<char>,
    i: usize,
    words: Vec<Word>,
    cur: Word,
    started: bool,
    discard: bool,
}

/// Split `text` into shell words and decode each one. An operator that ends a command
/// (`;`, `&`, `|`) stops the scan; a redirection and its target are dropped.
fn lex_words(text: &str) -> Vec<Word> {
    let mut lx = Lexer {
        chars: text.chars().collect(),
        i: 0,
        words: Vec::new(),
        cur: Vec::new(),
        started: false,
        discard: false,
    };
    lx.run();
    lx.flush();
    lx.words
}

impl Lexer {
    fn peek(&self, k: usize) -> Option<char> {
        self.chars.get(self.i + k).copied()
    }

    fn flush(&mut self) {
        if self.started {
            let word = std::mem::take(&mut self.cur);
            if self.discard {
                self.discard = false;
            } else {
                self.words.push(word);
            }
            self.started = false;
        }
    }

    fn push(&mut self, piece: Piece) {
        self.cur.push(piece);
        self.started = true;
    }

    fn run(&mut self) {
        while let Some(c) = self.peek(0) {
            match c {
                ' ' | '\t' | '\n' | '\r' => {
                    self.flush();
                    self.i += 1;
                }
                ';' | '&' | '|' => return,
                '<' | '>' => {
                    if self.peek(1) == Some('(') {
                        self.i += 2;
                        let inner = self.balanced_paren();
                        self.push(Piece::Subst(inner));
                    } else {
                        self.flush();
                        while matches!(self.peek(0), Some('<' | '>' | '&' | '-')) {
                            self.i += 1;
                        }
                        self.discard = true;
                    }
                }
                '\\' => {
                    self.i += 1;
                    match self.peek(0) {
                        Some('\n') => {
                            self.i += 1;
                        }
                        Some(n) => {
                            self.push(Piece::Lit(n));
                            self.i += 1;
                        }
                        None => self.push(Piece::Lit('\\')),
                    }
                }
                '\'' => {
                    self.i += 1;
                    self.started = true;
                    while let Some(n) = self.peek(0) {
                        self.i += 1;
                        if n == '\'' {
                            break;
                        }
                        self.cur.push(Piece::Lit(n));
                    }
                }
                '"' => {
                    self.i += 1;
                    self.started = true;
                    self.double_quoted();
                }
                '`' => {
                    self.i += 1;
                    let inner = self.backtick();
                    self.push(Piece::Subst(inner));
                }
                '$' => self.dollar(false),
                '~' if !self.started => self.tilde(),
                '*' | '?' => {
                    self.push(Piece::Glob(c));
                    self.i += 1;
                }
                '[' => self.class(),
                '{' => {
                    self.push(Piece::Open);
                    self.i += 1;
                }
                '}' => {
                    self.push(Piece::Close);
                    self.i += 1;
                }
                ',' => {
                    self.push(Piece::Comma);
                    self.i += 1;
                }
                '(' => {
                    self.i += 1;
                    let inner = self.balanced_paren();
                    self.push(Piece::Qual(inner));
                }
                _ => {
                    self.push(Piece::Lit(c));
                    self.i += 1;
                }
            }
        }
    }

    /// `~` at the start of a word: a tilde prefix up to the first `/` or the end.
    fn tilde(&mut self) {
        let mut j = self.i + 1;
        while let Some(c) = self.chars.get(j) {
            if c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-') {
                j += 1;
            } else {
                break;
            }
        }
        let ends = match self.chars.get(j) {
            None => true,
            Some(c) => matches!(
                c,
                '/' | ' ' | '\t' | '\n' | ';' | '&' | '|' | '<' | '>' | ')' | '{' | '}' | ','
            ),
        };
        if ends {
            self.push(Piece::Home);
            self.i = j;
        } else {
            self.push(Piece::Lit('~'));
            self.i += 1;
        }
    }

    /// `[...]` as a character class, or a literal `[` when it does not close.
    fn class(&mut self) {
        let mut j = self.i + 1;
        if matches!(self.chars.get(j), Some('!' | '^')) {
            j += 1;
        }
        if self.chars.get(j) == Some(&']') {
            j += 1;
        }
        while let Some(c) = self.chars.get(j) {
            if *c == ']' {
                let spec: String = self.chars[self.i + 1..j].iter().collect();
                self.push(Piece::Class(spec));
                self.i = j + 1;
                return;
            }
            j += 1;
        }
        self.push(Piece::Lit('['));
        self.i += 1;
    }

    /// Text up to the `)` that closes an already opened `(`; the cursor ends after it.
    fn balanced_paren(&mut self) -> String {
        let start = self.i;
        let mut depth = 1;
        while let Some(c) = self.peek(0) {
            match c {
                '\\' => self.i += 1,
                '\'' => {
                    self.i += 1;
                    while let Some(n) = self.peek(0) {
                        if n == '\'' {
                            break;
                        }
                        self.i += 1;
                    }
                }
                '"' => {
                    self.i += 1;
                    while let Some(n) = self.peek(0) {
                        if n == '\\' {
                            self.i += 1;
                        } else if n == '"' {
                            break;
                        }
                        self.i += 1;
                    }
                }
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        let inner: String = self.chars[start..self.i.min(self.chars.len())]
                            .iter()
                            .collect();
                        self.i += 1;
                        return inner;
                    }
                }
                _ => {}
            }
            self.i += 1;
        }
        self.chars[start.min(self.chars.len())..].iter().collect()
    }

    /// Text up to the closing backtick; the cursor ends after it.
    fn backtick(&mut self) -> String {
        let mut inner = String::new();
        while let Some(c) = self.peek(0) {
            self.i += 1;
            match c {
                '`' => break,
                '\\' => {
                    if let Some(n) = self.peek(0) {
                        if matches!(n, '`' | '\\' | '$') {
                            inner.push(n);
                        } else {
                            inner.push('\\');
                            inner.push(n);
                        }
                        self.i += 1;
                    }
                }
                _ => inner.push(c),
            }
        }
        inner
    }

    /// After the opening `"`: up to and including the closing `"`.
    fn double_quoted(&mut self) {
        while let Some(c) = self.peek(0) {
            match c {
                '"' => {
                    self.i += 1;
                    return;
                }
                '\\' => {
                    self.i += 1;
                    match self.peek(0) {
                        Some('\n') => self.i += 1,
                        Some(n) if matches!(n, '$' | '`' | '"' | '\\') => {
                            self.cur.push(Piece::Lit(n));
                            self.i += 1;
                        }
                        _ => self.cur.push(Piece::Lit('\\')),
                    }
                }
                '$' => self.dollar(true),
                '`' => {
                    self.i += 1;
                    let inner = self.backtick();
                    self.cur.push(Piece::Subst(inner));
                }
                _ => {
                    self.cur.push(Piece::Lit(c));
                    self.i += 1;
                }
            }
        }
    }

    /// A `$` form. `in_quotes` turns off `$'...'`.
    fn dollar(&mut self, in_quotes: bool) {
        self.started = true;
        let next = self.peek(1);
        match next {
            Some('\'') if !in_quotes => {
                self.i += 2;
                self.ansi_c();
            }
            Some('"') if !in_quotes => {
                self.i += 2;
                self.double_quoted();
            }
            Some('{') => {
                self.i += 2;
                let start = self.i;
                let mut depth = 1;
                while let Some(c) = self.peek(0) {
                    match c {
                        '{' => depth += 1,
                        '}' => {
                            depth -= 1;
                            if depth == 0 {
                                break;
                            }
                        }
                        _ => {}
                    }
                    self.i += 1;
                }
                let inner: String = self.chars[start..self.i.min(self.chars.len())]
                    .iter()
                    .collect();
                self.i += 1;
                self.cur.push(if inner == "HOME" {
                    Piece::Home
                } else {
                    Piece::Opaque
                });
            }
            Some('(') => {
                if self.peek(2) == Some('(') {
                    // Arithmetic: `$(( ... ))`.
                    self.i += 3;
                    let _ = self.balanced_paren();
                    self.cur.push(Piece::Opaque);
                } else {
                    self.i += 2;
                    let inner = self.balanced_paren();
                    self.cur.push(Piece::Subst(inner));
                }
            }
            Some(c) if c.is_ascii_alphabetic() || c == '_' => {
                let mut j = self.i + 1;
                while let Some(n) = self.chars.get(j) {
                    if n.is_ascii_alphanumeric() || *n == '_' {
                        j += 1;
                    } else {
                        break;
                    }
                }
                let name: String = self.chars[self.i + 1..j].iter().collect();
                self.i = j;
                self.cur.push(if name == "HOME" {
                    Piece::Home
                } else {
                    Piece::Opaque
                });
            }
            Some(c)
                if c.is_ascii_digit() || matches!(c, '@' | '*' | '#' | '?' | '$' | '!' | '-') =>
            {
                self.i += 2;
                self.cur.push(Piece::Opaque);
            }
            _ => {
                self.cur.push(Piece::Lit('$'));
                self.i += 1;
            }
        }
    }

    /// After `$'`: ANSI-C quoting, up to the closing `'`.
    fn ansi_c(&mut self) {
        while let Some(c) = self.peek(0) {
            self.i += 1;
            match c {
                '\'' => return,
                '\\' => {
                    let Some(e) = self.peek(0) else {
                        self.cur.push(Piece::Lit('\\'));
                        return;
                    };
                    self.i += 1;
                    let ch = match e {
                        'a' => Some('\u{7}'),
                        'b' => Some('\u{8}'),
                        'e' | 'E' => Some('\u{1b}'),
                        'f' => Some('\u{c}'),
                        'n' => Some('\n'),
                        'r' => Some('\r'),
                        't' => Some('\t'),
                        'v' => Some('\u{b}'),
                        '\\' | '\'' | '"' | '?' => Some(e),
                        'x' => self.hex(2),
                        'u' => self.hex(4),
                        'U' => self.hex(8),
                        '0'..='7' => {
                            let mut v = e.to_digit(8).unwrap_or(0);
                            for _ in 0..2 {
                                match self.peek(0).and_then(|d| d.to_digit(8)) {
                                    Some(d) => {
                                        v = v * 8 + d;
                                        self.i += 1;
                                    }
                                    None => break,
                                }
                            }
                            char::from_u32(v)
                        }
                        'c' => {
                            let c = self.peek(0);
                            self.i += 1;
                            c.and_then(|c| char::from_u32((c as u32) & 0x1f))
                        }
                        other => {
                            self.cur.push(Piece::Lit('\\'));
                            Some(other)
                        }
                    };
                    if let Some(ch) = ch {
                        self.cur.push(Piece::Lit(ch));
                    }
                }
                _ => self.cur.push(Piece::Lit(c)),
            }
        }
    }

    fn hex(&mut self, max: usize) -> Option<char> {
        let mut v: u32 = 0;
        let mut n = 0;
        while n < max {
            match self.peek(0).and_then(|d| d.to_digit(16)) {
                Some(d) => {
                    v = v.wrapping_mul(16).wrapping_add(d);
                    self.i += 1;
                    n += 1;
                }
                None => break,
            }
        }
        if n == 0 {
            None
        } else {
            char::from_u32(v)
        }
    }
}

/// The text of a word if every piece is a plain character.
fn plain_text(word: &Word) -> Option<String> {
    word.iter()
        .map(|p| match p {
            Piece::Lit(c) => Some(*c),
            _ => None,
        })
        .collect()
}

/// A word as shell text again, for a script that is parsed a second time. The home
/// folder becomes `$HOME`, any other expansion a variable the check does not know.
fn stringify(word: &Word) -> String {
    let mut s = String::new();
    for p in word {
        match p {
            Piece::Lit(c) => s.push(*c),
            Piece::Glob(c) => s.push(*c),
            Piece::Class(t) => {
                s.push('[');
                s.push_str(t);
                s.push(']');
            }
            Piece::Qual(t) => {
                s.push('(');
                s.push_str(t);
                s.push(')');
            }
            Piece::Open => s.push('{'),
            Piece::Close => s.push('}'),
            Piece::Comma => s.push(','),
            Piece::Home => s.push_str("$HOME"),
            Piece::Opaque => s.push_str("$__opaque"),
            Piece::Subst(t) => {
                s.push_str("$(");
                s.push_str(t);
                s.push(')');
            }
        }
    }
    s
}

// ---------------------------------------------------------------------------
// Brace expansion
// ---------------------------------------------------------------------------

/// Expand the unquoted brace groups of a word. `None` when there are too many
/// alternatives.
fn expand_braces(word: &[Piece], budget: &mut usize) -> Option<Vec<Word>> {
    let Some(open) = word.iter().position(|p| *p == Piece::Open) else {
        return Some(vec![word.to_vec()]);
    };
    let mut depth = 0;
    let mut close = None;
    let mut commas = Vec::new();
    for (k, p) in word.iter().enumerate().skip(open) {
        match p {
            Piece::Open => depth += 1,
            Piece::Close => {
                depth -= 1;
                if depth == 0 {
                    close = Some(k);
                    break;
                }
            }
            Piece::Comma if depth == 1 => commas.push(k),
            _ => {}
        }
    }
    let Some(close) = close else {
        // Unmatched: a literal brace.
        let mut q = word.to_vec();
        q[open] = Piece::Lit('{');
        return expand_braces(&q, budget);
    };
    if commas.is_empty() {
        let inner = &word[open + 1..close];
        let mut q: Word = word[..open].to_vec();
        if is_sequence(inner) {
            q.push(Piece::Lit('0'));
        } else {
            q.push(Piece::Lit('{'));
            q.extend(inner.iter().cloned());
            q.push(Piece::Lit('}'));
        }
        q.extend(word[close + 1..].iter().cloned());
        return expand_braces(&q, budget);
    }
    let mut arms: Vec<&[Piece]> = Vec::new();
    let mut start = open + 1;
    for &c in &commas {
        arms.push(&word[start..c]);
        start = c + 1;
    }
    arms.push(&word[start..close]);
    let mut out = Vec::new();
    for arm in arms {
        let mut combined: Word = word[..open].to_vec();
        combined.extend(arm.iter().cloned());
        combined.extend(word[close + 1..].iter().cloned());
        for w in expand_braces(&combined, budget)? {
            if *budget == 0 {
                return None;
            }
            *budget -= 1;
            out.push(w);
        }
    }
    Some(out)
}

/// `{1..3}`, `{a..e}`, `{01..10..2}`: a sequence, not a list.
fn is_sequence(inner: &[Piece]) -> bool {
    let Some(text) = plain_text(&inner.to_vec()) else {
        return false;
    };
    let parts: Vec<&str> = text.split("..").collect();
    (parts.len() == 2 || parts.len() == 3)
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'))
}

fn literalise(word: &[Piece]) -> Word {
    word.iter()
        .map(|p| match p {
            Piece::Open => Piece::Lit('{'),
            Piece::Close => Piece::Lit('}'),
            Piece::Comma => Piece::Lit(','),
            other => other.clone(),
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Globs
// ---------------------------------------------------------------------------

/// A segment as a pattern: qualifiers at the end dropped, any other group a `*`.
fn pattern_of(seg: &[Piece]) -> Vec<Piece> {
    let mut end = seg.len();
    while end > 0 && matches!(seg[end - 1], Piece::Qual(_)) {
        end -= 1;
    }
    seg[..end]
        .iter()
        .map(|p| match p {
            Piece::Qual(_) | Piece::Home | Piece::Opaque | Piece::Subst(_) => Piece::Glob('*'),
            other => other.clone(),
        })
        .collect()
}

fn class_matches(spec: &str, c: char) -> bool {
    if spec.contains("[:") {
        return true;
    }
    let chars: Vec<char> = spec.chars().collect();
    let (neg, mut i) = if matches!(chars.first(), Some('!' | '^')) {
        (true, 1)
    } else {
        (false, 0)
    };
    let mut hit = false;
    while i < chars.len() {
        if i + 2 < chars.len() && chars[i + 1] == '-' {
            if chars[i] <= c && c <= chars[i + 2] {
                hit = true;
            }
            i += 3;
        } else {
            if chars[i] == c {
                hit = true;
            }
            i += 1;
        }
    }
    hit != neg
}

fn glob_match(pat: &[Piece], text: &[char]) -> bool {
    match pat.first() {
        None => text.is_empty(),
        Some(Piece::Glob('*')) => (0..=text.len()).any(|k| glob_match(&pat[1..], &text[k..])),
        Some(Piece::Glob(_)) => !text.is_empty() && glob_match(&pat[1..], &text[1..]),
        Some(Piece::Class(spec)) => {
            !text.is_empty() && class_matches(spec, text[0]) && glob_match(&pat[1..], &text[1..])
        }
        Some(Piece::Lit(c)) => text.first() == Some(c) && glob_match(&pat[1..], &text[1..]),
        Some(_) => false,
    }
}

fn seg_matches(seg: &[Piece], literal: &str) -> bool {
    let text: Vec<char> = literal.chars().collect();
    glob_match(&pattern_of(seg), &text)
}

/// A segment that can match every entry of a directory, or every dotfile: `*`, `**`,
/// `?*`, `[!.]*`, `.*`, `.[!.]*`, `.??*`, `..?*`, and the same with a zsh qualifier.
fn is_wide(seg: &[Piece]) -> bool {
    if seg
        .iter()
        .any(|p| matches!(p, Piece::Opaque | Piece::Subst(_) | Piece::Home))
    {
        return false;
    }
    if !seg
        .iter()
        .any(|p| matches!(p, Piece::Glob(_) | Piece::Class(_)))
    {
        return false;
    }
    let pat = pattern_of(seg);
    let all = |names: &[&str]| {
        names
            .iter()
            .all(|n| glob_match(&pat, &n.chars().collect::<Vec<_>>()))
    };
    all(&["a", "abc", "x.y", "_u", "Z9", "-v", "1"])
        || all(&[".bashrc", ".config", ".ssh", ".gitconfig", ".local"])
        || all(&["..a", "..foo", "..bar9"])
}

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

fn is_dot(seg: &[Piece]) -> bool {
    seg == [Piece::Lit('.')]
}

fn is_dotdot(seg: &[Piece]) -> bool {
    seg == [Piece::Lit('.'), Piece::Lit('.')]
}

fn has_opaque(seg: &[Piece]) -> bool {
    seg.iter()
        .any(|p| matches!(p, Piece::Opaque | Piece::Subst(_)))
}

/// Split into path segments on `/`; empty segments (repeated slashes) are dropped.
fn segments(pieces: &[Piece]) -> Vec<Word> {
    let mut segs: Vec<Word> = Vec::new();
    let mut cur: Word = Vec::new();
    for p in pieces {
        if *p == Piece::Lit('/') {
            if !cur.is_empty() {
                segs.push(std::mem::take(&mut cur));
            }
        } else {
            cur.push(p.clone());
        }
    }
    if !cur.is_empty() {
        segs.push(cur);
    }
    segs
}

/// Decide one alternative of one operand. `true` means the path is the home folder,
/// above it, home plus a glob that covers its contents, or an undecodable word that
/// starts with a home prefix.
fn candidate_denies(word: &[Piece]) -> bool {
    let word = literalise(word);
    match word.first() {
        Some(Piece::Home) => {
            let rest = &word[1..];
            match rest.first() {
                None => return true,
                Some(Piece::Lit('/')) => {}
                // `$HOME*`, `$HOME[a]`: the pattern matches home itself.
                Some(Piece::Glob(_) | Piece::Class(_) | Piece::Qual(_)) => return true,
                // `$HOME$x`: starts with the home folder and cannot be decoded.
                Some(_) => {
                    return rest
                        .iter()
                        .any(|p| matches!(p, Piece::Opaque | Piece::Subst(_)))
                }
            }
            let segs = segments(rest);
            if segs.iter().any(|s| has_opaque(s)) {
                return true;
            }
            let mut stack: Vec<Word> = Vec::new();
            for seg in segs {
                if is_dot(&seg) {
                    continue;
                }
                if is_dotdot(&seg) {
                    if stack.pop().is_none() {
                        return true; // above the home folder
                    }
                    continue;
                }
                stack.push(seg);
            }
            stack.is_empty() || stack.iter().all(|s| is_wide(s))
        }
        Some(Piece::Lit('/')) => {
            let segs = segments(&word);
            let is_home_root = |seg: &Word| seg_matches(seg, "Users") || seg_matches(seg, "home");
            // Undecodable below a home prefix: `/Users/$x`, `/home/alice/$(cmd)`.
            if let Some(k) = segs.iter().position(|s| has_opaque(s)) {
                let prefix = normalise(&segs[..k]);
                return match prefix.first() {
                    Some(first) => is_home_root(first),
                    None => false,
                };
            }
            let stack = normalise(&segs);
            match stack.first() {
                None => true, // `/`
                Some(first) => {
                    if !is_home_root(first) {
                        return false;
                    }
                    // `/Users`, `/Users/<user>`, and glob contents below the user.
                    stack.len() <= 2 || stack[2..].iter().all(|s| is_wide(s))
                }
            }
        }
        _ => false,
    }
}

/// Apply `.` and `..` to a list of segments. A `..` at the root stays at the root.
fn normalise(segs: &[Word]) -> Vec<Word> {
    let mut stack: Vec<Word> = Vec::new();
    for seg in segs {
        if is_dot(seg) {
            continue;
        }
        if is_dotdot(seg) {
            stack.pop();
            continue;
        }
        stack.push(seg.clone());
    }
    stack
}

/// All alternatives of one operand. A word with too many alternatives is decided by its
/// start: the part before the first brace, then an undecodable tail.
fn operand_denies(word: &Word, depth: usize) -> bool {
    // A whole-word command substitution: the output may be the home folder.
    if let [Piece::Subst(inner)] = word.as_slice() {
        if subst_names_home(inner, depth) {
            return true;
        }
    }
    let mut budget = MAX_ALTERNATIVES;
    match expand_braces(word, &mut budget) {
        Some(alternatives) => alternatives.iter().any(|w| candidate_denies(w)),
        None => {
            let cut = word
                .iter()
                .position(|p| *p == Piece::Open)
                .unwrap_or(word.len());
            let mut head: Word = word[..cut].to_vec();
            head.push(Piece::Opaque);
            candidate_denies(&head)
        }
    }
}

/// `$(echo ~)`, `` `cd $HOME && pwd` ``: some word inside is the home folder.
fn subst_names_home(inner: &str, depth: usize) -> bool {
    if depth >= MAX_DEPTH {
        return false;
    }
    let Some(tree) = parse(inner) else {
        return false;
    };
    let mut found = false;
    visit(&tree.root_node(), &mut |node| {
        if node.kind() == "command" {
            for word in command_words(node, inner) {
                let mut budget = MAX_ALTERNATIVES;
                if let Some(alts) = expand_braces(&word, &mut budget) {
                    if alts.iter().any(|w| candidate_denies(w)) {
                        found = true;
                    }
                }
            }
        }
    });
    found
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

fn parse(source: &str) -> Option<tree_sitter::Tree> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_bash::LANGUAGE.into())
        .ok()?;
    parser.parse(source, None)
}

fn visit(node: &Node, f: &mut dyn FnMut(&Node)) {
    f(node);
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        visit(&child, f);
    }
}

fn scan(source: &str, depth: usize) -> bool {
    if depth > MAX_DEPTH {
        return false;
    }
    let Some(tree) = parse(source) else {
        return false;
    };
    let mut hit = false;
    visit(&tree.root_node(), &mut |node| {
        if hit {
            return;
        }
        match node.kind() {
            "command" => {
                let words = command_words(node, source);
                if words_deny(&words, depth) || redirected_script_denies(node, source, depth) {
                    hit = true;
                }
            }
            "redirected_statement" if redirected_script_denies(node, source, depth) => {
                hit = true;
            }
            _ => {}
        }
    });
    hit
}

/// The words of a simple command: its name and arguments, redirections and prefix
/// assignments left out.
fn command_words(command: &Node, source: &str) -> Vec<Word> {
    let mut words = Vec::new();
    let mut cursor = command.walk();
    for child in command.children(&mut cursor) {
        match child.kind() {
            "variable_assignment"
            | "file_redirect"
            | "heredoc_redirect"
            | "herestring_redirect" => {}
            _ => {
                if let Ok(text) = child.utf8_text(source.as_bytes()) {
                    words.extend(lex_words(text));
                }
            }
        }
    }
    words
}

/// `bash <<EOF ... EOF` and `bash <<< 'script'`: the body is a script.
fn redirected_script_denies(node: &Node, source: &str, depth: usize) -> bool {
    // A `redirected_statement` holds the command as its body; a here string is a child
    // of the command itself.
    let body = if node.kind() == "command" {
        *node
    } else {
        let Some(body) = node.child_by_field_name("body") else {
            return false;
        };
        body
    };
    if body.kind() != "command" {
        return false;
    }
    let words = command_words(&body, source);
    let Some(name) = words.first().and_then(plain_text) else {
        return false;
    };
    let base = name.rsplit('/').next().unwrap_or(&name);
    if !SHELLS.contains(&base) {
        return false;
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "heredoc_redirect" => {
                let mut quoted = false;
                let mut text = String::new();
                let mut c = child.walk();
                for part in child.children(&mut c) {
                    let t = part.utf8_text(source.as_bytes()).unwrap_or("");
                    match part.kind() {
                        "heredoc_start" => {
                            quoted = t.contains(['\'', '"', '\\']);
                        }
                        "heredoc_body" => text = t.to_string(),
                        _ => {}
                    }
                }
                let script = if quoted {
                    text
                } else {
                    unescape_heredoc(&text)
                };
                if script_variants_deny(&script, depth) {
                    return true;
                }
            }
            "herestring_redirect" => {
                if let Ok(t) = child.utf8_text(source.as_bytes()) {
                    let t = t.trim_start_matches('<').trim_start();
                    for w in lex_words(t) {
                        if script_variants_deny(&stringify(&w), depth) {
                            return true;
                        }
                    }
                }
            }
            _ => {}
        }
    }
    false
}

/// An unquoted here document: `\$`, `` \` `` and `\\` lose the backslash, and a
/// backslash-newline joins lines.
fn unescape_heredoc(text: &str) -> String {
    let mut out = String::new();
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.peek() {
                Some('$' | '`' | '\\') => out.push(chars.next().unwrap_or('\\')),
                Some('\n') => {
                    chars.next();
                }
                _ => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Remove the backslash before a quote, `$` or backtick. Layers of quoting often escape
/// the inner quotes; reading the script both ways is stricter and never looser.
fn deescape(text: &str) -> String {
    let mut out = String::new();
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' && matches!(chars.peek(), Some('"' | '\'' | '$' | '`')) {
            out.push(chars.next().unwrap_or('\\'));
        } else {
            out.push(c);
        }
    }
    out
}

fn script_variants_deny(script: &str, depth: usize) -> bool {
    scan(script, depth + 1) || {
        let alt = deescape(script);
        alt != script && scan(&alt, depth + 1)
    }
}

/// Options of a wrapper that take a value in the next word.
fn option_takes_value(wrapper: &str, option: &str) -> bool {
    let list: &[&str] = match wrapper {
        "sudo" | "doas" => &[
            "-u", "-g", "-h", "-p", "-r", "-t", "-C", "-D", "-R", "-T", "-U",
        ],
        "env" => &["-u", "-C", "--unset", "--chdir"],
        "timeout" => &["-s", "-k", "--signal", "--kill-after"],
        "nice" => &["-n", "--adjustment"],
        "ionice" => &["-c", "-n", "-p", "-P", "-t"],
        "stdbuf" => &["-i", "-o", "-e"],
        "xargs" => &["-n", "-I", "-L", "-P", "-s", "-d", "-E", "-a", "-J"],
        "exec" => &["-a"],
        _ => &[],
    };
    list.contains(&option)
}

const WRAPPERS: &[&str] = &[
    "command",
    "builtin",
    "exec",
    "noglob",
    "nocorrect",
    "-",
    "nohup",
    "time",
    "sudo",
    "doas",
    "env",
    "nice",
    "ionice",
    "timeout",
    "stdbuf",
    "xargs",
    "repeat",
];

/// Find `rm` behind wrappers, or a script behind a shell, `eval` or `find -exec`.
fn words_deny(words: &[Word], depth: usize) -> bool {
    let mut i = 0;
    while let Some(first) = words.get(i) {
        let Some(name) = plain_text(first) else {
            return false;
        };
        let base = name.rsplit('/').next().unwrap_or(&name).to_string();
        let base = base.as_str();
        match base {
            "rm" | "grm" => return rm_denies(&words[i + 1..], depth),
            "eval" => {
                let script = words[i + 1..]
                    .iter()
                    .map(stringify)
                    .collect::<Vec<_>>()
                    .join(" ");
                return script_variants_deny(&script, depth);
            }
            "find" => return find_exec_denies(&words[i + 1..], depth),
            b if SHELLS.contains(&b) => return shell_denies(&words[i + 1..], depth),
            b if WRAPPERS.contains(&b) => {
                let mut j = i + 1;
                let mut positional_to_skip = usize::from(matches!(b, "timeout" | "repeat"));
                while let Some(w) = words.get(j) {
                    let Some(text) = plain_text(w) else { break };
                    if b == "env" && (text == "-S" || text == "--split-string") {
                        return words
                            .get(j + 1)
                            .map(|s| script_variants_deny(&stringify(s), depth))
                            .unwrap_or(false);
                    }
                    if b == "command" && (text == "-v" || text == "-V") {
                        return false;
                    }
                    if text == "--" {
                        j += 1;
                        break;
                    }
                    if text.len() > 1 && text.starts_with('-') {
                        j += 1;
                        if option_takes_value(b, &text) {
                            j += 1;
                        }
                    } else if b == "env" && text.contains('=') {
                        j += 1;
                    } else if positional_to_skip > 0 {
                        positional_to_skip -= 1;
                        j += 1;
                    } else {
                        break;
                    }
                }
                i = j;
            }
            _ => return false,
        }
    }
    false
}

/// `bash -c 'script'`, `bash -lc`, `bash -c -- 'script'`, `su -c 'script' user`.
fn shell_denies(words: &[Word], depth: usize) -> bool {
    let mut c_seen = false;
    let mut end_of_options = false;
    let mut skip_next = false;
    for w in words {
        if skip_next {
            skip_next = false;
            continue;
        }
        let text = plain_text(w);
        if !end_of_options {
            if let Some(t) = &text {
                if t == "--" {
                    end_of_options = true;
                    continue;
                }
                if t.len() > 1 && (t.starts_with('-') || t.starts_with('+')) {
                    if t == "-o" || t == "+o" || t == "--rcfile" || t == "--init-file" {
                        skip_next = true;
                    } else if t.starts_with('-')
                        && !t.starts_with("--")
                        && t[1..].chars().all(|c| c.is_ascii_alphabetic())
                        && t.contains('c')
                    {
                        c_seen = true;
                    }
                    continue;
                }
            }
        }
        // First operand: the script when `-c` was given, otherwise a script file.
        return c_seen && script_variants_deny(&stringify(w), depth);
    }
    false
}

/// `find ... -exec cmd args ;`
fn find_exec_denies(words: &[Word], depth: usize) -> bool {
    let mut i = 0;
    while i < words.len() {
        let is_exec = plain_text(&words[i])
            .map(|t| matches!(t.as_str(), "-exec" | "-execdir" | "-ok" | "-okdir"))
            .unwrap_or(false);
        if is_exec {
            let mut j = i + 1;
            while j < words.len() {
                let end = plain_text(&words[j])
                    .map(|t| t == ";" || t == "+")
                    .unwrap_or(false);
                if end {
                    break;
                }
                j += 1;
            }
            if words_deny(&words[i + 1..j], depth) {
                return true;
            }
            i = j;
        }
        i += 1;
    }
    false
}

/// The operands of `rm`: words after the flags, or after `--`.
fn rm_denies(words: &[Word], depth: usize) -> bool {
    let mut options_done = false;
    for w in words {
        if !options_done {
            if let Some(text) = plain_text(w) {
                if text == "--" {
                    options_done = true;
                    continue;
                }
                if text.len() > 1 && text.starts_with('-') {
                    continue;
                }
            }
        }
        if operand_denies(w, depth) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lex(text: &str) -> Vec<Word> {
        lex_words(text)
    }

    #[test]
    fn decodes_quotes_escapes_and_ansi_c() {
        let w = lex("r\\m \"r\"''m $'\\x72m'");
        assert_eq!(w.len(), 3);
        for word in w {
            assert_eq!(plain_text(&word).as_deref(), Some("rm"));
        }
        let w = lex("$HOME/$'\\x2e\\x2e'/*");
        assert_eq!(
            w[0],
            vec![
                Piece::Home,
                Piece::Lit('/'),
                Piece::Lit('.'),
                Piece::Lit('.'),
                Piece::Lit('/'),
                Piece::Glob('*')
            ]
        );
    }

    #[test]
    fn tilde_is_home_only_at_the_start_and_unquoted() {
        assert_eq!(lex("~")[0], vec![Piece::Home]);
        assert_eq!(lex("~/x")[0][0], Piece::Home);
        assert_eq!(lex("~alice")[0], vec![Piece::Home]);
        assert_eq!(lex("'~'")[0], vec![Piece::Lit('~')]);
        assert_eq!(lex("\"~\"")[0], vec![Piece::Lit('~')]);
        assert_eq!(lex("\\~")[0], vec![Piece::Lit('~')]);
        assert_eq!(lex("a~")[0], vec![Piece::Lit('a'), Piece::Lit('~')]);
        assert_eq!(lex("~+")[0], vec![Piece::Lit('~'), Piece::Lit('+')]);
        assert_eq!(lex("$'~'")[0], vec![Piece::Lit('~')]);
    }

    #[test]
    fn redirections_end_the_word_and_drop_the_target() {
        let w = lex("$HOME>/dev/null 2>&1");
        assert_eq!(w[0], vec![Piece::Home]);
        assert_eq!(w.len(), 2); // `$HOME` and the file descriptor `2`
        assert_eq!(lex("~<in x").len(), 2);
    }

    #[test]
    fn brace_expansion_includes_the_empty_arm() {
        let w = lex("$HOME/{build,}");
        let mut budget = MAX_ALTERNATIVES;
        let alts = expand_braces(&w[0], &mut budget).unwrap();
        assert_eq!(alts.len(), 2);
        assert!(alts.iter().any(|a| candidate_denies(a)));
        let w = lex("~/{a,b}");
        let alts = expand_braces(&w[0], &mut MAX_ALTERNATIVES.clone()).unwrap();
        assert!(!alts.iter().any(|a| candidate_denies(a)));
        // A sequence is one alternative; a literal `{a}` keeps its braces.
        let w = lex("~/{1..3}");
        assert_eq!(
            expand_braces(&w[0], &mut MAX_ALTERNATIVES.clone())
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn too_many_alternatives_is_decided_by_the_start() {
        let big = format!("$HOME/{}", "{a,b}".repeat(12));
        assert!(denies(&format!("rm -rf {big}")));
        let big = format!("./x/{}", "{a,b}".repeat(12));
        assert!(!denies(&format!("rm -rf {big}")));
    }

    #[test]
    fn wide_globs() {
        let wide = |s: &str| is_wide(&lex(s)[0]);
        for s in [
            "*", "**", "?*", ".*", "[!.]*", "[^.]*", ".[!.]*", ".[^.]*", ".??*", "..?*", "*(D)",
            "**(D)", "*(N)", ".[a-z]*",
        ] {
            assert!(wide(s), "{s}");
        }
        for s in ["*.txt", ".*rc", ".cache", "a*", "build", "?x", "..foo"] {
            assert!(!wide(s), "{s}");
        }
    }

    #[test]
    fn paths_are_normalised() {
        for cmd in [
            "rm ~",
            "rm ~/",
            "rm ~//",
            "rm ~/.",
            "rm ~/./",
            "rm ~/build/..",
            "rm ~/..",
            "rm $HOME/a/../..",
            "rm /Users/x",
            "rm /Users/x/proj/..",
            "rm /Users",
            "rm /home",
            "rm /",
            "rm /Users/*",
            "rm /U*/x",
            "rm /Users/x/*",
        ] {
            assert!(denies(cmd), "{cmd}");
        }
        for cmd in [
            "rm ~/proj",
            "rm ~/proj/..hidden",
            "rm ~/a/../b",
            "rm /Users/x/proj",
            "rm /Users/x/proj/*",
            "rm /etc",
            "rm /tmp/x",
            "rm build",
            "rm ../x",
        ] {
            // `~/a/../b` and `~/proj/..hidden` are subpaths; this check does not add them.
            assert!(!denies(cmd), "{cmd}");
        }
    }

    #[test]
    fn undecodable_word_with_a_home_prefix_is_denied() {
        for cmd in [
            "rm $HOME$x",
            "rm ~/$x",
            "rm ${HOME}${x}",
            "rm $HOME$(true)",
            "rm /Users/$u/x",
            "rm /home/alice/$x",
            "rm /Users/$x",
        ] {
            assert!(denies(cmd), "{cmd}");
        }
        for cmd in ["rm $x", "rm $x/$y", "rm /$x", "rm ./$x", "rm $HOMEDIR"] {
            assert!(!denies(cmd), "{cmd}");
        }
    }

    #[test]
    fn finds_rm_behind_wrappers_and_scripts() {
        for cmd in [
            "\\rm ~",
            "/bin/rm ~",
            "command rm ~",
            "builtin rm ~",
            "exec rm ~",
            "sudo -u root rm ~",
            "env A=1 rm ~",
            "timeout 5 rm ~",
            "bash -c 'rm ~'",
            "bash -lc 'rm ~'",
            "sh -c -- 'rm ~'",
            "eval 'rm ~'",
            "echo `rm ~`",
            "echo $(rm ~)",
            "find . -exec rm ~ {} \\;",
            "if true; then rm ~; fi",
            "f() { rm ~; }",
            "sh <<EOF\nrm ~\nEOF",
            "bash <<< 'rm ~'",
        ] {
            assert!(denies(cmd), "{cmd}");
        }
        for cmd in [
            "echo rm ~",
            "echo \"rm ~\"",
            "command -v rm ~",
            "bash script.sh ~",
            "bash -c 'echo ~'",
            "printf '%s' rm ~",
        ] {
            assert!(!denies(cmd), "{cmd}");
        }
    }

    #[test]
    fn nesting_is_bounded() {
        let mut cmd = "rm -rf ~".to_string();
        for _ in 0..8 {
            cmd = format!("bash -c '{}'", cmd.replace('\'', "'\\''"));
        }
        // Deep nesting is refused without recursing forever; either answer is fine,
        // the call must return.
        let _ = denies(&cmd);
        assert!(denies("bash -c 'bash -c \"rm -rf ~\"'"));
    }
}
