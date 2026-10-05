//! A deliberately small Python data-processing grammar, not a Python evaluator.
//! Unknown tokens, names, attributes, dynamic calls and unsupported syntax fail
//! closed. Module members are exact pairs, never a wildcard or a suffix match.

const MODULES: &[&str] = &[
    "json",
    "sys",
    "re",
    "csv",
    "collections",
    "itertools",
    "math",
];
const BUILTINS: &[&str] = &[
    "print",
    "len",
    "sum",
    "min",
    "max",
    "abs",
    "round",
    "int",
    "float",
    "str",
    "bool",
    "list",
    "dict",
    "set",
    "tuple",
    "sorted",
    "reversed",
    "enumerate",
    "zip",
    "range",
    "map",
    "filter",
    "any",
    "all",
];
// Fixed local names, rather than accepting arbitrary user-defined identifiers.
const LOCALS: &[&str] = &[
    "x", "y", "i", "n", "row", "item", "line", "data", "value", "key", "match",
];
const KWARGS: &[&str] = &[
    "indent",
    "sort_keys",
    "ensure_ascii",
    "sep",
    "end",
    "key",
    "reverse",
    "default",
    "flags",
];
const METHODS: &[&str] = &[
    "get",
    "keys",
    "values",
    "items",
    "append",
    "extend",
    "split",
    "splitlines",
    "rsplit",
    "strip",
    "lstrip",
    "rstrip",
    "join",
    "count",
    "startswith",
    "endswith",
    "lower",
    "upper",
    "replace",
    "index",
    "find",
    "sort",
    "most_common",
    "group",
    "groups",
];

fn member(module: &str, name: &str) -> bool {
    let members: &[&str] = match module {
        "json" => &["load", "loads", "dump", "dumps"],
        "sys" => &["argv", "exit"],
        "re" => &["findall", "match", "search", "sub", "split", "compile"],
        "csv" => &["reader", "DictReader", "writer"],
        "collections" => &["Counter", "defaultdict", "OrderedDict"],
        "itertools" => &[
            "accumulate",
            "chain",
            "combinations",
            "combinations_with_replacement",
            "compress",
            "dropwhile",
            "filterfalse",
            "groupby",
            "islice",
            "pairwise",
            "permutations",
            "product",
            "starmap",
            "takewhile",
            "tee",
            "zip_longest",
        ],
        "math" => &[
            "acos",
            "acosh",
            "asin",
            "asinh",
            "atan",
            "atan2",
            "atanh",
            "ceil",
            "comb",
            "copysign",
            "cos",
            "cosh",
            "degrees",
            "dist",
            "erf",
            "erfc",
            "exp",
            "exp2",
            "expm1",
            "fabs",
            "factorial",
            "floor",
            "fmod",
            "frexp",
            "fsum",
            "gamma",
            "gcd",
            "hypot",
            "isclose",
            "isfinite",
            "isinf",
            "isnan",
            "isqrt",
            "lcm",
            "ldexp",
            "lgamma",
            "log",
            "log10",
            "log1p",
            "log2",
            "modf",
            "nextafter",
            "perm",
            "pow",
            "prod",
            "radians",
            "remainder",
            "sin",
            "sinh",
            "sqrt",
            "tan",
            "tanh",
            "trunc",
            "ulp",
            "e",
            "inf",
            "nan",
            "pi",
            "tau",
        ],
        _ => &[],
    };
    members.contains(&name)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Token<'a> {
    Name(&'a str),
    Literal,
    Number,
    Symbol(&'a str),
}

/// Strip comments and plain/r/b/br/rb strings, but retain a literal token so
/// adjacency cannot hide names. Reject f/t/u strings, triples and unterminated
/// literals. Escapes inside strings are data; escapes outside them are rejected.
fn lex(code: &str) -> Option<Vec<Token<'_>>> {
    let bytes = code.as_bytes();
    // Reject these everywhere, including inside comments and string literals.
    // Python treats CR as a newline; skipping it in a comment hides statements.
    if bytes.iter().any(|b| matches!(b, 0 | b'\r' | 0x0c)) {
        return None;
    }
    let mut tokens = Vec::new();
    let mut brackets = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if tokens.len() > 4096 {
            return None;
        }
        let start = i;
        let mut raw = false;
        let mut byte_string = false;
        match bytes[i] {
            b' ' | b'\t' => {
                if brackets.is_empty() && (i == 0 || bytes[i - 1] == b'\n') {
                    while matches!(bytes.get(i), Some(b' ' | b'\t')) {
                        i += 1;
                    }
                    if matches!(bytes.get(i), None | Some(b'\n' | b'#')) {
                        continue;
                    }
                    return None; // No indented suites in this grammar.
                }
                i += 1;
                continue;
            }
            b'\n' => {
                i += 1;
                if brackets.is_empty() {
                    tokens.push(Token::Symbol("\n"));
                }
                continue;
            }
            b'#' => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
                continue;
            }
            b'a'..=b'z' | b'A'..=b'Z' | b'_' => {
                i += 1;
                while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                    i += 1;
                }
                let name = &code[start..i];
                if !matches!(bytes.get(i), Some(b'\'' | b'"')) {
                    if name.contains("__") {
                        return None;
                    }
                    tokens.push(Token::Name(name));
                    continue;
                }
                if !matches!(name.to_ascii_lowercase().as_str(), "r" | "b" | "br" | "rb") {
                    return None;
                }
                raw = name.eq_ignore_ascii_case("r") || name.len() == 2;
                byte_string = !name.eq_ignore_ascii_case("r");
            }
            b'\'' | b'"' => {}
            b'0'..=b'9' => {
                i += 1;
                while i < bytes.len() && bytes[i].is_ascii_digit() {
                    i += 1;
                }
                // Nonzero decimal integers cannot have a leading zero in Python.
                if bytes[start] == b'0' && bytes[start..i].iter().any(|b| *b != b'0') {
                    return None;
                }
                if bytes.get(i) == Some(&b'.') {
                    i += 1;
                    while i < bytes.len() && bytes[i].is_ascii_digit() {
                        i += 1;
                    }
                }
                if matches!(bytes.get(i), Some(b'e' | b'E')) {
                    i += 1;
                    if matches!(bytes.get(i), Some(b'+' | b'-')) {
                        i += 1;
                    }
                    let exponent = i;
                    while i < bytes.len() && bytes[i].is_ascii_digit() {
                        i += 1;
                    }
                    if exponent == i {
                        return None;
                    }
                }
                tokens.push(Token::Number);
                continue;
            }
            b'(' | b'[' | b'{' => {
                brackets.push(bytes[i]);
            }
            b')' | b']' | b'}' => {
                let open = brackets.pop()?;
                if !matches!((open, bytes[i]), (b'(', b')') | (b'[', b']') | (b'{', b'}')) {
                    return None;
                }
            }
            b'.' | b',' | b':' | b';' | b'+' | b'-' | b'*' | b'/' | b'%' | b'<' | b'>' | b'='
            | b'!' | b'&' | b'|' | b'^' | b'~' => {}
            _ => return None,
        }
        if matches!(bytes.get(i), Some(b'\'' | b'"')) {
            let quote = bytes[i];
            if bytes.get(i + 1) == Some(&quote) && bytes.get(i + 2) == Some(&quote) {
                return None;
            }
            i += 1;
            loop {
                match bytes.get(i)? {
                    b'\\' => {
                        i += 1;
                        let escaped = *bytes.get(i)?;
                        if byte_string && !escaped.is_ascii() {
                            return None;
                        }
                        if !raw {
                            match escaped {
                                b'\\'
                                | b'\''
                                | b'"'
                                | b'a'
                                | b'b'
                                | b'f'
                                | b'n'
                                | b'r'
                                | b't'
                                | b'v'
                                | b'\n'
                                | b'0'..=b'7' => {}
                                b'x' | b'u' | b'U' => {
                                    if byte_string && escaped != b'x' {
                                        return None;
                                    }
                                    let count = match escaped {
                                        b'x' => 2,
                                        b'u' => 4,
                                        _ => 8,
                                    };
                                    let digits = bytes.get(i + 1..i + 1 + count)?;
                                    if !digits.iter().all(u8::is_ascii_hexdigit) {
                                        return None;
                                    }
                                    if escaped == b'U'
                                        && u32::from_str_radix(&code[i + 1..i + 1 + count], 16)
                                            .ok()?
                                            > 0x10ffff
                                    {
                                        return None;
                                    }
                                    i += count;
                                }
                                _ => return None,
                            }
                        }
                        i += 1;
                    }
                    b'\n' | b'\r' => return None,
                    b if *b == quote => {
                        i += 1;
                        break;
                    }
                    b if byte_string && !b.is_ascii() => return None,
                    _ => i += 1,
                }
            }
            tokens.push(Token::Literal);
        } else {
            i += 1;
            if matches!(
                bytes.get(start..start + 2),
                Some(b"==" | b"!=" | b"<=" | b">=" | b"//" | b"**" | b"<<" | b">>" | b":=")
            ) {
                i += 1;
            }
            tokens.push(Token::Symbol(&code[start..i]));
        }
        // Bound recursion and work on adversarially large literals/scripts.
        if brackets.len() > 64 || tokens.len() > 4096 {
            return None;
        }
    }
    brackets.is_empty().then_some(tokens)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Shape<'a> {
    Data,
    Callable(&'a str),
    Stdin,
    Stdout,
}

struct Parser<'a> {
    tokens: Vec<Token<'a>>,
    pos: usize,
    depth: usize,
    imported: Vec<(&'a str, &'a str)>,
}

impl<'a> Parser<'a> {
    fn take(&mut self, token: Token<'a>) -> bool {
        if self.tokens.get(self.pos) == Some(&token) {
            self.pos += 1;
            true
        } else {
            false
        }
    }
    fn symbol(&mut self, s: &'a str) -> bool {
        self.take(Token::Symbol(s))
    }
    fn name(&mut self, s: &'a str) -> bool {
        self.take(Token::Name(s))
    }
    fn identifier(&mut self) -> Option<&'a str> {
        let Token::Name(name) = *self.tokens.get(self.pos)? else {
            return None;
        };
        self.pos += 1;
        Some(name)
    }
    fn local(&mut self) -> Option<()> {
        LOCALS.contains(&self.identifier()?).then_some(())
    }

    fn statement(&mut self) -> Option<()> {
        if self.name("import") {
            loop {
                if !MODULES.contains(&self.identifier()?) {
                    return None;
                }
                if !self.symbol(",") {
                    break;
                }
            }
        } else if self.name("from") {
            let module = self.identifier()?;
            if !MODULES.contains(&module) || !self.name("import") {
                return None;
            }
            loop {
                let name = self.identifier()?;
                if !member(module, name) || name == "compile" {
                    return None;
                }
                self.imported.push((module, name));
                if !self.symbol(",") {
                    break;
                }
            }
        } else if self.name("for") {
            self.local()?;
            if !self.name("in") {
                return None;
            }
            self.expression(0, Some(Shape::Stdin))?;
            if !self.symbol(":") {
                return None;
            }
            // Only a simple one-line suite; no recursive compound statements.
            self.simple_statement()?;
        } else if self.name("if") {
            self.expression(0, None)?;
            if !self.symbol(":") {
                return None;
            }
            self.simple_statement()?;
        } else {
            self.simple_statement()?;
        }
        Some(())
    }

    fn simple_statement(&mut self) -> Option<()> {
        if matches!(self.tokens.get(self.pos), Some(Token::Name(n)) if LOCALS.contains(n))
            && self.tokens.get(self.pos + 1) == Some(&Token::Symbol("="))
        {
            self.pos += 2;
        }
        self.expression(0, None)?;
        Some(())
    }

    // Pratt parser: only explicitly supported expression syntax is exempt.
    fn expression(&mut self, min: u8, special: Option<Shape<'a>>) -> Option<Shape<'a>> {
        self.depth += 1;
        if self.depth > 64 {
            return None;
        }
        let result = self.expression_inner(min, special);
        self.depth -= 1;
        result
    }

    fn expression_inner(&mut self, min: u8, special: Option<Shape<'a>>) -> Option<Shape<'a>> {
        let mut shape = if min == 0 && self.name("lambda") {
            self.local()?;
            while self.symbol(",") {
                self.local()?;
            }
            if !self.symbol(":") {
                return None;
            }
            self.expression(0, None)?;
            Shape::Callable("lambda")
        } else if self.symbol("+")
            || self.symbol("-")
            || self.symbol("~")
            || (min <= 4 && self.name("not"))
        {
            self.expression(11, None)?;
            Shape::Data
        } else {
            self.atom(special)?
        };
        loop {
            if self.symbol(".") {
                let method = self.identifier()?;
                if shape != Shape::Data || !METHODS.contains(&method) {
                    return None;
                }
                shape = Shape::Callable(method);
            } else if self.symbol("(") {
                let Shape::Callable(call) = shape else {
                    return None;
                };
                self.arguments(call)?;
                shape = Shape::Data;
            } else if self.symbol("[") {
                if shape != Shape::Data {
                    return None;
                }
                if self.tokens.get(self.pos) != Some(&Token::Symbol(":")) {
                    self.expression(0, None)?;
                }
                if self.symbol(":")
                    && !matches!(self.tokens.get(self.pos), Some(Token::Symbol("]" | ":")))
                {
                    self.expression(0, None)?;
                }
                if self.symbol(":") && self.tokens.get(self.pos) != Some(&Token::Symbol("]")) {
                    self.expression(0, None)?;
                }
                if !self.symbol("]") {
                    return None;
                }
                shape = Shape::Data;
            } else {
                let (left, right) = match self.tokens.get(self.pos) {
                    Some(Token::Name("or")) => (1, 2),
                    Some(Token::Name("and")) => (3, 4),
                    Some(Token::Name("in" | "is"))
                    | Some(Token::Symbol("==" | "!=" | "<" | ">" | "<=" | ">=")) => (5, 6),
                    Some(Token::Symbol("|" | "^" | "&" | "<<" | ">>")) => (7, 8),
                    Some(Token::Symbol("+" | "-")) => (9, 10),
                    Some(Token::Symbol("*" | "/" | "//" | "%")) => (11, 12),
                    Some(Token::Symbol("**")) => (14, 13),
                    _ => break,
                };
                if left < min {
                    break;
                }
                if matches!(shape, Shape::Stdin | Shape::Stdout) {
                    return None;
                }
                self.pos += 1;
                self.expression(right, None)?;
                shape = Shape::Data;
            }
        }
        if min == 0 && self.name("if") {
            self.expression(1, None)?;
            if !self.name("else") {
                return None;
            }
            self.expression(0, None)?;
            shape = Shape::Data;
        }
        if matches!(shape, Shape::Stdin | Shape::Stdout) && special != Some(shape) {
            return None;
        }
        Some(shape)
    }

    fn atom(&mut self, special: Option<Shape<'a>>) -> Option<Shape<'a>> {
        if self.take(Token::Literal) {
            while self.take(Token::Literal) {}
            return Some(Shape::Data);
        }
        if self.take(Token::Number) {
            return Some(Shape::Data);
        }
        for (open, close) in [("(", ")"), ("[", "]"), ("{", "}")] {
            if self.symbol(open) {
                if self.symbol(close) {
                    return Some(Shape::Data);
                }
                let start = self.pos;
                let mut shape = self.expression(0, special)?;
                if self.symbol(":=") {
                    // Walrus targets must be one of the fixed local names.
                    if self.pos != start + 2
                        || !matches!(self.tokens.get(start), Some(Token::Name(n)) if LOCALS.contains(n))
                    {
                        return None;
                    }
                    self.expression(0, None)?;
                    shape = Shape::Data;
                }
                let dictionary = open == "{" && self.symbol(":");
                if dictionary {
                    self.expression(0, None)?;
                }
                if self.name("for") {
                    self.comprehension()?;
                    shape = Shape::Data;
                } else {
                    while self.symbol(",") {
                        if self.tokens.get(self.pos) == Some(&Token::Symbol(close)) {
                            break;
                        }
                        self.expression(0, None)?;
                        if open == "{" {
                            if self.symbol(":") != dictionary {
                                return None;
                            }
                            if dictionary {
                                self.expression(0, None)?;
                            }
                        }
                        shape = Shape::Data;
                    }
                }
                if !self.symbol(close) {
                    return None;
                }
                if open != "(" && matches!(shape, Shape::Stdin | Shape::Stdout) {
                    return None;
                }
                return Some(if open == "(" { shape } else { Shape::Data });
            }
        }
        let name = self.identifier()?;
        if MODULES.contains(&name) {
            if !self.symbol(".") {
                return None;
            }
            let attr = self.identifier()?;
            if name == "sys" && matches!(attr, "stdin" | "stdout") {
                if self.symbol(".") {
                    let method = self.identifier()?;
                    if (attr == "stdin" && matches!(method, "read" | "readline" | "readlines"))
                        || (attr == "stdout" && method == "write")
                    {
                        return Some(Shape::Callable(method));
                    }
                    return None;
                }
                return Some(if attr == "stdin" {
                    Shape::Stdin
                } else {
                    Shape::Stdout
                });
            }
            if !member(name, attr) {
                return None;
            }
            if (name == "sys" && attr == "argv")
                || (name == "math" && matches!(attr, "e" | "inf" | "nan" | "pi" | "tau"))
            {
                return Some(Shape::Data);
            }
            return Some(Shape::Callable(if name == "json" && attr == "load" {
                "json.load"
            } else if name == "json" && attr == "dump" {
                "json.dump"
            } else {
                attr
            }));
        }
        if let Some(&(module, attr)) = self.imported.iter().rev().find(|(_, attr)| *attr == name) {
            return Some(
                if (module == "sys" && attr == "argv")
                    || (module == "math" && matches!(attr, "e" | "inf" | "nan" | "pi" | "tau"))
                {
                    Shape::Data
                } else {
                    Shape::Callable(if module == "json" && attr == "load" {
                        "json.load"
                    } else if module == "json" && attr == "dump" {
                        "json.dump"
                    } else {
                        attr
                    })
                },
            );
        }
        if BUILTINS.contains(&name) {
            return Some(Shape::Callable(name));
        }
        if LOCALS.contains(&name) || matches!(name, "True" | "False" | "None") {
            return Some(Shape::Data);
        }
        None
    }

    fn arguments(&mut self, call: &str) -> Option<()> {
        if self.symbol(")") {
            return Some(());
        }
        let mut index = 0;
        let mut keywords = Vec::new();
        loop {
            let mut keyword = false;
            if matches!(self.tokens.get(self.pos), Some(Token::Name(n)) if KWARGS.contains(n))
                && self.tokens.get(self.pos + 1) == Some(&Token::Symbol("="))
            {
                let Token::Name(name) = self.tokens[self.pos] else {
                    return None;
                };
                if keywords.contains(&name) {
                    return None;
                }
                keywords.push(name);
                self.pos += 2;
                keyword = true;
            }
            if !keyword && !keywords.is_empty() {
                return None;
            }
            let special = match (call, index, keyword) {
                ("json.load", 0, false) => Some(Shape::Stdin),
                ("json.dump", 1, false) => Some(Shape::Stdout),
                _ => None,
            };
            self.expression(0, special)?;
            if self.name("for") {
                if keyword || index != 0 {
                    return None;
                }
                self.comprehension()?;
                return self.symbol(")").then_some(());
            }
            index += 1;
            if !self.symbol(",") {
                return self.symbol(")").then_some(());
            }
            if self.symbol(")") {
                return Some(());
            }
        }
    }

    fn comprehension(&mut self) -> Option<()> {
        loop {
            self.local()?;
            if !self.name("in") {
                return None;
            }
            self.expression(1, Some(Shape::Stdin))?;
            while self.name("if") {
                self.expression(1, None)?;
            }
            if !self.name("for") {
                return Some(());
            }
        }
    }
}

pub(super) fn is_allowlisted(code: &str) -> bool {
    let Some(tokens) = lex(code) else {
        return false;
    };
    if tokens.is_empty() || tokens.len() > 4096 {
        return false;
    }
    let mut parser = Parser {
        tokens,
        pos: 0,
        depth: 0,
        imported: Vec::new(),
    };
    while parser.pos < parser.tokens.len() {
        if parser.symbol("\n") {
            continue;
        }
        if parser.statement().is_none() {
            return false;
        }
        if parser.pos < parser.tokens.len() {
            if parser.symbol(";") {
                if matches!(
                    parser.tokens.get(parser.pos),
                    Some(Token::Name("for" | "if"))
                ) {
                    return false;
                }
            } else if !parser.symbol("\n") {
                return false;
            }
        }
    }
    true
}
