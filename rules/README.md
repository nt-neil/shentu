# Shentu code rules

Shentu's own rules for injection-class vulnerabilities in application code. Each rule
describes one pattern: **user input (a source) that reaches a dangerous call (a sink)
without passing through a sanitizer**. Package `rules/engine` applies them (see
[The engine](#the-engine)); `go test ./rules/...` checks that every rule is well
formed and that the engine finds every vulnerable sample and no safe one.

All rules and samples here are written for Shentu. Nothing is copied from Semgrep,
Opengrep, Bandit, progpilot, njsscan or any other tool, and no sample is taken from
the source code of a vulnerable project.

## Layout

```
rules/<lang>/<class>/<id>.toml
```

| field | values |
|---|---|
| `lang` | `php`, `python`, `js` |
| `class` | `sqli`, `cmdi`, `path-traversal` (includes file inclusion), `deserialization`, `code-eval` |

## Format

```toml
id = "php-sqli-string-concat"      # <lang>-<class>-<slug>, lowercase, unique, = file name
lang = "php"
class = "sqli"
cwe = "CWE-89"                     # must belong to the class (see below)
severity = "high"                  # critical | high | medium | low
tier = "info"                      # optional: info (default) | alert, see "Tiers"
title = "Request input concatenated into a SQL string"
frameworks = ["laravel"]           # optional: laravel, wordpress, django, flask, express
sources = ["$_GET", "$request->input("]   # where user input comes from
sinks = ["mysqli_query", "->query("]      # the dangerous calls
sanitizers = ["intval", "->prepare("]     # calls whose result is safe for these sinks; [] if none
text = []                          # optional: entries of sources/sinks that are text in strings (below)
fix = "One sentence the user sees: how to fix it."
refs = ["CVE-2026-56738"]          # CVE-YYYY-NNNN or GHSA-xxxx-xxxx-xxxx that inspired the rule

[[args]]                           # optional, see "Argument conditions"
sinks = ["mysqli_query"]
arg = 2

[[samples]]
kind = "vulnerable"                # must be reported
note = "optional: why"
code = '''
<?php
$rows = mysqli_query($db, "SELECT * FROM t WHERE name = '" . $_GET['name'] . "'");
'''

[[samples]]
kind = "safe"                      # must not be reported
code = '''
<?php
$stmt = $pdo->prepare('SELECT * FROM t WHERE name = ?');
$stmt->execute([$_GET['name']]);
'''
```

`sources`, `sinks` and `sanitizers` are written the way they appear in code: a
function or member name, with `(` when the call matters and a leading `->` or `.`
when the receiver varies. An empty `sanitizers = []` means no function makes input
safe for these sinks and the fix is to replace the sink (for example `pickle.loads`).

How the engine reads them:

- Each entry is lexed as code of the rule's language and matched token by token,
  so it never matches inside a comment or a string literal.
- A sink or sanitizer that starts with a name is that name called directly:
  `exec(` matches `exec($cmd)`, not `$pdo->exec(...)` or `regex.exec(s)`. A method
  on any receiver starts with `->` (PHP) or `.` (Python, JavaScript):
  `->orderByRaw(`, `.startsWith(`. A module-qualified call must be written out
  (`os.system(`). Sources match anywhere, so `request.args` also matches
  `self.request.args`.
- A string in a pattern compares its content, whatever the quotes; an unclosed
  one is a prefix: `$_SERVER['HTTP_` matches every `$_SERVER['HTTP_...']`.
- A **sanitizer** is a call whose result is clean (`intval(`, `shlex.quote(`,
  `.resolve(`), a cast or `typeof` (clean operand), or a check. A check is a
  sanitizer that answers yes or no, used as a condition: `in_array($x, $allowed)`,
  `typeof x !== "string"`, `p.startsWith(BASE)`, `path.is_relative_to(BASE)`,
  `ctype_digit($x)`. A transforming sanitizer used as a condition validates
  nothing: after `if (intval($x))`, `$x` is still user input. The checked value is clean
  where the check holds: inside `if (check)`, and after `if (!check) { return; }`
  or `if (!check) { $x = 'default'; }`. A prefix check (`str_starts_with`,
  `strncmp`, `startsWith`) counts only against a base that ends with a separator
  (`realpath(...) . DIRECTORY_SEPARATOR`, `path.resolve(...) + path.sep`), so
  `/var/www/assets-private` cannot pass a check for `/var/www/assets`. Lookups in a
  fixed list are checks in every rule: `in_array`, `array_key_exists`,
  `x in ALLOWED`, `ALLOWED.includes(x)`, `ALLOWED.has(x)`.
- Also built into every rule:
  - a number carries no injection: `(int)`, `(float)`, `(bool)`, `intval`,
    `absint`, `floatval`, `int()`, `float()`, `len()`, `parseInt`, `parseFloat`,
    `Number` give clean values;
  - comparing a value with a literal validates it where the comparison holds:
    after `if ('ASC' !== $order) { $order = 'DESC'; }` it is one of the two. Loose
    `==` counts only against a plain string (in PHP `"../x" == true` holds);
  - a source matches after a qualifier too: `request.form` also finds
    `flask.request.form` and `self.request.form`;
  - PHP `empty($x)`, or `isset($x)` being false, means `$x` holds nothing;
  - a regular-expression test is a check when it allows only letters, digits,
    `_` and `-` from start to end (`preg_match('/^[a-z0-9_]+$/i', $x)`,
    `re.fullmatch(r'[\w-]+', x)`, `/^\d+$/.test(x)`), or when it looks for any
    other character (`if (preg_match('|[^a-z0-9_]|', $x)) die();`). A dot, any
    other character, a range across kinds (`A-z`), alternation, or multiline
    mode (`m`) makes it no check, and so does `u` on the second form (invalid
    UTF-8 makes `preg_match` fail, and the failure looks like "no match");
  - PHP `array_intersect` and `array_intersect_key` return values and keys of
    their first argument, so `array_intersect($allowed, $input)` is clean;
    WordPress `apply_filters($tag, $value, ...)` returns the filtered `$value`;
  - WordPress `validate_file($f, $allowed)` returns 0 for an allowed path, so
    `if (validate_file($f, $allowed)) wp_die();` validates `$f`, and
    `validate_file_to_edit($f, $allowed)` as a statement of its own stops the
    request unless `$f` is allowed. Without the list, or with an empty one (`[]`),
    both check only for `..` and validate nothing. They count in the rules that list them as sanitizers.
- Writing one key of an array (`$args['limit'] = absint(...)`) is tracked for that
  key, and appending to it (`$q['w'] .= $input`) taints it; reading another key or
  the whole array still sees the array. Writing user
  input under a key that is not a literal (`$a[$i] = ...`) forgets every key.
- Sanitizers are per rule, not per sink. When a sanitizer protects one sink but
  not another (`escapeshellarg` protects `exec()` but not the fifth argument of
  `mail()`), the sinks go in separate rules; escaping functions protect a SQL value
  only inside quotes, so they are not listed as sanitizers.

### Tiers

`tier` decides where a finding is shown. An `info` rule (the default) is listed by
the `app_code_audit` tool and in chat, but the daily patrol report does not push
it. An `alert` rule is pushed as well. Every new rule starts as `info`; it becomes
`alert` only after it has been run on real, clean projects and its false-positive
rate is low, and the change says which measurement justified it.

### Text in strings

Some sources and sinks are not code but text inside a string literal: an SQL
clause (`ORDER BY`) or a stream URL (`php://input`). List them in `text` as well
as in `sources` or `sinks`. A text entry matches case-insensitively, with any run
of spaces, inside string literals only (never in comments). A text source makes
the string user input; a text sink is reported when what follows the text, in the
same string's interpolations or in the values joined after it, is user input:
`"... ORDER BY $orderby"` and `"... ORDER BY " . $sort`, but not
`"... WHERE a = '$x' ORDER BY id"`. All other entries never match inside strings.

### Argument conditions

`[[args]]` (optional, any number) says which argument of a sink call carries the
attack, and when other arguments make the call dangerous or safe. Rules without
it are unchanged: a sink is reported when any argument is tainted.

| field | meaning |
|---|---|
| `sinks` | the rule's sinks this entry applies to; omitted means all of them; a sink has at most one entry |
| `arg` | only this argument counts, from 1; `0` is the receiver of a method sink (`tf.extractall()`: the archive is the input) |
| `when` | the call is a sink only if one of these appears among its arguments |
| `unless` | the call is not a sink if one of these appears among its arguments |
| `whole` | the argument must be the input itself (or spread from it), not an object or array literal holding a value from it |
| `leading` | the input must be at the start of the argument: a fixed prefix makes the call safe, as `WP_PLUGIN_DIR . "/$name"` cannot choose a `phar://` stream. A fixed prefix is a literal (or a run of literals) holding a character no URL scheme has (`/`, `_`, a space) before any `:`, so `'phar' . $x` and `'ph' . 'ar' . $x` are none; a constant; a ternary whose branches both are; a variable assigned one; a property or array key the input never reached (`$this->dir`, `$u['basedir']`), but never a superglobal or request object (`$_COOKIE[...]`, `$_SERVER['HTTP_...']`; `$_SERVER['DOCUMENT_ROOT']` is allowed); a call whose arguments hold no input, even through a sanitizer (`dirname(__FILE__)`, `get_template_directory()`, `strval(intval($x))`, but not `trim(basename($_GET['d']))`); `sprintf` whose format starts with such a literal; or a Laravel path helper (`storage_path(...)`). A call on input (`basename($_GET['d'])`) is not; a clean call that returns `""` (`trim(' ')`, an unset `getenv()`) is a known miss |

`when` and `unless` entries are code fragments matched anywhere in the call's
arguments, with two refinements:

- a fragment ending in `:` or `=` names an option. In `when`, `shell:` counts with
  any value except a literal `false`, `0`, `null` or `None` (`shell: '/bin/bash'`,
  `shell: isUnix`). In `unless`, `root:` counts only when its value is not user
  input.
- in `unless`, a fragment with an option and a value (`Loader=yaml.SafeLoader`,
  `'allowed_classes' => false`) counts only when the option's whole value is
  exactly that, so `Loader=yaml.SafeLoader if x else yaml.Loader` does not
  silence the call;
- a fragment that is a single string (`"--"`) ends a command's options. It counts
  only when no user input comes before it in its list;
- any other `unless` fragment (`yaml.SafeLoader`) must be a whole argument.

Examples from the rules:

```toml
# yaml.load is safe with the safe loader, dangerous with Loader, FullLoader or UnsafeLoader
[[args]]
sinks = ["yaml.load(", "yaml.load_all("]
unless = ["Loader=yaml.SafeLoader", "Loader=yaml.CSafeLoader", "Loader=SafeLoader", "Loader=CSafeLoader",
          "yaml.SafeLoader", "yaml.CSafeLoader", "SafeLoader", "CSafeLoader"]

# spawn and execFile take an argument array, unless a shell option joins it into a command line
[[args]]
when = ["shell:"]

# unserialize cannot create objects with allowed_classes => false
[[args]]
unless = ["'allowed_classes' => false"]

# only the fifth argument of mail() reaches sendmail
[[args]]
arg = 5

# a stream wrapper must be at the start of the path
[[args]]
leading = true
```

Allowed CWEs per class:

| class | CWE |
|---|---|
| `sqli` | CWE-89 |
| `cmdi` | CWE-77, CWE-78, CWE-88 |
| `path-traversal` | CWE-22, CWE-23, CWE-36, CWE-73, CWE-98 |
| `deserialization` | CWE-502 |
| `code-eval` | CWE-94, CWE-95, CWE-1336 |

## What CI checks (`rules_test.go`)

- every file parses, and has no unknown keys;
- required fields are present and non-empty (`sanitizers` must be present, may be `[]`);
- `id` is unique, follows `<lang>-<class>-<slug>`, and matches the file path;
- `lang`, `class`, `severity`, `tier`, `frameworks` are in the allowed lists, and `cwe` belongs to the class;
- `refs` are well-formed CVE or GHSA ids, without duplicates;
- `text` entries are sources or sinks; `[[args]]` entries set something, name only
  the rule's sinks, give each sink at most one entry, and use `arg = 0` only for
  method sinks;
- there is at least one `vulnerable` and one `safe` sample, and each vulnerable sample
  contains one of the rule's sources and one of its sinks.

`engine/samples_test.go` then runs the engine on every sample: each vulnerable
sample must be reported by its own rule, and no safe sample may be reported by any
rule of its language.

## Adding a rule

1. **Find a real case.** Use only public, free sources: CVE.org, NVD, GitHub Advisory
   (`gh api '/advisories?ecosystem=composer&cwes=89'`, also `pip`, `npm` and CWEs 78,
   22, 98, 502, 94), OSV and CISA KEV. Huntr and HackerOne public reports may be read
   to learn techniques, but are not bulk-collected or quoted. Commercial databases
   (Snyk, WPScan and the like) are not used.
2. **Read the fix.** From the advisory's patch commit, note where the input came from,
   which call it reached, and what the fix changed. That is the source, sink,
   sanitizer and `fix`.
3. **Write the samples yourself.** A minimal snippet in ordinary framework style that
   shows the same flow, and a fixed version. Do not paste code from the project.
4. **Record the advisory** in `refs`, and only one whose fix commit (or WordPress
   plugin changeset) you have read and found to match the rule. Prefer an advisory in
   the rule's own language. A rule may cover several advisories; add new
   refs to an existing rule instead of creating a near-duplicate.
5. Run `go test ./rules/...` (format checks and the engine on the samples). If a
   sample needs a construct the engine does not follow, fix the engine, not the sample.

## The engine

`rules/engine` is Shentu's own code, without dependencies. Per file:

1. **Lexing.** Hand-written lexers for PHP, Python and JavaScript drop comments and
   keep string literals whole, so text in comments and plain strings is never
   code. Interpolations are lexed as code: PHP `"$x"`, `"{$x->y}"`, `"${x}"`,
   heredoc (nowdoc stays text) and backticks; Python f-strings; JavaScript
   template literals, nested to any depth. Unterminated strings and comments end
   at the end of the line or file.
2. **Statements and scopes.** Statements, `if`/`else`, loops, `try` and function
   bodies (braces in PHP and JavaScript, indentation in Python). Closures and arrow
   functions are scopes of their own that see the variables around them; PHP
   named functions and methods start empty. Keywords are per language, so `fn`,
   `use` or `from` are variable names in JavaScript and Python.
3. **Taint, in order, inside each function.** Layer A: a sink whose argument
   contains a source that is not wrapped in a sanitizer is reported. Layer B: an
   assignment from a tainted value taints the variable (also `$obj->prop`,
   `$arr[] =`, destructuring, loop variables, `with ... as`); taint flows through
   concatenation, interpolation, f-strings, calls, array and member access;
   sanitizer results, literals and comparisons are clean; checks clean the values
   they validate (see above); after an `if`, a value is tainted if it is tainted on
   any path that goes on. Each `switch` case is a branch (falling through until
   `break`); a `try` body may stop at any statement, so its handlers start from
   the state before or after it.
4. **Calls inside the file.** A call to a function of the same file (a function,
   a method through `$this->`, `self::`, `static::`, `parent::`, `this.`,
   Python's `self.`/`cls.`, or a closure assigned to a variable) uses that
   function's summary for the rule: which parameters reach a sink and at which
   lines (a tainted argument reports those lines), which parameters the return
   value carries (a helper that returns `intval($v)` gives a clean result), and
   whether it returns input of its own. Summaries are computed on demand, only
   for functions holding one of the rule's sources, sinks or sanitizers (or
   calling one that does); recursion is recomputed until it settles. Input that
   only went through a call the engine does not know (`get_post($_GET['id'])`)
   still reports inside its own function, as before, but does not cross into
   another function's sinks. Depth (32), body analyses per rule and file (4000)
   and recursion rounds (4) are capped; over a cap the file returns `ErrLimit`.
   A rule whose sinks do not occur in a file is skipped for that file.
5. **Library mode** (`Engine.Library`, off by default and never on for the server
   patrol). For a scanned tree that is itself a package: the parameters of
   public functions and methods (not private/protected, not `_name`/`#name`, not
   typed `int`/`float`/`bool`) are input, for the `sqli`, `cmdi` and `code-eval`
   rules only, and not in test files. A finding then needs the parameter
   embedded in a larger string (concatenated, interpolated, formatted) on its way
   to the sink: a query or command taken as a whole parameter is what such an API
   is for.

Findings carry the rule, file, line, severity, title, CWE and fix, never the
code: application code must not leave the host or reach an AI model. Each file is
capped in tokens and time (`engine.Limits`); the time counts every token the
analysis scans. A file over a cap, or nested deeper than the engine reads (where
an expression too deep to read counts as user input), returns `ErrLimit`; a
string or comment that runs to the end of the file returns `ErrPartial`. Both
come with the findings made so far.

What it does not do: follow values across files (input read in a controller and
used in another class of another file is missed), know framework semantics beyond
the rules (a lookup in a constant dict is not an allowlist), look into options
kept in a variable (`const opts = { shell: true }; spawn(cmd, opts)`), or prove a
finding.
No finding does not mean no vulnerability.

Secrets never go into samples. If a sample needs something that looks like a key,
use an obvious placeholder.
