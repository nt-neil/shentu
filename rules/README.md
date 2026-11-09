# Shentu code rules

Shentu's own rules for vulnerabilities in application code. Most rules describe one
pattern: **user input (a source) that reaches a dangerous call (a sink) without passing
through a sanitizer**. A rule without sources is about how a call is made instead (a
weak cipher, a password written in the code); see [Rules without sources](#rules-without-sources). Package `rules/engine` applies them (see
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
| `class` | `sqli`, `cmdi`, `path-traversal` (includes file inclusion), `deserialization`, `code-eval`, `xss`, `ssrf`, `open-redirect`, `xxe`, `ldapi`, `nosqli`, `file-upload`, `weak-crypto`, `hardcoded-secret` |

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
sources = ["$_GET", "$request->input("]   # where user input comes from; [] for a rule without sources
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
  - `wp_die`, `wp_send_json`, `wp_send_json_error` and `wp_send_json_success` end
    the request, so `if (!in_array($x, $allowed)) { wp_send_json_error(); }`
    validates `$x` after it;
  - `array_map('absint', $x)` (any sanitizer of the rule, or a number cast, as the
    callback) returns sanitized values, with the keys of `$x`;
  - `extract(shortcode_atts(array('id' => 0, ...), $atts))` and `extract(array(...))`
    define one variable per literal key;
  - an assignment written in a condition (`if ($x = $_GET['y'])`) is followed;
  - a variable holding a value written in the code (`$o = array('test_form' =>
    false)`, `const opts = { shell: true }`, `$f = LIBXML_NOENT`) is read in its place
    by the argument conditions `when` and `unless`; a name given two different values
    in the file is not known;
  - text sinks match outside string interpolations: `"... $where"` is the variable
    `$where`, not the operator text `'$where'`;
  - a number carries no injection: `(int)`, `(float)`, `(bool)`, `intval`,
    `absint`, `floatval`, `int()`, `float()`, `len()`, `parseInt`, `parseFloat`,
    `Number` give clean values;
  - comparing a value with a literal validates it where the comparison holds:
    after `if ('ASC' !== $order) { $order = 'DESC'; }` it is one of the two. Loose
    `==` counts only against a plain string (in PHP `"../x" == true` holds);
  - a source matches after a qualifier too: `request.form` also finds
    `flask.request.form` and `self.request.form`;
  - PHP `empty($x)`, or `isset($x)` being false, means `$x` holds nothing, and so
    does a plain value used as a condition where it is false (`if ($cb) {...}`:
    after it, `$cb` is either empty or what the branch made it);
  - `preg_replace` (PHP) or `re.sub` (Python) with a negated class of letters,
    digits, `_` and `-`, an empty replacement and no limit or count leaves only
    those characters, so its result is clean; on a PHP array the keys stay as
    they were, so `foreach ($clean as $k => $v)` still gives input in `$k`;
  - in the rules that list `check_admin_referer`, `check_ajax_referer` or
    `wp_verify_nonce` as sanitizers, a nonce check that gates the code stops the
    rule there: `check_admin_referer(...)` or `check_ajax_referer(...)` as a
    statement of its own (not with `false` as the third argument), or
    `wp_verify_nonce(...)` in an `if` on the branch where it passed. The request
    then came from the site's own pages, so a third party's link cannot pick the
    value. The open-redirect and PHP XSS rules list them with
    `current_user_can`: `check_ajax_referer` and `wp_verify_nonce` count only with
    a capability check on the same path (`if (!current_user_can(...)) wp_die();`),
    because a logged-out visitor can get a valid nonce for public AJAX handlers;
    `check_admin_referer('action')` (admin screens) counts alone. A request value
    read after such a check is the site's own request too. `check_ajax_referer`
    stops only when its third argument is `true` or left out (a variable or a
    named `die:` does not count), and `check_admin_referer()` without an action
    checks only the referer;
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
| `context` | output sinks only (`echo`, `res.send(`): the input counts only when it is written into one of these places of an HTML page: `html` (between tags), `attr` (an attribute value, or inside a tag), `url` (the start of an `href`, `src`, `action`... value), `js` (inside `<script>`, an `on*` handler, or after `javascript:`); see [Output contexts](#output-contexts) |
| `literal` | the argument named by `arg`, or the value of a `when` option (`password=`, `password:`), must be a non-empty string written in the code; used by rules without sources |
| `leading` | the input must be at the start of the argument: a fixed prefix makes the call safe, as `WP_PLUGIN_DIR . "/$name"` cannot choose a `phar://` stream. A fixed prefix is a literal (or a run of literals) holding a character no URL scheme has (`/`, `_`, a space) before any `:`, so `'phar' . $x` and `'ph' . 'ar' . $x` are none; a constant; a ternary whose branches both are; a variable assigned one; a property or array key the input never reached (`$this->dir`, `$u['basedir']`), but never a superglobal or request object (`$_COOKIE[...]`, `$_SERVER['HTTP_...']`; `$_SERVER['DOCUMENT_ROOT']` is allowed); a call whose arguments hold no input, even through a sanitizer (`dirname(__FILE__)`, `get_template_directory()`, `strval(intval($x))`, but not `trim(basename($_GET['d']))`); `sprintf` whose format starts with such a literal; a Laravel path helper (`storage_path(...)`); a WordPress URL helper that ends in a path (`admin_url(...)`, `get_permalink(...)`, `rest_url(...)`; `home_url('/...')` and `site_url('/...')` only with a path); `add_query_arg` / `remove_query_arg` whose URL argument is fixed (or absent: the request's own path); `apply_filters` whose filtered value is fixed; `trailingslashit` or `user_trailingslashit` whose first argument is fixed; In the `ssrf`, `open-redirect` and `xss` rules the prefix must also keep the request on a known host: a literal scheme and host followed by `/`, `?` or `#` (`https://api.example.com/...`), a root path whose second character is neither `/` nor `\` (`/account`, not `/` that the input turns into `//evil.com`), or a relative path (`users.php?id=`); `home_url()` without a path, `untrailingslashit` and `rtrim` are not fixed there, and a PHP constant is fixed only when this file defines it (`define('API', 'https://api.example.com/')`) with such a text, or when it names a folder (`__DIR__`, `ABSPATH`, `*_DIR`, `*_PATH`). A call on input (`basename($_GET['d'])`) is not; a clean call that returns `""` (`trim(' ')`, an unset `getenv()`) is a known miss |

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
| `xss` | CWE-79, CWE-80 |
| `ssrf` | CWE-918 |
| `open-redirect` | CWE-601 |
| `xxe` | CWE-611, CWE-776 |
| `ldapi` | CWE-90 |
| `nosqli` | CWE-943 |
| `file-upload` | CWE-434 |
| `weak-crypto` | CWE-327, CWE-328, CWE-916 |
| `hardcoded-secret` | CWE-798, CWE-259, CWE-321 |

### Output contexts

Which escaping makes a value safe depends on where it lands in the page:
`esc_html()` is enough between tags, but not in an `href` (a `javascript:` URL
passes it), not in an unquoted attribute (a space starts a new one) and not in an
`onclick` handler (the browser decodes the entities before the script runs). The
XSS rules come one per group of contexts, with an `[[args]] context`:

| name | contexts |
|---|---|
| `html` | between tags |
| `attr` | a quoted attribute value; an unquoted one, where an attribute name goes, or `srcdoc` |
| `url` | the start of a URL attribute value (`href`, `src`, `action`...) |
| `js` | code in `<script>`; a JavaScript string in a script or a handler; code in an `on*` handler or after `javascript:`; CSS |

The engine reads the context from the HTML written before the value, with a
scanner that follows the page byte by byte (tags, attributes and their quotes,
`<script>` and `<style>` bodies, JavaScript strings, template literals, comments
and regular expressions in them): the inline HTML of a PHP file and the literal
text its `echo` and `print` statements write are fed to it in order, so
`echo '<a href="'; echo esc_attr($u);` is one tag; within one output, the literal
text joined before each value decides its context. `<script type="text/html">`
templates read as HTML.

An escaping call written in the output is judged by the engine's own table of
the contexts it is safe in, whatever the rule lists: `esc_html`, `esc_attr`,
Python's `escape` and `escapeHtml` are safe between tags and in quoted
attributes (`htmlspecialchars` and `htmlentities` in single-quoted ones only with
`ENT_QUOTES`); `esc_url` in URLs; `esc_url_raw` and `sanitize_url` only in
double-quoted attributes that are not URLs; `esc_js` in JavaScript strings;
`wp_json_encode` / `json_encode` in script code outside strings (not with
`JSON_UNESCAPED_SLASHES` unless `JSON_HEX_TAG` is also given); Tornado's
`xhtml_escape` between tags and in double-quoted attributes; `urlencode`,
`rawurlencode` and `quote` everywhere but script code, template literals and CSS
(`quote` with a `safe=` holding `:` not in URLs);
`encodeURIComponent` between tags, in double-quoted and unquoted attributes and in
URLs (it keeps `'`); `wp_kses`, `strip_tags`, `sanitize_text_field` and HTML
sanitizers only between tags. In another context the escaped value is still the
input. A value escaped earlier and kept in a variable is judged by the rule's
sanitizers.

In a rule whose sinks all have a context (an output rule), a call passes on the
input it was given, unless it is an escaper, a number, or a call whose result is
not the request value: command output (`shell_exec`), file contents
(`file_get_contents`, `readFile`), counts and hashes, WordPress form helpers
(`selected`, `checked`), yes-or-no answers (`is_*`, `has_*`), getters (`get_*`,
`wp_get_*`), template renderers (a name with `render` or `template`, WordPress walkers), and
in PHP a method of an object that holds no input (PHP strings have no methods; a
method's result follows its arguments). A function or method defined in the same
file is never judged by its name: its summary decides, or, without one, whether an
argument is the input. Input only
inside an array argument (`plugins_api('info', ['slug' => $s])`, `$q = $_GET` passed
on) is a lookup key, not the text returned, except for calls that format or join
containers (`implode`, `print_r`, `sprintf`, `json_encode`, `JSON.stringify`,
`json.dumps`, `array_*`). A named field of what an unknown call returned
(`$result['message']`, `$api->name`) is that call's data, unless the field was
written later or the call decodes or splits its input (`json_decode`, `explode`,
`parse_url`). An object or a list sent by `res.send` or
`HttpResponse` is JSON, not markup, and Python keyword arguments other than
`content=`, `text=` and `body=` (`status=`) are not what the page shows. aiohttp's
`web.Response(text=...)` is `text/plain` unless `content_type` says HTML, so a rule
for it should add `when = ["'text/html'"]` (or the content types it is about). Templates that escape by
default (`render_template`, `res.render`, Blade `{{ }}`) are not sinks.

### Rules without sources

`sources = []` makes a rule about how a call is made, not about where its data comes
from: every sink call whose `[[args]]` conditions hold is reported. Such rules must
keep false positives low, so they name exact calls and conditions: a weak cipher in
the call (`when = ["'aes-128-ecb'"]`), XML entity expansion turned on
(`when = ["LIBXML_NOENT"]`), or a credential argument that is a string written in the
code (`literal = true`). Samples of `hardcoded-secret` rules write `__SECRET__` where
the value goes; the sample test puts a made-up value there at run time, so no
credential-like string is kept in the repository.

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
string or comment that runs to the end of the file returns `ErrPartial`. A
JavaScript file of at least 8 KB with at least half of its non-blank bytes in lines
of over 1000 non-blank bytes is minified or bundled code. It is read like any other
file, every line of it; when it stops early, `ErrMinified` is joined to `ErrLimit`
or `ErrPartial`, and the audit marks its findings `generated` and counts them apart.
Before the analysis, a rule is skipped for a file that holds none of the names of its
sinks or, outside library mode, of its sources: patterns match token by token, so
such a file cannot give it a finding. Both
come with the findings made so far.

What it does not do: follow values across files (input read in a controller and
used in another class of another file is missed), judge the output context of HTML
built in a variable and echoed later (the echo's own context is used), see a CSRF
nonce check whose result is kept in a variable, treat a check on a value derived from another (`in_array($ext, ...)`
after `$ext = pathinfo($name, ...)`) as a check on the original, while a check on part
of a value written in place counts for all of it (`in_array(pathinfo($n, PATHINFO_EXTENSION), ...)`
cleans `$n` for every rule, path traversal included), know framework semantics beyond
the rules (a lookup in a constant dict is not an allowlist), look into options
kept in a variable assigned differently on two paths, or prove a
finding.
No finding does not mean no vulnerability.

Secrets never go into samples. If a sample needs something that looks like a key,
use an obvious placeholder.
