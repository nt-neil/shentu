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
| `lang` | `php`, `python`, `js` (JavaScript rules also apply to TypeScript, see [TypeScript](#typescript)) |
| `class` | `sqli`, `cmdi`, `path-traversal` (includes file inclusion), `deserialization`, `code-eval`, `xss`, `ssrf`, `open-redirect`, `xxe`, `ldapi`, `nosqli`, `file-upload`, `weak-crypto`, `hardcoded-secret`, `prototype-pollution`, `crlf` (a line break written into a line of a network protocol: an IMAP command, an HTTP request line written to a socket; not a response header set with `header()`) |

## Format

```toml
id = "php-sqli-string-concat"      # <lang>-<class>-<slug>, lowercase, unique, = file name
lang = "php"
class = "sqli"
cwe = "CWE-89"                     # must belong to the class (see below)
severity = "high"                  # critical | high | medium | low
tier = "info"                      # optional: info (default) | alert, see "Tiers"
title = "Request input concatenated into a SQL string"
frameworks = ["laravel"]           # optional: laravel, wordpress, symfony, doctrine, django, flask, express, nestjs, nextjs, koa, fastify, hapi
route_input = false                # optional: route handlers' parameters are not this rule's input, only its sources (a rule for the Host header)
route_members = ["query", "body"]  # optional: of the request members a route model makes input, only these (a rule for a query object: req.params is always a string)
route_only = ["headers.host"]      # optional: of a route handler's request, only these values (as route_not writes them) are this rule's input, whatever the parameter is called ((r, s) => r.headers.host, NestJS's @Req() r or @Request() r), also with route_input = false; h.host after h = r.headers too. For the rule another rule's route_not hands those values to
route_not = ["headers.host"]       # optional: values under those members that are not this rule's input, as member.name (the Host header): in a route handler's parameters and in the rule's own sources that end in the member (req.headers.host, req.headers['host'], req.headers.get('host'), @Headers('host'), h.host after h = req.headers, also when req is a route handler's parameter or NestJS's @Req() req)
routes_not = ["wp-shortcode"]      # optional: route models (by id) whose handlers' input is another rule's (a shortcode's attributes)
receivers = ["MongoDB", "mongodb/mongodb"]  # optional, PHP: the library its method sinks belong to (class, namespace and function names; Composer packages, with a "/"). A method sink does not count, where calls are followed across the project, when the project never names one of them (as a name in its PHP code, other than after -> or ::, as a word in a string, in composer.json or composer.lock, or as a package name: a vendor/<vendor>/<package>/ path, or one the caller lists, as app_code_audit lists vendor/ without reading it), some class of the project declares a method of that name, every file given was read and indexed to its end, and the caller left no file of a rule language out (ProjectOptions.Incomplete: app_code_audit sets it for a folder it skips, node_modules/ or .git/ say, a folder more than 8 levels deep, a file over 1 MiB or not readable, over 20,000 files, or a walk cut short): $Db->find() of a plugin's own SQL helper is no MongoDB query. A package under vendor/ counts by its name only: one that uses MongoDB under another name is not seen. A file scanned on its own knows no project, so there it still counts
chain_not = ["AsyncClient"]        # optional: calls the chain form of a receiver.method( sink may not go through: they make another object (httpx.AsyncClient().get( is not httpx.get()
yields_to = ["php-sqli-yii-query"] # optional: rules of the same language and CWE this one leaves a sink to: its finding is left out where one of them reports the same line through the same sink call (one call holding the other: DB::raw(...) inside DB::select(...), the same ->where(...)); another sink on that line, or one reached through a function's summary or a text sink, still reports (yields.go)
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
  (`os.system(`). In JavaScript, the Node modules `fs` (with `fs/promises`),
  `child_process` and `vm` are read in one form whatever the spelling:
  `fs.promises.readFile(p)`, `require('node:fs').readFile(p)`, `fsp.readFile(p)`
  after `import fsp from 'fs/promises'` and `r(p)` after
  `const { readFile: r } = require('fs')` all read as `fs.readFile(p)`, and a sink
  written as a bare name (`readFileSync(`) also matches it as a member of one of
  these modules (`fs.readFileSync(p)`), never as a method of anything else. A name
  is a module only where the file requires or imports it, and not at all when the
  file declares the name again (scopes are not followed). Not followed:
  reassignment, conditional or dynamic `require`, spreads, brackets (`c['exec']`),
  `.call`, `module.require` and `import()`. Sources match anywhere, so
  `request.args` also matches `self.request.args`, unless written with a leading
  `^`: `^request.url` never matches as a member of something else
  (`this.request.url`); and a source that is a call by name (`request(`,
  `get_query_var(`) matches the function only, not a method of that name
  (`->request(`).
- `[*]` in a pattern matches any one index: the source `$_FILES[*]['name']`
  matches `$_FILES['doc']['name']` (and `$_FILES['doc']['name'][$i]`) but not
  `$_FILES['doc']['tmp_name']`. After `$f = $_FILES['doc']`, `$f['name']` is input
  and `$f['tmp_name']` is not.
- A call or index source whose `[[source_args]]` take only some names
  (`req.headers[` and `@Headers(` with `host` and `x-forwarded-host`) also gives
  those members of the whole object: after `h = req.headers` or NestJS's
  `@Headers() h`, `h.host` and `h['x-forwarded-host']` are input and `h.referer`
  is not.
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
  `/var/www/assets-private` cannot pass a check for `/var/www/assets`. In
  `path-traversal` rules the path checked must also be canonical: a `realpath()`
  result (Python `os.path.realpath`, `abspath`, `normpath`, `Path.resolve()`;
  JavaScript `path.resolve`, `path.normalize`, `fs.realpathSync`), inline or in a
  variable assigned one, since `uploads/../../wp-config.php` starts with
  `uploads/`. Lookups in a
  fixed list are checks in every rule: `in_array`, `array_key_exists`,
  `x in ALLOWED`, `ALLOWED.includes(x)`, `ALLOWED.has(x)`.
- Also built into every rule:
  - PHP 8 `match ($x) { 'a' => 'col_a', default => 'id' }` is one of its arms'
    values, never the subject: arms that are all fixed give a clean value, and an
    arm that throws gives none;
  - `wp_die`, `wp_send_json`, `wp_send_json_error` and `wp_send_json_success` end
    the request, so `if (!in_array($x, $allowed)) { wp_send_json_error(); }`
    validates `$x` after it;
  - Django's `Model._meta.get_field(name)` raises unless `name` is a field of the
    model, so in a rule that lists `._meta.get_field(` as a sanitizer, `name` is
    clean after the call (inside a `try`, the handler starts from before it);
  - `array_map('absint', $x)` (any sanitizer of the rule, or a number cast, as the
    callback) returns sanitized values, with the keys of `$x`;
  - `extract(shortcode_atts(array('id' => 0, ...), $atts))` and `extract(array(...))`
    define one variable per literal key; `extract()` of any other array that holds
    input (`extract($args)`, `extract(wp_parse_args($atts, [...]))`, which keeps
    every key of `$atts`) may define any variable and overwrite the ones already
    defined, so after it every variable of the scope holds that input until it is
    assigned again, a variable never assigned before included. The flags count:
    `EXTR_SKIP` and `EXTR_PREFIX_SAME` overwrite nothing, `EXTR_IF_EXISTS`
    overwrites but creates nothing, `EXTR_PREFIX_ALL` and `EXTR_PREFIX_IF_EXISTS`
    set only `prefix_` names (any such name when the prefix is not written out).
    A variable extract() creates around a closure is seen in it only through its
    `use (...)`, and its parameters are the caller's values; an arrow function
    sees the scope around it. (A variable defined before the closure is still
    copied into it, as for any PHP closure.) The keys of `$defaults` are those it
    is given in the same function. After `preg_match($p, $s, $m)`,
    `parse_str($q, $out)` or `exec($c, $output)` the variable written is the
    call's (what extract() set there is gone; whether it holds the subject's input
    is not followed), unless it is the subject itself (`preg_match($p, $m, $m)`),
    which keeps what it held; a `catch (E $e)` variable is the exception;
  - in the SSRF rules, a check of a parsed URL's host against an allowlist that
    is surely a collection (`.has(`, `.includes(`, `in` on a list, set, tuple
    or array written out, `new Set(...)`, `set(...)` or `frozenset(...)` of one
    of those, or a chain of reads ending in `.split(...)`, as the whole
    expression; Python's tuple without parentheses, `'a', 'b'`, too; or a name
    the file binds once, at its top level, to one of those and otherwise only
    reads. A parameter, destructuring, `catch`, `for`,
    `with`, a key of that name, a default value, `+=`, a tuple of targets or an
    argument anywhere in the file makes the name unknown, and so does Python's
    `from x import *` for every name; on a string or an
    environment value `.includes(` and `in` are substring tests) or a host
    written out (`=== 'a.example'`)
    validates that URL object: `u.hostname`, `u.host` or `u.origin` after
    `u = new URL(x)` (or `URL.parse`), `p.hostname` or `p.netloc` after
    `p = urlparse(x)` (or `urlsplit`), so `fetch(u)` and `requests.get(p.geturl())`
    are clean. Not the string `x` itself, which another parser (the client's,
    `url.parse`, PHP's `parse_url`) may read as another host; not a truth test, a
    pattern or a prefix check of the host; not a URL that is something else on one
    of the paths to the check, or given a new value, or written into after it
    (`u.host = v`, `Object.assign(u, ...)`, `Reflect.set(u, ...)`, a member of
    any alias `w = u`, `x = w`). In JavaScript a URL passed to any other call
    than the rule's sinks may be changed there (`setHost(u, v)`), so the check
    ends and u holds again the input it held before it; this also ends it for a
    call that only reads u (`log(u)`), which reports more than it must, except
    `console.log` (`.info`, `.warn`, `.error`, `.debug`, `.trace`),
    `JSON.stringify` and `String`, while the file uses `console`, `JSON` and
    `String` only to call them or, for `String`, as a TypeScript type (a
    parameter's, `f(a: String, b)`, included; no
    parameter or declaration of the name, no `console.log = f`,
    `globalThis.String = f` or `Object.assign(console, ...)`), and holds nothing
    that may replace them unseen: a global object (`globalThis`, `window`,
    `self`, `global`) other than read through a named member or after `typeof`, `eval` (the name
    anywhere), `Function(`, `runInThisContext`, a value's constructor read for
    anything but its name (`(() => {}).constructor`, `{ constructor: F } = f`), `with (`, anything under the
    prototype of `URL`, `String`, `JSON` or `Object`, `__proto__` or
    `Symbol.toPrimitive`. A module that replaces a global when it is imported
    is another file, which this does not see. So does
    a URL written into an object or array (`{ target: u }`, `[u]`), or used as
    a value in any other way than a member read (`u.valueOf()` is u itself, not a
    member; a method called by a computed name, `u[k]()`, counts as changing it
    whatever k is, `u['toString']()` too), a whole argument or the whole
    right side of an assignment (`a1 = u || null`, `c ? u : w`, `return u`). Only a
    plain name holds a checked URL (not `this.u`), and only while the binding
    of it (the function, or the module, where the name is a local) is not
    reached from elsewhere. In JavaScript no function written inside that
    binding's function may use it without binding it itself (a closure or
    callback that reads or changes u, whenever it runs: `() => { u.host = v }`,
    `[v].forEach(h => { u.host = h })`). In Python, whose parse results cannot
    be changed in place, a nested `def` or `lambda` that only reads u keeps the
    check; a `global` or `nonlocal` that resolves to that binding ends it
    (`def m(): nonlocal u; u = urlparse(v)`, a list of names and a statement
    continued with a backslash included), and `global u` in the function that
    assigns u ends it too. A `global` or `nonlocal` of another binding of the
    same name (another function's u) does not. Where the assignment's line does
    not show which binding it is, the name counts as reached when any of its
    bindings is. And only while fewer than 64 names hold it (each alias is kept with each
    other one).
    `p.geturl()` is a string the client parses again; urlparse and the client's
    parser agree on the host of what urlparse itself wrote out, which is why it
    counts, but a client with its own normalisation could read it otherwise. A URL whose host is allowed
    may still carry a script or a quote in its path, so no other rule reads it;
  - an assignment written in a condition (`if ($x = $_GET['y'])`) is followed;
  - a variable holding a value written in the code (`$o = array('test_form' =>
    false)`, `const opts = { shell: true }`, `$f = LIBXML_NOENT`) is read in its place
    by the argument conditions `when` and `unless`; a name given two different values
    in the file is not known;
  - a sink written as receiver, member and method (`Process::run(`, `res.send(`,
    `requests.get(`) also matches at the end of a chain of calls from the same
    receiver: `Process::timeout(30)->run($cmd)`, `res.status(400).send(x)`,
    `requests.Session().get(url)`, with the same argument conditions; not through
    a call the rule's `chain_not` names (`AsyncClient`: another object);
  - a sink written `receiver.Maker(*).method(` (`httpx.Client(*).get(`) matches
    `.method(` at the end of a chain from the receiver that goes through a call
    to `Maker`, with any arguments: `httpx.Client(timeout=5).get(u)`;
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

### TypeScript

TypeScript files (`.ts`, `.mts`, `.cts`, `.tsx`) are checked with the `js` rules.
The lexer reads them as JavaScript and then takes the type syntax out, since types
carry no data: annotations, type arguments and parameters (`f<T>(x)`, told apart
from `a < b` by what follows the `>`), `as` and `satisfies`, the non-null `!`,
`interface`, `type`, `enum`, `declare`, `namespace` headers, `implements`, and the
modifiers `public`, `private`, `protected`, `readonly`, `abstract`, `override`. In
`.tsx`, `<T>x` is an element, not a type assertion. Decorators are dropped, except
on a parameter, which becomes an assignment at the start of the body:
`find(@Param('id') id: string) { ... }` reads as `find(id) { id = @Param('id'); ... }`,
so a decorator is a source like any call (`@Body(`, `@Query(`, `@Param(`,
`@Headers(`); a destructured parameter (`run(@Body() { cmd }: Dto)`) becomes
`let { cmd } = @Body();`. With `@Req()` (or `@Request()`, the same decorator by
another name, which a rule that takes `@Req(` takes too) only the parts of the request that come
from the client are input (`query`, `body`, `params`, `headers`, `cookies`,
`originalUrl`, `url`, `get()`, `header()`), not what the server put on it
(`req.user`). `@Req()` is NestJS's request only in a NestJS application: a file
that imports `@nestjs/common` or `@nestjs/core`, or any file of a project one of
whose files does (another library's `@Req()` is an object like any other). A parameter with a NestJS parse pipe (`ParseIntPipe`, `ParseUUIDPipe`,
...) is not input; a DTO's class-validator decorators are not read. In `.jsx` and
`.tsx`, element text is not code: quotes, slashes and colons in it are text. A
declaration whose bracket never closes (`interface I {`) is dropped up to that
bracket only; the rest is read as code and the file is reported as not fully
analysed. Next.js route and page `params` are not sources yet (that needs the
route model).

A route handler's request is read by the rules' `req.` and `ctx.` sources
whatever it is called (reqalias.go). The names that hold it in a function are
followed: the handler's request parameter (`(r, s) => r.hostname`,
`r.get('host')`; a parameter used as a Koa context, `c.request` or
`c.body = ...`, stands for `ctx`, any other for `req`; a destructured one taking
`request`, `response`, `state`, `throw` or `assert`, `({ request }) => ...`,
for `ctx`), NestJS's `@Req() r`, an alias (`const q = r`, `const h = r.headers`)
and destructuring, of the parameter (`({ headers }, res) => headers.host`) or in
the body (`const { hostname: hn } = r`, `const { host } = req.headers`), nested
(`const { headers: { host } } = r`) and with a string key
(`const { 'x-forwarded-host': xfh } = req.headers`). Under such a name a
request's header index is lower case, as Node stores it (`r.headers['Host']`),
and a destructured name under a member route_not names is that rule's input no
more than the member is. A name assigned anything else, or a parameter of an
inner function with the same name, is not followed. A name assigned on some
paths only (in a branch, a loop's body, a `try`) is followed on the others. An
if/else joins its branches: after it a name holds what it held at the end of a
branch that goes on (one that returns or throws does not; without an else, the
state before the if is the else path), so a name assigned on every branch is no
longer followed. After a loop's body, a `try` or a `switch`, it holds what it
held before them and what it holds at their end.

A sample written in TypeScript says so with `dialect = "ts"` (or `"tsx"`); it is
lexed as such and must hold the same as any other sample of the rule.

### Tiers

`tier` decides where a finding is shown. An `info` rule (the default) is listed by
the `app_code_audit` tool and in chat, but the daily patrol report does not push
it. An `alert` rule is pushed as well. Every new rule starts as `info`; it becomes
`alert` only after it has been run on real, clean projects and its false-positive
rate is low, and the change says which measurement justified it.

A `reference` rule is about how a call is made, not about input reaching it (an
MD5 hash, a template rendered without a sandbox), so only a rule with
`sources = []` may have this tier (`rules_test` checks it). `app_code_audit` and
chat list its findings after the others, marked as reference; the daily report
gives them one line with their count. They are never pushed and never given to
attack detection, and cvebench counts them only in its "with reference" columns,
never in the main verdict. Such a rule may list sanitizers too: a method sink on
an object one of them made (`SandboxedEnvironment().from_string(x)`) is not
reported.

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
it are unchanged: a sink is reported when any argument is tainted. A sink may
have several blocks, each naming its `arg`: the call is reported when any one of
them holds (`spawn(cmd, args, { shell: true, cwd })`: the command or its
arguments, not the options).

| field | meaning |
|---|---|
| `sinks` | the rule's sinks this entry applies to; omitted means all of them; a sink has at most one entry |
| `arg` | only this argument counts, from 1; `0` is the receiver of a method sink (`tf.extractall()`: the archive is the input) |
| `when` | the call is a sink only if one of these appears among its arguments |
| `unless` | the call is not a sink if one of these appears among its arguments: an option with its value (`shell=True`), a string, a whole argument, or a name among flags joined by `\|` (`LIBXML_NOENT` in `LIBXML_DTDLOAD \| LIBXML_NOENT`) |
| `unless_at` | where `unless` looks: `start`, only at the start of the argument (`arg`, or the first): a Server-Sent Events line `"data: " + x`, not a ternary one branch of which is a line; `top`, only as an element or key of the argument itself (`arg`, or any one), not inside what it holds: TypeORM's `{ relations: [...] }`, not `{ projection: { relations: 1 } }`. Empty: anywhere among the arguments |
| `unless_content_type` | the call is not a sink once the response's Content-Type was set to one of these on every path before it in the same function: `res.setHeader("Content-Type", ...)`, `res.set`, `res.header`, `res.type`, `res.contentType`, `res.writeHead(200, {...})`, each as a statement of its own. Set in one branch only, asked about (`req.accepts(...)`) or set elsewhere (middleware) does not count. For Server-Sent Events: `text/event-stream` is read by EventSource, not rendered |
| `whole` | the argument must be the input itself (or spread from it), not an object or array literal holding a value from it |
| `context` | output sinks only (`echo`, `res.send(`): the input counts only when it is written into one of these places of an HTML page: `html` (between tags), `attr` (an attribute value, or inside a tag), `url` (the start of an `href`, `src`, `action`... value), `js` (inside `<script>`, an `on*` handler, or after `javascript:`); see [Output contexts](#output-contexts) |
| `markup` | with `context`: the input counts only after markup (a `<`) written before it in the same value (`'<p>' + x`, `` `<p>${x}</p>` ``); a body with none may be JSON or text (Koa's `ctx.body = x`). Markup put together in a variable first is not read |
| `key` | the argument is an object, dict or array literal (`{ Location: v }`, `['Location' => v]`): only the value under this key, in any case, counts; without the key the call is not this sink |
| `keys` | an argument that is an array, object or dict literal counts by its keys only: Yii's `orderBy([$column => SORT_ASC])` puts the key in the query, while the value only picks a direction. An item without a key (`[$column]`) counts as a key; an argument that is not a literal counts whole |
| `literal` | the argument named by `arg`, or the value of a `when` option (`password=`, `password:`), must be a non-empty string written in the code; used by rules without sources. The string may be reached through a variable, a constant, a PHP class constant (`self::KEY`), a property declared with it (`$this->key`, `self::$key`; not when the file assigns the property elsewhere), a concatenation, or a call that only reshapes it (`hash('sha256', '...')`, `base64_decode`, `substr`...), at most four steps deep; a name given two different values in the file is not known |
| `not_literal` | with `arg`, rules without sources only: the argument must not be what `literal` accepts, so a command or template written out in full (`os.system("make clean")`, or through a name holding it) is not reported, and one made from a value the code does not write out (`os.system(" ".join(args))`, a parameter) is. Such a rule's tier is `reference`. A limit: a command split into adjacent literals (`os.system('ls ' '-l')`, one string to Python) or joined from a list of literals (`' '.join(['ls', '-l'])`) is still taken as not written out |
| `fixed_ext` | with `arg`: the argument does not count when the name built in it ends with a fixed extension: its last part is a string written out ending in one (`$name . '.txt'`), a variable every value the file gives it is one (`$ext = '.jpg'` or `'.png'` on every path), or a variable assigned such a name on every path (`$basename = $base . '-image' . $ext`). Appending to the name afterwards (`.=`) forgets it, and a variable the file also writes some other way (a foreach target, a reference, a destructuring, or any `extract()`) is not read. Only extensions served as data count (images, text, PDF, archives, audio, video, office documents), never `.php`, `.phtml`, `.phar`, `.html` or `.svg`. A name like `shell.php.jpg` is not reported because `wp_upload_bits()`, the one sink using it, passes the name through `sanitize_file_name()`, which breaks up the inner extensions; for another sink this needs looking at again. For upload rules: the stored type is then the code's choice |
| `not_array` | with `arg` (PHP): the argument does not count when it is an array on every path that gives it input, for a sink that does nothing with an array: `maybe_unserialize()` unserializes strings only and returns anything else as is. A value is an array when it is `array(...)` or `[...]` holding input, a cast `(array) $x`, a variable written by key (`$a['k'] = $in`, `$a[] = $in`) that held no input of another kind, or the result of a function that never returns a string, whatever it is given (below). It is no longer one after anything else: one value of it (`$a['k']`, `$a[0]`, a `foreach` value or key, `list(...)` or `[...]` destructuring), a property, a string made from it (`implode()`, `.`, `(string)`, `.=`), any other call, spread into a call (`...$a`), a callback's parameter (`array_map()`, `array_walk()`: the values, not the array), or a path where the input arrives as something else (`isset($x) ? array($in) : $in`). A variable is not taken as one at all when the file may write it some way the engine does not follow: a reference `&$a`, a `foreach` target, a destructuring, any `extract()`; a variable of the global scope (named outside every function body) or declared `global` under its own name, which another file's function can write through `global` or `$GLOBALS` (a file merely holding `global $wpdb` keeps the mark of its other variables: almost every WordPress file does, and a function's own variable is written that way only when declared `global` there); any `$$name`, `${...}` or `$GLOBALS` in the file, or `parse_str()` with one argument; or passing it whole where a reference may be taken: to any method or constructor, to a computed callee (`$f($a)`), to a PHP function with a parameter by reference at that place (`rules/engine/php_refparams.txt`, generated from PHP's reflection: `settype`, `sscanf`, `preg_match`, ...), to a function of the file with an `&` there, to one another file of the project declares with a parameter by reference, or to one the project does not declare (WordPress's, another plugin's), except the WordPress functions listed, each with why it takes its arguments by value, in `rules/engine/wp_byvalue.txt` (`maybe_unserialize`, `wp_parse_args`, `apply_filters`, the option, transient and meta writers, ...). A file scanned on its own cannot read another file, so there any function it does not declare may take a reference. A property of an object or a call's result (`$this->x`, `$o->p`, `self::$x`, `$o->get()`) is never one, nor an index of a variable the file assigns an object with `new` (`$o['k']` is ArrayAccess's `offsetGet()`); a known limit: an object made another way (`$o = (new Bag())`, `$o = $p = new Bag()`, `Bag::make()`, `clone`) is not seen as one, so its index can still pass. A function of the code's own whose parameter reaches such a sink as is (no index, no call) is not reached by an array argument either. The functions: `array` (`array(...)` is read as a call); `explode`, `str_split`, `mb_str_split`, `preg_split`, `str_getcsv` (split a string into an array, or give false); `array_map`, `array_filter`, `array_values`, `array_keys`, `array_merge`, `array_slice`, `array_unique`, `array_reverse`, `array_combine`, `array_flip`, `array_chunk`, `array_column`, `array_diff`, `array_intersect`, `array_replace`, `array_fill_keys` (build a new array from arrays, or give null on bad arguments); `compact` (an array of the named variables); `wp_parse_args` (always an array: a string is parsed as a query string first), `wp_parse_list` (an array of the items of a list), `wp_list_pluck` (an array of one field of each item). Left out because they can return a string: `array_pop`, `array_shift`, `current`, `reset`, `end`, `next`, `prev` (one value of an array, which may be a string), `array_search`, `array_rand`, `key`, `array_key_first`, `array_key_last` (a key), `array_reduce` (whatever the callback returns), `apply_filters` (whatever a filter returns), `get_option`, `get_post_meta`, `get_user_meta`, `get_transient` (what was stored, which may be a serialized string), `json_decode`, `unserialize`, `maybe_unserialize` (a string or a scalar when the data holds one) |
| `min_len` | with `literal`: one of the strings the value is made from must be at least this long |
| `exclude` | with `literal`: regular expressions (any case); a string matching one does not count, so `exclude = ["^[a-z0-9_]+-(sha\|md5)[0-9]*$"]` leaves out a purpose label such as `'wp-sha384'` |
| `receiver` | method sinks only: the call does not count when the file shows its receiver is another kind of object than these. The receiver qualifies when one of the fragments appears in it, or in what its root name (`db`, `self._files`) is assigned, annotated or imported with in the file (`db = MongoClient(url).shop`, `def __init__(self, db: Database)`, `from pymongo.collection import Collection`), followed up to four steps; an import says what a name holds only when it comes from the standard library or a well-known package that is not MongoDB (`os`, `re`, `django`, `flask`...). A root the file says nothing about (no assignment, an import from a module of the project such as `from app.db import mongo` or `from .db import mongo`, a parameter without a type) still counts. So `finders.find(path)` after `from django.contrib.staticfiles import finders`, `'abc'.find(x)` and `data['text'].find(x)` after `data = request.get_json()` are not MongoDB queries, while `mongo.find(x)` after `from app.db import mongo` is; a `.find(` on an object of the project that is not a collection is then still reported (a false positive, kept over a miss) |
| `handle` | with `receiver`, function sinks: the argument (from 1) holding the handle the call works on (`fwrite($fp, ...)`: `1`). The call counts only when that argument was made by one of `receiver`: in place (`fwrite(fsockopen(...), ...)`), by the nearest assignment before the call in the same function (`$fp = fsockopen(...)`, through another name or a chained assignment), or, for `$this->x` not assigned in the same function, by an assignment to the property anywhere in its file (another method; a class in another file is read from its own file). Unlike `receiver`, a handle the code does not show the origin of does not count: a parameter, a constant such as `STDOUT`, a method's return value (`$this->fp = $this->connect()`), a static property set in another method, an array element or a `foreach` variable. `list()` and destructuring give every target the whole right side, so `[$a, $fp] = [$x, fsockopen(...)]` over-reports `$a`. A socket passed in from elsewhere is missed rather than every file write reported. A file with more than 4096 `$this->x =` assignments has no property table: its handles are not known, and its scan records the cut `handle-table`. Nothing is kept for a rule without a `handle` |
| `unless_imports`, `unless_imports_not` | method sinks only (JavaScript): the call does not count in a file that imports one of `unless_imports` (`import ... from 'typeorm'`, `require('typeorm')`), unless the file or the call's receiver also names one of `unless_imports_not` (an identifier, or an imported module: `MongoRepository`, `mongoose`, `collection`). For a TypeORM repository on an SQL database, whose `find({ where })` binds the values as parameters. A function analysed from a caller in another file leaves nothing out |
| `unless_after` | text patterns (any case): the arguments do not count when every value from the input in them comes after one of these texts in a string written in the call, read as a concatenation (`.` in PHP, `+` elsewhere) or a string's interpolated parts: `$wpdb->get_results("... ORDER BY $col")` is `php-sqli-orderby-identifier`'s, which reports it at that text. A call written there is read by its own arguments (`DB::select(DB::raw("... ORDER BY " . $col))`). Input before the text, or SQL built in a variable elsewhere, keeps the sink |
| `unless_subscript` | the argument does not count when it is, as a whole and written in the call, one item of one of these: `zipfile.ZipFile(request.files["archive"])` reads the upload's stream as a file object, not a path. `request.files["a"].filename`, or the item through a variable, still counts |
| `not_receiver` | method sinks only, the other way round: the call does not count when its receiver is surely an object of one of these classes, made in place (`(new WP_Query($args))->query($a)`, `new \WP_Query`) or a variable the file binds only to such objects (`$q = new WP_Query; $q->query($a)`): every occurrence of the name in the file is a statement assigning `new Class` or `new Class(...)`, a call or read through it, or the whole argument of a call. Assignments are not followed from one name to another (`$r = $q`), and a parameter is never taken to be of a class, its default value included (`function run($q = new WP_Query())`). The file is the one the code is in, also when it is reached from a caller in another file. An entry written as a variable names the object itself: `not_receiver = ["$wpdb"]` leaves out `$wpdb->query(...)` (WordPress's global wpdb, another rule's). A receiver the file says nothing about, or a name also assigned anything else or bound any other way (a parameter, `global`, `foreach ... as`, `list()`, `use`, `&`), still counts, so `$db->query($sql)` on a parameter is reported as before. Passing the name to a call (`update_post_thumbnail_cache($q)`) keeps it, unless the file declares a function or method of that name with a parameter by reference (`function f(&$x)`). A limit: a callee declared in another file that takes the object by reference and assigns it something else is not seen, and the sink is then left out; only the application's own code can do that, not its input |
| `receiver_from`, `receiver_names` | Python only, stricter than `receiver`. A method sink counts when its receiver, or what its root is assigned or imported with in the file (followed as for `receiver`, an import with its module and the name it imports, also under an alias), names one of `receiver_from` (`jinja2.Environment()`, `env = Environment()` after `from jinja2 import Environment`, `h.md5(x)` after `import hashlib as h`). It does not count when on the way the receiver is made by a class of another name (`Engine()`, `self.engine = Engine(debug=True)`), by another well-known package (`engines['django']` or `Engine.get_default()` after `from django.template import ...`) or by one of the rule's sanitizers (`jinja_env = SandboxedEnvironment()` at the top of the file, used in a function; `SE()` after `from jinja2.sandbox import SandboxedEnvironment as SE`), whatever it is called. A receiver the file says nothing about (a parameter), an attribute (`app.jinja_env`) or what a function returns (`make_env()`) counts only when its last name is one of `receiver_names`. A function sink (`md5(`, `Template(`) counts only when the file imports that name from one of `receiver_from` (`from hashlib import md5`); a name imported under another one (`from hashlib import md5 as m; m(x)`) is not matched by the sink. Limits: an attribute receiver is known by its name even where the file assigns it (`h.env = Engine()`, then `h.env.from_string(s)` is reported), and a method sink is only what the rule lists (`o.system(cmd)` after `import os as o` is not reported, while `h.md5(x)` after `import hashlib as h` is) |
| `ident_placeholder` | a prepare()-style sink (`$wpdb->prepare(`), without `arg`: a value after the format counts only when the format, the strings written in the first argument (or a variable holding only a literal), puts its placeholder inside backticks, outside an SQL string: ``UPDATE t SET `%s` = 1`` or a numbered `` `%2$s` ``. `$wpdb->prepare` quotes a `%s` value as a string, which protects it between quotes, standing alone, after `ORDER BY` or in `LIMIT`, but not as an identifier; `%d`, `%f` and `%i` (WordPress's identifier placeholder) do not count. Inside SQL comments (`/* */`, `-- `, `#`) quotes and backticks are no SQL's, but `prepare()` still fills their placeholders, which take their values in turn; MySQL runs the text of a `/*! ... */` comment, which is read as SQL. PHP's escapes in the string are read as PHP reads them (a `'...'` string has only `\\` and `\'`, a nowdoc none). Double quotes count as an SQL string, not an identifier, as they do unless MySQL runs with `ANSI_QUOTES`. `sanitize_title` is no sanitizer of this rule: it runs filters a plugin can change. Parts of the format that are no written string are not read |
| `leading` | the input must be at the start of the argument: a fixed prefix makes the call safe, as `WP_PLUGIN_DIR . "/$name"` cannot choose a `phar://` stream. A fixed prefix is a literal (or a run of literals) holding a character no URL scheme has (`/`, `_`, a space) before any `:`, so `'phar' . $x` and `'ph' . 'ar' . $x` are none; a constant; a ternary whose branches both are; a variable assigned one; a property or array key the input never reached (`$this->dir`, `$u['basedir']`), but never a superglobal or request object (`$_COOKIE[...]`, `$_SERVER['HTTP_...']`; `$_SERVER['DOCUMENT_ROOT']` is allowed); a call whose arguments hold no input, even through a sanitizer (`dirname(__FILE__)`, `get_template_directory()`, `strval(intval($x))`, but not `trim(basename($_GET['d']))`); `sprintf` whose format starts with such a literal; a Laravel path helper (`storage_path(...)`); a WordPress URL helper that ends in a path (`admin_url(...)`, `get_permalink(...)`, `rest_url(...)`; `home_url('/...')` and `site_url('/...')` only with a path); `add_query_arg` / `remove_query_arg` whose URL argument is fixed (or absent: the request's own path); `apply_filters` whose filtered value is fixed; `trailingslashit` or `user_trailingslashit` whose first argument is fixed; In the `ssrf`, `open-redirect` and `xss` rules the prefix must also keep the request on a known host: a literal scheme and host followed by `/`, `?` or `#` (`https://api.example.com/...`), a root path whose second character is neither `/` nor `\` (`/account`, not `/` that the input turns into `//evil.com`), or a relative path (`users.php?id=`); `home_url()` without a path, `untrailingslashit` and `rtrim` are not fixed there, and a PHP constant is fixed only when this file defines it (`define('API', 'https://api.example.com/')`) with such a text, or when it names a folder (`__DIR__`, `ABSPATH`, `*_DIR`, `*_PATH`). A call on input (`basename($_GET['d'])`) is not; a clean call that returns `""` (`trim(' ')`, an unset `getenv()`) is a known miss |

`when` and `unless` entries are code fragments matched anywhere in the call's
arguments, with these refinements:

- in `when`, a flag taken out with `~` is not set: `$flags & ~LIBXML_DTDLOAD`
  and `& ~(LIBXML_NOENT | LIBXML_DTDLOAD)` set neither; in `~LIBXML_DTDLOAD |
  LIBXML_NOENT`, `~` binds tighter, so `LIBXML_NOENT` is set;
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
| `prototype-pollution` | CWE-1321 |
| `crlf` | CWE-93, CWE-77 |

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
`JSON_UNESCAPED_SLASHES` unless `JSON_HEX_TAG` is also given), and with
`JSON_HEX_TAG` also between tags, which covers a `<script type="application/json">`
data block; Tornado's
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

### Source arguments

A call source, or an index source (one that ends with `[`, whose index is its
argument 1), can depend on one of its arguments. Joomla's
`$input->get($name, $default, $filter)` returns the raw value with the `raw`
filter, but only letters, digits, `.`, `-` and `_` with the default (`cmd`):

```toml
[[source_args]]
sources = ["->get("]     # call sources of the rule
arg = 3                  # the argument (from 1) that must be a string literal
values = ["raw", "string", "path", "html", "array", "trim"]   # any case
```

The call is input only when that argument is written as one of the values; with
another value, a variable, or no such argument it is not. `values = ["*"]` takes
any string literal: Express's `req.get('Referer')` reads a header, `req.get()`
reads none. A value written `!name` is never the source, also with `*`:
`values = ["*", "!host"]` takes every header but Host. `?` takes an argument
that is not a string literal (a variable, a template): `req.headers[name]` may
be any header. Two rules can so split one source between them: the Host header
to js-ssrf-host-header (`values = ["host", "x-forwarded-host"]`), every other
header to js-ssrf-http-request (`values = ["*", "?", "!host", "!x-forwarded-host"]`).

### Rules without sources

`sources = []` makes a rule about how a call is made, not about where its data comes
from: every sink call whose `[[args]]` conditions hold is reported. Such rules must
keep false positives low, so they name exact calls and conditions: a weak cipher in
the call (`when = ["'aes-128-ecb'"]`), XML entity expansion turned on
(`when = ["LIBXML_NOENT"]`), or a credential argument that is a string written in the
code (`literal = true`). Samples of `hardcoded-secret` rules write `__SECRET__` where
the value goes; the sample test puts a made-up value there at run time, so no
credential-like string is kept in the repository.

## Rules and attack detection

Since v0.4.0, the daily round puts each injection finding of these rules (rule, CWE, file,
line) into the host's vulnerability surface (`state_dir/surface.json`), with the routes
that register the handler the sink sits in when a route model in `routes/` shows them in the
same file. The patrol's attack detection reads the web
server's access logs against it: a request to one of those routes is L1, and one that also
carries a payload of the class the finding's CWE names (`CWE-89` is SQL injection, `CWE-78`
command injection, `CWE-22` path traversal and so on; `detect/surface.go` has the list) is
L2. A finding without routes is still in the surface, but no request can be tied to it.
How the levels are judged and alerted: [docs/attack-detection.md](../docs/attack-detection.md).

These rules are not the 27 attack signatures of attack detection (`detect/sig`). The rules
read the applications' code on disk and find where it is vulnerable; the signatures read
request lines in the access logs and find what an attacker sent. A rule added here can make
a request L1 or L2 through its routes and CWE; it never adds a signature.

## What CI checks (`rules_test.go`)

- every file parses, and has no unknown keys;
- required fields are present and non-empty (`sanitizers` must be present, may be `[]`);
- `id` is unique, follows `<lang>-<class>-<slug>`, and matches the file path;
- `lang`, `class`, `severity`, `tier`, `frameworks` are in the allowed lists, and `cwe` belongs to the class;
- `refs` are well-formed CVE or GHSA ids, without duplicates;
- `text` entries are sources or sinks; `[[args]]` entries set something, name only
  the rule's sinks, give each sink at most one entry, and use `arg = 0` only for
  method sinks; `min_len` and `exclude` come with `literal`, and `keys` not with
  `key`; `[[source_args]]` entries name call or index sources of the rule, an
  argument (1 for an index source) and values;
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

1. **Lexing.** Hand-written lexers for PHP, Python and JavaScript (TypeScript is
   JavaScript with its types taken out) drop comments and
   keep string literals whole, so text in comments and plain strings is never
   code. Interpolations are lexed as code: PHP `"$x"`, `"{$x->y}"`, `"${x}"`,
   heredoc (nowdoc stays text) and backticks; Python f-strings; JavaScript
   template literals, nested to any depth. Unterminated strings and comments end
   at the end of the line or file.
   A PHP property every assignment of its class gives WordPress's `$wpdb`
   (`$this->wpdb = $wpdb`, `= &$wpdb`, `self::$mysqli =& $wpdb`) is read as
   `$wpdb` wherever the class uses it as an object (`$this->wpdb->get_results(...)`),
   so the rules' `$wpdb` sinks and `$wpdb->prepare` match it. A property belongs
   to the class, trait, interface or enum it is written in, together with the
   traits of the file the class uses; `self::` and `static::` name the same one.
   A destructuring (`[$this->db] = ...`, `list($a, $this->db) = ...`), a reference
   (`&$this->db`) or a foreach target (`as $this->db`) counts as giving it
   something else. The property's name says nothing on its own. Not read: a
   property set in another file (a parent class's constructor), `ClassName::$db`,
   `parent::$db` and `$GLOBALS['wpdb']`.
   Limits: the cost of a file mixing k classes, k traits and k such properties
   grows as about n^1.5 (such a file is over 1 MB, the code audit's cap per
   file). A property written some way the file does not show as an assignment
   (`$this->{'db'} = $pdo`, `__set`, `Closure::bind`, a trait used inside a
   trait giving it a PDO) is still read as `$wpdb`, a possible false positive.
   Not followed: a local alias (`$db = $this->db; $db->get_results(...)`) and a
   parent class of the same file giving the property `$wpdb`.
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
   another function's sinks, and neither does an argument of `wp_send_json`,
   `wp_send_json_success` or `wp_send_json_error` in a rule that lists it as a
   sanitizer (it echoes JSON and ends the request; the XSS rules list them).
   Other sanitizer names are followed into their bodies as any function. Depth (32), body analyses per rule and file (4000)
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
such a file cannot give it a finding. PHP's `array(...)` holds its
values as `[...]` does, not as a call the engine does not know. Both
come with the findings made so far.

What it does not do: follow values across files (input read in a controller and
used in another class of another file is missed), judge the output context of HTML
built in a variable and echoed later (the echo's own context is used), see a CSRF
nonce check whose result is kept in a variable, treat a check on a value derived from another (`in_array($ext, ...)`
after `$ext = pathinfo($name, ...)`) as a check on the original (but for a URL's
host in the SSRF rules, see above), while a check on part
of a value written in place counts for all of it (`in_array(pathinfo($n, PATHINFO_EXTENSION), ...)`
cleans `$n` for every rule, path traversal included), tell apart the elements of an array
indexed by a variable (a check on `$a[$i]`, `in_array($a[$i], ...)` included, counts for
`$a[$j]` too: a key not written as a literal is `*`), know framework semantics beyond
the rules (a lookup in a constant dict is not an allowlist), look into options
kept in a variable assigned differently on two paths, or prove a
finding.
No finding does not mean no vulnerability.

Secrets never go into samples. If a sample needs something that looks like a key,
use an obvious placeholder.
