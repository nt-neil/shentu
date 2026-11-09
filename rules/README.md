# Shentu code rules

Shentu's own rules for injection-class vulnerabilities in application code. Each rule
describes one pattern: **user input (a source) that reaches a dangerous call (a sink)
without passing through a sanitizer**. The scanning engine that applies them (token
matching, then in-function taint tracking) is not written yet; for now `go test
./rules` only checks that every rule is well formed.

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
title = "Request input concatenated into a SQL string"
frameworks = ["laravel"]           # optional: laravel, wordpress, django, flask, express
sources = ["$_GET", "$request->input("]   # where user input comes from
sinks = ["mysqli_query", "->query("]      # the dangerous calls
sanitizers = ["intval", "->prepare("]     # calls whose result is safe for these sinks; [] if none
fix = "One sentence the user sees: how to fix it."
refs = ["CVE-2026-56738"]          # CVE-YYYY-NNNN or GHSA-xxxx-xxxx-xxxx that inspired the rule

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
- `lang`, `class`, `severity`, `frameworks` are in the allowed lists, and `cwe` belongs to the class;
- `refs` are well-formed CVE or GHSA ids, without duplicates;
- there is at least one `vulnerable` and one `safe` sample, and each vulnerable sample
  contains one of the rule's sources and one of its sinks.

When the engine exists, the same samples become its tests: every vulnerable sample
must be found and no safe sample may be.

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
5. Run `go test ./rules -run Rules`.

## Future: argument conditions

The format does not yet describe conditions on a call's arguments, so some rules
can only say it with sink and sanitizer strings plus samples. To be designed with
the taint-tracking engine (layer B). Known cases:

- `yaml.load(...)` is safe only with `Loader=yaml.SafeLoader`, dangerous with
  `Loader`, `FullLoader` or `UnsafeLoader`.
- `spawn(...)` / `execFile(...)` are safe with an argument array, but become a shell
  command line when the options contain `shell: true`.
- `unserialize($x)` is dangerous, but `unserialize($x, ['allowed_classes' => false])`
  cannot create objects.

Secrets never go into samples. If a sample needs something that looks like a key,
use an obvious placeholder.
