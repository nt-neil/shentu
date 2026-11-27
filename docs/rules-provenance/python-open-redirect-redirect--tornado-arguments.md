# python-open-redirect-redirect: Tornado request arguments as sources, self.redirect( as a sink

## Case
- CVE-2025-67502 (`bench/cves/CVE-2025-67502.toml`): pypi taguette 1.5.1 → 1.5.2, open-redirect.
- Cited in `refs` from this change, so it counts as "rule source".
- Missed because the rule had neither the source nor the sink. The miss triage
  named only the source; the probes found the sink missing too.

## Root cause
- `taguette/web/views.py:82` `next_ = self.get_argument('next', '')` reaches
  `:85` `return self.redirect(next_)`; the same code is at `:141` → `:144`.
- The fix (views.py 82 and 139), summarized: three lines, the argument, an
  `if not next_:` and a default of `self.reverse_url('index')`, become one:
  ```
  -        next_ = self.get_argument('next', '')
  +        next_ = self.sanitize_next_url(self.get_argument('next', ''))
  ```
  Before it, the target was replaced only when empty; nothing checked that it
  stays on the site. The check, `is_next_url_safe()` in `taguette/web/base.py:346`,
  matches `re.escape(base_path) + r'/[a-z]...'` from the start of the URL.
- The rule's sources were Flask, Django and Starlette request objects only, and
  its sink `redirect(` is a bare name, which matches a direct call and not a
  method call such as `self.redirect(` (`rules/README.md`, sinks and
  sanitizers).

## Design
- Sources: `self.get_argument(`, `self.get_query_argument(`, `self.get_body_argument(`.
- Sink: `self.redirect(`.
- Both sides are needed: with the sources alone, `self.redirect(self.get_argument('next'))`
  was still not reported. This correction came from the probes.
- Not chosen:
  - `.redirect(` on any receiver: another object's redirect method
    (`client.redirect(...)`) would count.
  - `self.get_arguments(`: it returns a list, not a URL.
  - `reverse_url(` as a sanitizer: it gives a default for an empty value, it
    checks nothing.
- Known limits:
  - reading `self.request.arguments[...]` directly is not covered;
  - a fixed false positive, known: when the check is written in another file
    (a base class), the product's per-file pass still reports the flow;
    cvebench scans with `Project.Scan`, which follows the call, and does not
    (see Measurement). Held out as `r277 tornado next-URL check in another file`;
  - `urlparse(n).netloc` compared before the redirect is not read as a check;
  - input handed to a route generator that builds a path on the site is still
    reported (`self.reverse_url(...)`, as at taguette `views.py:472`; a known
    issue in the CHANGELOG).

## Probes
| fixture | base faac5b02 | new build | expected |
|---|---|---|---|
| `get_argument` → default only when empty → `self.redirect` | - | reported | reported |
| `get_argument` → `self.redirect` | - | reported | reported |
| `self.redirect(self.get_argument('next', ''))` | - | reported | reported |
| Flask `request.args` → `redirect` (existing behavior) | reported | reported | reported |
| `request.args` → `self.redirect` | - | reported | reported |
| `self.redirect(self.reverse_url('index'))` | - | - | not reported |
| `client.redirect(self.get_argument(...))` | - | - | not reported |
| input only in the `status=` argument | - | - | not reported |
| the fix's form in one file (the check in another file) | - | reported | reported in a single file |

The rule's samples gained one vulnerable and two safe Tornado samples. The new
sink is in this rule only; every safe sample of the other rules stays clean.

## Process
- Rule lane: miss triage, design, probes (the probes corrected the design: the sink was missing too).
- Commander: approved the batch; the measurement gate.
- Reviewer: round 1 (see Review).

## Review
Round 1 at 759e1c87: B1 N3 S6, not mergeable. CI red (TestUnlessAfterOwnerReads,
TestHeldOut); the site was not regenerated and there was no CHANGELOG entry. Lines,
diffs and the single-case numbers were checked against the releases and the run.
No other tool or model is named, and no private path appears.
For this rule: round 1 asked why cvebench did not report the fixed release while
a minimal fixture of the same shape was reported; the answer is under Measurement.

## Measurement
Single case, base faac5b02, rules at e99a52e5: missed → caught; cvebench does
not report the fixed release, but the product does.

The two do not scan alike. cvebench scans a release with `Project.Scan`, which
follows `self.sanitize_next_url()` into `base.py` and reads the anchored
`re.match` in `is_next_url_safe()` as a check of how the URL starts
(`regexPrefix`, `rules/engine/regex.go`). The product (`tools/codeaudit.go`)
scans each file on its own first and then adds what the calls across files
find; it never takes back a finding of the first pass. On its own,
`taguette/web/views.py` sees an unknown method, so 1.5.2 is reported at
`views.py:83` and `:140` there.

Probes, two files (`views.py` calling `self.clean_next(self.get_argument('next', ''))`,
the method in a base class in `base.py`), product path / `Project.Scan`:

| the method in base.py | product | Project.Scan |
|---|---|---|
| returns url when `re.match(re.escape(base) + r"/[a-z][a-z0-9/_-]*$", url)` | reported | - |
| the same with `r"/[a-z]*$"` (the class may be empty) | reported | reported |
| the check is `True`, `len(url) > 0`, `url.startswith("/")` or `re.search(...)` | reported | reported |
| the check's result ignored, or url returned on both branches | reported | reported |
| returns url unchanged | reported | reported |
| returns `"/home"` or `url_for("index")` | reported | - |

So `Project.Scan` drops the flow only where the check or a clean value is
really there, and the product reports every flow whose check is in another
file.

Decision (commander): this is accepted as a known fixed false positive. The
held-out cases PY7, PY27, PY28 and QB32 lose the mark that held this rule back
(they are reported now, as they should be), and the CHANGELOG lists the case
under known issues. Moving cvebench to the product path, and dropping a per-file
finding the project scan shows safe, are separate work. Load (1-minute) 12.0 at the start, 13.3 at the peak
sampled, no segment voided.

Full measurement, base b8c15062 (integ), head 26ba87d6 (the rules of this
change); E7 twice on each side, cvebench on the three sets, all segments valid,
the 1-minute load peaking at 9.6 (first head run) and 14.5 (second), none voided
or rerun:

| set | caught base → head | with sink lines | fixed FP |
|---|---|---|---|
| cves, all (106) | 17 → 21 | 21 → 25 | 1 → 2 |
| cves, rule source | 5/27 → 9/31 | 5 → 9 | 0 → 1 |
| cves, independent | 12/79 → 12/75 (the same 12 cases) | 16 → 16 | 1 → 1 |
| holdout (22) | 3 → 3 | 4 → 4 | 0 → 0 |
| cves-ts (18) | 1 → 1 | 1 → 1 | 1 → 1 |

E7: the same 120 findings and the same cuts and unfinished files on every run.
cvebench lines: 23 more in cves (the four cases' own findings, two in tornado's
test handlers, and false positives of kinds listed as known issues), none fewer; holdout and
cves-ts line for line the same.

This rule's new lines: taguette 1.5.1 `views.py:85`, `:144` (the case);
tornado's test handlers `auth_test.py:563` and `httpclient_test.py:60` (input
redirected, in test code); and `views.py:472` (1.5.1) / `:468` (1.5.2),
`self.redirect(self.reverse_url('project', project.id))`, a false positive:
`reverse_url` builds a path on the site, and the id is a database integer.
