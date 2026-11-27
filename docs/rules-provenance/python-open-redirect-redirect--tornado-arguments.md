# python-open-redirect-redirect: Tornado request arguments as sources, self.redirect( as a sink

## Case
- CVE-2025-67502 (`bench/cves/CVE-2025-67502.toml`): pypi taguette 1.5.1 → 1.5.2, open-redirect.
- Cited in `refs` from this change, so it counts as "rule source".
- Missed because the rule had neither the source nor the sink. The miss triage
  named only the source; the probes found the sink missing too.

## Root cause
- `taguette/web/views.py:82` `next_ = self.get_argument('next', '')` reaches
  `:85` `return self.redirect(next_)`; the same code is at `:141` → `:144`.
- The fix (views.py 82 and 139):
  ```
  -        next_ = self.get_argument('next', '')
  +        next_ = self.sanitize_next_url(self.get_argument('next', ''))
  ```
  Before it, the target was replaced only when empty (`self.reverse_url('index')`);
  nothing checked that it stays on the site.
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
- Known limits: reading `self.request.arguments[...]` directly is not covered.

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
- Reviewer: pending.

## Review
Pending.

## Measurement
Single case, base faac5b02, rules at e99a52e5: missed → caught; the fixed
release is not reported (`sanitize_next_url`, the fix's check, is in
`taguette/web/base.py`; why the engine drops the flow there was not traced). Load (1-minute) 12.0 at the start, 13.3 at the peak
sampled, no segment voided. The full runs (independent, rule source, holdout,
E7) are pending.
