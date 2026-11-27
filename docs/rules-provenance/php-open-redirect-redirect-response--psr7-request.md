# php-open-redirect-redirect-response: PSR-7 request parameters as sources

## Case
- CVE-2024-21641 (`bench/cves/CVE-2024-21641.toml`): composer flarum/flarum-core v1.8.4 → v1.8.5, open-redirect.
- Cited in `refs` from this change, so it counts as "rule source".
- Missed because the source was not known.

## Root cause
- `src/Forum/Controller/LogOutController.php:85`
  `$url = Arr::get($request->getQueryParams(), 'return', ...)` reaches
  `new RedirectResponse($url)` at `:89` and `:106`.
- The fix routes the value through a new check:
  ```
  +        $return = $this->sanitizeReturnUrl((string) $returnUrl, $base);
  ```
  `sanitizeReturnUrl()` parses the URL and keeps it only when its host is in
  `getAllowedRedirectDomains()`.
- The rule's sources were Symfony and Laravel request getters; PSR-7's
  `getQueryParams()` was not one. The sink `RedirectResponse(` was known.

## Design
- Sources: `->getQueryParams(`, `->getParsedBody(`.
- A source, because the sink was known and the input's entry was missing.
- Any receiver (`->`), not `$request->`: a PSR-7 handler names its parameter as
  it likes (`$request`, `$req`, `$serverRequest`), and the two method names
  belong to `ServerRequestInterface`.
- Not chosen:
  - `->getCookieParams(`, `->getUploadedFiles(`: no case needed them yet.
  - `->getAttribute(`: set by routing or middleware, not always client input.
- Known limits:
  - the query parameters handed to a route generator
    (`$this->router->urlFor('list', [], $request->getQueryParams())`) are reported,
    though it builds a path on the site;
  - a host checked with `parse_url(..., PHP_URL_HOST)` is not read as a check.

## Probes
| fixture | base faac5b02 | new build | expected |
|---|---|---|---|
| `Arr::get(getQueryParams())` → `RedirectResponse`, two calls | - | reported, both | reported |
| `getParsedBody()['next']` → `RedirectResponse` | - | reported | reported |
| `in_array($t, [...], true)` allowlist before the redirect | - | - | not reported |
| input read, a fixed URL redirected to | - | - | not reported |
| the fix's form in one file (`sanitizeReturnUrl` not defined there) | - | reported | reported in a single file |

The rule's samples gained one vulnerable and one safe PSR-7 sample.

## Process
- Rule lane: miss triage, design, probes.
- Commander: approved the batch; the measurement gate.
- Reviewer: round 1 (see Review).

## Review
Round 1 at 759e1c87: B1 N3 S6, not mergeable. CI red (TestUnlessAfterOwnerReads,
TestHeldOut); the site was not regenerated and there was no CHANGELOG entry. Lines,
diffs and the single-case numbers were checked against the releases and the run.
No other tool or model is named, and no private path appears.

## Measurement
Single case, base faac5b02, rules at e99a52e5: missed → caught; the fixed
release is not reported. Load (1-minute) 12.0 at the start, 13.3 at the peak
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

This rule's new lines: flarum v1.8.4 `LogOutController.php:89`, `:106` (the
case), and `SavePasswordController.php:93` in both releases, a false positive:
a token looked up from the body goes to `$this->url->to('forum')->route(...)`,
a route generator (known issue).
