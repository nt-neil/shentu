# elementor-editor-after-save: the `hooks` field of route models

## Case
- CVE-2025-13393 (`bench/cves/CVE-2025-13393.toml`): WordPress plugin featured-image-from-url 5.3.1 → 5.3.2, ssrf.
- The field was added for the route model `elementor-editor-after-save`, which cites the case in `refs`.

## Root cause
- The case's input is the second parameter of a callback registered with
  `add_action('elementor/editor/after_save', ...)` (see
  `elementor-editor-after-save--route.md`).
- A route model could say which call registers a handler (`register`), which
  argument holds it (`handler`) and that the first argument must be a path
  (`path`), but not which hook the call names. `add_action` registers callbacks
  for every WordPress hook, and what each callback gets depends on the hook.

## Design
- `hooks`: a list of hook names. The registering call counts only when its first
  argument is one string literal spelling one of them exactly.
- Fail closed: a variable, a constant, a joined string or a string with `$`
  (interpolated) in the first argument does not count, since the hook it names is
  not known.
- `path` and `hooks` both name the first argument, so a route model with both is
  refused when the models load, as is `hooks` without `register` or a hook name
  with surrounding spaces (`Route.check`, `TestRouteCheck`, and `TestRulesValid`
  over the shipped models).
- Applied where `path` is: in `rules/engine/routes.go`, both where handlers are
  found in a file and where registrations are listed across files.
- Not chosen:
  - a pattern (`elementor/*`): no case needs it, and a hook family mixes callbacks
    given input with ones given ids;
  - matching the hook name in the `register` pattern itself: `register` names a
    call, not its arguments, everywhere else.

## Probes
| fixture | expected | new build |
|---|---|---|
| the hook named exactly | handler found | reported |
| another hook (`save_post`) | not a handler | not reported |
| the hook name in a variable | not a handler | not reported |
| one character off | not a handler | not reported |
| `path = true` with `hooks` | refused at load | `TestRouteCheck` |

## Process
- Rule lane: found the gap while designing the route model, asked the rule
  engine lane whether open work touches `rules/rules.go` or
  `rules/engine/routes.go` (none that conflicts), wrote the field.
- Commander: assigned the field to the rule lane, set the rules (exact literal,
  fail closed, not with `path`, checked by the tests).
- Reviewer: see Review.

## Review
Round 1 at dd1696bf: B0 N0 S3, mergeable; the field's fail-closed reading of the
first argument was probed (a variable, a constant, a joined or interpolated
string do not count) and the load-time refusals checked. See
`elementor-editor-after-save--route.md` for the suggestions taken.

## Measurement
Measured with the route model, see `elementor-editor-after-save--route.md`: the
field changes nothing alone (no shipped route model used it before), and E7's
output is the same with it.
