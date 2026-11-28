# elementor-editor-after-save: Elementor's after-save hook as a route model

## Case
- CVE-2025-13393 (`bench/cves/CVE-2025-13393.toml`): WordPress plugin featured-image-from-url 5.3.1 → 5.3.2, ssrf.
- Cited in the route model's `refs`, so it counts as "rule source" (cvebench reads route models' `refs` as it reads rules').
- Missed because the input was not a source: the editor data a hook callback gets was read by no rule or route model.

## Root cause
- `elementor/widgets/widget.php`: the plugin hooks Elementor's save
  (`add_action('elementor/editor/after_save', 'fifu_image_after_save_elementor_data', 10, 2)`).
  The callback's second parameter, `$editor_data`, is the element tree the editor
  sent. It is walked recursively; `$el['settings']['fifu_input_url']` is checked
  only with `filter_var($image_url, FILTER_VALIDATE_URL)` (which allows any host)
  and fetched at `:94` with `getimagesize($image_url)`.
- The fix validates the URL before fetching it:
  ```
  +                        $validated_url = wp_http_validate_url($image_url);
  +                        if ($validated_url === false) {
  +                            continue;
  ```
- `php-ssrf-url-readers` knows `getimagesize(` as a sink and `wp_http_validate_url`
  as a sanitizer; only the source was missing.

## Design
- A route model in `rules/routes/php/wordpress.toml`: `register = ["add_action"]`,
  `hooks = ["elementor/editor/after_save"]`, `handler = 2`, `params = [2]`.
- Why a route model: Elementor fires this hook for every post built with it, and
  any plugin can hook it. The data is what contributors and up save in the editor.
  It is Elementor's interface, like `elementor-widget-settings`, not one plugin's
  function name.
- Why `hooks` (a new field, see `elementor-editor-after-save--hooks-field.md`):
  without it, `add_action` would make the second parameter of every action
  callback input (`save_post`'s `$post`, for one).
- Only the second parameter: the first is the post id Elementor passes.
- Not chosen:
  - a source naming the plugin's walker or its `$editor_data` variable: one plugin's names;
  - a route on `add_action` with no hook name: every hook's callback.
- Known limits: the hook is matched by its literal name only; a plugin registering
  it through a variable or a constant is not read (fail closed).

## Probes
Fixtures (neutral code, not the plugin's): an after-save callback that walks the
elements and passes a widget setting to `getimagesize()`.

| fixture | base 3c59339f | new build | expected |
|---|---|---|---|
| `add_action('elementor/editor/after_save', ...)`, setting fetched | - | php-ssrf-url-readers (and php-deserialization-phar-wrapper, `getimagesize()` reads `phar://`) | reported |
| the same, `wp_http_validate_url()` first | - | - | not reported |
| the same callback on `save_post` | - | - | not reported |
| the hook name in a variable (`add_action($hook, ...)`) | - | - | not reported |
| `'elementor/editor/after_saves'` (one character off) | - | - | not reported |

The route model has one vulnerable and four safe samples, the same cases.

## Process
- Rule lane: miss triage, root cause, probes (a probe with an unfiltered `add_action` route showed the flow is followed and that a hook name is needed), the `hooks` field and the route model.
- Commander: scope of the second batch (framework-level only), the decision that the rule lane adds the `hooks` field in a PR of its own, the measurement gate.
- Reviewer: see Review.

## Review
Pending (the pull request's first round).

## Measurement
Full A/B, base e0d8f79d (integ), head 14f308cd (this change), in a throwaway
Linux VM (4 CPU, 6 GB) on a separate machine, the measurement environment since
it was checked line for line against the work machine's runs. E7 twice on each
side, cvebench on the three sets; every segment valid, the other machine's
1-minute load peaking at 3.9 and the VM's at 2.9, none voided or rerun.

| set | caught base → head | with sink lines | fixed FP |
|---|---|---|---|
| cves, all (106) | 21 → 22 | 25 → 26 | 3 → 3 |
| cves, rule source | 9/31 → 10/32 | 9 → 10 | 2 → 2 |
| cves, independent | 12/75 → 12/74 (the same 12 cases) | 16 → 16 | 1 → 1 |
| holdout (22) | 3 → 3 | 4 → 4 | 0 → 0 |
| cves-ts (18) | 1 → 1 | 1 → 1 | 1 → 1 |

E7: the same output on all four runs (no line more, none fewer). cvebench lines:
2 more in cves, none fewer; holdout and cves-ts line for line the same. Both new
lines are the case itself, featured-image-from-url 5.3.1
`elementor/widgets/widget.php:94` (`getimagesize($image_url)`):
php-ssrf-url-readers (the CVE) and php-deserialization-phar-wrapper
(`getimagesize()` opens a `phar://` URL too, which unserializes its metadata on
PHP before 8.0). 5.3.2, with `wp_http_validate_url()`, reports neither.
