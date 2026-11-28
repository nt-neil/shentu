# CVE bench

2026-11-28, 132 rules, 22 cases.

scan path: product (as app_code_audit: each file on its own, then the calls across files, merged; no audit clock, no list cap); project caps MaxTime 15m0s, MaxHeap 1024 MiB, MaxTokens 3000000, MaxWork 1500000000.

- caught: a rule of the case's class reports within 10 lines of a line the fix changed, in the vulnerable release.
- fixed FP: a rule that caught the case still reports at the fix in the fixed release; the rate is over caught cases.
- rule source: a rule cites the id in its refs, so the rule was written from it; independent: no rule cites it.
- in fix files: reports of the case's class anywhere in the fix files of the vulnerable release, near the fix or not.
- findings and time: every report of every rule on the whole release, and the time to scan it.
- known gaps: cases the rules cannot catch yet (known_gap says why), run and listed apart, out of the rates.
- with sink lines: as caught and fixed FP, a finding of the class on the very line of the call the fix protects also counting (a case's [[sinks]], one per case, with the upstream fix as its basis). A cross-file flow is reported at the callee's sink, outside the fix files. Shown next to the main verdict, which does not count them. "shared helper": other flows reach that line too.
- with reference: as caught and fixed FP, a reference-tier rule (about how a call is made, not about input reaching it) also counting. The main verdict and the with-sink-lines columns leave those rules out; a reference rule's own rows say "caught (reference)".
- unfinished files: files a limit cut short, or too big to read; calls cut: files checked to the end whose calls were not all followed (cross-file findings may be missing). Cuts by cause count both.

## Summary

| group | cases | caught | catch rate | fixed FP | fixed FP rate | findings per release (vulnerable / fixed) | scan time per release | caught with sink lines | fixed FP with sink lines | caught with reference | fixed FP with reference |
|---|---|---|---|---|---|---|---|---|---|---|---|
| all | 22 | 3 | 13.6% | 0 | 0.0% | 6.2 / 6.0 | 2.3s | 4 (18.2%) | 1 (25.0%) | 3 (13.6%) | 0 (0.0%) |
| independent | 22 | 3 | 13.6% | 0 | 0.0% | 6.2 / 6.0 | 2.3s | 4 (18.2%) | 1 (25.0%) | 3 (13.6%) | 0 (0.0%) |
| composer | 5 | 0 | 0.0% | 0 | - | 22.4 / 21.6 | 5.1s | 0 (0.0%) | 0 (-) | 0 (0.0%) | 0 (-) |
| npm | 6 | 0 | 0.0% | 0 | - | 0.0 / 0.0 | 0.0s | 0 (0.0%) | 0 (-) | 0 (0.0%) | 0 (-) |
| pypi | 3 | 0 | 0.0% | 0 | - | 3.0 / 4.7 | 0.8s | 0 (0.0%) | 0 (-) | 0 (0.0%) | 0 (-) |
| wordpress-plugin | 8 | 3 | 37.5% | 0 | 0.0% | 1.9 / 1.4 | 2.8s | 4 (50.0%) | 1 (25.0%) | 3 (37.5%) | 0 (0.0%) |
| cmdi | 3 | 0 | 0.0% | 0 | - | 0.0 / 0.0 | 0.0s | 0 (0.0%) | 0 (-) | 0 (0.0%) | 0 (-) |
| code-eval | 3 | 1 | 33.3% | 0 | 0.0% | 19.0 / 18.0 | 3.8s | 1 (33.3%) | 0 (0.0%) | 1 (33.3%) | 0 (0.0%) |
| deserialization | 8 | 1 | 12.5% | 0 | 0.0% | 8.0 / 8.1 | 3.4s | 1 (12.5%) | 0 (0.0%) | 1 (12.5%) | 0 (0.0%) |
| path-traversal | 6 | 1 | 16.7% | 0 | 0.0% | 1.5 / 1.3 | 1.9s | 2 (33.3%) | 1 (50.0%) | 1 (16.7%) | 0 (0.0%) |
| sqli | 2 | 0 | 0.0% | 0 | - | 3.0 / 3.0 | 0.1s | 0 (0.0%) | 0 (-) | 0 (0.0%) | 0 (-) |

## Cuts by cause

| cause | files (vulnerable / fixed) |
|---|---|
| ambiguous-call | 13 / 13 |
| call-work | 1 / 1 |
| callable-param | 32 / 32 |
| summary | 37 / 37 |
| summary-inner | 37 / 37 |

## Cases

| case | package | releases | class | group | rule | vulnerable | fixed | in fix files | findings | unfinished files | scan time | calls cut | cuts by cause | at sink line (vulnerable / fixed) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| CVE-2017-5954 | npm serialize-to-js | 0.5.0 → 1.0.0 | deserialization | independent | js-deserialization-node-serialize | - | - | 0 | 0 / 0 | 0 / 0 | 0.0s / 0.0s | 0 / 0 | - / - | - |
| CVE-2017-5954 | npm serialize-to-js | 0.5.0 → 1.0.0 | deserialization | independent | js-deserialization-yaml-load | - | - | 0 | 0 / 0 | 0 / 0 | 0.0s / 0.0s | 0 / 0 | - / - | - |
| CVE-2021-23352 | npm madge | 4.0.0 → 4.0.1 | cmdi | independent | js-cmdi-exec | - | - | 0 | 0 / 0 | 0 / 0 | 0.0s / 0.0s | 0 / 0 | - / - | - |
| CVE-2021-23352 | npm madge | 4.0.0 → 4.0.1 | cmdi | independent | js-cmdi-promisified-exec | - | - | 0 | 0 / 0 | 0 / 0 | 0.0s / 0.0s | 0 / 0 | - / - | - |
| CVE-2021-23352 | npm madge | 4.0.0 → 4.0.1 | cmdi | independent | js-cmdi-spawn-sh-c | - | - | 0 | 0 / 0 | 0 / 0 | 0.0s / 0.0s | 0 / 0 | - / - | - |
| CVE-2021-23352 | npm madge | 4.0.0 → 4.0.1 | cmdi | independent | js-cmdi-spawn-shell | - | - | 0 | 0 / 0 | 0 / 0 | 0.0s / 0.0s | 0 / 0 | - / - | - |
| CVE-2021-33420 | npm replicator | 1.0.3 → 1.0.4 | deserialization | independent | js-deserialization-node-serialize | - | - | 0 | 0 / 0 | 0 / 0 | 0.0s / 0.0s | 0 / 0 | - / - | - |
| CVE-2021-33420 | npm replicator | 1.0.3 → 1.0.4 | deserialization | independent | js-deserialization-yaml-load | - | - | 0 | 0 / 0 | 0 / 0 | 0.0s / 0.0s | 0 / 0 | - / - | - |
| CVE-2022-35942 | npm loopback-connector-postgresql | 5.5.0 → 5.5.1 | sqli | independent | js-sqli-node-http-query | - | - | 0 | 0 / 0 | 0 / 0 | 0.0s / 0.0s | 0 / 0 | - / - | - |
| CVE-2022-35942 | npm loopback-connector-postgresql | 5.5.0 → 5.5.1 | sqli | independent | js-sqli-object-input | - | - | 0 | 0 / 0 | 0 / 0 | 0.0s / 0.0s | 0 / 0 | - / - | - |
| CVE-2022-35942 | npm loopback-connector-postgresql | 5.5.0 → 5.5.1 | sqli | independent | js-sqli-raw-interpolation | - | - | 0 | 0 / 0 | 0 / 0 | 0.0s / 0.0s | 0 / 0 | - / - | - |
| CVE-2022-35942 | npm loopback-connector-postgresql | 5.5.0 → 5.5.1 | sqli | independent | js-sqli-sequelize-literal | - | - | 0 | 0 / 0 | 0 / 0 | 0.0s / 0.0s | 0 / 0 | - / - | - |
| CVE-2023-3343 | wordpress-plugin user-registration | 3.0.1 → 3.0.2 | deserialization | independent | php-deserialization-phar-wrapper | - | - | 0 | 3 / 2 | 0 / 0 | 14.6s / 13.7s | 1 / 1 | call-work:1 / call-work:1 | - |
| CVE-2023-3343 | wordpress-plugin user-registration | 3.0.1 → 3.0.2 | deserialization | independent | php-deserialization-unserialize | - | - | 0 | 3 / 2 | 0 / 0 | 14.6s / 13.7s | 1 / 1 | call-work:1 / call-work:1 | - |
| CVE-2023-3343 | wordpress-plugin user-registration | 3.0.1 → 3.0.2 | deserialization | independent | php-deserialization-wp-maybe-unserialize | - | - | 0 | 3 / 2 | 0 / 0 | 14.6s / 13.7s | 1 / 1 | call-work:1 / call-work:1 | - |
| CVE-2023-6933 | wordpress-plugin better-search-replace | 1.4.4 → 1.4.5 | deserialization | independent | php-deserialization-phar-wrapper | - | - | 0 | 1 / 1 | 0 / 0 | 0.2s / 0.2s | 0 / 0 | - / - | - |
| CVE-2023-6933 | wordpress-plugin better-search-replace | 1.4.4 → 1.4.5 | deserialization | independent | php-deserialization-unserialize | - | - | 0 | 1 / 1 | 0 / 0 | 0.2s / 0.2s | 0 / 0 | - / - | - |
| CVE-2023-6933 | wordpress-plugin better-search-replace | 1.4.4 → 1.4.5 | deserialization | independent | php-deserialization-wp-maybe-unserialize | - | - | 0 | 1 / 1 | 0 / 0 | 0.2s / 0.2s | 0 / 0 | - / - | - |
| CVE-2024-10871 | wordpress-plugin category-ajax-filter | 2.8.2 → 2.8.3 | path-traversal | independent | php-path-traversal-file-include | caught | - | 1 | 1 / 0 | 0 / 0 | 0.6s / 0.6s | 0 / 0 | - / - | - |
| CVE-2024-10871 | wordpress-plugin category-ajax-filter | 2.8.2 → 2.8.3 | path-traversal | independent | php-path-traversal-file-read | - | - | 1 | 1 / 0 | 0 / 0 | 0.6s / 0.6s | 0 / 0 | - / - | - |
| CVE-2024-10871 | wordpress-plugin category-ajax-filter | 2.8.2 → 2.8.3 | path-traversal | independent | php-path-traversal-file-write | - | - | 1 | 1 / 0 | 0 / 0 | 0.6s / 0.6s | 0 / 0 | - / - | - |
| CVE-2024-10871 | wordpress-plugin category-ajax-filter | 2.8.2 → 2.8.3 | path-traversal | independent | php-path-traversal-joomla-file | - | - | 1 | 1 / 0 | 0 / 0 | 0.6s / 0.6s | 0 / 0 | - / - | - |
| CVE-2024-10871 | wordpress-plugin category-ajax-filter | 2.8.2 → 2.8.3 | path-traversal | independent | php-path-traversal-laravel-storage | - | - | 1 | 1 / 0 | 0 / 0 | 0.6s / 0.6s | 0 / 0 | - / - | - |
| CVE-2024-10871 | wordpress-plugin category-ajax-filter | 2.8.2 → 2.8.3 | path-traversal | independent | php-path-traversal-symfony-file-response | - | - | 1 | 1 / 0 | 0 / 0 | 0.6s / 0.6s | 0 / 0 | - / - | - |
| CVE-2024-10871 | wordpress-plugin category-ajax-filter | 2.8.2 → 2.8.3 | path-traversal | independent | php-path-traversal-wp-filesystem | - | - | 1 | 1 / 0 | 0 / 0 | 0.6s / 0.6s | 0 / 0 | - / - | - |
| CVE-2024-10871 | wordpress-plugin category-ajax-filter | 2.8.2 → 2.8.3 | path-traversal | independent | php-path-traversal-wp-template-loader | - | - | 1 | 1 / 0 | 0 / 0 | 0.6s / 0.6s | 0 / 0 | - / - | - |
| CVE-2024-1770 | wordpress-plugin meta-tag-manager | 3.0.2 → 3.1 | deserialization | independent | php-deserialization-phar-wrapper | - | - | 0 | 0 / 0 | 0 / 0 | 0.5s / 0.5s | 0 / 0 | - / - | - |
| CVE-2024-1770 | wordpress-plugin meta-tag-manager | 3.0.2 → 3.1 | deserialization | independent | php-deserialization-unserialize | - | - | 0 | 0 / 0 | 0 / 0 | 0.5s / 0.5s | 0 / 0 | - / - | - |
| CVE-2024-1770 | wordpress-plugin meta-tag-manager | 3.0.2 → 3.1 | deserialization | independent | php-deserialization-wp-maybe-unserialize | - | - | 0 | 0 / 0 | 0 / 0 | 0.5s / 0.5s | 0 / 0 | - / - | - |
| CVE-2024-1872 | wordpress-plugin button | 1.1.27 → 1.1.28 | deserialization | independent | php-deserialization-phar-wrapper | - | - | 1 | 1 / 0 | 0 / 0 | 0.2s / 0.2s | 0 / 0 | - / - | - |
| CVE-2024-1872 | wordpress-plugin button | 1.1.27 → 1.1.28 | deserialization | independent | php-deserialization-unserialize | caught | - | 1 | 1 / 0 | 0 / 0 | 0.2s / 0.2s | 0 / 0 | - / - | - |
| CVE-2024-1872 | wordpress-plugin button | 1.1.27 → 1.1.28 | deserialization | independent | php-deserialization-wp-maybe-unserialize | - | - | 1 | 1 / 0 | 0 / 0 | 0.2s / 0.2s | 0 / 0 | - / - | - |
| CVE-2024-2023 | wordpress-plugin folders | 3.0.1 → 3.0.2 | path-traversal | independent | php-path-traversal-file-include | - | - | 2 | 4 / 4 | 0 / 0 | 5.7s / 4.9s | 0 / 0 | - / - | - / - |
| CVE-2024-2023 | wordpress-plugin folders | 3.0.1 → 3.0.2 | path-traversal | independent | php-path-traversal-file-read | - | - | 2 | 4 / 4 | 0 / 0 | 5.7s / 4.9s | 0 / 0 | - / - | - / - |
| CVE-2024-2023 | wordpress-plugin folders | 3.0.1 → 3.0.2 | path-traversal | independent | php-path-traversal-file-write | - | - | 2 | 4 / 4 | 0 / 0 | 5.7s / 4.9s | 0 / 0 | - / - | caught / still reports |
| CVE-2024-2023 | wordpress-plugin folders | 3.0.1 → 3.0.2 | path-traversal | independent | php-path-traversal-joomla-file | - | - | 2 | 4 / 4 | 0 / 0 | 5.7s / 4.9s | 0 / 0 | - / - | - / - |
| CVE-2024-2023 | wordpress-plugin folders | 3.0.1 → 3.0.2 | path-traversal | independent | php-path-traversal-laravel-storage | - | - | 2 | 4 / 4 | 0 / 0 | 5.7s / 4.9s | 0 / 0 | - / - | - / - |
| CVE-2024-2023 | wordpress-plugin folders | 3.0.1 → 3.0.2 | path-traversal | independent | php-path-traversal-symfony-file-response | - | - | 2 | 4 / 4 | 0 / 0 | 5.7s / 4.9s | 0 / 0 | - / - | - / - |
| CVE-2024-2023 | wordpress-plugin folders | 3.0.1 → 3.0.2 | path-traversal | independent | php-path-traversal-wp-filesystem | - | - | 2 | 4 / 4 | 0 / 0 | 5.7s / 4.9s | 0 / 0 | - / - | - / - |
| CVE-2024-2023 | wordpress-plugin folders | 3.0.1 → 3.0.2 | path-traversal | independent | php-path-traversal-wp-template-loader | - | - | 2 | 4 / 4 | 0 / 0 | 5.7s / 4.9s | 0 / 0 | - / - | - / - |
| CVE-2024-4098 | wordpress-plugin shariff | 4.6.13 → 4.6.14 | path-traversal | independent | php-path-traversal-file-include | - | - | 1 | 4 / 4 | 0 / 0 | 1.4s / 1.4s | 0 / 0 | - / - | - |
| CVE-2024-4098 | wordpress-plugin shariff | 4.6.13 → 4.6.14 | path-traversal | independent | php-path-traversal-file-read | - | - | 1 | 4 / 4 | 0 / 0 | 1.4s / 1.4s | 0 / 0 | - / - | - |
| CVE-2024-4098 | wordpress-plugin shariff | 4.6.13 → 4.6.14 | path-traversal | independent | php-path-traversal-file-write | - | - | 1 | 4 / 4 | 0 / 0 | 1.4s / 1.4s | 0 / 0 | - / - | - |
| CVE-2024-4098 | wordpress-plugin shariff | 4.6.13 → 4.6.14 | path-traversal | independent | php-path-traversal-joomla-file | - | - | 1 | 4 / 4 | 0 / 0 | 1.4s / 1.4s | 0 / 0 | - / - | - |
| CVE-2024-4098 | wordpress-plugin shariff | 4.6.13 → 4.6.14 | path-traversal | independent | php-path-traversal-laravel-storage | - | - | 1 | 4 / 4 | 0 / 0 | 1.4s / 1.4s | 0 / 0 | - / - | - |
| CVE-2024-4098 | wordpress-plugin shariff | 4.6.13 → 4.6.14 | path-traversal | independent | php-path-traversal-symfony-file-response | - | - | 1 | 4 / 4 | 0 / 0 | 1.4s / 1.4s | 0 / 0 | - / - | - |
| CVE-2024-4098 | wordpress-plugin shariff | 4.6.13 → 4.6.14 | path-traversal | independent | php-path-traversal-wp-filesystem | - | - | 1 | 4 / 4 | 0 / 0 | 1.4s / 1.4s | 0 / 0 | - / - | - |
| CVE-2024-4098 | wordpress-plugin shariff | 4.6.13 → 4.6.14 | path-traversal | independent | php-path-traversal-wp-template-loader | - | - | 1 | 4 / 4 | 0 / 0 | 1.4s / 1.4s | 0 / 0 | - / - | - |
| CVE-2024-9593 | wordpress-plugin time-clock | 1.2.2 → 1.2.3 | code-eval | independent | php-code-eval-dynamic-callback | caught | - | 1 | 1 / 0 | 0 / 0 | 0.3s / 0.3s | 0 / 0 | - / - | - |
| CVE-2024-9593 | wordpress-plugin time-clock | 1.2.2 → 1.2.3 | code-eval | independent | php-code-eval-eval | - | - | 1 | 1 / 0 | 0 / 0 | 0.3s / 0.3s | 0 / 0 | - / - | - |
| CVE-2024-9593 | wordpress-plugin time-clock | 1.2.2 → 1.2.3 | code-eval | independent | php-code-eval-smarty-string | - | - | 1 | 1 / 0 | 0 / 0 | 0.3s / 0.3s | 0 / 0 | - / - | - |
| CVE-2024-9593 | wordpress-plugin time-clock | 1.2.2 → 1.2.3 | code-eval | independent | php-code-eval-template-string | - | - | 1 | 1 / 0 | 0 / 0 | 0.3s / 0.3s | 0 / 0 | - / - | - |
| CVE-2026-110634 | npm git-diff | 2.0.6 → 2.0.7 | cmdi | independent | js-cmdi-exec | - | - | 0 | 0 / 0 | 0 / 0 | 0.0s / 0.0s | 0 / 0 | - / - | - |
| CVE-2026-110634 | npm git-diff | 2.0.6 → 2.0.7 | cmdi | independent | js-cmdi-promisified-exec | - | - | 0 | 0 / 0 | 0 / 0 | 0.0s / 0.0s | 0 / 0 | - / - | - |
| CVE-2026-110634 | npm git-diff | 2.0.6 → 2.0.7 | cmdi | independent | js-cmdi-spawn-sh-c | - | - | 0 | 0 / 0 | 0 / 0 | 0.0s / 0.0s | 0 / 0 | - / - | - |
| CVE-2026-110634 | npm git-diff | 2.0.6 → 2.0.7 | cmdi | independent | js-cmdi-spawn-shell | - | - | 0 | 0 / 0 | 0 / 0 | 0.0s / 0.0s | 0 / 0 | - / - | - |
| CVE-2026-115355 | pypi mistune | 3.2.0 → 3.3.0 | path-traversal | independent | python-path-traversal-archive-extract | - | - | 0 | 0 / 0 | 0 / 0 | 0.1s / 0.1s | 0 / 0 | - / - | - |
| CVE-2026-115355 | pypi mistune | 3.2.0 → 3.3.0 | path-traversal | independent | python-path-traversal-image-open | - | - | 0 | 0 / 0 | 0 / 0 | 0.1s / 0.1s | 0 / 0 | - / - | - |
| CVE-2026-115355 | pypi mistune | 3.2.0 → 3.3.0 | path-traversal | independent | python-path-traversal-send-file | - | - | 0 | 0 / 0 | 0 / 0 | 0.1s / 0.1s | 0 / 0 | - / - | - |
| CVE-2026-115355 | pypi mistune | 3.2.0 → 3.3.0 | path-traversal | independent | python-path-traversal-upload-filename | - | - | 0 | 0 / 0 | 0 / 0 | 0.1s / 0.1s | 0 / 0 | - / - | - |
| CVE-2026-46633 | composer twigphp/Twig | v3.25.0 → v3.26.0 | code-eval | independent | php-code-eval-dynamic-callback | - | - | 0 | 0 / 0 | 0 / 0 | 0.6s / 0.5s | 0 / 0 | - / - | - |
| CVE-2026-46633 | composer twigphp/Twig | v3.25.0 → v3.26.0 | code-eval | independent | php-code-eval-eval | - | - | 0 | 0 / 0 | 0 / 0 | 0.6s / 0.5s | 0 / 0 | - / - | - |
| CVE-2026-46633 | composer twigphp/Twig | v3.25.0 → v3.26.0 | code-eval | independent | php-code-eval-smarty-string | - | - | 0 | 0 / 0 | 0 / 0 | 0.6s / 0.5s | 0 / 0 | - / - | - |
| CVE-2026-46633 | composer twigphp/Twig | v3.25.0 → v3.26.0 | code-eval | independent | php-code-eval-template-string | - | - | 0 | 0 / 0 | 0 / 0 | 0.6s / 0.5s | 0 / 0 | - / - | - |
| CVE-2026-49260 | composer pontedilana/php-weasyprint | 2.5.0 → 2.5.1 | cmdi | independent | php-cmdi-mail-params | - | - | 0 | 0 / 0 | 0 / 0 | 0.0s / 0.0s | 0 / 0 | - / - | - / - |
| CVE-2026-49260 | composer pontedilana/php-weasyprint | 2.5.0 → 2.5.1 | cmdi | independent | php-cmdi-process-shell-commandline | - | - | 0 | 0 / 0 | 0 / 0 | 0.0s / 0.0s | 0 / 0 | - / - | - / - |
| CVE-2026-49260 | composer pontedilana/php-weasyprint | 2.5.0 → 2.5.1 | cmdi | independent | php-cmdi-shell-exec | - | - | 0 | 0 / 0 | 0 / 0 | 0.0s / 0.0s | 0 / 0 | - / - | - / - |
| CVE-2026-52777 | composer yeswiki/yeswiki | v4.6.5 → v4.6.6 | deserialization | independent | php-deserialization-phar-wrapper | - | - | 0 | 56 / 54 | 0 / 0 | 10.0s / 10.8s | 0 / 0 | - / - | - |
| CVE-2026-52777 | composer yeswiki/yeswiki | v4.6.5 → v4.6.6 | deserialization | independent | php-deserialization-unserialize | - | - | 0 | 56 / 54 | 0 / 0 | 10.0s / 10.8s | 0 / 0 | - / - | - |
| CVE-2026-52777 | composer yeswiki/yeswiki | v4.6.5 → v4.6.6 | deserialization | independent | php-deserialization-wp-maybe-unserialize | - | - | 0 | 56 / 54 | 0 / 0 | 10.0s / 10.8s | 0 / 0 | - / - | - |
| CVE-2026-52778 | composer yeswiki/yeswiki | v4.6.5 → v4.6.6 | code-eval | independent | php-code-eval-dynamic-callback | - | - | 0 | 56 / 54 | 0 / 0 | 10.7s / 10.2s | 0 / 0 | - / - | - |
| CVE-2026-52778 | composer yeswiki/yeswiki | v4.6.5 → v4.6.6 | code-eval | independent | php-code-eval-eval | - | - | 0 | 56 / 54 | 0 / 0 | 10.7s / 10.2s | 0 / 0 | - / - | - |
| CVE-2026-52778 | composer yeswiki/yeswiki | v4.6.5 → v4.6.6 | code-eval | independent | php-code-eval-smarty-string | - | - | 0 | 56 / 54 | 0 / 0 | 10.7s / 10.2s | 0 / 0 | - / - | - |
| CVE-2026-52778 | composer yeswiki/yeswiki | v4.6.5 → v4.6.6 | code-eval | independent | php-code-eval-template-string | - | - | 0 | 56 / 54 | 0 / 0 | 10.7s / 10.2s | 0 / 0 | - / - | - |
| CVE-2026-54732 | npm libreoffice-convert | 1.8.1 → 1.8.2 | path-traversal | independent | js-path-traversal-archive-extract | - | - | 0 | 0 / 0 | 0 / 0 | 0.0s / 0.0s | 0 / 0 | - / - | - / - |
| CVE-2026-54732 | npm libreoffice-convert | 1.8.1 → 1.8.2 | path-traversal | independent | js-path-traversal-exists-probe | - | - | 0 | 0 / 0 | 0 / 0 | 0.0s / 0.0s | 0 / 0 | - / - | - / - |
| CVE-2026-54732 | npm libreoffice-convert | 1.8.1 → 1.8.2 | path-traversal | independent | js-path-traversal-fs-ops | - | - | 0 | 0 / 0 | 0 / 0 | 0.0s / 0.0s | 0 / 0 | - / - | - / - |
| CVE-2026-54732 | npm libreoffice-convert | 1.8.1 → 1.8.2 | path-traversal | independent | js-path-traversal-send-file | - | - | 0 | 0 / 0 | 0 / 0 | 0.0s / 0.0s | 0 / 0 | - / - | - / - |
| CVE-2026-55509 | pypi WsgiDAV | 4.3.4 → 4.3.5 | sqli | independent | python-sqli-dbapi-format | - | - | 0 | 6 / 6 | 0 / 0 | 0.2s / 0.2s | 0 / 0 | - / - | - |
| CVE-2026-55509 | pypi WsgiDAV | 4.3.4 → 4.3.5 | sqli | independent | python-sqli-django-kwargs-alias | - | - | 0 | 6 / 6 | 0 / 0 | 0.2s / 0.2s | 0 / 0 | - / - | - |
| CVE-2026-55509 | pypi WsgiDAV | 4.3.4 → 4.3.5 | sqli | independent | python-sqli-orm-raw-query | - | - | 0 | 6 / 6 | 0 / 0 | 0.2s / 0.2s | 0 / 0 | - / - | - |
| CVE-2026-55509 | pypi WsgiDAV | 4.3.4 → 4.3.5 | sqli | independent | python-sqli-pandas-read-sql | - | - | 0 | 6 / 6 | 0 / 0 | 0.2s / 0.2s | 0 / 0 | - / - | - |
| CVE-2026-55509 | pypi WsgiDAV | 4.3.4 → 4.3.5 | sqli | independent | python-sqli-sqlalchemy-text | - | - | 0 | 6 / 6 | 0 / 0 | 0.2s / 0.2s | 0 / 0 | - / - | - |
| CVE-2026-63222 | composer codeigniter4/CodeIgniter4 | v4.7.3 → v4.7.4 | path-traversal | independent | php-path-traversal-file-include | - | - | 0 | 0 / 0 | 0 / 0 | 4.1s / 4.2s | 44 / 44 | ambiguous-call:13 callable-param:32 summary:37 summary-inner:37 / ambiguous-call:13 callable-param:32 summary:37 summary-inner:37 | - |
| CVE-2026-63222 | composer codeigniter4/CodeIgniter4 | v4.7.3 → v4.7.4 | path-traversal | independent | php-path-traversal-file-read | - | - | 0 | 0 / 0 | 0 / 0 | 4.1s / 4.2s | 44 / 44 | ambiguous-call:13 callable-param:32 summary:37 summary-inner:37 / ambiguous-call:13 callable-param:32 summary:37 summary-inner:37 | - |
| CVE-2026-63222 | composer codeigniter4/CodeIgniter4 | v4.7.3 → v4.7.4 | path-traversal | independent | php-path-traversal-file-write | - | - | 0 | 0 / 0 | 0 / 0 | 4.1s / 4.2s | 44 / 44 | ambiguous-call:13 callable-param:32 summary:37 summary-inner:37 / ambiguous-call:13 callable-param:32 summary:37 summary-inner:37 | - |
| CVE-2026-63222 | composer codeigniter4/CodeIgniter4 | v4.7.3 → v4.7.4 | path-traversal | independent | php-path-traversal-joomla-file | - | - | 0 | 0 / 0 | 0 / 0 | 4.1s / 4.2s | 44 / 44 | ambiguous-call:13 callable-param:32 summary:37 summary-inner:37 / ambiguous-call:13 callable-param:32 summary:37 summary-inner:37 | - |
| CVE-2026-63222 | composer codeigniter4/CodeIgniter4 | v4.7.3 → v4.7.4 | path-traversal | independent | php-path-traversal-laravel-storage | - | - | 0 | 0 / 0 | 0 / 0 | 4.1s / 4.2s | 44 / 44 | ambiguous-call:13 callable-param:32 summary:37 summary-inner:37 / ambiguous-call:13 callable-param:32 summary:37 summary-inner:37 | - |
| CVE-2026-63222 | composer codeigniter4/CodeIgniter4 | v4.7.3 → v4.7.4 | path-traversal | independent | php-path-traversal-symfony-file-response | - | - | 0 | 0 / 0 | 0 / 0 | 4.1s / 4.2s | 44 / 44 | ambiguous-call:13 callable-param:32 summary:37 summary-inner:37 / ambiguous-call:13 callable-param:32 summary:37 summary-inner:37 | - |
| CVE-2026-63222 | composer codeigniter4/CodeIgniter4 | v4.7.3 → v4.7.4 | path-traversal | independent | php-path-traversal-wp-filesystem | - | - | 0 | 0 / 0 | 0 / 0 | 4.1s / 4.2s | 44 / 44 | ambiguous-call:13 callable-param:32 summary:37 summary-inner:37 / ambiguous-call:13 callable-param:32 summary:37 summary-inner:37 | - |
| CVE-2026-63222 | composer codeigniter4/CodeIgniter4 | v4.7.3 → v4.7.4 | path-traversal | independent | php-path-traversal-wp-template-loader | - | - | 0 | 0 / 0 | 0 / 0 | 4.1s / 4.2s | 44 / 44 | ambiguous-call:13 callable-param:32 summary:37 summary-inner:37 / ambiguous-call:13 callable-param:32 summary:37 summary-inner:37 | - |
| CVE-2026-78683 | pypi nltk | 3.9.4 → 3.10.0 | deserialization | independent | python-deserialization-downloaded-pickle | - | - | 0 | 3 / 8 | 0 / 0 | 2.2s / 2.0s | 0 / 0 | - / - | - |
| CVE-2026-78683 | pypi nltk | 3.9.4 → 3.10.0 | deserialization | independent | python-deserialization-pickle | - | - | 0 | 3 / 8 | 0 / 0 | 2.2s / 2.0s | 0 / 0 | - / - | - |
| CVE-2026-78683 | pypi nltk | 3.9.4 → 3.10.0 | deserialization | independent | python-deserialization-torch-load | - | - | 0 | 3 / 8 | 0 / 0 | 2.2s / 2.0s | 0 / 0 | - / - | - |
| CVE-2026-78683 | pypi nltk | 3.9.4 → 3.10.0 | deserialization | independent | python-deserialization-yaml-load | - | - | 0 | 3 / 8 | 0 / 0 | 2.2s / 2.0s | 0 / 0 | - / - | - |
