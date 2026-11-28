# CVE bench

2026-11-28, 132 rules, 18 cases.

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
| all | 18 | 1 | 5.6% | 1 | 100.0% | 4.4 / 4.2 | 7.2s | 1 (5.6%) | 1 (100.0%) | 1 (5.6%) | 1 (100.0%) |
| independent | 18 | 1 | 5.6% | 1 | 100.0% | 4.4 / 4.2 | 7.2s | 1 (5.6%) | 1 (100.0%) | 1 (5.6%) | 1 (100.0%) |
| github | 18 | 1 | 5.6% | 1 | 100.0% | 4.4 / 4.2 | 7.2s | 1 (5.6%) | 1 (100.0%) | 1 (5.6%) | 1 (100.0%) |
| cmdi | 1 | 0 | 0.0% | 0 | - | 17.0 / 12.0 | 32.4s | 0 (0.0%) | 0 (-) | 0 (0.0%) | 0 (-) |
| code-eval | 7 | 0 | 0.0% | 0 | - | 3.4 / 3.4 | 3.3s | 0 (0.0%) | 0 (-) | 0 (0.0%) | 0 (-) |
| path-traversal | 9 | 1 | 11.1% | 1 | 100.0% | 3.4 / 3.4 | 6.7s | 1 (11.1%) | 1 (100.0%) | 1 (11.1%) | 1 (100.0%) |
| sqli | 1 | 0 | 0.0% | 0 | - | 8.0 / 8.0 | 13.6s | 0 (0.0%) | 0 (-) | 0 (0.0%) | 0 (-) |

## Cuts by cause

| cause | files (vulnerable / fixed) |
|---|---|
| ambiguous-call | 196 / 192 |
| summary | 125 / 126 |
| summary-inner | 125 / 126 |
| summary-work | 1 / 1 |
| tokens | 2 / 1 |

## Cases

| case | package | releases | class | group | rule | vulnerable | fixed | in fix files | findings | unfinished files | scan time | calls cut | cuts by cause | at sink line (vulnerable / fixed) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| CVE-2022-23340 | github laurent22/joplin | v2.6.2 → v2.7.1 | code-eval | independent | js-code-eval-eval | - | - | 0 | 0 / 0 | 2 / 3 | 5.4s / 5.2s | 15 / 9 | ambiguous-call:15 summary:5 summary-inner:5 tokens:1 / ambiguous-call:9 summary:1 summary-inner:1 | - |
| CVE-2022-23340 | github laurent22/joplin | v2.6.2 → v2.7.1 | code-eval | independent | js-code-eval-template-options | - | - | 0 | 0 / 0 | 2 / 3 | 5.4s / 5.2s | 15 / 9 | ambiguous-call:15 summary:5 summary-inner:5 tokens:1 / ambiguous-call:9 summary:1 summary-inner:1 | - |
| CVE-2022-35204 | github vitejs/vite | v2.9.12 → v2.9.13 | path-traversal | independent | js-path-traversal-archive-extract | - | - | 0 | 2 / 2 | 0 / 0 | 4.4s / 5.0s | 3 / 3 | ambiguous-call:3 / ambiguous-call:3 | - |
| CVE-2022-35204 | github vitejs/vite | v2.9.12 → v2.9.13 | path-traversal | independent | js-path-traversal-exists-probe | - | - | 0 | 2 / 2 | 0 / 0 | 4.4s / 5.0s | 3 / 3 | ambiguous-call:3 / ambiguous-call:3 | - |
| CVE-2022-35204 | github vitejs/vite | v2.9.12 → v2.9.13 | path-traversal | independent | js-path-traversal-fs-ops | - | - | 0 | 2 / 2 | 0 / 0 | 4.4s / 5.0s | 3 / 3 | ambiguous-call:3 / ambiguous-call:3 | - |
| CVE-2022-35204 | github vitejs/vite | v2.9.12 → v2.9.13 | path-traversal | independent | js-path-traversal-send-file | - | - | 0 | 2 / 2 | 0 / 0 | 4.4s / 5.0s | 3 / 3 | ambiguous-call:3 / ambiguous-call:3 | - |
| CVE-2023-27562 | github n8n-io/n8n | n8n@0.216.0 → n8n@0.216.1 | path-traversal | independent | js-path-traversal-archive-extract | - | - | 3 | 10 / 10 | 0 / 0 | 6.5s / 6.7s | 8 / 8 | ambiguous-call:8 summary:1 summary-inner:1 / ambiguous-call:8 summary:1 summary-inner:1 | - |
| CVE-2023-27562 | github n8n-io/n8n | n8n@0.216.0 → n8n@0.216.1 | path-traversal | independent | js-path-traversal-exists-probe | - | - | 3 | 10 / 10 | 0 / 0 | 6.5s / 6.7s | 8 / 8 | ambiguous-call:8 summary:1 summary-inner:1 / ambiguous-call:8 summary:1 summary-inner:1 | - |
| CVE-2023-27562 | github n8n-io/n8n | n8n@0.216.0 → n8n@0.216.1 | path-traversal | independent | js-path-traversal-fs-ops | - | - | 3 | 10 / 10 | 0 / 0 | 6.5s / 6.7s | 8 / 8 | ambiguous-call:8 summary:1 summary-inner:1 / ambiguous-call:8 summary:1 summary-inner:1 | - |
| CVE-2023-27562 | github n8n-io/n8n | n8n@0.216.0 → n8n@0.216.1 | path-traversal | independent | js-path-traversal-send-file | caught | still reports | 3 | 10 / 10 | 0 / 0 | 6.5s / 6.7s | 8 / 8 | ambiguous-call:8 summary:1 summary-inner:1 / ambiguous-call:8 summary:1 summary-inner:1 | - |
| CVE-2023-3224 | github nuxt/nuxt | v3.4.2 → v3.4.3 | code-eval | independent | js-code-eval-eval | - | - | 0 | 0 / 0 | 0 / 0 | 0.5s / 0.5s | 0 / 0 | - / - | - |
| CVE-2023-3224 | github nuxt/nuxt | v3.4.2 → v3.4.3 | code-eval | independent | js-code-eval-template-options | - | - | 0 | 0 / 0 | 0 / 0 | 0.5s / 0.5s | 0 / 0 | - / - | - |
| CVE-2023-39584 | github hexojs/hexo | v7.1.1 → v7.2.0 | path-traversal | independent | js-path-traversal-archive-extract | - | - | 0 | 0 / 0 | 0 / 0 | 0.3s / 0.3s | 3 / 0 | ambiguous-call:3 / - | - |
| CVE-2023-39584 | github hexojs/hexo | v7.1.1 → v7.2.0 | path-traversal | independent | js-path-traversal-exists-probe | - | - | 0 | 0 / 0 | 0 / 0 | 0.3s / 0.3s | 3 / 0 | ambiguous-call:3 / - | - |
| CVE-2023-39584 | github hexojs/hexo | v7.1.1 → v7.2.0 | path-traversal | independent | js-path-traversal-fs-ops | - | - | 0 | 0 / 0 | 0 / 0 | 0.3s / 0.3s | 3 / 0 | ambiguous-call:3 / - | - |
| CVE-2023-39584 | github hexojs/hexo | v7.1.1 → v7.2.0 | path-traversal | independent | js-path-traversal-send-file | - | - | 0 | 0 / 0 | 0 / 0 | 0.3s / 0.3s | 3 / 0 | ambiguous-call:3 / - | - |
| CVE-2023-50710 | github honojs/hono | v3.11.6 → v3.11.7 | code-eval | independent | js-code-eval-eval | - | - | 0 | 1 / 1 | 0 / 0 | 1.4s / 1.5s | 1 / 1 | ambiguous-call:1 / ambiguous-call:1 | - |
| CVE-2023-50710 | github honojs/hono | v3.11.6 → v3.11.7 | code-eval | independent | js-code-eval-template-options | - | - | 0 | 1 / 1 | 0 / 0 | 1.4s / 1.5s | 1 / 1 | ambiguous-call:1 / ambiguous-call:1 | - |
| CVE-2024-31621 | github FlowiseAI/Flowise | flowise@1.8.0 → flowise@1.8.1 | code-eval | independent | js-code-eval-eval | - | - | 0 | 7 / 7 | 0 / 0 | 2.5s / 2.5s | 0 / 0 | - / - | - |
| CVE-2024-31621 | github FlowiseAI/Flowise | flowise@1.8.0 → flowise@1.8.1 | code-eval | independent | js-code-eval-template-options | - | - | 0 | 7 / 7 | 0 / 0 | 2.5s / 2.5s | 0 / 0 | - / - | - |
| CVE-2025-64765 | github withastro/astro | astro@5.15.7 → astro@5.15.8 | path-traversal | independent | js-path-traversal-archive-extract | - | - | 0 | 4 / 4 | 0 / 0 | 6.0s / 5.5s | 68 / 68 | ambiguous-call:68 summary:56 summary-inner:56 / ambiguous-call:68 summary:56 summary-inner:56 | - |
| CVE-2025-64765 | github withastro/astro | astro@5.15.7 → astro@5.15.8 | path-traversal | independent | js-path-traversal-exists-probe | - | - | 0 | 4 / 4 | 0 / 0 | 6.0s / 5.5s | 68 / 68 | ambiguous-call:68 summary:56 summary-inner:56 / ambiguous-call:68 summary:56 summary-inner:56 | - |
| CVE-2025-64765 | github withastro/astro | astro@5.15.7 → astro@5.15.8 | path-traversal | independent | js-path-traversal-fs-ops | - | - | 0 | 4 / 4 | 0 / 0 | 6.0s / 5.5s | 68 / 68 | ambiguous-call:68 summary:56 summary-inner:56 / ambiguous-call:68 summary:56 summary-inner:56 | - |
| CVE-2025-64765 | github withastro/astro | astro@5.15.7 → astro@5.15.8 | path-traversal | independent | js-path-traversal-send-file | - | - | 0 | 4 / 4 | 0 / 0 | 6.0s / 5.5s | 68 / 68 | ambiguous-call:68 summary:56 summary-inner:56 / ambiguous-call:68 summary:56 summary-inner:56 | - |
| CVE-2026-104853 | github nrwl/nx | 22.7.9 → 22.7.10 | path-traversal | independent | js-path-traversal-archive-extract | - | - | 0 | 5 / 5 | 1 / 1 | 11.6s / 11.4s | 1 / 1 | ambiguous-call:1 / ambiguous-call:1 | - |
| CVE-2026-104853 | github nrwl/nx | 22.7.9 → 22.7.10 | path-traversal | independent | js-path-traversal-exists-probe | - | - | 0 | 5 / 5 | 1 / 1 | 11.6s / 11.4s | 1 / 1 | ambiguous-call:1 / ambiguous-call:1 | - |
| CVE-2026-104853 | github nrwl/nx | 22.7.9 → 22.7.10 | path-traversal | independent | js-path-traversal-fs-ops | - | - | 0 | 5 / 5 | 1 / 1 | 11.6s / 11.4s | 1 / 1 | ambiguous-call:1 / ambiguous-call:1 | - |
| CVE-2026-104853 | github nrwl/nx | 22.7.9 → 22.7.10 | path-traversal | independent | js-path-traversal-send-file | - | - | 0 | 5 / 5 | 1 / 1 | 11.6s / 11.4s | 1 / 1 | ambiguous-call:1 / ambiguous-call:1 | - |
| CVE-2026-104871 | github angular/angular-cli | v22.1.6 → v22.1.7 | path-traversal | independent | js-path-traversal-archive-extract | - | - | 0 | 2 / 2 | 0 / 0 | 3.6s / 3.7s | 3 / 3 | ambiguous-call:3 summary:1 summary-inner:1 / ambiguous-call:3 summary:1 summary-inner:1 | - |
| CVE-2026-104871 | github angular/angular-cli | v22.1.6 → v22.1.7 | path-traversal | independent | js-path-traversal-exists-probe | - | - | 0 | 2 / 2 | 0 / 0 | 3.6s / 3.7s | 3 / 3 | ambiguous-call:3 summary:1 summary-inner:1 / ambiguous-call:3 summary:1 summary-inner:1 | - |
| CVE-2026-104871 | github angular/angular-cli | v22.1.6 → v22.1.7 | path-traversal | independent | js-path-traversal-fs-ops | - | - | 0 | 2 / 2 | 0 / 0 | 3.6s / 3.7s | 3 / 3 | ambiguous-call:3 summary:1 summary-inner:1 / ambiguous-call:3 summary:1 summary-inner:1 | - |
| CVE-2026-104871 | github angular/angular-cli | v22.1.6 → v22.1.7 | path-traversal | independent | js-path-traversal-send-file | - | - | 0 | 2 / 2 | 0 / 0 | 3.6s / 3.7s | 3 / 3 | ambiguous-call:3 summary:1 summary-inner:1 / ambiguous-call:3 summary:1 summary-inner:1 | - |
| CVE-2026-24763 | github openclaw/openclaw | v2026.1.24 → v2026.1.29 | cmdi | independent | js-cmdi-exec | - | - | 0 | 17 / 12 | 0 / 0 | 32.2s / 32.7s | 1 / 1 | ambiguous-call:1 summary:1 summary-inner:1 / ambiguous-call:1 summary:1 summary-inner:1 | - |
| CVE-2026-24763 | github openclaw/openclaw | v2026.1.24 → v2026.1.29 | cmdi | independent | js-cmdi-promisified-exec | - | - | 0 | 17 / 12 | 0 / 0 | 32.2s / 32.7s | 1 / 1 | ambiguous-call:1 summary:1 summary-inner:1 / ambiguous-call:1 summary:1 summary-inner:1 | - |
| CVE-2026-24763 | github openclaw/openclaw | v2026.1.24 → v2026.1.29 | cmdi | independent | js-cmdi-spawn-sh-c | - | - | 0 | 17 / 12 | 0 / 0 | 32.2s / 32.7s | 1 / 1 | ambiguous-call:1 summary:1 summary-inner:1 / ambiguous-call:1 summary:1 summary-inner:1 | - |
| CVE-2026-24763 | github openclaw/openclaw | v2026.1.24 → v2026.1.29 | cmdi | independent | js-cmdi-spawn-shell | - | - | 0 | 17 / 12 | 0 / 0 | 32.2s / 32.7s | 1 / 1 | ambiguous-call:1 summary:1 summary-inner:1 / ambiguous-call:1 summary:1 summary-inner:1 | - |
| CVE-2026-27702 | github Budibase/budibase | 3.30.3 → 3.30.4 | code-eval | independent | js-code-eval-eval | - | - | 0 | 12 / 12 | 0 / 0 | 8.8s / 8.9s | 21 / 21 | ambiguous-call:21 summary:6 summary-inner:6 / ambiguous-call:21 summary:6 summary-inner:6 | - |
| CVE-2026-27702 | github Budibase/budibase | 3.30.3 → 3.30.4 | code-eval | independent | js-code-eval-template-options | - | - | 0 | 12 / 12 | 0 / 0 | 8.8s / 8.9s | 21 / 21 | ambiguous-call:21 summary:6 summary-inner:6 / ambiguous-call:21 summary:6 summary-inner:6 | - |
| CVE-2026-28399 | github nocodb/nocodb | 0.301.2 → 0.301.3 | sqli | independent | js-sqli-node-http-query | - | - | 0 | 8 / 8 | 4 / 4 | 13.2s / 14.0s | 25 / 28 | ambiguous-call:25 summary:16 summary-inner:16 tokens:1 / ambiguous-call:28 summary:20 summary-inner:20 tokens:1 | - |
| CVE-2026-28399 | github nocodb/nocodb | 0.301.2 → 0.301.3 | sqli | independent | js-sqli-object-input | - | - | 0 | 8 / 8 | 4 / 4 | 13.2s / 14.0s | 25 / 28 | ambiguous-call:25 summary:16 summary-inner:16 tokens:1 / ambiguous-call:28 summary:20 summary-inner:20 tokens:1 | - |
| CVE-2026-28399 | github nocodb/nocodb | 0.301.2 → 0.301.3 | sqli | independent | js-sqli-raw-interpolation | - | - | 0 | 8 / 8 | 4 / 4 | 13.2s / 14.0s | 25 / 28 | ambiguous-call:25 summary:16 summary-inner:16 tokens:1 / ambiguous-call:28 summary:20 summary-inner:20 tokens:1 | - |
| CVE-2026-28399 | github nocodb/nocodb | 0.301.2 → 0.301.3 | sqli | independent | js-sqli-sequelize-literal | - | - | 0 | 8 / 8 | 4 / 4 | 13.2s / 14.0s | 25 / 28 | ambiguous-call:25 summary:16 summary-inner:16 tokens:1 / ambiguous-call:28 summary:20 summary-inner:20 tokens:1 | - |
| CVE-2026-3089 | github actualbudget/actual | v26.2.1 → v26.3.0 | path-traversal | independent | js-path-traversal-archive-extract | - | - | 2 | 8 / 8 | 7 / 7 | 2.9s / 2.9s | 1 / 2 | ambiguous-call:1 / ambiguous-call:2 summary:1 summary-inner:1 | - |
| CVE-2026-3089 | github actualbudget/actual | v26.2.1 → v26.3.0 | path-traversal | independent | js-path-traversal-exists-probe | - | - | 2 | 8 / 8 | 7 / 7 | 2.9s / 2.9s | 1 / 2 | ambiguous-call:1 / ambiguous-call:2 summary:1 summary-inner:1 | - |
| CVE-2026-3089 | github actualbudget/actual | v26.2.1 → v26.3.0 | path-traversal | independent | js-path-traversal-fs-ops | - | - | 2 | 8 / 8 | 7 / 7 | 2.9s / 2.9s | 1 / 2 | ambiguous-call:1 / ambiguous-call:2 summary:1 summary-inner:1 | - |
| CVE-2026-3089 | github actualbudget/actual | v26.2.1 → v26.3.0 | path-traversal | independent | js-path-traversal-send-file | - | - | 2 | 8 / 8 | 7 / 7 | 2.9s / 2.9s | 1 / 2 | ambiguous-call:1 / ambiguous-call:2 summary:1 summary-inner:1 | - |
| CVE-2026-35570 | github Gitlawb/openclaude | v0.5.0 → v0.5.1 | path-traversal | independent | js-path-traversal-archive-extract | - | - | 0 | 0 / 0 | 0 / 0 | 26.2s / 21.3s | 39 / 39 | ambiguous-call:39 summary:36 summary-inner:36 summary-work:1 / ambiguous-call:39 summary:36 summary-inner:36 summary-work:1 | - |
| CVE-2026-35570 | github Gitlawb/openclaude | v0.5.0 → v0.5.1 | path-traversal | independent | js-path-traversal-exists-probe | - | - | 0 | 0 / 0 | 0 / 0 | 26.2s / 21.3s | 39 / 39 | ambiguous-call:39 summary:36 summary-inner:36 summary-work:1 / ambiguous-call:39 summary:36 summary-inner:36 summary-work:1 | - |
| CVE-2026-35570 | github Gitlawb/openclaude | v0.5.0 → v0.5.1 | path-traversal | independent | js-path-traversal-fs-ops | - | - | 0 | 0 / 0 | 0 / 0 | 26.2s / 21.3s | 39 / 39 | ambiguous-call:39 summary:36 summary-inner:36 summary-work:1 / ambiguous-call:39 summary:36 summary-inner:36 summary-work:1 | - |
| CVE-2026-35570 | github Gitlawb/openclaude | v0.5.0 → v0.5.1 | path-traversal | independent | js-path-traversal-send-file | - | - | 0 | 0 / 0 | 0 / 0 | 26.2s / 21.3s | 39 / 39 | ambiguous-call:39 summary:36 summary-inner:36 summary-work:1 / ambiguous-call:39 summary:36 summary-inner:36 summary-work:1 | - |
| CVE-2026-41159 | github mermaid-js/mermaid | mermaid@11.14.0 → mermaid@11.15.0 | code-eval | independent | js-code-eval-eval | - | - | 0 | 4 / 4 | 0 / 0 | 1.0s / 1.0s | 4 / 5 | ambiguous-call:4 / ambiguous-call:5 | - |
| CVE-2026-41159 | github mermaid-js/mermaid | mermaid@11.14.0 → mermaid@11.15.0 | code-eval | independent | js-code-eval-template-options | - | - | 0 | 4 / 4 | 0 / 0 | 1.0s / 1.0s | 4 / 5 | ambiguous-call:4 / ambiguous-call:5 | - |
| CVE-2026-53766 | github ChromeDevTools/chrome-devtools-mcp | chrome-devtools-mcp-v1.0.1 → chrome-devtools-mcp-v1.1.0 | path-traversal | independent | js-path-traversal-archive-extract | - | - | 0 | 0 / 0 | 1 / 1 | 0.7s / 0.8s | 3 / 3 | ambiguous-call:3 summary:3 summary-inner:3 / ambiguous-call:3 summary:3 summary-inner:3 | - |
| CVE-2026-53766 | github ChromeDevTools/chrome-devtools-mcp | chrome-devtools-mcp-v1.0.1 → chrome-devtools-mcp-v1.1.0 | path-traversal | independent | js-path-traversal-exists-probe | - | - | 0 | 0 / 0 | 1 / 1 | 0.7s / 0.8s | 3 / 3 | ambiguous-call:3 summary:3 summary-inner:3 / ambiguous-call:3 summary:3 summary-inner:3 | - |
| CVE-2026-53766 | github ChromeDevTools/chrome-devtools-mcp | chrome-devtools-mcp-v1.0.1 → chrome-devtools-mcp-v1.1.0 | path-traversal | independent | js-path-traversal-fs-ops | - | - | 0 | 0 / 0 | 1 / 1 | 0.7s / 0.8s | 3 / 3 | ambiguous-call:3 summary:3 summary-inner:3 / ambiguous-call:3 summary:3 summary-inner:3 | - |
| CVE-2026-53766 | github ChromeDevTools/chrome-devtools-mcp | chrome-devtools-mcp-v1.0.1 → chrome-devtools-mcp-v1.1.0 | path-traversal | independent | js-path-traversal-send-file | - | - | 0 | 0 / 0 | 1 / 1 | 0.7s / 0.8s | 3 / 3 | ambiguous-call:3 summary:3 summary-inner:3 / ambiguous-call:3 summary:3 summary-inner:3 | - |
| CVE-2026-73651 | github typeorm/typeorm | 0.3.30 → 0.3.31 | code-eval | independent | js-code-eval-eval | - | - | 0 | 0 / 0 | 0 / 0 | 3.9s / 3.8s | 0 / 0 | - / - | - |
| CVE-2026-73651 | github typeorm/typeorm | 0.3.30 → 0.3.31 | code-eval | independent | js-code-eval-template-options | - | - | 0 | 0 / 0 | 0 / 0 | 3.9s / 3.8s | 0 / 0 | - / - | - |
