# CVE bench

2026-11-16, 127 rules, 18 cases.

- caught: a rule of the case's class reports within 10 lines of a line the fix changed, in the vulnerable release.
- fixed FP: a rule that caught the case still reports at the fix in the fixed release; the rate is over caught cases.
- rule source: a rule cites the id in its refs, so the rule was written from it; independent: no rule cites it.
- in fix files: reports of the case's class anywhere in the fix files of the vulnerable release, near the fix or not.
- findings and time: every report of every rule on the whole release, and the time to scan it.

## Summary

| group | cases | caught | catch rate | fixed FP | fixed FP rate | findings per release (vulnerable / fixed) | scan time per release |
|---|---|---|---|---|---|---|---|
| all | 18 | 1 | 5.6% | 1 | 100.0% | 4.4 / 4.1 | 5.5s |
| independent | 18 | 1 | 5.6% | 1 | 100.0% | 4.4 / 4.1 | 5.5s |
| github | 18 | 1 | 5.6% | 1 | 100.0% | 4.4 / 4.1 | 5.5s |
| cmdi | 1 | 0 | 0.0% | 0 | - | 17.0 / 12.0 | 22.4s |
| code-eval | 7 | 0 | 0.0% | 0 | - | 3.4 / 3.4 | 2.5s |
| path-traversal | 9 | 1 | 11.1% | 1 | 100.0% | 3.3 / 3.3 | 5.4s |
| sqli | 1 | 0 | 0.0% | 0 | - | 8.0 / 8.0 | 10.7s |

## Cases

| case | package | releases | class | group | rule | vulnerable | fixed | in fix files | findings | unfinished files | scan time |
|---|---|---|---|---|---|---|---|---|---|---|---|
| CVE-2022-23340 | github laurent22/joplin | v2.6.2 → v2.7.1 | code-eval | independent | js-code-eval-eval | - | - | 0 | 0 / 0 | 2 / 3 | 4.4s / 3.7s |
| CVE-2022-23340 | github laurent22/joplin | v2.6.2 → v2.7.1 | code-eval | independent | js-code-eval-template-options | - | - | 0 | 0 / 0 | 2 / 3 | 4.4s / 3.7s |
| CVE-2022-35204 | github vitejs/vite | v2.9.12 → v2.9.13 | path-traversal | independent | js-path-traversal-archive-extract | - | - | 0 | 2 / 2 | 0 / 0 | 3.6s / 3.8s |
| CVE-2022-35204 | github vitejs/vite | v2.9.12 → v2.9.13 | path-traversal | independent | js-path-traversal-exists-probe | - | - | 0 | 2 / 2 | 0 / 0 | 3.6s / 3.8s |
| CVE-2022-35204 | github vitejs/vite | v2.9.12 → v2.9.13 | path-traversal | independent | js-path-traversal-fs-ops | - | - | 0 | 2 / 2 | 0 / 0 | 3.6s / 3.8s |
| CVE-2022-35204 | github vitejs/vite | v2.9.12 → v2.9.13 | path-traversal | independent | js-path-traversal-send-file | - | - | 0 | 2 / 2 | 0 / 0 | 3.6s / 3.8s |
| CVE-2023-27562 | github n8n-io/n8n | n8n@0.216.0 → n8n@0.216.1 | path-traversal | independent | js-path-traversal-archive-extract | - | - | 3 | 10 / 10 | 0 / 0 | 4.1s / 6.5s |
| CVE-2023-27562 | github n8n-io/n8n | n8n@0.216.0 → n8n@0.216.1 | path-traversal | independent | js-path-traversal-exists-probe | - | - | 3 | 10 / 10 | 0 / 0 | 4.1s / 6.5s |
| CVE-2023-27562 | github n8n-io/n8n | n8n@0.216.0 → n8n@0.216.1 | path-traversal | independent | js-path-traversal-fs-ops | - | - | 3 | 10 / 10 | 0 / 0 | 4.1s / 6.5s |
| CVE-2023-27562 | github n8n-io/n8n | n8n@0.216.0 → n8n@0.216.1 | path-traversal | independent | js-path-traversal-send-file | caught | still reports | 3 | 10 / 10 | 0 / 0 | 4.1s / 6.5s |
| CVE-2023-3224 | github nuxt/nuxt | v3.4.2 → v3.4.3 | code-eval | independent | js-code-eval-eval | - | - | 0 | 0 / 0 | 0 / 0 | 0.4s / 0.3s |
| CVE-2023-3224 | github nuxt/nuxt | v3.4.2 → v3.4.3 | code-eval | independent | js-code-eval-template-options | - | - | 0 | 0 / 0 | 0 / 0 | 0.4s / 0.3s |
| CVE-2023-39584 | github hexojs/hexo | v7.1.1 → v7.2.0 | path-traversal | independent | js-path-traversal-archive-extract | - | - | 0 | 0 / 0 | 0 / 0 | 0.2s / 0.2s |
| CVE-2023-39584 | github hexojs/hexo | v7.1.1 → v7.2.0 | path-traversal | independent | js-path-traversal-exists-probe | - | - | 0 | 0 / 0 | 0 / 0 | 0.2s / 0.2s |
| CVE-2023-39584 | github hexojs/hexo | v7.1.1 → v7.2.0 | path-traversal | independent | js-path-traversal-fs-ops | - | - | 0 | 0 / 0 | 0 / 0 | 0.2s / 0.2s |
| CVE-2023-39584 | github hexojs/hexo | v7.1.1 → v7.2.0 | path-traversal | independent | js-path-traversal-send-file | - | - | 0 | 0 / 0 | 0 / 0 | 0.2s / 0.2s |
| CVE-2023-50710 | github honojs/hono | v3.11.6 → v3.11.7 | code-eval | independent | js-code-eval-eval | - | - | 0 | 1 / 1 | 0 / 0 | 1.3s / 1.6s |
| CVE-2023-50710 | github honojs/hono | v3.11.6 → v3.11.7 | code-eval | independent | js-code-eval-template-options | - | - | 0 | 1 / 1 | 0 / 0 | 1.3s / 1.6s |
| CVE-2024-31621 | github FlowiseAI/Flowise | flowise@1.8.0 → flowise@1.8.1 | code-eval | independent | js-code-eval-eval | - | - | 0 | 7 / 7 | 0 / 0 | 2.9s / 2.0s |
| CVE-2024-31621 | github FlowiseAI/Flowise | flowise@1.8.0 → flowise@1.8.1 | code-eval | independent | js-code-eval-template-options | - | - | 0 | 7 / 7 | 0 / 0 | 2.9s / 2.0s |
| CVE-2025-64765 | github withastro/astro | astro@5.15.7 → astro@5.15.8 | path-traversal | independent | js-path-traversal-archive-extract | - | - | 0 | 4 / 4 | 0 / 0 | 3.9s / 3.7s |
| CVE-2025-64765 | github withastro/astro | astro@5.15.7 → astro@5.15.8 | path-traversal | independent | js-path-traversal-exists-probe | - | - | 0 | 4 / 4 | 0 / 0 | 3.9s / 3.7s |
| CVE-2025-64765 | github withastro/astro | astro@5.15.7 → astro@5.15.8 | path-traversal | independent | js-path-traversal-fs-ops | - | - | 0 | 4 / 4 | 0 / 0 | 3.9s / 3.7s |
| CVE-2025-64765 | github withastro/astro | astro@5.15.7 → astro@5.15.8 | path-traversal | independent | js-path-traversal-send-file | - | - | 0 | 4 / 4 | 0 / 0 | 3.9s / 3.7s |
| CVE-2026-104853 | github nrwl/nx | 22.7.9 → 22.7.10 | path-traversal | independent | js-path-traversal-archive-extract | - | - | 0 | 5 / 5 | 1 / 1 | 9.4s / 8.5s |
| CVE-2026-104853 | github nrwl/nx | 22.7.9 → 22.7.10 | path-traversal | independent | js-path-traversal-exists-probe | - | - | 0 | 5 / 5 | 1 / 1 | 9.4s / 8.5s |
| CVE-2026-104853 | github nrwl/nx | 22.7.9 → 22.7.10 | path-traversal | independent | js-path-traversal-fs-ops | - | - | 0 | 5 / 5 | 1 / 1 | 9.4s / 8.5s |
| CVE-2026-104853 | github nrwl/nx | 22.7.9 → 22.7.10 | path-traversal | independent | js-path-traversal-send-file | - | - | 0 | 5 / 5 | 1 / 1 | 9.4s / 8.5s |
| CVE-2026-104871 | github angular/angular-cli | v22.1.6 → v22.1.7 | path-traversal | independent | js-path-traversal-archive-extract | - | - | 0 | 2 / 2 | 0 / 0 | 2.0s / 2.3s |
| CVE-2026-104871 | github angular/angular-cli | v22.1.6 → v22.1.7 | path-traversal | independent | js-path-traversal-exists-probe | - | - | 0 | 2 / 2 | 0 / 0 | 2.0s / 2.3s |
| CVE-2026-104871 | github angular/angular-cli | v22.1.6 → v22.1.7 | path-traversal | independent | js-path-traversal-fs-ops | - | - | 0 | 2 / 2 | 0 / 0 | 2.0s / 2.3s |
| CVE-2026-104871 | github angular/angular-cli | v22.1.6 → v22.1.7 | path-traversal | independent | js-path-traversal-send-file | - | - | 0 | 2 / 2 | 0 / 0 | 2.0s / 2.3s |
| CVE-2026-24763 | github openclaw/openclaw | v2026.1.24 → v2026.1.29 | cmdi | independent | js-cmdi-exec | - | - | 0 | 17 / 12 | 0 / 0 | 22.6s / 22.2s |
| CVE-2026-24763 | github openclaw/openclaw | v2026.1.24 → v2026.1.29 | cmdi | independent | js-cmdi-promisified-exec | - | - | 0 | 17 / 12 | 0 / 0 | 22.6s / 22.2s |
| CVE-2026-24763 | github openclaw/openclaw | v2026.1.24 → v2026.1.29 | cmdi | independent | js-cmdi-spawn-sh-c | - | - | 0 | 17 / 12 | 0 / 0 | 22.6s / 22.2s |
| CVE-2026-24763 | github openclaw/openclaw | v2026.1.24 → v2026.1.29 | cmdi | independent | js-cmdi-spawn-shell | - | - | 0 | 17 / 12 | 0 / 0 | 22.6s / 22.2s |
| CVE-2026-27702 | github Budibase/budibase | 3.30.3 → 3.30.4 | code-eval | independent | js-code-eval-eval | - | - | 0 | 12 / 12 | 0 / 0 | 5.3s / 5.6s |
| CVE-2026-27702 | github Budibase/budibase | 3.30.3 → 3.30.4 | code-eval | independent | js-code-eval-template-options | - | - | 0 | 12 / 12 | 0 / 0 | 5.3s / 5.6s |
| CVE-2026-28399 | github nocodb/nocodb | 0.301.2 → 0.301.3 | sqli | independent | js-sqli-node-http-query | - | - | 0 | 8 / 8 | 4 / 4 | 10.3s / 11.0s |
| CVE-2026-28399 | github nocodb/nocodb | 0.301.2 → 0.301.3 | sqli | independent | js-sqli-object-input | - | - | 0 | 8 / 8 | 4 / 4 | 10.3s / 11.0s |
| CVE-2026-28399 | github nocodb/nocodb | 0.301.2 → 0.301.3 | sqli | independent | js-sqli-raw-interpolation | - | - | 0 | 8 / 8 | 4 / 4 | 10.3s / 11.0s |
| CVE-2026-28399 | github nocodb/nocodb | 0.301.2 → 0.301.3 | sqli | independent | js-sqli-sequelize-literal | - | - | 0 | 8 / 8 | 4 / 4 | 10.3s / 11.0s |
| CVE-2026-3089 | github actualbudget/actual | v26.2.1 → v26.3.0 | path-traversal | independent | js-path-traversal-archive-extract | - | - | 3 | 7 / 7 | 7 / 7 | 2.3s / 1.9s |
| CVE-2026-3089 | github actualbudget/actual | v26.2.1 → v26.3.0 | path-traversal | independent | js-path-traversal-exists-probe | - | - | 3 | 7 / 7 | 7 / 7 | 2.3s / 1.9s |
| CVE-2026-3089 | github actualbudget/actual | v26.2.1 → v26.3.0 | path-traversal | independent | js-path-traversal-fs-ops | - | - | 3 | 7 / 7 | 7 / 7 | 2.3s / 1.9s |
| CVE-2026-3089 | github actualbudget/actual | v26.2.1 → v26.3.0 | path-traversal | independent | js-path-traversal-send-file | - | - | 3 | 7 / 7 | 7 / 7 | 2.3s / 1.9s |
| CVE-2026-35570 | github Gitlawb/openclaude | v0.5.0 → v0.5.1 | path-traversal | independent | js-path-traversal-archive-extract | - | - | 0 | 0 / 0 | 0 / 0 | 21.0s / 22.5s |
| CVE-2026-35570 | github Gitlawb/openclaude | v0.5.0 → v0.5.1 | path-traversal | independent | js-path-traversal-exists-probe | - | - | 0 | 0 / 0 | 0 / 0 | 21.0s / 22.5s |
| CVE-2026-35570 | github Gitlawb/openclaude | v0.5.0 → v0.5.1 | path-traversal | independent | js-path-traversal-fs-ops | - | - | 0 | 0 / 0 | 0 / 0 | 21.0s / 22.5s |
| CVE-2026-35570 | github Gitlawb/openclaude | v0.5.0 → v0.5.1 | path-traversal | independent | js-path-traversal-send-file | - | - | 0 | 0 / 0 | 0 / 0 | 21.0s / 22.5s |
| CVE-2026-41159 | github mermaid-js/mermaid | mermaid@11.14.0 → mermaid@11.15.0 | code-eval | independent | js-code-eval-eval | - | - | 0 | 4 / 4 | 0 / 0 | 0.7s / 0.7s |
| CVE-2026-41159 | github mermaid-js/mermaid | mermaid@11.14.0 → mermaid@11.15.0 | code-eval | independent | js-code-eval-template-options | - | - | 0 | 4 / 4 | 0 / 0 | 0.7s / 0.7s |
| CVE-2026-53766 | github ChromeDevTools/chrome-devtools-mcp | chrome-devtools-mcp-v1.0.1 → chrome-devtools-mcp-v1.1.0 | path-traversal | independent | js-path-traversal-archive-extract | - | - | 0 | 0 / 0 | 1 / 1 | 0.5s / 0.6s |
| CVE-2026-53766 | github ChromeDevTools/chrome-devtools-mcp | chrome-devtools-mcp-v1.0.1 → chrome-devtools-mcp-v1.1.0 | path-traversal | independent | js-path-traversal-exists-probe | - | - | 0 | 0 / 0 | 1 / 1 | 0.5s / 0.6s |
| CVE-2026-53766 | github ChromeDevTools/chrome-devtools-mcp | chrome-devtools-mcp-v1.0.1 → chrome-devtools-mcp-v1.1.0 | path-traversal | independent | js-path-traversal-fs-ops | - | - | 0 | 0 / 0 | 1 / 1 | 0.5s / 0.6s |
| CVE-2026-53766 | github ChromeDevTools/chrome-devtools-mcp | chrome-devtools-mcp-v1.0.1 → chrome-devtools-mcp-v1.1.0 | path-traversal | independent | js-path-traversal-send-file | - | - | 0 | 0 / 0 | 1 / 1 | 0.5s / 0.6s |
| CVE-2026-73651 | github typeorm/typeorm | 0.3.30 → 0.3.31 | code-eval | independent | js-code-eval-eval | - | - | 0 | 0 / 0 | 0 / 0 | 3.1s / 2.8s |
| CVE-2026-73651 | github typeorm/typeorm | 0.3.30 → 0.3.31 | code-eval | independent | js-code-eval-template-options | - | - | 0 | 0 / 0 | 0 / 0 | 3.1s / 2.8s |

<!-- measured at ccce0428f822a93b92a5171a9a87678b2008c8f7 -->
