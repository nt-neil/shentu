# Changelog

Each release has one section: `## vX.Y.Z — YYYY-MM-DD` (or `## vX.Y.Z (unreleased)`).
The website (`go generate ./cmd/sitegen`) reads this file. The rules added or removed in
a release are not written here: they are worked out from the rule snapshots in
`docs/site-src/rules-history/`.

## v0.2.5 (unreleased)

- `app_code_audit` follows calls across files: input read in one file and used in a sink
  of another is reported at the sink, with the file it came from.
- Framework route models: the parameters of WordPress hooks, shortcodes and REST routes,
  Laravel routes, Django URLs, Flask and FastAPI views and Express handlers are input,
  also when the route is registered in another file.
- New rule classes: LDAP injection, NoSQL operator injection, dangerous file uploads,
  weak cryptography and hard-coded credentials; TypeScript files are checked with the
  JavaScript rules.
- Audits keep their results between runs, so a large application is covered over a few
  patrols instead of one.
- The audit sizes itself to the server: heap at most min(1 GiB, 25% of available memory,
  50% of the service's cgroup), workers from the CPU count and the load.
- Fewer false positives: `wp_send_json` output, `JSON_HEX_TAG` data blocks, MongoDB queries
  on objects that are not collections, and Django `_meta.get_field` checks.
- Known issue: an audit spread over several runs can still report a few findings that
  differ from one run without a time limit; a fix is in progress.

## v0.2.4 — 2026-11-09

- Rules move to their own format, checked in CI, starting with 33 rules.
- `accounts_audit` reports shared SSH keys, `ld.so.preload` and PAM modules that belong
  to no package.
- `processes` flags cryptominers.
- Patrol reports one line per webshell.

## v0.2.3 — 2026-11-09

- `app_code_audit`: an offline audit of the applications' own files.

## v0.2.2 — 2026-11-08

- `package_vulns` reports each actively exploited CVE once.

## v0.2.1 — 2026-11-08

- `shentu bot`: talk to Shentu from Telegram, with guarded pairing and four ranges of levels.
- Usage tracking and an optional monthly AI budget.
- Round 2 of the model comparison: 14 models, 11 scenarios.

## v0.2.0 — 2026-11-07

- One command from install to running: a guided setup.
- Site survey and an application dependency scan.

## v0.1.1 — 2026-11-07

- `package_vulns` marks actively exploited vulnerabilities (CISA KEV).
- Slack and Discord webhooks.
- Security invariant tests, a prompt-injection suite and govulncheck before each release.

## v0.1.0 — 2026-11-07

- First release: `shentu chat` and `shentu patrol` for Linux servers, with `shentu setup`
  for a local model or an API key.
