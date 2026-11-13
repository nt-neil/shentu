# Changelog

Each release has one section: `## vX.Y.Z — YYYY-MM-DD` (or `## vX.Y.Z (unreleased)`).
The website (`go generate ./cmd/sitegen`) reads this file. The rules added or removed in
a release are not written here: they are worked out from the rule snapshots in
`docs/site-src/rules-history/`. `CHANGELOG.zh-TW.md` holds the same releases in Traditional
Chinese for the zh-TW pages; keep the two in step.

## v0.3.0 (unreleased)

- Windows Server 2022 and 2025, verified on GitHub-hosted windows-2022/2025 runners (amd64;
  arm64 built too): a Windows collector reads the host
  through the Windows APIs only (registry, services, processes, sockets, accounts, scheduled
  tasks, the event log, WMI and the firewall), no PowerShell and no external commands.
- Windows checks: autostart entries (Run keys, services, scheduled tasks, startup folders, WMI
  event subscriptions), RDP without NLA, SMB signing and SMBv1, insecure WinRM, firewall
  profiles, Defender state and exclusions, logon failures and cleared logs.
- Missing Windows updates against Microsoft's monthly security releases (MSRC), with the
  CISA KEV list marking the exploited ones first.
- IIS: web roots from `applicationHost.config`; the code audit reads ASP and ASP.NET pages and
  flags webshells and scripts in upload folders, UTF-16 pages included.
- Two Windows services, `Shentu` (patrol) and `ShentuBot` (Telegram), installed with
  `shentu service install [--bot]` from `%ProgramFiles%\Shentu`; configuration and state in
  `%ProgramData%\Shentu`, open to SYSTEM and Administrators only.
- The `ssh_logins`, `processes`, `accounts_audit` and `log_search` tools work on Windows
  (logon events, process list, local accounts, event logs).
- Failed SSH logins are read from journald first: its ssh and sshd units are labelled by
  journald itself, so a local user cannot forge them. The text logs (`auth.log`, `secure`)
  are read when journald is missing, times out (60 s), or has no sshd entries; anyone on the
  host can write an sshd line to them with `logger`, so `auth_events` is then partial with
  the new reason `unverified_source`, and brute-force findings and patrol SSH alerts carry a
  note saying so.
  A journal that hides the system's entries from a non-root user is no longer reported as
  "no failed logins".
- A code audit root written with a trailing slash (`/var/www/html/`) or as `/` is no longer
  skipped when an audit resumes inside it. Roots are now cleaned, so the first audit after
  the upgrade does not find the place the last one stopped and walks from the start once.

### Known issues

- Windows is read-only: `block_ip` and `unblock_ip` are not supported there.
- Windows Server 2019 is best effort: expected to work (the same Windows APIs, build 17763)
  but not verified on GitHub-hosted runners (they offer no 2019 image).
- `shentu setup` does not run on Windows yet; the configuration is written by hand.
- The Windows binary is not code-signed and there is no MSI; SmartScreen or an antivirus may
  warn about it.

## v0.2.5 — 2026-11-13

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

### Known issues

- An audit spread over several runs can still report a few findings that differ from one
  run without a time limit; a fix is in progress.
- `php-deserialization-phar-wrapper` reports `filesize()` on an upload's temporary path in
  WordPress's REST attachments controller, a false positive: the path is PHP's own, but the
  engine cannot yet tell an upload's `tmp_name` from its client-set `name`.
- js-nosqli-mongo-query reports TypeORM repository calls on SQL databases (find/findOne whose
  options hold a where built from request values, e.g. n8n's public API and credential
  lookups) as MongoDB queries; TypeORM sends those values as SQL parameters, so these are
  false positives, to be told apart by a TypeORM-aware receiver check in v0.2.6.
- `js-cmdi-spawn-shell` still reports `spawn()` and `execFile()` calls whose command and
  arguments are fixed when only the options (such as `cwd` or `env`) carry request values.
- js-xss-response has no Server-Sent Events exception: res.write("data: " + value) in a
  text/event-stream handler is reported as XSS (a false positive), and nothing is missed
  because of SSE; telling streams apart by the handler's Content-Type is planned for v0.2.6.
- `->get_settings()` counts as Elementor widget input in every class, so `WP_Widget::get_settings()`
  and WooCommerce `WC_Settings_Page::get_settings()` values (saved by administrators) are reported
  too. Limiting the source to classes extending `\Elementor\Widget_Base` needs class-scoped sources
  in the engine (planned for v0.2.6). Values read through ->get_settings() can also be followed
  into WordPress admin field definitions and into a few SQL sinks that are already guarded (an
  isset() check, or a value bound through $wpdb->prepare() inside ORDER BY FIELD()), which gives
  extra false positives there. Narrowing the source to Elementor widgets is planned for v0.2.6.
- In `$wpdb->prepare()`/`->prepare()` formats, a placeholder list built by a callback that returns
  a constant (`implode(',', array_map(fn($v) => '%d', $ids))`, or the same with
  `function ($v) { return '%d'; }`) is still treated as input and reported when `$ids` comes from
  the request. `array_fill(0, count($ids), '%d')` and `sizeof()` are recognised. Reading a callback's
  return value needs an engine change (planned for v0.2.6).
- `python-path-traversal-send-file` reports `zipfile.ZipFile(request.files[...])`, which opens the
  uploaded stream rather than a path, a false positive. Telling a request's file stream from a
  client-set file name inside one argument needs an engine change (planned for v0.2.6).

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
