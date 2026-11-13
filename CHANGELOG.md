# Changelog

Each release has one section: `## vX.Y.Z — YYYY-MM-DD` (or `## vX.Y.Z (unreleased)`).
The website (`go generate ./cmd/sitegen`) reads this file. The rules added or removed in
a release are not written here: they are worked out from the rule snapshots in
`docs/site-src/rules-history/`. `CHANGELOG.zh-TW.md` holds the same releases in Traditional
Chinese for the zh-TW pages; keep the two in step.

## v0.3.0 — 2026-11-13

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
- Amazon Linux 2 and 2023: package vulnerabilities come from Amazon's ALAS advisories
  (the repositories' `updateinfo`, checked against the sha256 in `repomd.xml` and cached),
  Amazon Linux 2's extras topics included. Amazon Linux 1, past its end of life, answers
  "cannot tell". Recorded on an Amazon Linux 2023 VM; Amazon Linux 2 is covered by tests only.
- Alpine Linux: packages from the apk database (OSV), OpenRC services and runlevels,
  `/etc/local.d`, busybox crond (`/etc/crontabs`, `/etc/periodic`) and `/etc/inittab` as
  persistence, and sshd lines of busybox syslog's auth facilities, marked unverified.
  Recorded on an Alpine 3.22 VM, as root and as a user.
- SUSE: openSUSE Leap and Tumbleweed, and SLES, SLED and SLES for SAP (one OSV ecosystem per
  SLE 15 module; the ones OSV does not carry are listed as not queried). Leap is tested with
  a synthetic fixture and SLES on no real host yet.
- The daily report says when a vulnerability check failed or covered only part, and a
  package list that parsed to nothing is "cannot tell" instead of "no vulnerabilities".
- macOS (new, read-only, never with sudo): platform, accounts (dscl), processes, listeners
  (netstat, or lsof when macOS hides sockets), the application firewall, SIP, Gatekeeper,
  FileVault, XProtect, launchd jobs and other persistence, sshd settings, and installed apps
  and Homebrew packages. The OS version is checked against Apple's software update catalog
  (gdmf.apple.com); packages answer "cannot tell", since OSV has no Homebrew ecosystem.
  Tested only with a synthetic fixture (an invented host); not yet verified on a real Mac.
  Login items are not parsed (the Background Task Management store), so macOS persistence is
  always partial.
  periodic.conf and daily/weekly/monthly.local are listed line by line, every line but blanks
  and plain comments (a # line with no quote, $ or backtick: in a heredoc such a line is data
  and runs its commands); they are short. A stock /etc/defaults/periodic.conf is left out, and
  the files periodic_conf_files names are read too.
- A code audit root written with a trailing slash (`/var/www/html/`) or as `/` is no longer
  skipped when an audit resumes inside it. Roots are now cleaned, so the first audit after
  the upgrade does not find the place the last one stopped and walks from the start once.
- sshd settings: a `Match` block inside an included file (`Include sshd_config.d/*.conf`) no
  longer hides the settings that follow the Include in the main file (sshd restores the Match
  state after each Include), so e.g. a later `PermitRootLogin yes` is reported. An Include
  nested more than 4 deep, or past 256 config files, is listed as unread.

### Known issues

- Building from source now needs Go 1.26 or later (was 1.23): the Windows collector uses
  golang.org/x/sys, the second dependency.
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
