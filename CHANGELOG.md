# Changelog

Each release has one section: `## vX.Y.Z — YYYY-MM-DD` (or `## vX.Y.Z (unreleased)`).
The website (`go generate ./cmd/sitegen`) reads this file. The rules added or removed in
a release are not written here: they are worked out from the rule snapshots in
`docs/site-src/rules-history/`. `CHANGELOG.zh-TW.md` holds the same releases in Traditional
Chinese for the zh-TW pages; keep the two in step.

## v0.5.1 — 2026-11-20

- Dispatch archive (#112): each sub-agent dispatch is saved to `state_dir/dispatch/<date>.jsonl`
  (0600 in a 0700 directory, kept 30 days) before its reports go back: roles, statuses and
  reasons as fixed words, counts, and the proposed addresses in canonical form with what the
  Telegram gate says of each. No text a sub-agent or a log wrote is kept. Every field is checked
  when a record is written and when it is read; an archive another user could write, or a link,
  is not read. The daily report has a section on the last day's dispatches, with addresses
  masked to /24 (/64 for IPv6).
- Proposal buttons (#116, #122): after a Telegram answer that dispatched, the bot lists the
  proposed blocks, with a button for each one that passes the checks `block_ip` runs from
  Telegram (#108's gate included) at that moment and was written in canonical form, at most
  five; any other gets a fixed word for why. A button carries only the dispatch id and a number.
  Pressing it runs the checks again, then asks for ✅ (with `[bot] confirm = 4` too), then
  blocks. A press is refused for another pairing, after 24 hours, a second time (after a restart
  too), or when the archive's address differs.
- Automatic incident checks (#117), off by default (`[agents] auto_incident`): an L3 group the
  patrol pushed dispatches the read-only `incident` sub-agent on its own. One a round, at most 3
  a day, a group once a day; none for unverified or overflow groups, none without
  `[budget] monthly_tokens` or past 80% of it, and none while the archive or `log.jsonl` cannot
  be read to its end. The notice carries fixed words and numbers; its proposals get the same
  buttons, sent only while the bot service runs and can change the firewall.
- The bot's and `shentu chat`'s monthly AI budget limit counts a `log.jsonl` it could not read
  to its end as used up.

### Known issues

- Sub-agents still run one after another, and they are built and tested for Linux only.
- A line cut short in the archive (a full disk, say) stops automatic incident checks for at most
  72 hours (usually about two days), until its file is out of the window they read; the daily
  report says so.
- With a 7B local model, sub-agents often use up their 6 steps and are reported incomplete.

## v0.5.0 — 2026-11-20

- Sub-agents (Linux, one host): in the Telegram bot and `shentu chat`, the agent can hand
  read-only checks to up to 3 sub-agents with the `dispatch` tool, each in one role: `patrol`,
  `surface`, `attack` or `incident` (#101). Each role has a fixed list of read-only tools; a
  sub-agent cannot block or unblock an address, notify, use a skill or dispatch again. They run
  one after another. Patrol rounds and the eval bot never dispatch.
- Limits: a sub-agent gets at most 6 model calls, 3 tool calls a step, 2048 output tokens a
  call, 40,000 tokens and 5 minutes; a dispatch at most 120,000 tokens and 12 minutes, and the
  monthly budget still applies. Tokens are estimated before each call and counted after it,
  reasoning tokens included. A sub-agent stopped by a limit, or one that does not answer in the
  required report, is reported incomplete with the reason, never as done. A model call cut off
  by a time limit is no longer retried.
- Reports: each sub-agent answers in a fixed JSON shape (findings, proposals, what it did not
  check), checked field by field and masked, and the agent reads it marked untrusted. A proposal
  to block is only a suggestion: after a dispatch, every `block_ip` or `unblock_ip` in that
  conversation asks for the ✅ button even with `[bot] confirm = 4`, until `/new`, and its audit
  log line names the dispatch. The bot's progress message shows the sub-agents' steps (the last
  12), and a tool name it does not know as "unknown tool".

## v0.4.3 — 2026-11-20

- SSRF: after a URL's host is checked, `console.log(u)`, `JSON.stringify(u)` or `String(u)`
  no longer ends the check, while the file uses `console`, `JSON` and `String` only to call
  them (no parameter or declaration of those names, no `console.log = f`) and holds nothing that
  may replace them unseen (a global object such as `globalThis` other than read through a named
  member, `eval`, `Function(`, a `with` statement, anything under a built-in's prototype)
  (#119).
- JavaScript route handlers: destructuring with a string key,
  `const { 'x-forwarded-host': xfh } = req.headers`, is followed, so the value is reported by
  js-ssrf-host-header instead of js-ssrf-http-request. In a Koa route handler, a destructured
  parameter taking `request` (`({ request }) => request.header.host`) is read as Koa's context
  when the file, or another file of the project, imports `koa`, `@koa/router` or `koa-router`
  (#119).
- New sources: Next 15's `(await headers()).get(...)`, so a Host header read that way and passed
  to a redirect is reported by js-open-redirect-next; Laravel's `Request::query(` and
  `Request::get(` in php-sqli-orderby-identifier (`DB::raw`, `->orderBy(`) (#118).
- NestJS: a field of a whole `@Headers()` object written into a response (`h['x-note']` in
  `res.send(`) is reported by js-xss-response (#125).
- Duplicate reports removed. One call, one SQL injection rule: where two rules report the same
  call on the same line, one of them leaves it to the other (`yields_to`). `->where(` with
  Symfony's `$request->query->get(` is php-sqli-doctrine-query-text's, no longer also
  php-sqli-drupal-db-query's; `DB::raw(...)` inside one of php-sqli-laravel-raw's calls is
  laravel-raw's where laravel-raw reports it. Another call on the same line is still reported
  (#125). And in the SSRF rules, after `const x = h` where `h` is a whole NestJS `@Headers()`
  object or Express's `r.headers`, `x.host` (also `x['Host']`, `x['x-forwarded-host']`) is
  reported by js-ssrf-host-header alone, no longer by js-ssrf-http-request too; a name that may
  also hold another value of the request (`r.query` on one branch) is still reported by both
  (#132).

### Upgrade notes

- Some findings move to another rule: `sa.text(...)` built from request input is reported by
  python-sqli-sqlalchemy-text instead of python-sqli-dbapi-format (#118); a string-key
  destructuring of a Host header by js-ssrf-host-header instead of js-ssrf-http-request (#119);
  and a call two SQL injection rules reported is reported once (#125). php-sqli-laravel-raw's fix
  now says an ORDER BY column or direction needs an allowlist. With them, the routes attack
  detection takes as reachable may change.

### Known issues

- A Koa middleware registered with `app.use` is not a route handler: its context is followed
  only as written (`ctx.request.headers['x-forwarded-host']`), not through destructuring
  (`const { host } = ctx.request.headers`) or an alias (`const h = ctx.request.headers`).
- A name reassigned on every branch is still followed after them, which reports more than it
  must.
- Next 15's `const h = await headers(); h.get(name)` and the sync `h = headers()` are not
  sources yet.
- The JavaScript read-only calls do not yet see `Object.getPrototypeOf`, an alias of `Function`,
  `Reflect.construct`, `vm.compileFunction`, or a global object reached through `this`, `GLOBAL`
  or `top`; and `typeof window` sends the whole file back to ending the check at `console.log(u)`.

## v0.4.2 — 2026-11-20

- The JavaScript rules follow a route handler's request whatever it is called: a parameter not
  named `req` (`(r, s) =>`), a Koa context not named `ctx`, an alias (`const q = r`,
  `const h = r.headers`) and destructuring (`({ headers }, res) =>`,
  `const { headers, hostname: hn } = r`, `const { host } = req.headers`). So `r.hostname`,
  `r.get('host')`, `c.host` and a destructured `headers` are reported now; a Host header read this
  way goes to js-ssrf-host-header, other headers to js-ssrf-http-request. A request header index
  is read in lower case, as Node stores it (`r.headers['Host']`). In the SSRF rules, Koa's
  `ctx.header` and `ctx.request.get(` are sources too, and so are `ctx.request.header.host` and
  `ctx.request.headers.host` for the Host header (#106).
- NestJS: `@Request()` counts as the handler's request, as `@Req()` does, in the 13 JavaScript
  rules that read `@Req()` (SSRF, SQL and NoSQL injection, command injection, code evaluation, path
  traversal, LDAP injection, deserialization). Both count as NestJS's only when the file, or another
  file of the project, imports `@nestjs/common` or `@nestjs/core`; elsewhere they are an object like
  any other (#103, #106).
- Python: `global` and `nonlocal` continued with a backslash are read to the end of the
  statement, so a name on the next line is declared too (#103).
- SSRF: after a URL's host is checked, `a = u.valueOf()` followed by a change to `a`, or a method
  of `u` called by a computed name (`u['valueOf']()`, `u[k](...)`), ends the check, as `a = u`
  does (#103).

### Fixed

- A web log owned by the server's own account no longer backs a block when systemd's userdb
  directories (`/etc/userdb`, `/run/userdb`, `/run/host/userdb`, `/usr/local/lib/userdb`,
  `/usr/lib/userdb`) hold any entry or cannot be read: userdb can add accounts and group
  memberships that `/etc/passwd` and `/etc/group` do not show (#113).
- Hardening only: the block check also reads an address in an `inet_aton` form (`3405803788`,
  `0xcb.0.113.12`, ...), and the block check and campaigns read `::ffff:a.b.c.d` as `a.b.c.d`.
  Access logs never yield these forms (since v0.4.0 a client must be a plain address, and
  `::ffff:` is read as IPv4), so nothing changes in practice (#113, #124).

### Upgrade notes

- Some JavaScript findings move to another rule: a Host header read as
  `r.headers['X-Forwarded-Host']` or `const { host } = req.headers` is reported by
  js-ssrf-host-header instead of js-ssrf-http-request; `@Req()` in a project that does not import
  NestJS is reported by js-ssrf-http-request; `const { host } = req.headers` written into a
  response is no longer reported by js-xss-response, as Host has not been XSS input since v0.4.1.
  With them, the routes attack detection takes as reachable may change.
- On a host whose systemd userdb directories hold any entry, the server's own account no longer
  counts as apart after the upgrade: a log that could back a block in v0.4.1 (Rocky 9 nginx's,
  say) is judged `web_user_writable` again. The conditions are in `docs/attack-detection-limits.md`
  under "Which web logs can back a block". Default Ubuntu 24.04 and Rocky 9 installs have none of
  the five directories, so they are not affected (checked on both at 4fcfc52).
- A correction to v0.4.1's notes: "an address logged in another form (brackets, a port, a
  zone, leading zeros) is refused" cannot happen through the access logs, which keep only plain
  addresses. It takes effect only when a log has an IPv4-compatible (`::a.b.c.d`) or NAT64
  (`64:ff9b::a.b.c.d`) client. The released v0.4.1 entry is left as it was.

### Known issues

- A Koa handler's context is recognized by how the handler uses it (`c.request`, `c.response`,
  `c.state`, `c.throw`, `c.assert`, or setting `c.body`, `c.status` or `c.type`); any other
  parameter is read as Express's request. A destructured parameter is read as Express's request,
  so Koa's `({ request }) =>` is not followed. Nested patterns (`{ headers: { host } }`) and
  string keys (`{ 'x-forwarded-host': xfh }`) are not followed either; the latter is still
  reported, by js-ssrf-http-request.
- Request aliases are kept per function, and an alias reassigned on one branch is no longer
  followed on any path.
- `@Req() req` in a file that does not import NestJS, outside a project that does, is not NestJS's:
  its `req.headers.host` is reported by both js-ssrf-host-header and js-ssrf-http-request.
- The URL check fails closed: `global u` or `nonlocal u` anywhere in a file, backslash-continued
  too, ends it for every `u` of the file; `fetch(u.valueOf())` after a check, and a harmless
  `u['toString']()`, are reported.

## v0.4.1 — 2026-11-20

- The host survey warns about nginx 1.9.5 through 1.31.8 serving HTTP/2 (a `listen ... http2`, or
  `http2 on` for a server): CVE-2026-123007 and CVE-2026-123633, HTTP/2 memory corruption that lets
  a client crash the workers. Upgrade to 1.31.9 or 1.30.7, or to the distribution's fixed package;
  until then, turning HTTP/2 off avoids it. It is advice: the configuration is not changed. A
  distribution package whose changelog names the CVEs (a backported fix) is not warned about; the
  package scan reports the distributions' advisories once they reach OSV, and this check covers
  nginx.org's packages and builds from source, which that scan does not.
- A web log owned by the server's own account (`nginx` on Rocky Linux, say) can back a block,
  as a log root owns can, when nothing else runs as that account: no PHP-FPM pool, systemd unit,
  crontab, supervisord program, sudo or doas rule or login shell, and at the patrol no process
  but the server's own; the account databases come only from the files, and everything checked
  was read. Anything unread leaves the log `web_user_writable`. The shared default accounts
  (`www-data`, `apache`, `nobody`) never count. The other conditions are in
  the limits document, `docs/attack-detection-limits.md`, under "Which web logs can back a block".
- nginx's access log sent to journald (`access_log syslog:server=unix:/dev/log,...`) is read and
  verified line by line: a line counts only when it came over syslog from nginx's own program,
  running as nginx's worker account in `nginx.service`. A line another program sent is read but not
  verified.
- `shentu log-trust suggest` prints the changes that would let this host's web logs back a block:
  the journald line for nginx, a drop-in lifting journald's rate limit for nginx,
  `kernel.yama.ptrace_scope = 1`, and PHP-FPM pools of their own account. It only prints them and
  changes nothing.
- Apache's modules are judged against a list: modules that only configure, control access, cache
  or proxy are no concern; those that run programs as the children's account, and `RewriteMap`'s
  `prg:`, want `ptrace_scope` 1 or more; `mod_php`, `mod_cgi` and unknown modules count as
  application code.
- An attack hit in a route placeholder's segment that carries `;` parameters (`/user/42;x` for
  `/user/:id`) now reaches L2; before, it stayed at L1.
- The response-size baseline used for L3 now leaves out only requests taken to L2; requests with
  hits that are unanchored or noise are learned from.
- Rule precision: findings that two rules both reported on one line now have one owner (Host
  header against SSRF, SQL injection, `ORDER BY` identifiers), and an SSRF host checked against a
  fixed allowlist on a parsed URL counts as checked. Some findings appear or go away, and with them
  the routes attack detection takes as reachable.

### Fixed

- From Telegram, `block_ip` now blocks only an address with evidence Shentu verified: a verified L2
  or L3 attack group listing it, or SSH login events sshd itself logged. Any other address is
  refused there, to be checked and blocked on the server with `shentu chat`, as v0.4.0 said of
  unverified attempts. Before, an address its attack groups did not list (past the ten a group
  lists, in a group evicted from the state, or logged in another form) was judged by its SSH logins
  alone, so one with none could be blocked from Telegram on unverified attempts. A group lists at
  most ten addresses, so the eleventh and later of even a verified L2 or L3 group are refused from
  Telegram too, by design, and are to be blocked on the server.
- On the server, an address past the addresses a group lists is refused as a listed one is, also
  after the group is merged into an overflow summary, and so is the rest of its network. So is an
  address logged in another form: brackets, a port, a zone, leading zeros (read both ways), or IPv4
  embedded in IPv6. A verified group allows a block only of the address it lists. Once an overflow
  or sink-wide summary has more sources than it keeps hashes of (64), it refuses every address it
  does not list; the operator may override on the server.

### Upgrade notes

- v0.4.0's known issue that default nginx logs cannot back a block, planned for v0.4.1, now
  stands as follows (`docs/attack-detection-limits.md` has the details):
  Debian 12 and Ubuntu 24.04 nginx stay `web_user_writable` (`www-data` is PHP's account too):
  send the access log to journald, with `ptrace_scope` 1. Debian 12 and Ubuntu 24.04 Apache are
  verified with `ptrace_scope` 1. Rocky 9 nginx stays `web_user_writable`, because the default
  `nsswitch.conf` also asks sss: taken out (where no SSSD is used), with PHP-FPM as `apache`, it
  is verified. Rocky 9 httpd wants `ptrace_scope` 1, and `AllowOverride None` everywhere if
  `mod_lua` stays loaded.
- Once a log is judged verified, new attempts go into verified groups, while the old unverified
  groups expire only after up to 7 days: until then one target may show two groups. A new
  journald source is read the first time from its latest position on, not from the past.

## v0.4.0 — 2026-11-18

- Attack detection (Linux): each patrol round reads the web server's logs and picks out the
  requests aimed at vulnerabilities this host really has. It alerts; it never blocks on its
  own. What it cannot see and what it may miss are listed in
  `docs/attack-detection-limits.md`.
- The vulnerability surface: the daily round saves what this host is known to be vulnerable to
  in `state_dir/surface.json`, and the other rounds read it: code audit findings, with the
  routes registering the handler a finding sits in when the same file shows them (#84);
  advisories of application dependencies and of installed OS packages, compared in dpkg's and
  rpm's version order; installed WordPress plugins and their versions (#91). A surface missing,
  unreadable or older than 26 hours is said in the round's notices and the report, never used quietly.
- Log sources: the access logs nginx and Apache are configured to write, custom formats
  included, PHP-FPM's logs and journald for application units, read from where the last round
  stopped across rotation (#85). A log counts as verified only when root alone could have
  written it; otherwise its attempts are marked unverified and the alert names the reason.
- 27 attack signatures, written for Shentu or drafted from reviewed nuclei-templates (MIT,
  see `detect/sig/NOTICE`), matched after decoding a request at most twice (#87). A request
  that only reaches a route of a vulnerable handler is L1; one that also carries a payload of
  the vulnerability's class is L2; L3 needs a sign it had an effect: a response size far from
  the route's usual one, or an error at the vulnerable file and line (#90). A request cut where
  it may hide a payload is Unknown. A vulnerability the host does not have is noise.
- Alerts are the detector's own plain text, sent through the notify channel, not through the
  model. Attempts are grouped by network (/24 or /64), target and level, and a group is sent
  once a day. L1 is counted in the daily report, never pushed; Unknown is pushed only when one
  target gets 20 of them within 24 hours. Sensitive parameters in samples are masked, and the daily file
  `state_dir/reports/attacks-<date>.txt` (kept 30 days) masks addresses (#90, #91).
  `shentu detect [--since] [--json]` reads and judges a round without sending or saving;
  the `attack_attempts` tool and the bot's `/attacks` list the last day's groups.
- `block_ip` and attack detection: an address the detector saw is blocked, after the operator
  confirms, only for a verified L2 or L3 group of its own. Attempts from unverified logs, at L1
  or Unknown, and internal addresses are refused unless the operator overrides with
  `override_unverified` on the server (`shentu chat`); Telegram never can. An address listed
  only in an overflow summary of many sources is refused, override or not (#91).
  On an Ubuntu VM, an attack in a verified log was judged L3 and could be blocked; one in an
  unverified log reached L2 at most, and its block was refused from Telegram.
- `block_ip`'s SSH evidence counts a login only when sshd's own events in journald confirm it
  (#91): sshd lines that another program in sshd's own unit writes to journald (for example
  with `logger`) no longer back a block; v0.3.1 blocked on them. Lines forged into text logs
  were refused already.
- Engine: summary runs that cannot change the result are skipped, and the analysis copies less.
  Measured as user CPU time on a Mac, WordPress is scanned about 34% faster than v0.3.1 and
  TypeScript projects about 22% faster, with the same findings (#92). Measured as elapsed time
  on an Ubuntu 24.04 VM (arm64, 4 CPUs, 4 GB), one version after another on the same machine,
  the WordPress scan took 97.2 s (v0.3.1 120.0 s, v0.3.0 72.1 s), 19% less than v0.3.1, with
  the same 2279 files and 43 findings and a peak memory of 848–858 MB in all three; the daily
  patrol as root took 126 s (v0.3.1 146 s, v0.3.0 99 s). Benchmark unchanged: published vulnerabilities 16 of 97 caught, 1
  fixed-release false positive; held-out cases 3 of 30; TypeScript cases 1 of 18 with 1
  fixed-release false positive.
- `tools/detecteval`, run in CI, measures attack detection on synthetic requests (#94): requests converted from nuclei-templates v10.5.2: a signature of the same class matched 40.5% of them (1548 of 3822 classified templates). This is a match on the request line, not an alert; ordinary requests for 152 routes of 8 applications: 0 false alerts; 363 of them differ in more than tracking parameters, so the rate can only be said to be below about 0.8% (95% upper bound); templates for vulnerabilities the test host has: 3 of 10 alerted, 2 of them only at L1 (the payload is in the request body).

### Fixed

- When one request hits several rules on the same line of code, you get one alert that lists
  every rule, instead of one alert per rule (#97).
- Alerts for a package's CVE no longer carry the note on what routes mean; that note is for
  alerts about your own code only (#97).
- When an ACL lets another account write a log or a directory above it, the reason names that
  account, for example `ACL grants write to www-data (uid 33)` (#97).
- When the patrol runs as an account that is not root and not in the `systemd-journal` or `adm`
  group, the SSH result is marked as only partly read (#97).

### Upgrade notes

- An attack state saved by a v0.4.0 build from before these fixes (one group per rule) is
  merged into the new format (one group per line of code) when it is loaded (#97, #98). The
  counts from before the upgrade are a lower bound: when rules of different classes on the same
  line were hit by different requests, the count may be too low. This changes only the counts
  shown, not alerts or blocks. v0.3.x keeps no attack state, so an upgrade from it has nothing
  to merge.

### Known issues

- Attack detection is for Linux only.
- Access logs do not record request bodies (POST forms, JSON, uploads): a payload there is
  never seen, and such a request is L1 at most.
- The signatures expect the plain form of an attack. Rewritten forms (other encodings, padded
  paths, comments or other whitespace inside SQL, commands split by quotes) may be missed.
- With nginx as installed by default on Debian, Ubuntu and Rocky Linux, v0.4.0 judges its access
  log `web_user_writable` (the web server's account could write it or a directory above it): its
  attempts are alerted on, but they cannot back a block. On Debian and Ubuntu nginx and PHP both
  run as `www-data`, so the risk is real (on Ubuntu the log is `www-data:adm`, and logrotate
  creates it with `create 0640 www-data adm`). On Rocky Linux nginx runs as `nginx` and PHP-FPM
  as `apache`, which cannot write nginx's log: there v0.4.0 is only being cautious. Changing the
  log's owner by hand is undone at the next rotation. This is planned for v0.4.1. Rocky Linux's default httpd configuration loads modules outside the list
  Shentu knows to be safe, so its Apache logs are always judged `web_user_writable` too; weighing
  those modules is planned for v0.4.1.
- There are no signatures for particular WordPress plugin vulnerabilities yet.
- Scans are still slower than v0.3.0: WordPress about 35% (elapsed time on the Ubuntu VM above),
  TypeScript projects about 20% (user CPU time on a Mac, #92).
- Still open from v0.3.1: CVE-2021-23664's fixed release is reported; `filesize()` on an
  upload's temporary path in WordPress; `markup` not followed through a variable.

## v0.3.1 — 2026-11-16

- Code audit rules: 70 → 127 (PHP 25 → 51, Python 22 → 43, JavaScript and TypeScript
  23 → 33). PHP: WordPress, Laravel, Symfony, Joomla, Drupal, CodeIgniter, Yii and Smarty
  sinks, sockets and HTTP clients, XML DTDs, template strings, crypto keys and shortcodes
  (#76). Python: keyword arguments (`args=`, `search_filter=`, `where=`), ldap3 filters and
  helper flows (#36). JavaScript and TypeScript: Koa and chained Express responses, BSON and
  launder sanitizers, Host-header redirects and SSRF; `.execute(` counts only on a receiver
  that may be a database client (#70).
- The v0.2.5 known false positives are fixed in the engine: TypeORM repository calls in a file
  importing `typeorm` are no MongoDB queries, unless the file uses a MongoDB repository, driver
  or Mongoose (`unless_imports`, #59); `spawn()` and `execFile()` with `shell: true` are reported
  only when the command or its arguments carry input, not the options (several `[[args]]` blocks
  per sink, #62); a Server-Sent Events handler (`Content-Type: text/event-stream` set on every
  path) is no XSS (`unless_content_type`, #58; `unless_at`, #57); `->get_settings()` is Elementor
  widget input only in classes extending `\Elementor\Widget_Base` (#60); a placeholder list built
  by `array_map` with a callback returning a constant is no input (#61);
  `zipfile.ZipFile(request.files[...])` opens the upload's stream, not a path
  (`unless_subscript`, #67).
- `js-ssrf-http-request` now reads the referrer and origin in Koa, hapi and Fetch API spelling
  (`ctx.request.header.referer`, `request.headers.referer`, `request.headers.get('x-callback-url')`;
  not Host), which were missed. Input written into a prepared statement's text is reported once,
  by `php-sqli-prepare-query-text`, instead of also by `php-sqli-string-concat`. The benchmark
  numbers are unchanged.
- Engine: `new URL(a, base)` takes its path and query from `a` when `a` starts with `/` or a
  scheme (#63); method calls on an object of a class in the same file are followed (#64); an
  anchored regex test fixing a value's start (`re.match(re.escape(base) + r'/[a-z]', url)`) is
  a check for redirect and URL rules (#65); a helper returning a string constant is followed
  (#66); `markup` makes an output sink count input only after literal markup (#71); recursive
  cycles are followed until they settle and paid for once, so WordPress files whose calls were
  cut went from 48 to 4 (#72); `route_input = false` for the Host-header rules, and Koa's `ctx`
  in the Express model (#50).
- Survey warns about Apache 2.4.55–2.4.70 with `mod_http2` loaded and `h2` or `h2c` in
  `Protocols` (CVE-2026-119618; upgrade to 2.4.71, or set `Protocols http/1.1` until then)
  (#54). When a file that could load `mod_http2` or turn on h2 cannot be read (no rights, a link
  not trusted), the check is listed as not checked instead of passed over; the warning says it
  can be ignored when the distribution has backported the fix.
- Code audit: a resumed walk cut before its stored position keeps that position, and the
  position is stored by the root's path; vendor, node_modules and WordPress code folders count
  only below the site root; `wp-content/blogs.dir/*/files` and `/var/www/<uploads|files>`
  without a site's index are upload folders; `authorized_key_unparsed` lists the first 20 line
  numbers (#73).
- The hourly and daily reports list SSH logins as not checked when the login logs could not
  be read in full (journald hiding the system's entries from a non-root user, `auth.log` or
  `secure` unreadable, a log cut short). Before, such a run said "nothing new" (#80).
  The reason given is what kept the logs from counting (on a quiet host: a journal with no sshd
  entry and no text auth log), and running as root is advised only when rights were missing; on
  macOS, which keeps sshd's events where Shentu does not read, the report says it has no sshd log
  source there.
- Linux builds no longer send an EDNS(0) record with DNS queries, as glibc does not: some
  DNS servers, VMware's NAT DNS among them, answered such queries without the address, so
  every lookup (OSV, GitHub) failed with "no such host". When a lookup still fails, the daily
  report's Not checked line says to check the host's DNS (#80).
- `block_ip` refuses an IP whose SSH login events come only from text
  logs anyone on the host can write to (`verified` false), or whose logins cannot be read;
  `override_unverified` goes ahead after the operator has checked them, from `shentu chat`
  only. From the Telegram bot it is always refused, at every confirm level.
  The check covers SSH login evidence only: a block based on other logs (syslog, nginx, an
  application log through `log_search`) is not checked and is the operator's to judge.
  On a host whose journald has no sshd entries (text logs only), `block_ip` refuses every IP
  with SSH login events, whatever the date of the lines; such a block cannot be made from
  Telegram, only on the server with `shentu chat` and `override_unverified`. `ssh_logins`
  looks back at most 720 hours, as far as the check (#80). A refusal for login events that may
  be forged names the text logs they are in.
- macOS: binary plists count array and dictionary entries, and UTF-16 strings at 9 bytes a
  character, against the decoding limit; a program path ending in a space is kept as it is;
  a process named on two `ps` lines is marked `parse_error`; `periodic_conf_files` past 16
  files are listed as not read (#80). CI runs `go vet` and `go test` on macOS 15 (#81); no
  macOS binary is published yet.
- Tests build credential-shaped fake values at run time, so the tree has no secret-shaped
  literals (#77).
- Benchmark against v0.3.0: published vulnerabilities 16 of 97 caught (was 15), 1 fixed-release
  false positive (was 0, see below); held-out cases 3 of 30 (was 2), no fixed-release false
  positive; TypeScript cases 1 of 18 with 1 fixed-release false positive
  (n8n), both unchanged.

### Known issues

- CVE-2021-23664 (`@isomorphic-git/cors-proxy`): `js-ssrf-http-request` still reports the
  fixed release. The proxy forwards `req.url` after an allow check the engine does not yet read
  as a sanitizer; reading such checks before a request is planned.
- Scans take longer with the added rules, as each file is run through more rules: WordPress
  about 40–60% depending on the machine (on an Ubuntu VM the code audit went from 73.8 s to
  120.0 s and the daily patrol from 100 s to 144 s, with the same findings and peak RSS),
  TypeScript projects about 43%. The fix at the root is planned after v0.3.1.
- `block_ip`'s check covers SSH login evidence only (see above): a block based on other logs
  is the operator's to judge.
- `php-deserialization-phar-wrapper` still reports `filesize()` on an upload's temporary path
  in WordPress's REST attachments controller: the engine cannot yet tell an upload's
  `tmp_name` from its client-set `name`.
- `markup` does not follow markup put together in a variable first
  (`const h = '<p>' + x; ctx.body = h`).

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
