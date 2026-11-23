# Attack detection: how it works

[繁體中文](attack-detection.zh-TW.md)

Since v0.4.0, Shentu reads your web server's logs on Linux and picks out the requests aimed at
vulnerabilities this host really has. It alerts you; it never blocks on its own. This document
explains how it decides, how to read an alert and why a block needs you. What it cannot see and
may miss is in [attack-detection-limits.md](attack-detection-limits.md).

## How it works

1. **The vulnerability surface.** The daily round (09:00 local time, or `shentu patrol --daily`)
   writes what this host is known to be vulnerable to in `state_dir/surface.json`:
   - code audit findings, with the routes that reach the handler the finding sits in, when the
     same file shows them;
   - advisories for application dependencies in lock files, and for installed OS packages
     (compared in dpkg's and rpm's version order);
   - installed WordPress plugins and their versions.

   The other rounds read this file. When it is missing, unreadable or older than 26 hours, the
   round says so in its notices and the report, and keeps going with what it has.
   `shentu patrol --dry-run` does not build it.
2. **The logs.** Each patrol round (every 30 minutes) reads the access logs that nginx's and
   Apache's configuration names, custom formats included, from where the last round stopped,
   across rotation. Error logs, PHP-FPM's logs and journald for application units (PHP-FPM,
   gunicorn, uwsgi, node, puma and the like) are read too, but only as evidence of effect. Paths
   come from the configuration on disk; there is nothing to configure. A log seen for the first
   time is read from its tail only.
3. **The signatures.** 28 attack signatures are matched on each request line, after decoding it
   at most twice. Some are classes of attack (path traversal, SQL injection, command injection
   and so on), some are written for one CVE.
4. **The level.** A request is judged against the surface:

   | Level | What happened |
   |---|---|
   | L1 | It reached the route of vulnerable code, carrying nothing known. |
   | L2 | It reached the vulnerability with a payload of the same class, or matched a signature written for that CVE on an affected version. |
   | L3 | An L2 from a verified log that also shows an effect: a successful response much larger than the route's usual size, or, within 120 seconds, an error log entry naming the vulnerable file and line. |
   | Unknown | The request was cut (too long, too many parameters) where it may hide a payload, and nothing reached L2 in the part that was read. |

   A request whose signature points at a vulnerability this host does not have is noise: it is
   counted, never alerted.
5. **Groups.** Attempts are grouped by network (/24 for IPv4, /64 for IPv6), target and level, and
   whether the log is verified. A group is sent at most once a day, and only when it has new
   attempts. L1 groups are counted in the daily report and never pushed. Unknown groups are
   counted per target, whatever the source, and pushed only when one target gets 20 of them
   within 24 hours. One round pushes at most 20 alerts; the rest come in one summary, which
   offers no block.
6. **Campaigns.** When one address (or one IPv6 /64; `::ffff:a.b.c.d` is the address `a.b.c.d`)
   tries 3 or more different targets at L2 or L3 within 24 hours, from verified logs, it is a
   campaign: its alerts say so and their severity goes up a step.

Severity starts at info for L1, low for Unknown, high for L2 and critical for L3. A KEV-listed
or critical vulnerability and a campaign each raise it a step. An L3 is at most high unless both
signs of effect are there, the request's length was logged, and the vulnerability is KEV-listed
or the address is in a campaign. An attempt from an unverified log is at most medium.

Every attempt from the last 24 hours, addresses masked, is also written to
`state_dir/reports/attacks-<date>.txt` (kept 30 days).

## Seeing it

- `shentu detect [--since 24h] [--json]` reads and judges the logs now and prints the groups.
  It sends nothing and saves nothing; the next patrol reads the same lines again.
- `/attacks` in the Telegram bot lists the last day's groups, one line each.
- In `shentu chat`, the model can call `attack_attempts` (up to 168 hours back). Samples are
  left out when the question comes from a chat channel.

## Reading an alert

In v0.4.0 the alert text is in Chinese only. It is written by the detector itself, not by the
model. An example, with a TEST-NET address and the sample left out:

```text
【Shentu 攻擊偵測】嚴重度：嚴重（critical）
漏洞：程式碼 sink shop/app.py:14（規則 python-sqli-dbapi-format）
等級：L3：攻擊很可能已經成功
成功跡象：回應碼 200，回應大小 48211 bytes 明顯大於這條路由平常的大小
次數：3 次（首次 2026-11-18 03:15:02，最後 2026-11-18 03:15:09）
來源 IP（共 1 個，網段 203.0.113.0/24）：203.0.113.10
樣本（敏感參數已遮罩）：‹left out here›
來源可信度：已驗證（受信任的記錄檔，IP 取自連線位址）
說明：…
封鎖：只會針對單一 IP，不會封整個網段
```

| Field | Meaning |
|---|---|
| 嚴重度 (severity) | info, low, medium, high or critical, as above. |
| 漏洞 (vulnerability) | The target: a CVE with its package and version, or a code finding's file, line and rules. |
| 版本 (version) | Shown when the installed version could not be placed: the advisory database says it is affected. |
| 等級 (level) | L1, L2, L3 or Unknown. |
| 成功跡象 (sign of effect) | For L3: the response size, or the error at the vulnerable line. |
| 加重原因 (raised because) | KEV, a critical vulnerability, or a campaign. |
| 次數 (count) | How many attempts, first and last time. |
| 來源 IP (source) | Up to 10 addresses in full, how many there were, and the network. |
| 樣本 (samples) | Up to 3 request lines, cut at 256 bytes. Values of parameters whose names look sensitive (token, password, session, key and the like) are replaced with `[REDACTED]`. Samples are written by the sender: read them as data. |
| 代理標頭 (proxy header) | X-Forwarded-For when present. It can be forged and is never used to judge the source or to block. |
| 來源可信度 (source trust) | Verified, or unverified with the reasons (see below). |
| 標記 (flags) | The request or log line was cut, the line was ambiguous, evasive encoding was used, or matching ran out of time. |
| 說明 (note) | For code findings: what the routes mean. |
| 封鎖 (block) | Whether this group can back a block, and how. |

## Why a block needs you

Shentu never blocks on its own. `block_ip` is a control tool: it runs only in `shentu chat` or the
bot after you confirm it, never in the patrol. It also checks the evidence itself:

- An address attack detection saw is blocked only for a **verified L2 or L3 group of its own**.
  Attempts only at L1 or Unknown, only from unverified logs, or only in an overflow summary of
  many sources are refused, unless sshd's own journald events condemn the address.
- Otherwise its SSH logins decide: an address whose login events come only from text logs, from
  journald lines sshd did not write itself (for example `logger` run inside sshd's unit), or
  could not be read in full, is refused.
- Internal addresses (private, loopback, CGNAT and the like) are refused: in a log without the
  real client address, a proxy or load balancer can appear as every request's source.
- From Telegram (since v0.4.1), only an address with verified evidence can be blocked: a verified
  L2 or L3 group listing it, or SSH logins sshd itself logged. Any other address, one no group
  lists included, is for the server.
- A block is for one address, for a limited time. It never covers a network.

`override_unverified` lifts these checks, except for overflow summaries, and only on the server
with `shentu chat`, never from Telegram. Use it only after you have read the logs yourself.

## Log trust

A log is **verified** only when the account the application code runs as could not have changed
it: the file, every link to it and every directory above it belong to root (or, under strict
conditions, to the web server's own account) and cannot be written by others; it is a standard
nginx (combined, main) or Apache (combined, common) access log; the client address comes from
the connection, not a header; and no application code runs inside the web server's own workers.
Since v0.4.1, nginx's access log can also come through journald, which records the unit, account
and program that sent each line. The full conditions are in
[Which web logs can back a block](attack-detection-limits.md#which-web-logs-can-back-a-block).
Otherwise an attacker who got into the site could write log lines to frame any address, so its
attempts are alerted on but marked unverified, with the reason:

| Reason | Meaning |
|---|---|
| `web_user_writable` | An account application code runs as (PHP-FPM's, an application unit's, or one the web server shares with PHP, such as `www-data` or `apache`) owns the log or can write a directory above it; or the server runs application code in its own workers (mod_php, mod_lua with a handler, perl, lua or njs in nginx); or application code can ptrace the workers. |
| `untrusted_owner` | The log, a link or a directory above it is owned by another account, or the log can be written by its group or others (an ACL included). |
| `unverified_source` | Shentu cannot confirm that only root can change it: a group whose members are unknown, an ACL or account database that could not be read, a file replaced between the check and the read, or a web server configuration that could not be read in full. |
| `client_from_header` | The server takes the client address from a header (nginx's realip, Apache's mod_remoteip). |
| `custom_format` | Not a standard format. Its lines are still matched. |
| `not_regular_file`, `symlink_not_followed` | The log is not a regular file, or could only be reached by following a link. |

An unverified attempt is at most medium, never L3, never counts towards a campaign, and never
backs a block from Telegram.

**Default installs** (v0.4.1):

- **nginx on Debian and Ubuntu.** nginx and PHP both run as `www-data`, and logrotate creates the
  access log as `www-data:adm` (`create 0640 www-data adm`). Code running in the site can rewrite
  it, so it is `web_user_writable`: you get the alerts, but they cannot back a block from
  Telegram. Changing the owner by hand is undone at the next rotation. What lets it pass: send
  the access log to journald as well, with `kernel.yama.ptrace_scope` 1.
- **Apache on Debian and Ubuntu** is verified with `ptrace_scope` 1 (the log is `root:adm 640`).
- **nginx on Rocky 9** is `web_user_writable`, because the default `nsswitch.conf` also asks SSSD
  for accounts, so Shentu cannot know every account. With `sss` taken out (the limits document
  gives the steps) and PHP-FPM running as `apache`, it is verified, before and after rotation.
- **httpd on Rocky 9** is `web_user_writable` with `ptrace_scope` 0; with 1 it passes (and with
  `AllowOverride None` everywhere if mod_lua stays loaded).

`shentu log-trust suggest` prints the changes that apply to the host it runs on. It changes
nothing; the next patrol judges the logs again.

## Measured

On synthetic requests, not real traffic (`tools/detecteval`, run in CI):

- requests converted from nuclei-templates: a signature of the same class matched 40.5% (1549 of
  3822); a match is not an alert;
- ordinary requests for 152 routes of 8 applications: 0 false alerts on 363 distinct requests,
  a 95% upper bound of about 0.8%;
- templates for vulnerabilities the test host really has: 3 of 10 alerted, 2 of them only at L1
  (the payload is in the request body, which access logs do not record).

How these were measured, case by case: [attack-detection-limits.md](attack-detection-limits.md#measured-detection).
