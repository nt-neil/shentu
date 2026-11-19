# Security policy

Shentu runs with elevated privileges on servers, so we take reports seriously.

## Reporting a vulnerability

Please **do not** open a public issue. Report privately through GitHub:
[Report a vulnerability](https://github.com/nt-neil/shentu/security/advisories/new)
(the repository's Security tab → "Report a vulnerability").

Include the version (`shentu version`), the distribution, and steps to reproduce.
We aim to reply within 3 working days and to ship a fix for confirmed issues within 30 days.

## Scope

In scope: anything that lets an attacker make Shentu run a control action without the operator's
confirmation, read files outside the configured paths, leak secrets to the LLM or the notify
channel, or escalate privileges.

Also in scope, for attack detection (v0.4.0 and later, Linux): anything that lets someone who does
not control the host's root-owned logs get `block_ip` to accept an address it should refuse, for
example by forging or rewriting a log line, by making an unverified log count as verified (see
[Log trust](docs/attack-detection.md#log-trust)), by passing off journald lines as sshd's own, or
by getting a block from Telegram for an address without verified evidence or with
`override_unverified`. A request Shentu misses or rates too low is a known limit when it is listed
in [docs/attack-detection-limits.md](docs/attack-detection-limits.md); other misses are welcome as
ordinary issues.

Prompt injection that only changes the wording of a report, without causing an unconfirmed
action or a leak, is a known limitation of LLMs; reports that reduce it are still welcome.

## Supported versions

Fixes go into the latest release only. Upgrade to it before reporting, if you can.
