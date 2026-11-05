# Security policy

Shentu runs with elevated privileges on servers, so we take reports seriously.

## Reporting a vulnerability

Please **do not** open a public issue. Report privately through
[GitHub Security Advisories](https://github.com/nt-nerdtechnic/shentu/security/advisories/new)
or by email to **SECURITY_CONTACT_TBD**.

Include the version (`shentu version`), the distribution, and steps to reproduce.
We aim to reply within 3 working days and to ship a fix for confirmed issues within 30 days.

## Scope

In scope: anything that lets an attacker make Shentu run a control action without the operator's
confirmation, read files outside the configured paths, leak secrets to the LLM or the notify
channel, or escalate privileges.

Prompt injection that only changes the wording of a report, without causing an unconfirmed
action or a leak, is a known limitation of LLMs; reports that reduce it are still welcome.
