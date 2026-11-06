# Shentu

**A small, open-source security assistant for Linux servers, powered by an LLM.**

Shentu (神荼) is named after one of the two door gods who guard the gate in Chinese tradition.
It is one static binary. It gives a language model a set of security tools and playbooks, so you
can ask your server questions in plain language and get short, readable reports. It never changes
anything on its own: every action waits for a human to confirm it.

```
$ sudo shentu chat
> Did anyone try to brute-force SSH last night?

203.0.113.7 made 1,284 failed SSH logins between 01:12 and 03:40 and never got in.
Password login is enabled, which makes this worth fixing.
Suggested: block 203.0.113.7 for 24h; switch SSH to key-only login.

> Block it.

⚠️  block_ip wants to run:
    nft add element inet shentu block4 { 203.0.113.7 timeout 86400s }   # SSH brute force
Allow? [y/N] y
Blocked 203.0.113.7 until tomorrow 09:14. To undo: "unblock 203.0.113.7".
```

## What it does

- **`shentu chat`**: ask about your server's security in plain language. The model chooses
  which tools to run and explains what it found.
- **`shentu patrol`**: run by a systemd timer every 30 minutes. It runs fixed checks without the
  LLM. If something new shows up, the LLM explains it and the report goes to Telegram, ntfy or a
  webhook. If the LLM is down, you still get the raw findings.
- **`shentu setup`**: picks the LLM. It can download a local model sized to the server's memory
  (through Ollama, so nothing leaves the machine), or take an API key for Anthropic, OpenAI or
  OpenRouter. Any other OpenAI-compatible endpoint can be set in the config.

## Tools

| Tool | What it looks at |
|---|---|
| `ssh_logins` | failed and successful SSH logins by source IP (auth.log, secure or journald) |
| `listening_ports` | listening TCP and UDP ports and the process behind each one |
| `processes` | deleted executables, programs running from /tmp or /dev/shm, shells run by web users |
| `accounts_audit` | extra UID 0 accounts, sudo rules, authorized_keys |
| `package_vulns` | installed packages checked against [OSV](https://osv.dev) (Ubuntu, Debian, Alpine, Rocky, Alma) |
| `file_changes` | recently changed files in watched directories, plus webshell patterns |
| `cert_expiry` | TLS certificate expiry |
| `log_search` | regex search, limited to configured log files |
| `block_ip` / `unblock_ip` | timed nftables blocks in a separate `inet shentu` table. **Chat only, needs your confirmation.** |
| `notify` | send a message to your channel |

## Skills

Skills are playbooks in the `SKILL.md` format that tell the model how to use the tools:
`triage`, `daily-patrol`, `ssh-bruteforce`, `vuln-patrol`, `suspicious-process` and `incident-report`.
To add your own, put it in `/etc/shentu/skills/<name>/SKILL.md`.

## Install

```sh
curl -fsSL https://github.com/nt-neil/shentu/releases/latest/download/install.sh | sudo sh
sudo shentu setup                        # download a local model sized for this server, or enter an API key
sudo nano /etc/shentu/shentu.toml        # set the notify channel
sudo shentu chat
sudo systemctl enable --now shentu-patrol.timer shentu-daily.timer
```

`.deb`, `.rpm` and `.apk` packages are also attached to each release. Supported systems:
Ubuntu 22.04 and 24.04, Debian 12, Rocky and Alma 9, and Alpine, on amd64 and arm64.

Not sure which model to use? [Choosing a model](docs/models.md) compares 12 models on the same
planted intrusion: accuracy, prompt-injection resistance, speed and cost.

## Configuration

See [`packaging/shentu.toml`](packaging/shentu.toml). Secrets such as bot tokens and API keys go in
`/etc/shentu/env` and are referenced as `${VAR}`.

## Security design

- **Tool output is untrusted.** Logs and file names can be written by an attacker. The model is
  told this, and it cannot do harm on its own anyway: patrol has no control tools, and in chat
  every control action shows the exact command and waits for `y`.
- **Secrets are masked** before anything reaches the model or the log: private keys, cloud and API
  tokens, JWTs and `password=` values.
- **Self-lockout guards**: `block_ip` refuses loopback, the server's own addresses and the IPs of
  active SSH sessions. Every block has a time limit.
- **No listening ports, no daemon, no database.** Every tool call is recorded in
  `/var/lib/shentu/log.jsonl`.
- **Small attack surface**: one third-party dependency (a TOML parser), and everything else is the
  Go standard library.

Report vulnerabilities as described in [SECURITY.md](SECURITY.md).

## Build

```sh
CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" .
```

## License

[Apache-2.0](LICENSE)
