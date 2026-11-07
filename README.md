# Shentu

**A small, open-source security assistant for Linux servers, powered by an LLM.**

Shentu (神荼) is named after one of the two door gods who guard the gate in Chinese tradition.
It is one static binary. It gives a language model a set of security tools and playbooks, so you
can ask your server questions in plain language and get short, readable reports. It never changes
the system on its own: every action that changes something waits for a human to confirm it.
(Sending a notification does not need confirmation.)

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
  LLM. If something new shows up, the LLM explains it and the report goes to Telegram, Slack, Discord,
  ntfy or a webhook. If the LLM is down, you still get the raw findings.
- **`shentu setup`**: picks the LLM. It can download a local model sized to the server's memory
  (through Ollama, so nothing leaves the machine), or take an API key for Anthropic, OpenAI,
  OpenRouter or AppleToken. Any other OpenAI-compatible endpoint can be set in the config.

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
| `notify` | send a message to your channel (Telegram, Slack, Discord, ntfy or a signed JSON webhook) |

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

Step by step, with notify setup and troubleshooting: [Getting started](docs/getting-started.md)
([繁體中文](docs/getting-started.zh-TW.md)).

To read the script before running it, download it first:
`curl -fsSLO https://github.com/nt-neil/shentu/releases/latest/download/install.sh`, then
`sudo sh install.sh`. The script checks the archive against `checksums.txt`. Every release file
also carries a signed build provenance, which you can check with the GitHub CLI:
`gh attestation verify shentu_linux_amd64.tar.gz --repo nt-neil/shentu`.

`.deb` and `.rpm` packages are also attached to each release. Supported systems
(systemd is required for the patrol timers): Ubuntu 22.04 and 24.04, Debian 12, Rocky and Alma 9,
on amd64 and arm64. Tested end to end on Ubuntu 24.04, Debian 12 and Rocky 9 (arm64). `block_ip` needs
nftables, which many cloud images leave out: `apt install nftables` or `dnf install nftables`.

Not sure which model to use? [Choosing a model](docs/models.md) compares 12 models on the same
planted intrusion: accuracy, prompt-injection resistance, speed and cost.

## Configuration

See [`packaging/shentu.toml`](packaging/shentu.toml). Secrets such as bot tokens and API keys go in
`/etc/shentu/env` and are referenced as `${VAR}`.

`shentu setup` writes the model choice to `/etc/shentu/llm.toml`, which overrides `[llm]` in
`shentu.toml`; run `setup` again (or edit `llm.toml`) to change the model. For a non-interactive
setup, pass the key in `SHENTU_API_KEY`: `sudo SHENTU_API_KEY=… shentu setup --provider anthropic`.
Default models: `claude-haiku-5-5` (Anthropic), `gpt-6-luna` (OpenAI), `anthropic/claude-haiku-5-5` (OpenRouter),
`grok-4-1-fast-reasoning` (AppleToken), and on a local server the
largest of `qwen2.5:3b`/`7b`/`14b` that fits in memory. `--model` picks another one.

## Security design

- **Tool output is untrusted.** Logs and file names can be written by an attacker. The model is
  told this, and it cannot do harm on its own anyway: patrol has no control tools, and in chat
  every control action shows the exact command and waits for `y`.
- **Secrets are masked** before anything reaches the model or the log: private keys, cloud and API
  tokens, JWTs and `password=` values.
- **Self-lockout guards**: `block_ip` refuses loopback, the server's own addresses, its default
  gateway and DNS servers, and the IPs of active SSH sessions. Every block has a time limit.
- **No listening ports, no daemon, no database.** Every tool call and model call is
  recorded in `/var/lib/shentu/log.jsonl`.
- **Small attack surface**: one third-party dependency (a TOML parser), and everything else is the
  Go standard library.
- **Guarantees are tests**: `invariants_test.go` plays a hostile model and checks each rule above
  (no control tools in patrol, confirmation before every control action, lockout guards, log
  allowlist, masking, the patrol sandbox, one dependency). A change that breaks one fails CI.
  `injection_test.go` runs a real model against attacker-written log lines before each release,
  and `govulncheck` blocks a release with a known reachable vulnerability.

Report vulnerabilities as described in [SECURITY.md](SECURITY.md).

## Build

```sh
CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" .
go test ./...
```

Go 1.23 or later. Issues and pull requests are welcome; please keep the dependency count at one.

## License

[Apache-2.0](LICENSE)
