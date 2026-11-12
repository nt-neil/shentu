# Getting started

From a fresh server to daily reports in about ten minutes. [繁體中文版](getting-started.zh-TW.md)

## 0. Check the server

- Linux on amd64 or arm64. Tested end to end on Ubuntu 24.04, Debian 12 and Rocky 9; Ubuntu 22.04
  and Alma 9 are also supported.
- Root access (sudo) and systemd (for the patrol timers).
- `block_ip` needs nftables, which many cloud images leave out:

  ```sh
  sudo apt install nftables     # Ubuntu, Debian
  sudo dnf install nftables     # Rocky, Alma
  ```

- An LLM: an API key (Anthropic, OpenAI, OpenRouter or AppleToken), or a local model. A local
  model needs about 4 GB of memory for the smallest one, and nothing leaves the server.

## 1. Install

```sh
curl -fsSL https://github.com/nt-neil/shentu/releases/latest/download/install.sh | sudo sh
```

The script:

- checks the download against `checksums.txt`;
- installs `/usr/local/bin/shentu`, plus a `/usr/bin/shentu` link so that `sudo shentu` works on
  RHEL-family systems;
- creates `/etc/shentu/shentu.toml` and the root-only secrets file `/etc/shentu/env`;
- installs the systemd timers without enabling them.

To read the script first, download it with `curl -fsSLO …/install.sh`, read it, then run
`sudo sh install.sh`. `.deb` and `.rpm` packages are attached to every release as well.
Check the install:

```sh
sudo shentu version
```

On a fresh install the script then starts a guided setup, `sudo shentu setup`, that covers steps 2
to 7 with five questions and sensible defaults. The sections below explain each step and how to
do it by hand.

## 2. Choose the LLM

```sh
sudo shentu setup
```

| Choice | What happens |
|---|---|
| 1. Local model | Installs Ollama with its official script, then downloads the largest of `qwen2.5:3b`/`7b`/`14b` that fits in memory |
| 2. Anthropic | Asks for the API key; default `claude-haiku-5-5` |
| 3. OpenAI | Asks for the API key; default `gpt-6-luna` |
| 4. OpenRouter | Asks for the API key; default `anthropic/claude-haiku-5-5` |
| 5. AppleToken | Asks for the API key; default `grok-4-1-fast-reasoning` |

Setup writes `/etc/shentu/llm.toml`, stores the key in `/etc/shentu/env` (mode 600) and calls the
model once. `OK` means it is ready. Without the menu:

```sh
sudo SHENTU_API_KEY=<your key> shentu setup --provider appletoken
sudo shentu setup --local --model qwen2.5:3b
```

`--model` picks another model. [Choosing a model](models.md) compares 12 of them on accuracy,
prompt-injection resistance, speed and cost.

## 3. Set the notify channel

Webhook URLs and tokens are secrets. Put them in `/etc/shentu/env` and refer to them from the config:

```sh
# /etc/shentu/env
NOTIFY_URL=https://hooks.slack.com/services/XXX/YYY/ZZZ
```

```toml
# /etc/shentu/shentu.toml
[notify]
url = "${NOTIFY_URL}"
```

| Channel | URL |
|---|---|
| Telegram | `telegram://<bot token>@telegram?chats=<chat id>[,<chat id>]` |
| Slack | `https://hooks.slack.com/services/…` (incoming webhook) |
| Discord | `https://discord.com/api/webhooks/…` |
| ntfy | `ntfy://ntfy.sh/<your topic>[?token=<token>]` |
| Webhook | `https://…`: JSON, signed with `SHENTU_WEBHOOK_SECRET` when it is set |

**Telegram, step by step**

1. In Telegram, open **@BotFather**, send `/newbot`, and follow the prompts. It replies with the
   bot token, which looks like `123456789:AA…`.
2. Open a chat with your new bot and press **Start** (or send any message). A bot cannot write to
   you first, so this step is required.
3. Find your chat ID. On the server:

   ```sh
   curl -s "https://api.telegram.org/bot<bot token>/getUpdates" | grep -o '"chat":{"id":-\?[0-9]*'
   ```

   The number after `"id":` is the chat ID. For a group, add the bot to the group and send a message
   there first; group IDs start with `-`.
4. Put both in `/etc/shentu/env`:

   ```sh
   NOTIFY_URL=telegram://<bot token>@telegram?chats=<chat id>
   ```

5. Send a test with `sudo shentu patrol --daily`.

Long reports are split into several messages. Other useful settings in `shentu.toml`:

- `language = "繁體中文"` for answers and reports in another language;
- `[tools] log_paths` and `watch_paths` for the logs and directories to watch;
- `cert_targets = ["localhost:443"]` for certificate expiry checks.

## 4. Survey the server

```sh
sudo shentu survey
```

This lists the services and whether the network can reach them, the web and app stacks, databases,
firewall, effective SSH settings, containers, cron files and login accounts, with the risks that
follow. Patrol keeps it as the baseline and reports changes. If your apps live outside `/var/www`,
`/srv`, `/opt` or the home folders, set `[tools] app_paths`. If they run as their own account (for
example `node`), add it to `[tools] web_users`.

## 5. Try a report

```sh
sudo shentu patrol --daily --dry-run     # print only
sudo shentu patrol --daily               # send it, and check that it arrives
```

## 6. Ask questions

```sh
sudo shentu chat
> Did anyone try to brute-force SSH last night?
> Do installed packages have known vulnerabilities?
> Which ports are listening, and which programs own them?
> Any suspicious processes?
> Which files under /var/www changed recently?
```

`sudo shentu chat "When do my certificates expire?"` asks once and exits.

To block an address, say "block 203.0.113.7 for 24 hours". Shentu shows the exact `nft` command and
runs it only after you type `y`. Every block expires on its own, and "unblock 203.0.113.7" removes
it early.

## 7. Turn on patrols

```sh
sudo systemctl enable --now shentu-patrol.timer shentu-daily.timer
systemctl list-timers 'shentu*'
```

- `shentu-patrol` runs the checks every 30 minutes and notifies only about new findings. The same
  alert is not repeated within 24 hours.
- `shentu-daily` sends a report every morning.
- If the LLM is down, the raw findings are still sent.

## 8. Talk to Shentu from Telegram (optional)

`shentu bot` answers your questions in Telegram, like `shentu chat`. It uses the bot from your
`telegram://` notify URL, or `[bot] telegram_token`. It connects out to Telegram, so no port is
opened.

```sh
sudo systemctl enable --now shentu-bot
sudo shentu bot pair
```

`bot pair` prints a code. Send `/pair <code>` to your bot in a private chat. The server terminal
then asks you to approve that Telegram user with `y`. Until you approve, the bot answers no one.

- Only the paired user, in that private chat, is answered. Groups, forwarded messages and other
  bots are ignored, and strangers get no reply at all.
- The code is single use. It lasts 10 minutes and stops working after 5 wrong tries.
- Pairing and unpairing are sent to your notify channel. `sudo shentu bot unpair` revokes access,
  and `sudo shentu bot status` shows who is paired.
- What the bot may do is set by four ranges under `[bot]`, each a level from 1 (safest) to 4. The
  guided setup asks them when you choose Telegram. Defaults are marked ★.

  | Range | 1 | 2 | 3 | 4 |
  |---|---|---|---|---|
  | `interaction` | notifications only ★ | questions | + block/unblock IPs | + every control tool |
  | `answers` | problem or not | summary ★ | full, deleted after 24h | full, kept |
  | `confirm` (actions) | approve on the server (`shentu bot approve`) | ✅ + one-time code ★ (`shentu bot totp`) | ✅ only | none |
  | `protection` | strict: token leak → pause, 08–20h, 50 answers a day | standard: leak → pause ★ | loose: leak → alert | off |

  Levels live in the server's config, so only someone who can log in there can raise them. Every
  change is logged and notified. Only interaction 3 and 4 give the service the right to change the
  firewall. `/lockdown` from the paired user stops the bot at any level, and
  `sudo shentu bot resume` starts it again.
- `/new` starts a fresh conversation.
- Upgrading from an older version keeps your `shentu.toml`, so add the `[bot]` section yourself
  (see `packaging/shentu.toml`), or put the bot in a `telegram://` notify URL.

## Day to day

- Every tool call and model call is logged in `/var/lib/shentu/log.jsonl`.
- To change the model, run `sudo shentu setup` again or edit `/etc/shentu/llm.toml`.
- To add your own playbook, put it in `/etc/shentu/skills/<name>/SKILL.md`.

## Windows Server (from v0.3.0)

Windows Server 2022 and 2025 are supported (amd64; arm64 is built too), tested on GitHub's
Windows runners. Windows Server 2019 is expected to work but has not been checked on a real
host yet.

1. Download `shentu_windows_amd64.zip` and check it against `checksums.txt` or with
   `gh attestation verify shentu_windows_amd64.zip --repo nt-neil/shentu`.
2. In an elevated prompt copy `shentu.exe` to `%ProgramFiles%\Shentu` and run
   `shentu service install` (patrol) and, for Telegram, `shentu service install --bot`.
   `service install` accepts the binary only in `%ProgramFiles%\Shentu` and locks that folder to
   administrators.
3. Configuration and state live in `%ProgramData%\Shentu`, open to SYSTEM and Administrators
   only. Copy the zip's `shentu.toml` there and edit it; secrets go in `env` in the same folder
   (`NAME=value`, referenced as `${NAME}`).
4. Start them with `shentu service start` and `shentu service start --bot`. Both run as
   LocalSystem (reading the Security log needs it), each stopped and restarted on its own.

Limits: Windows is read-only (`block_ip` and `unblock_ip` are not supported); `shentu setup`
does not run on Windows yet, so the configuration is written by hand; no MSI; the binary is not
code-signed, so SmartScreen may warn and Microsoft Defender or another antivirus may flag it
(Shentu reads the event log, autostart keys and WMI subscriptions, as malware scanners do).
Full steps: `packaging/windows/INSTALL.md`.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `sudo: shentu: command not found` | Install again with the latest `install.sh`, or run `sudo /usr/local/bin/shentu` |
| A block fails with "nft not found" | Install nftables (step 0) |
| `LLM unavailable` in a report | Check the key and the network; for a local model, `systemctl status ollama` |
| Patrol says `notify failed` | Check the URL in `/etc/shentu/env`; findings are kept and sent next time |

## What Shentu will and will not do

- It never changes the system without your `y`. It also refuses to block loopback, the server's own
  addresses, its gateway and DNS servers, and the addresses of active SSH sessions.
- Passwords, keys and tokens are masked before anything goes to the model. Log lines still go to the
  model you chose; use a local model if no data may leave the server.
- Logs can contain text written by an attacker. Small local models are easier to fool, which is why
  control actions are also guarded in code and always need confirmation.
