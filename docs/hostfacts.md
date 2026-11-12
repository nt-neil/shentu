# hostfacts/1: the host facts schema

Shentu has two core modules. The **rules engine** (`rules/engine`) analyses application code. The
**host environment module** (`hostenv`) analyses the machine.

`hostenv` detects the platform, reads system files and APIs, and runs a few read-only commands. It
returns one normalized document, `hostenv.Facts`. Host checks (`checks`) read that document and
nothing else, so the same check works on every platform that has a collector.

```
patrol / survey / bot / LLM tools
        │
     checks ── reads ──> hostenv.Facts  (schema hostfacts/1)
                              ▲
                     Collector (linux, windows, …)
                              ▲
                     Source (Live | Recorder | Replay)
```

## Versioning

- `schema` is `"hostfacts/1"`.
- Adding a field, a `kind` value or a `reason` keeps the version. Consumers must ignore fields
  they do not know.
- Renaming or removing a field, or changing what an existing field means, bumps it to
  `hostfacts/2`. Checks then declare which versions they read.
- `collector.version` (currently `0.1.0`) changes whenever a collector gathers something new or
  gathers it differently. Golden fixtures pin both versions.

## Observations: never mistake "unknown" for "empty"

Every fact is wrapped in an observation:

```json
{ "status": "partial", "reason": "permission_denied", "detail": "…", "value": … }
```

| status           | meaning                                                   | what checks do                            |
|------------------|-----------------------------------------------------------|-------------------------------------------|
| `ok`             | complete                                                  | judge `value`                             |
| `partial`        | usable, but some entries are missing; `reason` says why   | judge `value`, and may add a `cannot_tell` |
| `unknown`        | could not be determined                                   | one `cannot_tell` finding (無法判斷)      |
| `not_applicable` | the platform has no such thing (RDP on Linux)             | stay silent                               |
| `error`          | the collector itself failed                               | one `cannot_tell` finding                 |

A missing or unreadable fact never passes a check. A check that needs a fact the collector marked
`unknown` reports `cannot_tell` with that fact's `reason`.

| reason                  | typical cause                                               |
|-------------------------|-------------------------------------------------------------|
| `permission_denied`     | not root or not an elevated Administrator                   |
| `not_installed`         | the file, command or service does not exist                 |
| `timeout`               | a command ran past its timeout                              |
| `output_truncated`      | output over the cap, or a category over its item cap        |
| `not_collected`         | this collector does not gather the fact yet                 |
| `unsupported_platform`  | no collector exists for this OS                             |
| `not_recorded`          | a replayed fixture lacks the data (the collector changed)   |
| `command_failed`        | non-zero exit, or another failure                           |
| `symlink_not_followed`  | a user-controlled path was a link and was not followed      |
| `not_regular_file`      | a FIFO, device or socket where a file was expected          |

## Fields

| field | type | Linux source (collector 0.1.0) | Windows source (Phase 2) |
|---|---|---|---|
| `platform` | `os`, `family`, `distro`, `version`, `pretty_name`, `build`, `kernel`, `arch`, `in_container`, `server_core` | `/etc/os-release`, `/proc/sys/kernel/osrelease`, container markers | registry `CurrentVersion` (`CurrentBuild`, `UBR`, `InstallationType`) |
| `privilege` | `elevated` | effective uid 0 | token elevation |
| `resources` | `mem_total_bytes`, `mem_available_bytes`, `load1`, `cgroup_memory_limit`, `cgroup_cpus` | `/proc/meminfo`, `/proc/loadavg`, the collector's own cgroup limits | `GlobalMemoryStatusEx` (Phase 2) |
| `packages` | `manager`, `ecosystem` (OSV), `items[]` (`name`, `source`, `version`, `arch`) | `dpkg-query`, `rpm -qa`, `/lib/apk/db/installed` | registry `Uninstall` keys (HKLM, WOW6432Node, HKU) |
| `patches` | `[]{id, installed_on}` | not applicable (patches are package versions) | WMI `Win32_QuickFixEngineering`; build+UBR is the main signal |
| `services` | `[]{name, exe, start_mode, state, run_as}` | not collected yet (Phase 1c) | SCM (`svc/mgr`) |
| `processes` | `[]{pid, ppid, name, exe, exe_known, exe_exists, in_temp, cmdline, user, uid, started, start_ticks}` | `/proc/<pid>/{comm,status,cmdline,exe,stat}`, mtime of `/proc/<pid>` | Toolhelp32 + `QueryFullProcessImageName`; WMI for command lines |
| `accounts` | `[]{name, uid, home, shell, can_login, is_admin, disabled}` | `/etc/passwd`, `/etc/group` (sudo, wheel, admin) | `NetUserEnum`, Administrators (S-1-5-32-544) members |
| `listeners` | `[]{proto, addr, port, pid, process, uid}` (one row per owner: a second process on a port stays visible) | `/proc/net/{tcp,udp}{,6}` + `/proc/*/fd` | `GetExtendedTcpTable` / `GetExtendedUdpTable` |
| `persistence` | `[]{kind, location, command, detail}` | cron and cron files, `ld.so.preload`, `rc.local`, `/etc/systemd/system`, `authorized_keys`, sudo rules, PAM modules no package installed |
| `ssh_keys` | `[]{user, path, lines, modified, keys[], unparsed, unread}` | `~/.ssh/authorized_keys{,2}` of every account, read without following a final symlink | Phase 2 (`administrators_authorized_keys`) | Run keys, services, scheduled tasks, WMI subscriptions, startup folders, IFEO |
| `firewall` | `backend`, `enabled`, `default_inbound`, `profiles`, `extra` | ufw config, firewalld running, `nft list ruleset`, nftables at boot, `iptables -S`; `extra.summary` is survey's line | `INetFwPolicy2` / registry `FirewallPolicy` |
| `remote_access.ssh` | `config_path`, `settings`, `unread`, `hash` | `sshd_config` with `Include`, up to the first `Match` | `C:\ProgramData\ssh\sshd_config` (same parser) |
| `remote_access.rdp` | `enabled`, `nla`, `port`, `security_layer` | not applicable | registry `Terminal Server`, `RDP-Tcp` |
| `remote_access.winrm` | `running`, `http_listener`, `allow_unencrypted`, `basic_auth` | not applicable | registry `WSMAN\Service`, policy keys, ports 5985/5986 |
| `remote_access.smb` | `smb1_enabled`, `signing_required`, `writable_shares` | not collected yet (Samba) | registry `LanmanServer\Parameters`, `NetShareEnum` |
| `antimalware` | `product`, `real_time`, `signature_age_days`, `exclusions` | not applicable | WMI `MSFT_MpComputerStatus`, `MSFT_MpPreference` |
| `auth_events` | `window_hours`, `failed_by_source`, `notable[]` | auth/secure logs (rotated, gzipped) or journald, streamed | Event Log 4625, 4624 type 10, 1102, 4720, 4732, 7045 |
| `web` | `server`, `webroots`, `upload_dirs` | nginx `root` and Apache `DocumentRoot` lines (upload folders: the code audit) | `applicationHost.config` |

`persistence.kind` values: `cron`, `cron_file`, `systemd`, `ld_preload`, `rc_local`,
`authorized_key`, `authorized_key_unparsed`, `sudo_rule`, `pam_unpackaged`, and on Windows `run_key`
(`detail` tells `winlogon`, `ifeo` and `appinit_dlls` apart), `service`, `schtask`,
`wmi_subscription`, `startup_folder`. macOS uses `launchd`.

`auth_events.notable[].kind` values: `log_cleared`, `account_created`, `group_member_added`,
`service_installed`.

## Large inputs

Logs and long command output are streamed line by line (`ScanLines`, `RunLines`; `.gz` is
unpacked on the fly), never read whole: Shentu must run on a 512 MB machine. Login events are
counted by `SSHLogins`, which tracks at most 2048 sources (exact up to that, then the least
active source that never logged in makes room). Measured: a 200 MB auth.log peaks at about
6 MB of heap.

## What never goes into facts

- File contents. Facts keep paths, hashes and the parsed fields that checks need.
- Secrets. Every Source runs its output through `MaskSecrets` before a parser sees it, and command
  lines are masked again and capped at 512 bytes.
- SSH public keys. Only the type and the SHA256 fingerprint are kept.

## Commands

Collectors list every command they may run as an exact argv (`Collector.Allowlist`). The runner:

- refuses anything off the list, relative paths, shells and script hosts (including `powershell`
  and `cmd`);
- applies a timeout (10 s by default, 60 s at most);
- caps stdout at 4 MiB and stderr at 64 KiB;
- passes a fixed environment and no stdin.

On Windows the plan is to run no commands at all, using registry, SCM, WMI and the Event Log
instead.

## Fixtures

`go run ./cmd/hostfacts -record DIR` on a real host saves every read and command result as
`hostenv-fixture/1`: a `manifest.json` plus content-addressed `blobs/`.

Before anything is written, the recording is masked. The masker replaces:

- host names and human users;
- IP addresses, keeping their class: private addresses become 10/8, public ones become
  198.51.100/24, and loopback stays as it is;
- GECOS fields;
- SSH keys and their comments.

Review the fixture and run gitleaks before you commit it. `TestReplayGolden` then replays each
fixture under `hostenv/testdata/<os>/<case>` and compares the result with `facts.golden.json`; run
it with `-update` once the change is intended.
