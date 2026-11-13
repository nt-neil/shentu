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
| `untrusted_owner`       | readable, but owned or writable by someone other than root (Windows: SYSTEM, Administrators, TrustedInstaller); the content is not used |
| `unverified_source`     | read, but the source does not record who wrote it, so a local user could have forged it (text auth logs, busybox `/var/log/messages`) |

## Fields

| field | type | Linux source | Windows source |
|---|---|---|---|
| `platform` | `os`, `family`, `distro`, `version`, `pretty_name`, `build`, `kernel`, `arch`, `in_container`, `server_core` | `/etc/os-release`, `/proc/sys/kernel/osrelease`, container markers | registry `CurrentVersion` (`CurrentBuild`, `UBR`, `InstallationType`) |
| `privilege` | `elevated` | effective uid 0 | token elevation |
| `resources` | `mem_total_bytes`, `mem_available_bytes`, `load1`, `cgroup_memory_limit`, `cgroup_cpus` | `/proc/meminfo`, `/proc/loadavg`, the collector's own cgroup limits | not collected yet |
| `packages` | `manager`, `ecosystem` (OSV), `feed` (see below), `items[]` (`name`, `source`, `version`, `arch`) | `dpkg-query`, `rpm -qa`, `/lib/apk/db/installed`; `feed` from `/etc/os-release` | registry `Uninstall` keys (HKLM, WOW6432Node, HKU) |
| `patches` | `[]{id, installed_on}` | not applicable (patches are package versions) | registry Component Based Servicing packages, one per KB in the Installed state; build+UBR in `platform` is the main signal |
| `services` | `[]{name, exe, start_mode, state, run_as}` | OpenRC: `/etc/init.d` and `/usr/local/etc/init.d` scripts, `start_mode` `auto` when linked from any `/etc/runlevels` folder, else `manual`; systemd not collected yet | SCM (`svc/mgr`) |
| `processes` | `[]{pid, ppid, name, exe, exe_known, exe_exists, in_temp, cmdline, user, uid, started, start_ticks}` | `/proc/<pid>/{comm,status,cmdline,exe,stat}`, mtime of `/proc/<pid>` | Toolhelp32 + `QueryFullProcessImageName`; `NtQueryInformationProcess` (ProcessCommandLineInformation) for command lines |
| `accounts` | `[]{name, uid, home, shell, can_login, is_admin, disabled}` | `/etc/passwd`, `/etc/group` (sudo, wheel, admin) | `NetUserEnum`, Administrators (S-1-5-32-544) members |
| `listeners` | `[]{proto, addr, port, pid, process, uid}` (one row per owner: a second process on a port stays visible) | `/proc/net/{tcp,udp}{,6}` + `/proc/*/fd` | `GetExtendedTcpTable` / `GetExtendedUdpTable` |
| `persistence` | `[]{kind, location, command, detail}` | cron and cron files (`/etc/crontabs` and `/etc/periodic/*` for busybox crond), `ld.so.preload`, `rc.local`, `/etc/systemd/system`, enabled OpenRC scripts, `/etc/local.d`, `/etc/inittab`, `authorized_keys`, sudo rules, PAM modules no package installed | Run keys, services, scheduled tasks, WMI subscriptions, startup folders, IFEO |
| `ssh_keys` | `[]{user, path, modified, keys[{line, type, fingerprint, options, cloud_init_refusal}], unparsed_lines, unread}` | `~/.ssh/authorized_keys{,2}` of every account, read without following a final symlink; a home that is not a folder (`/dev/null`) has none | not collected yet |
| `firewall` | `backend`, `enabled`, `default_inbound`, `profiles`, `extra` | ufw config, firewalld running, `nft list ruleset`, nftables at boot, `iptables -S` (`/sbin/iptables` too); `extra.summary` is survey's line | `INetFwPolicy2` / registry `FirewallPolicy` |
| `remote_access.ssh` | `config_path`, `settings`, `unread`, `hash` | `sshd_config` with `Include` (relative to the main file's folder, sorted): the main file's first `Match` ends the global part, one in an included file ends only that file; at most 4 levels of Include and 256 files, more listed in `unread` | `C:\ProgramData\ssh\sshd_config` (same parser), `Include` followed as sshd does (relative to `C:\ProgramData\ssh`, globs sorted, first value wins, no network paths). Every file read and every folder up to `C:\ProgramData\ssh`, `C:\ProgramData` or the drive root must be owned and writable only by SYSTEM, Administrators or TrustedInstaller; otherwise unknown with `untrusted_owner` and no setting used. A `Match` in an included file ends that file only. A missing target that users could create (nothing exists up to `C:\ProgramData` or the drive root), a folder that is a link someone else may change, or a link to a missing target: `untrusted_owner`. An include that cannot be read, nesting past 4, or more than 256 files: partial, later settings `unknown`. Include was checked with sshd 9.5p2 on the windows-2025 runner; the windows-2022 runner has no sshd |
| `remote_access.rdp` | `enabled`, `nla`, `port`, `security_layer` | not applicable | registry `Terminal Server`, `RDP-Tcp` |
| `remote_access.winrm` | `running`, `http_listener`, `allow_unencrypted`, `basic_auth` | not applicable | registry `WSMAN\Service`, policy keys, ports 5985/5986 |
| `remote_access.smb` | `smb1_enabled`, `signing_required`, `writable_shares` | not collected yet (Samba) | registry `LanmanServer\Parameters`, `NetShareEnum` |
| `antimalware` | `product`, `real_time`, `signature_age_days`, `exclusions` | not applicable | WMI `MSFT_MpComputerStatus`; exclusions from the registry (Defender `Exclusions` and its policy key) |
| `protections` | `integrity`, `app_verification`, `disk_encryption` (each `on`, `off` or `""`), `extra` | not collected yet | not collected yet (BitLocker) |
| `auth_events` | `window_hours`, `failed_by_source`, `notable[]` | journald's ssh and sshd units first, then the ssh@ and sshd@ units of a socket-activated sshd (since the snapshot minus 24 h, at most `JournalTimeout`, 60 s): ok. No sshd entry and no text auth log to compare: partial with `unverified_source` (journald may not keep them). Text auth/secure logs (rotated, gzipped, streamed) when journald is missing, fails, times out or has no sshd entries, and without journald busybox `/var/log/messages` (sshd lines of the auth and authpriv facilities only): partial with `unverified_source`. Neither readable: unknown (a journal that hides the system's entries from a non-root user is `permission_denied`, not "no failed logins") | Event Log 4625, 4624 type 10, 1102, 4720, 4732, 7045 |
| `web` | `server`, `webroots`, `upload_dirs`, `config_unreadable` ("path (why)") | nginx `root` and Apache `DocumentRoot` lines (upload folders: the code audit) | `applicationHost.config` |

`persistence.kind` values: `cron`, `cron_file`, `systemd`, `openrc` (`detail` names the runlevels,
and says so when no package installed the script; a runlevel entry that stacks another runlevel,
or names no script, is listed on its own), `local_d`, `inittab` (busybox init: `detail` is the
action, `command` the process), `ld_preload`, `rc_local`,
`authorized_key`, `authorized_key_unparsed`, `sudo_rule`, `pam_unpackaged`, and on Windows `run_key`
(`detail` tells `winlogon`, `ifeo` and `appinit_dlls` apart), `service`, `schtask`,
`wmi_subscription`, `startup_folder`. macOS uses `launchd` (`detail` says daemon, agent or user
agent, the folder, and whether it runs at load or is kept alive), `cron` (also periodic scripts),
`periodic_conf`, `at_job`, `security_agent_plugin`, `startup_item`, `login_hook`, `sudo_rule` and
`authorized_key`.

`packages.feed` says where the host's security fixes are published:

| distribution (`ID`) | `kind` | `ecosystems` / `release` | `version_fmt` | `upgrade` |
|---|---|---|---|---|
| debian, ubuntu | `osv` | `Debian:12`, `Ubuntu:24.04:LTS` | `evr` | `apt-get update && apt-get upgrade` |
| rocky, almalinux | `osv` | `Rocky Linux:9`, `AlmaLinux:9` | `evr` | `dnf upgrade --security` |
| alpine | `osv` | `Alpine:v3.22` | `evr` | `apk upgrade` |
| opensuse-leap | `osv` | `openSUSE:Leap 15.6` | `vr` | `zypper patch --category security` |
| opensuse-tumbleweed, opensuse-slowroll | `osv` | `openSUSE:Tumbleweed` | `vr` | `zypper dup` |
| sles | `osv` | one per SLE 15 module, e.g. `SUSE:Linux Enterprise Module for Basesystem 15 SP5`, with Python 3, HPC, Live Patching, High Availability Extension and `SUSE:Package Hub 15 SP5`; Real Time is no OSV ecosystem and is listed in `not_queried` when the host has it (`/etc/products.d/SLE_RT.prod` or `kernel-rt`) | `vr` | `zypper patch --category security` |
| sled | `osv` | the modules a desktop has (Basesystem, Desktop Applications, Development Tools, Python 3, Workstation Extension, Package Hub); `SUSE:Linux Enterprise Desktop` is no OSV ecosystem, which `note` says (its packages are in the modules, so nothing goes unchecked) | `vr` | `zypper patch --category security` |
| sles_sap | `osv` | the sles modules and `SUSE:Linux Enterprise Server for SAP Applications 15 SP5`; `Module for SAP Applications` is no OSV ecosystem and is listed in `not_queried`, as is SLES for SAP 12 | `vr` | `zypper patch --category security` |
| macos (darwin) | `apple` | `release` is the major version; Apple's software update catalog (gdmf.apple.com) gives the newest release of each major version; a version newer than every listed one (a beta) is cannot tell | | `softwareupdate --install --all` |
| amzn | `alas` | `release` `2` or `2023`; on 2, `repos` lists the amazon-linux-extras topics enabled (`kernel-5.10`, `php8.2`), whose updateinfo is read too | | `yum update --security` (2), `dnf upgrade --security` (2023) |

`version_fmt` `vr` means OSV spells rpm versions without a `0:` epoch. `alas` is matched against
the release's public `updateinfo.xml` (cdn.amazonlinux.com), streamed. An unknown distribution has
no `feed`; neither has Amazon Linux 1 (2018.03), past its end of life, so `package_vulns` answers
cannot tell.

On Windows, `firewall.profiles` maps `Domain`, `Private` and `Public` to whether that profile is
on, and `extra.active_profiles` lists the profiles in force now, comma-separated.
`default_inbound` is `block` only when every active profile is on and either blocks all inbound
traffic or does not allow unmatched inbound connections; otherwise `allow`. It is empty, and
`active_profiles` absent, when no profile is known to be active, which is always the case when
`INetFwPolicy2` is unavailable and the registry is read instead. `extra.service` is the state
of the firewall service (MpsSvc); when it is not `running`, every profile counts as off and a
known `default_inbound` becomes `allow`.

`auth_events.notable[].kind` values: `log_cleared`, `account_created`, `group_member_added`,
`service_installed`.

## macOS

The darwin collector reads, as whoever runs it and never with sudo:

| fact | source |
|---|---|
| `platform` | `SystemVersion.plist` (`sw_vers` if missing), `sysctl kern.osrelease`; `family` and `distro` are `macos` |
| `resources` | `sysctl hw.memsize vm.loadavg` (available memory not known) |
| `packages` | Homebrew `Cellar` and `Caskroom` folders (`source` `homebrew`, `homebrew-cask`), `/Applications` `Info.plist` (`source` `app`, name is the bundle id); always `partial`: installer receipts are not listed. `feed.kind` `apple`: only the OS version can be checked (OSV has no Homebrew ecosystem) |
| `services` | launchd jobs in `/Library/LaunchDaemons`, `/Library/LaunchAgents` and each login account's `~/Library/LaunchAgents` (wherever the home is; a link anywhere below the home is not followed); `/System` is Apple's sealed volume and is not reported. `exe` is `Program` or the first of `ProgramArguments`, whole; a daemon runs as its `UserName` (root when none); launchctl's overrides decide `disabled`: `/var/db/com.apple.xpc.launchd/disabled.plist` a daemon's, `disabled.<uid>.plist` that user's agents' (both readable by every user); one that cannot be read is said in the detail. With accounts unknown (dscl failed), user LaunchAgents are listed as not read. At most 64 arguments and 512 bytes of a command are kept (partial when cut) |
| `processes` | `ps` (`comm` is the executable, `args` the masked command line, `etime` gives the start time); `partial` when the command lines were cut short or could not be read |
| `accounts` | `dscl . -list /Users` (UniqueID, UserShell, NFSHomeDirectory) and the `admin` group; `partial`, saying which, when one of these queries fails |
| `listeners` | `netstat -anv`; macOS may hide every Internet socket from a program's `netstat`, and then `lsof` lists this user's processes and the fact is `partial`; output past the cap is kept as far as read, `partial` |
| `persistence` | launchd jobs, `/etc/crontab`, `/usr/lib/cron/tabs` (root), periodic scripts, `/etc/periodic.conf(.local)` and `/etc/daily.local`, `weekly.local`, `monthly.local` listed line by line as `periodic_conf` (every line but blanks and plain comments: a `#` line with no quote, `$` or backtick, as a heredoc runs those; no shell is simulated), the files `periodic_conf_files` names (also when exported), `/etc/defaults/periodic.conf` left out only when it is a stock file (sha256 of Apple's published versions), the folders `local_periodic` names (also `export local_periodic=`), at jobs in `/usr/lib/cron/jobs` (`at_job`, root), `/Library/Security/SecurityAgentPlugins` (`security_agent_plugin`), `/Library/StartupItems` (`startup_item`), LoginHook and LogoutHook in `com.apple.loginwindow` (`login_hook`), sudoers (root), authorized_keys. Login items are not read at all (the Background Task Management store is not parsed, as root either), so the fact is always `partial` and says so; every location that could not be read is listed in the detail |
| `firewall` | `socketfilterfw` (`backend`, `enabled`; `extra.block_all`, `extra.stealth`, `extra.mode`), `pfctl -s info` (`extra.pf` only: pf enabled with rules unread does not make the firewall enabled; `unknown` without root) |
| `protections` | `csrutil status` (SIP), `spctl --status` (Gatekeeper), `fdesetup status` (FileVault) |
| `antimalware` | XProtect: the newer of its two bundles gives version and signature age; `real_time` is assumed (macOS has no switch to turn XProtect off) and the detail says so. The `antimalware.stale_signatures` check allows XProtect 30 days |
| `remote_access.ssh` | `/etc/ssh/sshd_config`, the Linux parser |

`system_profiler` and `ioreg` are never on the allowlist: they print the serial number and the
hardware UUID.

## Large inputs

Logs and long command output are streamed line by line (`ScanLines`, `RunLines`; `.gz` is
unpacked on the fly), never read whole: Shentu must run on a 512 MB machine. Login events are
counted by `SSHLogins`, which tracks at most 2048 sources (exact up to that, then the least
active source that never logged in makes room). Measured: a 200 MB auth.log peaks at about
6 MB of heap.

## What never goes into facts

- File contents. Facts keep paths, hashes and the parsed fields that checks need.
- Secrets. File contents reach the parsers raw (masking them corrupted facts such as sudo's
  `NOPASSWD:ALL` or sshd's `sk-ssh-ed25519-cert-v01@openssh.com`), but every free-text field that
  leaves — command lines (capped at 512 bytes), cron and systemd commands, streamed log lines,
  command output — is masked with `MaskSecrets`, and fixtures are masked by the Masker.
- SSH public keys. Only the type and the SHA256 fingerprint are kept.

## Commands

Collectors list every command they may run as an exact argv (`Collector.Allowlist`). The runner:

- refuses anything off the list, relative paths, shells and script hosts (including `powershell`
  and `cmd`);
- applies a timeout (10 s by default, 60 s at most);
- caps stdout at 4 MiB and stderr at 64 KiB;
- passes a fixed environment and no stdin.

On Windows no command is run (the allowlist is empty): the collector reads the registry, SCM,
WMI, the Event Log and Win32 APIs.

## Fixtures

`go run ./cmd/hostfacts -record DIR` on a real host saves every read and command result as
`hostenv-fixture/1`: a `manifest.json` plus content-addressed `blobs/`.

Before anything is written, the recording is masked. The masker replaces:

- host names and human users;
- IP addresses, keeping their class: private addresses become 10/8, public ones become
  198.51.100/24, and loopback stays as it is;
- GECOS fields;
- SSH keys and their comments;
- `.local` host names, UUIDs and email addresses (not OpenSSH algorithm names such as
  `aes256-gcm@openssh.com`, nor file names such as `com.example.db@2.plist`);
- paths below a human user's home, except `.ssh` and `Library/LaunchAgents`, which become
  `redactedN`.

On a person's own machine, add `-drop-args`: process command lines are then recorded as the
executable only, since arguments can hold anything. `-mask-host NAME` masks further names, such as
an old host name or a company name.

Review the fixture and run gitleaks before you commit it. `TestReplayGolden` then replays each
fixture under `hostenv/testdata/<os>/<case>` and compares the result with `facts.golden.json`; run
it with `-update` once the change is intended.
