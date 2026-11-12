# Shentu on Windows Server

[English](#english) · [繁體中文](#繁體中文)

## English

Supported: Windows Server 2022 and 2025 (tested on GitHub's runners);
Windows Server 2019 builds and is expected to work but has not been tested
on a real host yet. amd64 is the release target; arm64 is built too.

### Install

Run these in an elevated prompt (Run as administrator):

```
mkdir "%ProgramFiles%\Shentu"
copy shentu.exe "%ProgramFiles%\Shentu\"
cd /d "%ProgramFiles%\Shentu"
shentu.exe service install
copy shentu.toml "%ProgramData%\Shentu\shentu.toml"
notepad "%ProgramData%\Shentu\shentu.toml"
shentu.exe service start
```

`service install` also creates `%ProgramData%\Shentu` with its protected
permissions. In `shentu.toml` set `[llm]` (a local Ollama, or an API with
`api_key_env`) and `[notify] url`. Secrets go in `%ProgramData%\Shentu\env`,
one `NAME=value` per line, referenced as `${NAME}` (`shentu setup` does not
run on Windows yet).

The Telegram bot is a second service, optional:

```
shentu.exe service install --bot
shentu.exe service start --bot
```

`service install` only accepts `shentu.exe` in `%ProgramFiles%\Shentu`:
it sets that folder to administrators-only (a user who could replace the
binary would run code as SYSTEM). Elsewhere it refuses.

- Configuration and state: `%ProgramData%\Shentu` (`shentu.toml`, `env`,
  `state\`), readable and writable by SYSTEM and Administrators only.
  Shentu refuses a configuration folder anyone else owns or can write.
- Services: `Shentu` (patrol every 30 minutes, daily report at 09:00) and
  `ShentuBot`, both LocalSystem, started automatically, restarted on
  failure. `shentu service status [--bot]`, `stop`, `uninstall`.
- The bot token stays in the protected configuration; it is never in the
  service command line or the event log.

### Permissions

The services run as LocalSystem: reading the Security event log, the
scheduled-task store and other users' processes needs it. Run `shentu`
from an elevated prompt; unelevated, some checks report "unknown".

### Limits (v0.3.0)

- Read-only: `block_ip` and `unblock_ip` are not supported on Windows;
  Shentu reports, it does not change the host.
- Windows Server 2019 has not been checked on a real host yet.
- The binary is not code-signed. SmartScreen may warn when it is started,
  and Microsoft Defender or another antivirus may flag it (it reads the
  event log, the registry's autostart keys and WMI subscriptions, as
  malware scanners do). Check the download against `checksums.txt` and the
  release attestation:
  `gh attestation verify shentu_windows_amd64.zip --repo nt-neil/shentu`.
- No MSI installer yet, and `shentu setup` does not run on Windows yet:
  the configuration is written by hand (see Install).

## 繁體中文

支援 Windows Server 2022 與 2025（在 GitHub 的 runner 上測試過）；
Windows Server 2019 可以建置，預期可用，但尚未在實機上驗證。正式發布以
amd64 為主，arm64 也一併建置。

### 安裝

在系統管理員權限的命令列（以系統管理員身分執行）中：

```
mkdir "%ProgramFiles%\Shentu"
copy shentu.exe "%ProgramFiles%\Shentu\"
cd /d "%ProgramFiles%\Shentu"
shentu.exe service install
copy shentu.toml "%ProgramData%\Shentu\shentu.toml"
notepad "%ProgramData%\Shentu\shentu.toml"
shentu.exe service start
```

`service install` 會一併建立權限受保護的 `%ProgramData%\Shentu`。在
`shentu.toml` 設定 `[llm]`（本機 Ollama，或用 `api_key_env` 指定 API 金鑰的
環境變數）與 `[notify] url`。金鑰寫在 `%ProgramData%\Shentu\env`，一行一個
`NAME=value`，設定檔中以 `${NAME}` 引用（Windows 上目前還不能用 `shentu setup`）。

Telegram bot 是另一個服務，可選：

```
shentu.exe service install --bot
shentu.exe service start --bot
```

`service install` 只接受放在 `%ProgramFiles%\Shentu` 的 `shentu.exe`，並把該
資料夾設為只有系統管理員能寫入（能替換執行檔的人，就能以 SYSTEM 身分執行
程式）。放在其他位置會拒絕安裝。

- 設定與狀態：`%ProgramData%\Shentu`（`shentu.toml`、`env`、`state\`），只有
  SYSTEM 和 Administrators 能讀寫。若設定資料夾的擁有者或寫入權限不是這兩者，
  Shentu 會拒絕載入。
- 服務：`Shentu`（每 30 分鐘巡檢、每天 09:00 日報）與 `ShentuBot`，都以
  LocalSystem 執行、開機自動啟動、失敗自動重啟。指令：
  `shentu service status [--bot]`、`stop`、`uninstall`。
- bot token 只存在受保護的設定檔中，不會出現在服務命令列或事件記錄。

### 權限需求

服務以 LocalSystem 執行：讀取 Security 事件記錄、排程工作與其他使用者的
程序都需要這個權限。手動執行 `shentu` 請用系統管理員權限的命令列；未提權時，
部分檢查會回報「無法判斷」。

### 目前的限制（v0.3.0）

- 只讀不寫：Windows 上不支援 `block_ip`、`unblock_ip`，Shentu 只回報，不改動主機。
- Windows Server 2019 尚未在實機上驗證。
- 執行檔沒有程式碼簽章。啟動時 SmartScreen 可能出現警告，Microsoft Defender
  或其他防毒也可能誤判（Shentu 會讀取事件記錄、登錄檔的自動啟動機碼與 WMI
  訂閱，行為與惡意程式掃描工具相似）。請用 `checksums.txt` 與發布證明核對下載檔：
  `gh attestation verify shentu_windows_amd64.zip --repo nt-neil/shentu`。
- 目前沒有 MSI 安裝檔；`shentu setup` 也還不能在 Windows 上執行，設定需要手動
  撰寫（見「安裝」）。
