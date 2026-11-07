# 安裝與使用說明

從一台新伺服器，到每天收到資安日報，大約 10 分鐘。[English](getting-started.md)

## 0. 確認環境

- Linux，amd64 或 arm64。實測過 Ubuntu 24.04、Debian 12、Rocky 9；也支援 Ubuntu 22.04、Alma 9。
- 要有 root 權限（sudo），以及 systemd（自動巡邏的排程要用）。
- 「封鎖 IP」功能需要 nftables，很多雲端映像檔沒有預先安裝：

  ```sh
  sudo apt install nftables     # Ubuntu、Debian
  sudo dnf install nftables     # Rocky、Alma
  ```

- AI 模型二選一：
  - 雲端 API 金鑰：Anthropic、OpenAI、OpenRouter 或 AppleToken。
  - 本機模型：最小的模型約需 4GB 記憶體，資料完全不會離開伺服器。

## 1. 一行安裝

```sh
curl -fsSL https://github.com/nt-neil/shentu/releases/latest/download/install.sh | sudo sh
```

安裝程式會做這些事：

- 下載後用 `checksums.txt` 核對檔案；
- 把程式裝到 `/usr/local/bin/shentu`，並建立 `/usr/bin/shentu` 連結，讓紅帽系的 `sudo shentu` 也找得到；
- 建立設定檔 `/etc/shentu/shentu.toml`，以及只有 root 讀得到的金鑰檔 `/etc/shentu/env`；
- 裝好 systemd 排程，但先不啟用。

想先看過腳本內容的話，用 `curl -fsSLO …/install.sh` 下載下來，看完再執行 `sudo sh install.sh`。每個版本也都附有 `.deb` 和 `.rpm` 套件。裝完確認一下：

```sh
sudo shentu version
```

## 2. 選擇 AI 模型

```sh
sudo shentu setup
```

| 選項 | 說明 |
|---|---|
| 1. 本機模型 | 用 Ollama 官方腳本安裝 Ollama，再依記憶體大小，從 `qwen2.5:3b`/`7b`/`14b` 挑最大放得下的 |
| 2. Anthropic | 貼上 API 金鑰，預設 `claude-haiku-5-5` |
| 3. OpenAI | 貼上 API 金鑰，預設 `gpt-6-luna` |
| 4. OpenRouter | 貼上 API 金鑰，預設 `anthropic/claude-haiku-5-5` |
| 5. AppleToken | 貼上 API 金鑰，預設 `grok-4-1-fast-reasoning` |

設定完成後，它會：

- 把設定寫進 `/etc/shentu/llm.toml`；
- 把金鑰存進 `/etc/shentu/env`（權限 600）；
- 實際呼叫一次模型。

看到 `OK` 就代表可以用了。不想用選單的話，可以這樣設定：

```sh
sudo SHENTU_API_KEY=<你的金鑰> shentu setup --provider appletoken
sudo shentu setup --local --model qwen2.5:3b
```

加上 `--model` 可以換成其他模型。不知道選哪個的話，可以看[模型評測](models.md)：12 個模型在準確度、抗提示注入、速度和成本上的比較。

## 3. 設定通知管道

Webhook 網址和 token 都是機密，放在 `/etc/shentu/env` 裡，設定檔只寫變數名稱：

```sh
# /etc/shentu/env
NOTIFY_URL=https://hooks.slack.com/services/XXX/YYY/ZZZ
```

```toml
# /etc/shentu/shentu.toml
[notify]
url = "${NOTIFY_URL}"
```

| 管道 | 網址格式 |
|---|---|
| Telegram | `telegram://<bot token>@telegram?chats=<chat ID>[,<chat ID>]` |
| Slack | `https://hooks.slack.com/services/…`（Incoming Webhook） |
| Discord | `https://discord.com/api/webhooks/…` |
| ntfy | `ntfy://ntfy.sh/<自訂主題>[?token=<token>]`，手機裝 ntfy App 訂閱這個主題就能收到 |
| 自架 Webhook | `https://…`，送出 JSON；有設 `SHENTU_WEBHOOK_SECRET` 的話會附上簽章 |

**Telegram 設定步驟**

1. 在 Telegram 打開 **@BotFather**，傳 `/newbot`，照提示幫 bot 取名。完成後它會給你 bot token，長得像 `123456789:AA…`。
2. 打開跟新 bot 的對話，按「開始」（Start），或隨便傳一句話。bot 不能主動找人說話，所以這一步一定要做。
3. 查出你的 chat ID。在伺服器上執行：

   ```sh
   curl -s "https://api.telegram.org/bot<bot token>/getUpdates" | grep -o '"chat":{"id":-\?[0-9]*'
   ```

   `"id":` 後面那串數字就是 chat ID。要發到群組的話，先把 bot 拉進群組，在群組裡傳一句話再查；群組的 ID 開頭是 `-`。
4. 把兩個值寫進 `/etc/shentu/env`：

   ```sh
   NOTIFY_URL=telegram://<bot token>@telegram?chats=<chat ID>
   ```

5. 用 `sudo shentu patrol --daily` 發一份報告測試。

報告太長時，會自動分成好幾則送出。`shentu.toml` 裡另外幾個常用設定：

- `language = "繁體中文"`：回答和報告改用中文；
- `[tools] log_paths`、`watch_paths`：要讀的 log 檔，以及要監控的目錄；
- `cert_targets = ["localhost:443"]`：要檢查到期日的憑證。

## 4. 勘查這台伺服器

```sh
sudo shentu survey
```

這會列出這台伺服器的現況：
- 有哪些服務、外部網路連不連得到
- 網站和應用程式用什麼技術、有哪些資料庫
- 防火牆和實際生效的 SSH 設定
- 容器、排程檔和可登入的帳號

接著列出這些設定帶來的風險。巡邏會把這份結果當作基準，之後有變動就通知你。如果你的網站程式不在 `/var/www`、`/srv`、`/opt` 或家目錄底下，請設定 `[tools] app_paths`。如果程式是用自己的帳號執行（例如 `node`），請把那個帳號加進 `[tools] web_users`。

## 5. 試跑一次

```sh
sudo shentu patrol --daily --dry-run     # 只印在畫面上，不發送
sudo shentu patrol --daily               # 實際發送，確認手機有收到
```

## 6. 開始對話

```sh
sudo shentu chat
> 昨晚有沒有人在暴力破解 SSH？
> 這台機器的套件有沒有已知漏洞？
> 列出監聽中的連接埠和背後的程序
> 有沒有可疑的程序？
> /var/www 最近有哪些檔案被改過？
```

只想問一句就結束：`sudo shentu chat "憑證什麼時候到期？"`

要封鎖 IP，就直接說「封鎖 203.0.113.7 24 小時」。Shentu 會先列出要執行的 `nft` 指令，等你按 `y` 才執行。每次封鎖都有期限，時間到會自動解除；要提早解除，就說「解除封鎖 203.0.113.7」。

## 7. 開啟自動巡邏

```sh
sudo systemctl enable --now shentu-patrol.timer shentu-daily.timer
systemctl list-timers 'shentu*'
```

- `shentu-patrol`：每 30 分鐘巡一次，有新狀況才通知。同一個告警 24 小時內不會重複發。
- `shentu-daily`：每天早上發一份日報。
- AI 掛掉的時候，照樣會把原始告警送出。

## 日常使用

- 每一次工具呼叫和模型呼叫都記錄在 `/var/lib/shentu/log.jsonl`。
- 要換模型，就再跑一次 `sudo shentu setup`，或直接改 `/etc/shentu/llm.toml`。
- 要加自己的處理流程（skill），放在 `/etc/shentu/skills/<名稱>/SKILL.md`。

## 常見問題

| 狀況 | 處理方式 |
|---|---|
| 出現 `sudo: shentu: command not found` | 用最新的 `install.sh` 重裝一次，或改打 `sudo /usr/local/bin/shentu` |
| 封鎖失敗，說找不到 nft | 照步驟 0 安裝 nftables |
| 報告裡出現 `LLM unavailable` | 檢查金鑰和網路；用本機模型的話，檢查 `systemctl status ollama` |
| 巡邏出現 `notify failed` | 檢查 `/etc/shentu/env` 裡的網址；這次的告警會保留，下次巡邏再送 |

## Shentu 會做和不會做的事

- 沒有你按 `y`，它不會更動系統。它也不會封鎖本機位址、伺服器自己的 IP、閘道、DNS，以及正在連線的 SSH 來源。
- 資料送給模型之前，密碼、金鑰、token 會先遮掉。但 log 內容本身還是會送到你選的模型；完全不想讓資料離開伺服器，就用本機模型。
- log 裡可能有攻擊者故意寫進去的文字。小型本機模型比較容易被騙，所以危險動作在程式層另有防護，而且一定要人工確認。
