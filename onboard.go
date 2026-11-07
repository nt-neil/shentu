package main

// The guided setup: `shentu setup` with no flags (install.sh starts it too) goes
// from the model to the first report, one question at a time, with defaults.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/nt-neil/shentu/tools"
)

type wiz struct {
	zh  bool
	yes bool
}

// t picks the English or the Chinese text.
func (w *wiz) t(en, zh string) string {
	if w.zh {
		return zh
	}
	return en
}

func (w *wiz) step(n int, en, zh string) {
	fmt.Printf("\n[%d/5] %s\n", n, w.t(en, zh))
}

// yesNo asks a question; an empty answer takes def.
func (w *wiz) yesNo(in *bufio.Reader, question string, def bool) bool {
	hint := map[bool]string{true: " [Y/n] ", false: " [y/N] "}[def]
	a := strings.ToLower(ask(in, question+hint))
	if a == "" {
		return def
	}
	return a == "y" || a == "yes"
}

func wizard(ctx context.Context, in *bufio.Reader, yes bool) error {
	w := &wiz{yes: yes}
	fmt.Println("Shentu setup · 神荼設定")
	fmt.Println("[1/5] Language / 語言:  1) English   2) 繁體中文")
	if ask(in, "Choose / 請選擇 [1]: ") == "2" {
		w.zh = true
	}
	lang := w.t("English", "繁體中文")
	fmt.Println(w.t("Press Enter to accept the value in [brackets].", "直接按 Enter 就會採用 [括號] 裡的預設值。"))

	w.step(2, "AI model", "AI 模型")
	if cfg, err := loadConfig(configPath()); err == nil && cfg.LLM.BaseURL != "" && fileExists(filepath.Join(configDir(), "llm.toml")) {
		fmt.Printf(w.t("Already set: %s at %s\n", "已經設定：%s（%s）\n"), cfg.LLM.Model, cfg.LLM.BaseURL)
		if !w.yesNo(in, w.t("Change it?", "要更換嗎？"), false) {
			goto notify
		}
	}
	for {
		err := chooseLLM(ctx, in, w)
		if err == nil {
			break
		}
		fmt.Println(w.t("Problem: ", "發生問題：") + err.Error())
		if !w.yesNo(in, w.t("Try again?", "要重試嗎？"), true) {
			fmt.Println(w.t("Skipped. Without a model, reports contain the raw findings only. Run `sudo shentu setup` later.",
				"已跳過。沒有模型時，報告只會列出原始發現。之後可以再執行 `sudo shentu setup`。"))
			break
		}
	}

notify:
	w.step(3, "Notifications", "通知管道")
	notifyURL, keep := "", false
	if cfg, err := loadConfig(configPath()); err == nil && cfg.Notify.URL != "" {
		kind := strings.SplitN(cfg.Notify.URL, ":", 2)[0]
		fmt.Printf(w.t("Already set: %s\n", "已經設定：%s\n"), kind)
		keep = !w.yesNo(in, w.t("Change it?", "要更換嗎？"), false)
	}
	for !keep {
		var err error
		notifyURL, err = w.chooseNotify(ctx, in)
		if err == nil {
			break
		}
		fmt.Println(w.t("Problem: ", "發生問題：") + err.Error())
		if !w.yesNo(in, w.t("Try again (or pick another channel)?", "要重試（或改選其他管道）嗎？"), true) {
			break
		}
	}
	if err := writeSetup(lang, notifyURL != ""); err != nil {
		return err
	}

	w.step(4, "Survey this server", "勘查這台伺服器")
	cfg, err := loadConfig(configPath())
	if err != nil {
		return err
	}
	tools.SetWebUsers(cfg.Tools.WebUsers)
	env := &tools.Env{LogPaths: cfg.Tools.LogPaths, WatchPaths: cfg.Tools.WatchPaths, CertTargets: cfg.Tools.CertTargets,
		AppPaths: cfg.Tools.AppPaths, NotifyURL: cfg.Notify.URL, HTTP: &http.Client{Timeout: 30 * time.Second}}
	p, err := survey(ctx, cfg, env)
	if err != nil {
		return err
	}
	fmt.Println(p.Brief())
	if len(p.Risks) == 0 {
		fmt.Println(w.t("No configuration risks found.", "沒有發現設定上的風險。"))
	}
	for _, r := range p.Risks {
		fmt.Printf("  [%s] %s\n", r.Severity, r.Summary)
	}
	if _, err := exec.LookPath("nft"); err != nil {
		fmt.Println(w.t("  Note: nftables is not installed, so blocking IPs will not work (apt/dnf install nftables).",
			"  提醒：沒有安裝 nftables，封鎖 IP 功能無法使用（apt/dnf install nftables）。"))
	}

	w.step(5, "Turn on patrols", "開啟自動巡邏")
	if exec.CommandContext(ctx, "systemctl", "is-enabled", "--quiet", "shentu-patrol.timer").Run() == nil {
		fmt.Println(w.t("Patrols are already on.", "巡邏已經是開啟狀態。"))
	} else if w.yesNo(in, w.t("Check every 30 minutes and send a report every morning?", "每 30 分鐘巡邏一次，每天早上發一份日報？"), true) {
		out, err := exec.CommandContext(ctx, "systemctl", "enable", "--now", "shentu-patrol.timer", "shentu-daily.timer").CombinedOutput()
		if err != nil {
			fmt.Println(w.t("Could not enable the timers: ", "無法開啟排程：") + strings.TrimSpace(string(out)))
		} else {
			fmt.Println(w.t("Patrols are on.", "巡邏已開啟。"))
		}
	}
	if cfg.Notify.URL != "" && w.yesNo(in, w.t("Send the first report now? (takes up to a minute)", "現在就發第一份報告？（最多約一分鐘）"), true) {
		if err := patrol(ctx, cfg, env, true, false); err != nil {
			fmt.Println(w.t("The report could not be sent: ", "報告發送失敗：") + err.Error())
		}
	}

	fmt.Println("\n" + w.t("Done. Shentu is running.", "完成，神荼已經上線。"))
	fmt.Println(w.t("  Ask a question:      sudo shentu chat", "  問問題：            sudo shentu chat"))
	fmt.Println(w.t("  Change settings:     sudo shentu setup", "  修改設定：          sudo shentu setup"))
	fmt.Println(w.t("  Settings files:      /etc/shentu/ (secrets in /etc/shentu/env, root only)", "  設定檔：            /etc/shentu/（機密在 /etc/shentu/env，只有 root 能讀）"))
	return nil
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// chooseNotify sets up one channel, sends a test message, and returns the URL it
// stored in the env file (NOTIFY_URL), or "" when skipped.
func (w *wiz) chooseNotify(ctx context.Context, in *bufio.Reader) (string, error) {
	fmt.Println(w.t("Where should reports and alerts go?", "報告和告警要送到哪裡？"))
	fmt.Println("  1) Telegram   2) Slack   3) Discord   4) ntfy   5) " + w.t("skip", "先跳過"))
	var u string
	var err error
	switch ask(in, w.t("Choose [1]: ", "請選擇 [1]：")) {
	case "", "1":
		u, err = w.telegram(ctx, in)
	case "2":
		u, err = w.webhook(in, "Slack", "https://hooks.slack.com/services/")
	case "3":
		u, err = w.webhook(in, "Discord", "https://discord.com/api/webhooks/")
	case "4":
		topic := "shentu-" + randomHex(16) // 128 bits: on ntfy.sh the topic name is the only secret
		t := ask(in, fmt.Sprintf(w.t("ntfy topic (anyone who knows it can read it) [%s]: ", "ntfy 主題（知道名稱的人都能讀取）[%s]："), topic))
		if t != "" {
			topic = t
		}
		u = "ntfy://ntfy.sh/" + topic
		fmt.Printf(w.t("Subscribe in the ntfy app to: %s\n", "請在 ntfy App 訂閱：%s\n"), "https://ntfy.sh/"+topic)
	default:
		return "", nil
	}
	if err != nil || u == "" {
		return "", err
	}
	env := &tools.Env{NotifyURL: u, HTTP: &http.Client{Timeout: 30 * time.Second}}
	if err := tools.Notify(ctx, env, w.t("Shentu is connected", "神荼已連線"), w.t("Reports and alerts from this server will arrive here.", "這台伺服器的報告和告警會送到這裡。"), "info"); err != nil {
		return "", fmt.Errorf(w.t("the test message failed: %v", "測試訊息發送失敗：%v"), err)
	}
	fmt.Println(w.t("Test message sent. Check that it arrived.", "已發送測試訊息，請確認有收到。"))
	if err := setEnv("NOTIFY_URL", u); err != nil {
		return "", err
	}
	return u, nil
}

func (w *wiz) webhook(in *bufio.Reader, name, prefix string) (string, error) {
	u := askSecret(in, fmt.Sprintf(w.t("%s webhook URL (input hidden): ", "%s Webhook 網址（輸入時不會顯示）："), name))
	if !strings.HasPrefix(u, prefix) {
		return "", fmt.Errorf(w.t("a %s webhook URL starts with %s", "%s 的 Webhook 網址開頭應該是 %s"), name, prefix)
	}
	return u, nil
}

// telegramAPI for the setup; tests replace it.
var setupTelegramAPI = "https://api.telegram.org"

// telegram finds the chat ID for the user: it shows a one-time start link, waits for
// that exact /start in a private chat, and asks root to confirm who it is.
func (w *wiz) telegram(ctx context.Context, in *bufio.Reader) (string, error) {
	fmt.Println(w.t("Create a bot: in Telegram open @BotFather, send /newbot, and copy the token it gives you.",
		"建立 bot：在 Telegram 打開 @BotFather，傳 /newbot，複製它給你的 token。"))
	token := askSecret(in, w.t("Bot token (input hidden): ", "Bot token（輸入時不會顯示）："))
	if !strings.Contains(token, ":") {
		return "", errors.New(w.t("that does not look like a bot token (123456:ABC…)", "這不像 bot token（格式是 123456:ABC…）"))
	}
	tg := &telegramClient{api: setupTelegramAPI, token: token, hc: &http.Client{Timeout: 70 * time.Second}}
	var me struct{ Username string }
	if err := tg.call(ctx, "getMe", nil, &me); err != nil {
		return "", err
	}
	code := typedCode() // 8 characters, valid 10 minutes, and root still confirms the user
	fmt.Printf(w.t("\nIn Telegram on your phone, search for @%s, open the chat and send this code (valid 10 minutes):\n\n    %s\n\n(With Telegram on this computer you can open https://t.me/%s?start=%s instead.)\nWaiting…\n",
		"\n請在手機的 Telegram 搜尋 @%s，打開對話，傳送這組代碼（10 分鐘內有效）：\n\n    %s\n\n（這台電腦有裝 Telegram 的話，也可以直接打開 https://t.me/%s?start=%s）\n等待中…\n"),
		me.Username, code[:4]+"-"+code[4:], me.Username, code)
	chat, who, err := waitForStart(ctx, tg, code, 10*time.Minute)
	if err != nil {
		return "", err
	}
	if !w.yesNo(in, fmt.Sprintf(w.t("Telegram user %s (id %d) sent the code. Is this you?", "Telegram 使用者 %s（ID %d）傳來了正確的代碼。這是你嗎？"), who, chat), false) {
		return "", errors.New(w.t("not confirmed; run `sudo shentu setup` again for a new link", "未確認；請重新執行 `sudo shentu setup` 取得新連結"))
	}
	return fmt.Sprintf("telegram://%s@telegram?chats=%d", token, chat), nil
}

// waitForStart polls getUpdates for "/start <code>" sent in a private chat. Other
// messages are ignored; updates are confirmed so they are not seen again.
func waitForStart(ctx context.Context, tg *telegramClient, code string, limit time.Duration) (int64, string, error) {
	deadline := time.Now().Add(limit)
	var offset int64
	for time.Now().Before(deadline) {
		var ups []struct {
			UpdateID int64 `json:"update_id"`
			Message  *struct {
				Text string `json:"text"`
				Chat struct {
					ID   int64  `json:"id"`
					Type string `json:"type"`
				} `json:"chat"`
				From *struct {
					IsBot    bool   `json:"is_bot"`
					Username string `json:"username"`
					First    string `json:"first_name"`
				} `json:"from"`
			} `json:"message"`
		}
		wait := min(25*time.Second, time.Until(deadline))
		if err := tg.call(ctx, "getUpdates", map[string]any{"offset": offset, "timeout": int(wait.Seconds()), "allowed_updates": []string{"message"}}, &ups); err != nil {
			if strings.Contains(err.Error(), "409") {
				return 0, "", errors.New("another program is reading this bot's messages (Telegram error 409); use a bot only Shentu uses")
			}
			return 0, "", err
		}
		for _, u := range ups {
			offset = u.UpdateID + 1
			m := u.Message
			if m == nil || m.From == nil || m.From.IsBot || m.Chat.Type != "private" || !codeMatches(m.Text, code) {
				continue
			}
			tg.call(ctx, "getUpdates", map[string]any{"offset": offset, "timeout": 0}, nil) // confirm
			who := "@" + m.From.Username
			if m.From.Username == "" {
				who = m.From.First
			}
			return m.Chat.ID, who, nil
		}
		if ctx.Err() != nil {
			return 0, "", ctx.Err()
		}
	}
	return 0, "", errors.New("the code did not arrive within 10 minutes")
}

// typedCode is easy to type on a phone: 8 characters without 0/O or 1/I (40 bits).
func typedCode() string {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)] // 256 is a multiple of 32: no bias
	}
	return string(b)
}

// codeMatches accepts the code typed by hand (any case, with or without the dash or
// spaces) or sent by the start link ("/start CODE").
func codeMatches(text, code string) bool {
	t := strings.TrimPrefix(strings.TrimSpace(text), "/start")
	t = strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(t))
	return t == code
}

type telegramClient struct {
	api, token string
	hc         *http.Client
}

func (t *telegramClient) call(ctx context.Context, method string, payload, out any) error {
	if payload == nil {
		payload = map[string]any{}
	}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, "POST", t.api+"/bot"+t.token+"/"+method, bytes.NewReader(body))
	if err != nil {
		return errors.New("telegram: bad request")
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := t.hc.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fmt.Errorf("telegram %s: %v", method, err)
	}
	defer resp.Body.Close()
	var r struct {
		OK          bool            `json:"ok"`
		Description string          `json:"description"`
		Result      json.RawMessage `json:"result"`
	}
	json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&r)
	if !r.OK {
		return fmt.Errorf("telegram %s: HTTP %d %s", method, resp.StatusCode, strings.ReplaceAll(r.Description, t.token, "***"))
	}
	if out != nil {
		return json.Unmarshal(r.Result, out)
	}
	return nil
}

// randomHex returns n random bytes as 2n hex characters.
func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return fmt.Sprintf("%x", b)
}

// writeSetup stores the choices that are not secrets in setup.toml, which overrides
// shentu.toml. The notify URL itself stays in the root-only env file.
func writeSetup(lang string, notify bool) error {
	var b strings.Builder
	b.WriteString("# Written by `shentu setup`; overrides shentu.toml. Run setup again to change it.\n")
	fmt.Fprintf(&b, "language = %q\n", lang)
	if notify {
		b.WriteString("\n[notify]\nurl = \"${NOTIFY_URL}\"   # the value is in /etc/shentu/env\n")
	}
	p := filepath.Join(configDir(), "setup.toml")
	if err := os.WriteFile(p, []byte(b.String()), 0o644); err != nil {
		return err
	}
	fmt.Println("Saved", p)
	return nil
}
