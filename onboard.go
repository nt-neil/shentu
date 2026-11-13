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
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/nt-neil/shentu/tools"
)

type wiz struct {
	zh       bool
	yes      bool
	tgChat   int64 // the Telegram chat confirmed in this run (0: none)
	tgWho    string
	startBot bool // start shentu-bot once setup.toml has the levels
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
	if runtime.GOOS == "windows" {
		return errSetupWindows
	}
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
	w.askBudget(in)
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
	old, _ := os.ReadFile(filepath.Join(configDir(), "setup.toml"))
	notifyInSetup := notifyURL != "" || keep && strings.Contains(string(old), "${NOTIFY_URL}")
	botBlock := ""
	if i := strings.Index(string(old), "\n[bot]"); i >= 0 {
		botBlock = string(old)[i+1:] // keep earlier choices unless Telegram is set up again
	}
	if w.tgChat != 0 {
		botBlock = w.chooseInteraction(ctx, in)
	}
	if err := writeSetup(lang, notifyInSetup, botBlock); err != nil {
		return err
	}
	if w.startBot {
		w.startBotService(ctx)
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
	w.tgChat, w.tgWho = chat, who
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
func writeSetup(lang string, notify bool, botBlock string) error {
	var b strings.Builder
	b.WriteString("# Written by `shentu setup`; overrides shentu.toml. Run setup again to change it.\n")
	fmt.Fprintf(&b, "language = %q\n", lang)
	if notify {
		b.WriteString("\n[notify]\nurl = \"${NOTIFY_URL}\"   # the value is in /etc/shentu/env\n")
	}
	if botBlock != "" {
		b.WriteString("\n" + strings.TrimLeft(botBlock, "\n"))
	}
	p := filepath.Join(configDir(), "setup.toml")
	if err := os.WriteFile(p, []byte(b.String()), 0o644); err != nil {
		return err
	}
	fmt.Println("Saved", p)
	return nil
}

// chooseInteraction asks the four Telegram levels for the user confirmed in this run,
// pairs them (they just proved who they are with the code and root's y), and
// returns the [bot] block for setup.toml.
func (w *wiz) chooseInteraction(ctx context.Context, in *bufio.Reader) string {
	pick := func(r int, def int, risks [4][2]string) int {
		fmt.Println("\n" + w.t(rangeNames[r][0], rangeNames[r][1]) + ":")
		for l := 0; l < 4; l++ {
			star := ""
			if l+1 == def {
				star = " ★"
			}
			fmt.Printf("  %d) %s%s — %s\n", l+1, w.t(levelNames[r][l][0], levelNames[r][l][1]), star, w.t(risks[l][0], risks[l][1]))
		}
		a := ask(in, fmt.Sprintf(w.t("Choose [%d]: ", "請選擇 [%d]："), def))
		if n, err := strconv.Atoi(a); err == nil && n >= 1 && n <= 4 {
			return n
		}
		return def
	}
	fmt.Println(w.t("\nShould this Telegram account also talk to Shentu? Each range has four levels; ★ is the default.",
		"\n要不要讓這個 Telegram 帳號也能跟神荼對話？每個範圍有四個等級，★ 是預設值。"))
	l := [4]int{1, 2, 2, 2}
	l[0] = pick(0, 1, [4][2]string{
		{"reports and alerts only; the bot reads nothing", "只收報告和告警，bot 不讀任何訊息"},
		{"ask questions; nothing on the server changes", "可以問問題，伺服器不會有任何改變"},
		{"also block and unblock IPs", "還可以封鎖、解除封鎖 IP"},
		{"also every control tool added later", "還包括之後新增的所有控制功能"}})
	if l[0] >= 2 {
		l[1] = pick(1, 2, [4][2]string{
			{"least detail in the chat", "聊天室裡留下的資訊最少"},
			{"findings and advice, no raw logs", "重點和建議，不附原始 log"},
			{"as detailed as on the server, deleted after 24h", "跟在伺服器上一樣詳細，24 小時後刪除"},
			{"detailed and kept in the chat", "詳細內容會一直留在聊天室"}})
		if l[0] >= 3 {
			l[2] = pick(2, 2, [4][2]string{
				{"Telegram only proposes; root runs `shentu bot approve`", "Telegram 只能提出，要到伺服器核准"},
				{"a stolen phone is not enough without the code app", "手機被偷，沒有驗證器也動不了"},
				{"a stolen Telegram account can act", "Telegram 帳號被盜就能操作"},
				{"DANGEROUS: actions run at once", "危險：動作會直接執行"}})
		}
		l[3] = pick(3, 2, [4][2]string{
			{"token leak → pause; 08–20h; 50 answers a day", "token 外洩就暫停；只在 08–20 點；每天 50 次"},
			{"token leak → pause", "token 外洩就暫停"},
			{"token leak → alert only", "token 外洩只發告警"},
			{"no checks", "不做任何偵測"}})
	}
	block := fmt.Sprintf("[bot]\ninteraction = %d\nanswers     = %d\nconfirm     = %d\nprotection  = %d\n", l[0], l[1], l[2], l[3])
	if l[0] < 2 {
		writeActionDropIn(false)
		exec.CommandContext(ctx, "systemctl", "disable", "--now", "shentu-bot").Run()
		return block
	}
	cfg, err := loadConfig(configPath())
	if err == nil {
		err = withBotState(cfg.StateDir, func(s *botState) error {
			s.ChatID, s.UserID, s.UserName, s.PairedAt, s.Pending, s.CodeHash, s.Paused = w.tgChat, w.tgChat, w.tgWho, time.Now(), nil, "", ""
			return nil
		})
	}
	if err != nil {
		fmt.Println(w.t("Could not pair: ", "無法配對：") + err.Error())
		return block
	}
	newAuditLog(cfg.StateDir).write(logEntry{Actor: "setup", Tool: "bot_pair", Args: fmt.Sprintf("%s (id %d)", w.tgWho, w.tgChat), Confirmed: true, OK: true})
	if l[0] >= 3 && l[2] == 2 {
		fmt.Println(w.t("\nSet up the one-time code app now:", "\n現在設定動態密碼 App："))
		for botTOTP(cfg, in, os.Stdout) != nil {
			if !w.yesNo(in, w.t("Try again?", "要重試嗎？"), true) {
				fmt.Println(w.t("Later: sudo shentu bot totp. Until then actions are refused.", "之後可執行：sudo shentu bot totp。在那之前，動作一律拒絕。"))
				break
			}
		}
	}
	if err := writeActionDropIn(l[0] >= 3); err != nil {
		fmt.Println(err)
	}
	w.startBot = true
	return block
}

// startBotService (re)starts shentu-bot so it reads the levels just saved.
func (w *wiz) startBotService(ctx context.Context) {
	exec.CommandContext(ctx, "systemctl", "daemon-reload").Run()
	exec.CommandContext(ctx, "systemctl", "enable", "shentu-bot").Run()
	if out, err := exec.CommandContext(ctx, "systemctl", "restart", "shentu-bot").CombinedOutput(); err != nil {
		fmt.Println(w.t("Could not start the bot: ", "無法啟動 bot：") + strings.TrimSpace(string(out)))
		return
	}
	fmt.Println(w.t("The bot is running. Send /lockdown to it at any time to stop it.", "bot 已啟動。隨時傳 /lockdown 給它就能緊急關閉。"))
}

// askBudget offers the optional monthly limit; Enter skips it. Local models cost nothing.
func (w *wiz) askBudget(in *bufio.Reader) {
	cfg, err := loadConfig(configPath())
	if err != nil || cfg.LLM.BaseURL == "" || strings.Contains(cfg.LLM.BaseURL, "127.0.0.1") || strings.Contains(cfg.LLM.BaseURL, "localhost") {
		return
	}
	cur := ""
	if cfg.Budget.MonthlyCost > 0 {
		cur = strconv.FormatFloat(cfg.Budget.MonthlyCost, 'f', -1, 64)
	}
	fmt.Println(w.t("Optional: a monthly AI budget in USD. At 80% you get an alert; at 100% the AI stops until next month (patrol alerts keep coming).",
		"可選：每月 AI 預算上限（美元）。用到 80% 會通知你；用完後這個月就不再呼叫 AI（巡邏告警照常送出）。"))
	a := ask(in, w.t(fmt.Sprintf("Monthly budget, Enter for %s: ", map[bool]string{true: "none", false: cur}[cur == ""]),
		fmt.Sprintf("每月上限（美元），直接按 Enter %s：", map[bool]string{true: "不設定", false: "維持 " + cur}[cur == ""])))
	if a == "" {
		return
	}
	v, err := strconv.ParseFloat(strings.TrimPrefix(a, "$"), 64)
	if err != nil || v < 0 {
		fmt.Println(w.t("Not a number; skipped. Set it later with: sudo shentu budget --cost 5", "不是數字，已略過。之後可以執行：sudo shentu budget --cost 5"))
		return
	}
	if err := writeBudget(v, cfg.Budget.MonthlyTokens); err != nil {
		fmt.Println(w.t("Could not save: ", "無法儲存：") + err.Error())
	}
}
