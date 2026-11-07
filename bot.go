package main

// shentu bot: talk to Shentu from Telegram.
//
// Pairing is the security boundary, so it has several independent locks:
//   - only root on the server can start it (`shentu bot pair` writes the code);
//   - the code is 8 random characters, valid for 10 minutes, single use, and void
//     after 5 wrong tries; only its SHA-256 is stored;
//   - a correct code only creates a pending request: root must still approve it
//     with y on the server terminal, so a leaked code alone is not enough;
//   - one Telegram user in one private chat; groups, forwards and bots are ignored;
//   - strangers get no reply at all, and every pairing change is notified.
// Control tools are off unless [bot] allow_control = true, and each one then needs
// a ✅ press from the paired user on that exact request within 5 minutes.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/nt-neil/shentu/tools"
)

var telegramBotAPI = "https://api.telegram.org" // replaced in tests

const (
	pairCodeTTL     = 10 * time.Minute
	pairMaxTries    = 5
	confirmTimeout  = 5 * time.Minute
	botHistoryLimit = 20
)

type pendingPair struct {
	ChatID   int64     `json:"chat_id"`
	UserID   int64     `json:"user_id"`
	UserName string    `json:"user_name"`
	At       time.Time `json:"at"`
}

type botState struct {
	ChatID      int64        `json:"chat_id,omitempty"`
	UserID      int64        `json:"user_id,omitempty"`
	UserName    string       `json:"user_name,omitempty"`
	PairedAt    time.Time    `json:"paired_at,omitempty"`
	CodeHash    string       `json:"code_hash,omitempty"`
	CodeExpires time.Time    `json:"code_expires,omitempty"`
	CodeTries   int          `json:"code_tries,omitempty"`
	Pending     *pendingPair `json:"pending,omitempty"`
	Offset      int64        `json:"offset,omitempty"`
}

// withBotState loads bot.json under an exclusive lock, lets fn change it and saves it.
// The bot service and `shentu bot pair` both write the file.
func withBotState(dir string, fn func(*botState) error) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	lock, err := os.OpenFile(filepath.Join(dir, "bot.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	st := &botState{}
	p := filepath.Join(dir, "bot.json")
	if b, err := os.ReadFile(p); err == nil {
		json.Unmarshal(b, st)
	}
	if err := fn(st); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(st, "", "  ")
	if err := os.WriteFile(p+".tmp", b, 0o600); err != nil {
		return err
	}
	return os.Rename(p+".tmp", p)
}

func hashCode(code string) string {
	h := sha256.Sum256([]byte(strings.ToUpper(strings.TrimSpace(code))))
	return hex.EncodeToString(h[:])
}

func newPairCode() string {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // no 0/O, 1/I
	b := make([]byte, 8)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			panic(err)
		}
		b[i] = alphabet[n.Int64()]
	}
	return string(b)
}

func botToken(cfg *Config) string {
	if cfg.Bot.TelegramToken != "" {
		return cfg.Bot.TelegramToken
	}
	// Fall back to the bot of a telegram:// notify URL.
	if u, err := url.Parse(cfg.Notify.URL); err == nil && u.Scheme == "telegram" {
		t := u.User.Username()
		if pw, ok := u.User.Password(); ok {
			t += ":" + pw
		}
		return t
	}
	return ""
}

// botCommand runs `shentu bot`, `shentu bot pair`, `shentu bot unpair` or `shentu bot status`.
func botCommand(ctx context.Context, cfg *Config, env *tools.Env, args []string) error {
	sub := ""
	if len(args) > 0 {
		sub = args[0]
	}
	if sub != "" && os.Geteuid() != 0 {
		return errors.New("bot " + sub + " changes /var/lib/shentu; run it with sudo")
	}
	audit := newAuditLog(cfg.StateDir)
	switch sub {
	case "":
		token := botToken(cfg)
		if token == "" {
			return errors.New("no Telegram bot token: set [bot] telegram_token or a telegram:// notify url")
		}
		b := &bot{cfg: cfg, env: env, token: token, api: telegramBotAPI, hc: &http.Client{Timeout: 70 * time.Second}, log: audit}
		return b.run(ctx)
	case "pair":
		return botPair(ctx, cfg, env, audit, bufio.NewReader(os.Stdin), os.Stdout)
	case "unpair":
		var who string
		err := withBotState(cfg.StateDir, func(s *botState) error {
			who = fmt.Sprintf("%s (id %d)", s.UserName, s.UserID)
			s.ChatID, s.UserID, s.UserName, s.Pending, s.CodeHash = 0, 0, "", nil, ""
			return nil
		})
		if err != nil {
			return err
		}
		audit.write(logEntry{Actor: "bot", Tool: "bot_unpair", Args: who, OK: true})
		tools.Notify(ctx, env, "Telegram bot unpaired", "The bot no longer accepts commands from "+who+".", "warning")
		fmt.Println("Unpaired. The bot now ignores everyone until you pair again.")
		return nil
	case "status":
		return withBotState(cfg.StateDir, func(s *botState) error {
			if s.UserID == 0 {
				fmt.Println("Not paired.")
			} else {
				fmt.Printf("Paired with %s (user id %d) since %s.\n", s.UserName, s.UserID, s.PairedAt.Format(time.RFC3339))
			}
			fmt.Println("Control actions from Telegram:", map[bool]string{true: "on (each needs ✅)", false: "off"}[cfg.Bot.AllowControl])
			return nil
		})
	}
	return errors.New("usage: shentu bot [pair|unpair|status]")
}

// botPair writes a new code, waits for the bot service to receive it, then asks root.
func botPair(ctx context.Context, cfg *Config, env *tools.Env, audit *auditLog, in *bufio.Reader, out io.Writer) error {
	code := newPairCode()
	err := withBotState(cfg.StateDir, func(s *botState) error {
		s.CodeHash, s.CodeExpires, s.CodeTries, s.Pending = hashCode(code), time.Now().Add(pairCodeTTL), 0, nil
		return nil
	})
	if err != nil {
		return err
	}
	audit.write(logEntry{Actor: "bot", Tool: "bot_pair_code", OK: true})
	fmt.Fprintf(out, "In a private chat with your bot, send within 10 minutes:\n\n    /pair %s\n\nThe bot service must be running (systemctl start shentu-bot). Waiting…\n", code)
	deadline := time.Now().Add(pairCodeTTL)
	for time.Now().Before(deadline) {
		var p *pendingPair
		withBotState(cfg.StateDir, func(s *botState) error { p = s.Pending; return nil })
		if p != nil {
			fmt.Fprintf(out, "\nTelegram user %q (user id %d) wants to pair. Allow? [y/N] ", p.UserName, p.UserID)
			line, _ := in.ReadString('\n')
			ok := strings.EqualFold(strings.TrimSpace(line), "y")
			withBotState(cfg.StateDir, func(s *botState) error {
				if ok && s.Pending != nil && s.Pending.UserID == p.UserID {
					s.ChatID, s.UserID, s.UserName, s.PairedAt = p.ChatID, p.UserID, p.UserName, time.Now()
				}
				s.Pending, s.CodeHash = nil, ""
				return nil
			})
			who := fmt.Sprintf("%s (id %d)", p.UserName, p.UserID)
			if !ok {
				audit.write(logEntry{Actor: "bot", Tool: "bot_pair", Args: who, Error: "declined on the server"})
				fmt.Fprintln(out, "Declined. Run `shentu bot pair` again for a new code.")
				return nil
			}
			audit.write(logEntry{Actor: "bot", Tool: "bot_pair", Args: who, Confirmed: true, OK: true})
			tools.Notify(ctx, env, "Telegram bot paired", "The bot now accepts questions from "+who+". If this was not you, run: sudo shentu bot unpair", "warning")
			fmt.Fprintln(out, "Paired.")
			// Tell the user in Telegram too; their last message there was "code accepted".
			if token := botToken(cfg); token != "" {
				b := &bot{cfg: cfg, token: token, api: telegramBotAPI, hc: &http.Client{Timeout: 30 * time.Second}}
				b.send(ctx, p.ChatID, b.t("paired"), nil)
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
	withBotState(cfg.StateDir, func(s *botState) error { s.CodeHash = ""; return nil })
	return errors.New("no pairing request within 10 minutes; the code has expired")
}

// --- Telegram ---

type tgUser struct {
	ID       int64  `json:"id"`
	IsBot    bool   `json:"is_bot"`
	Username string `json:"username"`
	First    string `json:"first_name"`
}

type tgMessage struct {
	MessageID int64   `json:"message_id"`
	From      *tgUser `json:"from"`
	Chat      struct {
		ID   int64
		Type string
	} `json:"chat"`
	Text          string          `json:"text"`
	ForwardOrigin json.RawMessage `json:"forward_origin"`
	ForwardFrom   json.RawMessage `json:"forward_from"`
	ViaBot        json.RawMessage `json:"via_bot"`
}

type tgUpdate struct {
	UpdateID int64      `json:"update_id"`
	Message  *tgMessage `json:"message"`
	Callback *struct {
		ID      string     `json:"id"`
		From    tgUser     `json:"from"`
		Data    string     `json:"data"`
		Message *tgMessage `json:"message"`
	} `json:"callback_query"`
}

type bot struct {
	cfg   *Config
	env   *tools.Env
	token string
	api   string
	hc    *http.Client
	log   *auditLog

	mu       sync.Mutex
	busy     bool
	history  []message
	histFor  string               // pairing the history belongs to (user id + paired time)
	waiting  map[string]chan bool // confirmation nonce -> answer
	ignoreAt map[int64]time.Time  // last audit entry per ignored chat
}

func (b *bot) call(ctx context.Context, method string, payload, out any) error {
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, "POST", b.api+"/bot"+b.token+"/"+method, bytes.NewReader(body))
	if err != nil {
		return errors.New("telegram: bad request")
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := b.hc.Do(req)
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
		return fmt.Errorf("telegram %s: HTTP %d %s", method, resp.StatusCode, strings.ReplaceAll(r.Description, b.token, "***"))
	}
	if out != nil {
		return json.Unmarshal(r.Result, out)
	}
	return nil
}

func (b *bot) send(ctx context.Context, chat int64, text string, keyboard any) (int64, error) {
	var last int64
	for _, part := range tools.Chunks(text, 4000) {
		p := map[string]any{"chat_id": chat, "text": part, "disable_web_page_preview": true}
		if keyboard != nil {
			p["reply_markup"] = keyboard
		}
		var m tgMessage
		if err := b.call(ctx, "sendMessage", p, &m); err != nil {
			return 0, err
		}
		last = m.MessageID
	}
	return last, nil
}

func (b *bot) run(ctx context.Context) error {
	b.waiting, b.ignoreAt = map[string]chan bool{}, map[int64]time.Time{}
	if err := b.call(ctx, "deleteWebhook", map[string]any{}, nil); err != nil {
		return err
	}
	fmt.Println("shentu bot: listening (pair with `sudo shentu bot pair`)")
	backoff := time.Second
	for ctx.Err() == nil {
		var offset int64
		withBotState(b.cfg.StateDir, func(s *botState) error { offset = s.Offset; return nil })
		var ups []tgUpdate
		err := b.call(ctx, "getUpdates", map[string]any{"offset": offset, "timeout": 50, "allowed_updates": []string{"message", "callback_query"}}, &ups)
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			fmt.Fprintln(os.Stderr, "shentu bot:", err) // 409: another program reads this bot's updates
			time.Sleep(backoff)
			backoff = min(backoff*2, 5*time.Minute)
			continue
		}
		backoff = time.Second
		for _, u := range ups {
			b.handle(ctx, u)
			withBotState(b.cfg.StateDir, func(s *botState) error { s.Offset = u.UpdateID + 1; return nil })
		}
	}
	return nil
}

func (b *bot) handle(ctx context.Context, u tgUpdate) {
	var st botState
	withBotState(b.cfg.StateDir, func(s *botState) error { st = *s; return nil })
	if c := u.Callback; c != nil {
		b.call(ctx, "answerCallbackQuery", map[string]any{"callback_query_id": c.ID}, nil)
		nonce, answer, ok := strings.Cut(c.Data, ":")
		if !ok || st.UserID == 0 || c.From.ID != st.UserID || c.Message == nil || c.Message.Chat.ID != st.ChatID {
			b.ignored(0, "callback from someone who is not the paired user")
			return
		}
		b.mu.Lock()
		ch := b.waiting[nonce]
		delete(b.waiting, nonce)
		b.mu.Unlock()
		if ch != nil {
			ch <- answer == "y"
		}
		return
	}
	m := u.Message
	if m == nil || m.From == nil || m.From.IsBot || len(m.ForwardOrigin) > 0 || len(m.ForwardFrom) > 0 || len(m.ViaBot) > 0 {
		return
	}
	if m.Chat.Type != "private" {
		b.ignored(m.Chat.ID, "not a private chat")
		return
	}
	text := strings.TrimSpace(m.Text)
	if st.UserID == 0 || m.From.ID != st.UserID || m.Chat.ID != st.ChatID {
		if strings.HasPrefix(text, "/pair ") {
			b.tryPair(ctx, m, strings.TrimPrefix(text, "/pair "))
			return
		}
		b.ignored(m.Chat.ID, "not paired")
		return
	}
	if text == "/new" {
		b.mu.Lock()
		b.history = nil
		b.mu.Unlock()
		b.send(ctx, m.Chat.ID, b.t("new"), nil)
		return
	}
	b.mu.Lock()
	// A new pairing never sees the previous user's conversation.
	if who := fmt.Sprintf("%d@%d", st.UserID, st.PairedAt.UnixNano()); b.histFor != who {
		b.history, b.histFor = nil, who
	}
	if b.busy {
		b.mu.Unlock()
		b.send(ctx, m.Chat.ID, b.t("busy"), nil)
		return
	}
	b.busy = true
	b.mu.Unlock()
	go b.answer(ctx, m.Chat.ID, text)
}

// tryPair checks a /pair code. A correct code only records a pending request for root.
func (b *bot) tryPair(ctx context.Context, m *tgMessage, code string) {
	accepted := false
	withBotState(b.cfg.StateDir, func(s *botState) error {
		if s.CodeHash == "" || time.Now().After(s.CodeExpires) || s.CodeTries >= pairMaxTries {
			return nil
		}
		if subtle.ConstantTimeCompare([]byte(hashCode(code)), []byte(s.CodeHash)) != 1 {
			s.CodeTries++
			if s.CodeTries >= pairMaxTries {
				s.CodeHash = ""
			}
			return nil
		}
		name := m.From.Username
		if name == "" {
			name = m.From.First
		}
		s.Pending = &pendingPair{ChatID: m.Chat.ID, UserID: m.From.ID, UserName: name, At: time.Now()}
		s.CodeHash = "" // single use
		accepted = true
		return nil
	})
	if !accepted {
		b.ignored(m.Chat.ID, "wrong, expired or used pairing code")
		return
	}
	b.log.write(logEntry{Actor: "bot", Tool: "bot_pair_request", Args: fmt.Sprintf("user id %d", m.From.ID), OK: true})
	b.send(ctx, m.Chat.ID, b.t("accepted"), nil)
}

// ignored records a refused message, at most once an hour per chat. Strangers get no reply.
func (b *bot) ignored(chat int64, why string) {
	b.mu.Lock()
	last := b.ignoreAt[chat]
	if time.Since(last) < time.Hour {
		b.mu.Unlock()
		return
	}
	b.ignoreAt[chat] = time.Now()
	b.mu.Unlock()
	b.log.write(logEntry{Actor: "bot", Tool: "bot_ignored", Args: fmt.Sprintf("chat %d", chat), Error: why})
}

func (b *bot) answer(ctx context.Context, chat int64, text string) {
	defer func() { b.mu.Lock(); b.busy = false; b.mu.Unlock() }()
	skills := loadSkills(filepath.Join(filepath.Dir(configPath()), "skills"))
	a := &agent{
		cfg: b.cfg, llm: newLLM(b.cfg), env: b.env, skills: skills,
		allowControl: b.cfg.Bot.AllowControl, actor: "bot", log: b.log,
		confirm: func(tool, preview string) bool { return b.confirm(ctx, chat, tool, preview) },
	}
	b.mu.Lock()
	owner := b.histFor // the pairing this answer belongs to
	hist := append([]message{{Role: "system", Content: systemPrompt(b.cfg, skills)}}, b.history...)
	b.mu.Unlock()
	hist = append(hist, message{Role: "user", Content: text})
	b.send(ctx, chat, "…", nil)
	answer, msgs, err := a.run(ctx, hist)
	if err != nil {
		b.send(ctx, chat, b.t("error")+mask(err.Error()), nil)
		return
	}
	b.send(ctx, chat, strings.TrimSpace(answer), nil)
	var keep []message // keep plain turns only, so tool output does not pile up
	for _, m := range msgs[1:] {
		if (m.Role == "user" || m.Role == "assistant") && len(m.ToolCalls) == 0 && m.Content != "" {
			keep = append(keep, m)
		}
	}
	b.mu.Lock()
	if b.histFor == owner { // the pairing changed while this answer ran: drop it
		b.history = keep[max(0, len(keep)-botHistoryLimit):]
	}
	b.mu.Unlock()
}

// confirm shows the exact command with ✅/❌ and waits for the paired user to press one.
func (b *bot) confirm(ctx context.Context, chat int64, tool, preview string) bool {
	nb := make([]byte, 12)
	rand.Read(nb)
	nonce := hex.EncodeToString(nb)
	ch := make(chan bool, 1)
	b.mu.Lock()
	b.waiting[nonce] = ch
	b.mu.Unlock()
	defer func() { b.mu.Lock(); delete(b.waiting, nonce); b.mu.Unlock() }()
	kb := map[string]any{"inline_keyboard": [][]map[string]string{{
		{"text": b.t("run"), "callback_data": nonce + ":y"},
		{"text": b.t("cancel"), "callback_data": nonce + ":n"},
	}}}
	id, err := b.send(ctx, chat, fmt.Sprintf(b.t("confirm"), tool, printable(preview)), kb)
	if err != nil {
		return false
	}
	ok := false
	select {
	case ok = <-ch:
	case <-time.After(confirmTimeout):
	case <-ctx.Done():
	}
	b.call(ctx, "editMessageReplyMarkup", map[string]any{"chat_id": chat, "message_id": id, "reply_markup": map[string]any{"inline_keyboard": [][]any{}}}, nil)
	if ok {
		tools.Notify(ctx, b.env, "Approved from Telegram", tool+": "+preview, "warning")
	} else {
		b.send(ctx, chat, b.t("cancelled"), nil)
	}
	return ok
}

var botText = map[string][2]string{ // English, Chinese
	"accepted":  {"Code accepted. Approve the request on the server terminal to finish pairing.", "已收到配對碼。請在伺服器終端機核准這個要求，才會完成配對。"},
	"paired":    {"✅ Paired. Ask me anything about this server. /new starts a fresh conversation.", "✅ 配對完成，可以開始提問了。傳 /new 可以開始新的對話。"},
	"new":       {"OK, new conversation.", "好，開始新的對話。"},
	"busy":      {"Still working on the previous question.", "上一個問題還在處理中，請稍候。"},
	"error":     {"Error: ", "發生錯誤："},
	"run":       {"✅ Run", "✅ 執行"},
	"cancel":    {"❌ Cancel", "❌ 取消"},
	"confirm":   {"⚠️ %s wants to run:\n%s\n\nValid for 5 minutes.", "⚠️ %s 要執行：\n%s\n\n5 分鐘內有效。"},
	"cancelled": {"Cancelled.", "已取消。"},
}

// t returns a fixed bot message in the configured language (Chinese or English).
func (b *bot) t(key string) string {
	if strings.Contains(b.cfg.Language, "中文") || strings.HasPrefix(strings.ToLower(b.cfg.Language), "zh") {
		return botText[key][1]
	}
	return botText[key][0]
}
