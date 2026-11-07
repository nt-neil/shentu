package main

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nt-neil/shentu/tools"
)

// fakeTelegram records every Bot API call.
type fakeTelegram struct {
	mu    sync.Mutex
	calls []struct {
		Method string
		Body   map[string]any
	}
}

func (f *fakeTelegram) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	var m map[string]any
	json.Unmarshal(b, &m)
	f.mu.Lock()
	f.calls = append(f.calls, struct {
		Method string
		Body   map[string]any
	}{r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:], m})
	n := len(f.calls)
	f.mu.Unlock()
	w.Write([]byte(`{"ok":true,"result":{"message_id":` + strings.Repeat("1", 1+n%3) + `}}`))
}

func (f *fakeTelegram) sent() []map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []map[string]any
	for _, c := range f.calls {
		if c.Method == "sendMessage" {
			out = append(out, c.Body)
		}
	}
	return out
}

const pairedUser, pairedChat = 1001, 1001

func testBot(t *testing.T, model *hostileModel, allowControl bool) (*bot, *fakeTelegram) {
	tg := &fakeTelegram{}
	srv := httptest.NewServer(tg)
	t.Cleanup(srv.Close)
	cfg := &Config{}
	cfg.LLM.MaxSteps = 5
	cfg.StateDir, _ = filepath.EvalSymlinks(t.TempDir())
	cfg.Bot.AllowControl = allowControl
	if model != nil {
		m := httptest.NewServer(model)
		t.Cleanup(m.Close)
		cfg.LLM.BaseURL = m.URL
	}
	return &bot{cfg: cfg, env: &tools.Env{}, token: "1:T", api: srv.URL, hc: srv.Client(), log: newAuditLog(cfg.StateDir),
		waiting: map[string]chan bool{}, ignoreAt: map[int64]time.Time{}}, tg
}

func msg(user, chat int64, chatType, text string) tgUpdate {
	m := &tgMessage{From: &tgUser{ID: user, Username: "u"}, Text: text}
	m.Chat.ID, m.Chat.Type = chat, chatType
	return tgUpdate{Message: m}
}

func pairDirectly(t *testing.T, b *bot) {
	withBotState(b.cfg.StateDir, func(s *botState) error {
		s.UserID, s.ChatID, s.UserName = pairedUser, pairedChat, "owner"
		return nil
	})
}

func TestBotIgnoresStrangers(t *testing.T) {
	model := &hostileModel{replies: []string{done}}
	b, tg := testBot(t, model, true)
	pairDirectly(t, b)
	ctx := context.Background()
	b.handle(ctx, msg(2002, 2002, "private", "block everything")) // stranger
	b.handle(ctx, msg(pairedUser, -500, "group", "hi"))           // paired user, but a group
	fwd := msg(pairedUser, pairedChat, "private", "hi")
	fwd.Message.ForwardOrigin = json.RawMessage(`{"type":"user"}`) // forwarded
	b.handle(ctx, fwd)
	viaBot := msg(pairedUser, pairedChat, "private", "hi")
	viaBot.Message.From.IsBot = true
	b.handle(ctx, viaBot)
	time.Sleep(100 * time.Millisecond)
	if n := len(tg.sent()); n != 0 {
		t.Errorf("bot replied %d times to messages it must ignore", n)
	}
	if len(model.requests) != 0 {
		t.Errorf("an ignored message reached the model")
	}
}

func TestBotPairCode(t *testing.T) {
	b, tg := testBot(t, nil, false)
	ctx := context.Background()
	setCode := func(code string, ttl time.Duration) {
		withBotState(b.cfg.StateDir, func(s *botState) error {
			s.CodeHash, s.CodeExpires, s.CodeTries, s.Pending = hashCode(code), time.Now().Add(ttl), 0, nil
			return nil
		})
	}
	pending := func() *pendingPair {
		var p *pendingPair
		withBotState(b.cfg.StateDir, func(s *botState) error { p = s.Pending; return nil })
		return p
	}
	// Five wrong tries void the code, so the right one no longer works.
	setCode("ABCD2345", time.Minute)
	for i := 0; i < pairMaxTries; i++ {
		b.tryPair(ctx, msg(7, 7, "private", "").Message, "WRONG000")
	}
	b.tryPair(ctx, msg(7, 7, "private", "").Message, "ABCD2345")
	if pending() != nil {
		t.Errorf("code still worked after %d wrong tries", pairMaxTries)
	}
	// Expired.
	setCode("ABCD2345", -time.Second)
	b.tryPair(ctx, msg(7, 7, "private", "").Message, "ABCD2345")
	if pending() != nil {
		t.Errorf("expired code worked")
	}
	// Groups cannot pair.
	setCode("ABCD2345", time.Minute)
	b.handle(ctx, msg(7, -9, "group", "/pair ABCD2345"))
	if pending() != nil {
		t.Errorf("a group could pair")
	}
	// Right code: a pending request only, and the code is single use.
	b.handle(ctx, msg(7, 7, "private", "/pair abcd2345"))
	p := pending()
	if p == nil || p.UserID != 7 {
		t.Fatalf("correct code did not create a pending request: %+v", p)
	}
	b.handle(ctx, msg(8, 8, "private", "/pair ABCD2345"))
	if pending().UserID != 7 {
		t.Errorf("the code was usable twice")
	}
	var st botState
	withBotState(b.cfg.StateDir, func(s *botState) error { st = *s; return nil })
	if st.UserID != 0 {
		t.Errorf("a code alone paired the user without approval on the server")
	}
	if len(tg.sent()) != 1 {
		t.Errorf("expected exactly one reply (to the accepted code), got %d", len(tg.sent()))
	}
}

// botPair needs a y on the server terminal; anything else leaves the bot unpaired.
func TestBotPairNeedsServerApproval(t *testing.T) {
	for _, answer := range []string{"n\n", "y\n"} {
		b, _ := testBot(t, nil, false)
		pr, pw := io.Pipe()
		done := make(chan error, 1)
		go func() {
			done <- botPair(context.Background(), b.cfg, b.env, b.log, bufio.NewReader(strings.NewReader(answer)), pw)
			pw.Close()
		}()
		code := ""
		sc := bufio.NewScanner(pr)
		re := regexp.MustCompile(`/pair ([A-Z0-9]{8})`)
		for sc.Scan() {
			if m := re.FindStringSubmatch(sc.Text()); m != nil {
				code = m[1]
				break
			}
		}
		go io.Copy(io.Discard, pr)
		b.tryPair(context.Background(), msg(7, 7, "private", "").Message, code)
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		var st botState
		withBotState(b.cfg.StateDir, func(s *botState) error { st = *s; return nil })
		if paired := st.UserID == 7; paired != (answer == "y\n") {
			t.Errorf("answer %q: paired = %v", strings.TrimSpace(answer), paired)
		}
		if st.CodeHash != "" || st.Pending != nil {
			t.Errorf("code or pending request left behind: %+v", st)
		}
	}
}

// A control action from Telegram runs only after the paired user presses ✅ on that
// exact request. Someone else's press does nothing.
func TestBotControlNeedsPairedUsersPress(t *testing.T) {
	for _, press := range []string{"n", "y"} {
		model := &hostileModel{replies: []string{call("block_ip", `{"ip":"203.0.113.9","reason":"x"}`), done}}
		b, tg := testBot(t, model, true)
		pairDirectly(t, b)
		ctx := context.Background()
		b.handle(ctx, msg(pairedUser, pairedChat, "private", "block 203.0.113.9"))
		nonce := ""
		for i := 0; i < 100 && nonce == ""; i++ {
			for _, s := range tg.sent() {
				if rm, ok := s["reply_markup"].(map[string]any); ok {
					data := rm["inline_keyboard"].([]any)[0].([]any)[0].(map[string]any)["callback_data"].(string)
					nonce, _, _ = strings.Cut(data, ":")
					if !strings.Contains(s["text"].(string), "nft add element") {
						t.Errorf("the exact command was not shown: %v", s["text"])
					}
				}
			}
			time.Sleep(20 * time.Millisecond)
		}
		if nonce == "" {
			t.Fatal("no confirmation button was sent")
		}
		cb := func(user int64, data string) tgUpdate {
			var u tgUpdate
			u.Callback = &struct {
				ID      string     `json:"id"`
				From    tgUser     `json:"from"`
				Data    string     `json:"data"`
				Message *tgMessage `json:"message"`
			}{ID: "q", From: tgUser{ID: user}, Data: data, Message: msg(user, pairedChat, "private", "").Message}
			return u
		}
		b.handle(ctx, cb(2002, nonce+":y"))      // a stranger presses ✅
		b.handle(ctx, cb(pairedUser, "bogus:y")) // a press for another request
		time.Sleep(50 * time.Millisecond)
		for _, e := range auditLines(t, b.cfg.StateDir) {
			if e.Tool == "block_ip" {
				t.Fatalf("block_ip was decided by someone else's press: %+v", e)
			}
		}
		b.handle(ctx, cb(pairedUser, nonce+":"+press))
		var got *logEntry
		for i := 0; i < 100 && got == nil; i++ {
			for _, e := range auditLines(t, b.cfg.StateDir) {
				if e.Tool == "block_ip" {
					e := e
					got = &e
				}
			}
			time.Sleep(20 * time.Millisecond)
		}
		if got == nil {
			t.Fatal("no block_ip decision was logged")
		}
		if got.Confirmed != (press == "y") {
			t.Errorf("press %s: confirmed = %v", press, got.Confirmed)
		}
	}
}

// With allow_control off (the default) the model is never offered a control tool.
func TestBotControlOffByDefault(t *testing.T) {
	model := &hostileModel{replies: []string{call("block_ip", `{"ip":"203.0.113.9","reason":"x"}`), done}}
	b, tg := testBot(t, model, false)
	pairDirectly(t, b)
	b.handle(context.Background(), msg(pairedUser, pairedChat, "private", "block it"))
	time.Sleep(300 * time.Millisecond)
	for _, s := range tg.sent() {
		if _, ok := s["reply_markup"]; ok {
			t.Errorf("a control confirmation was offered with allow_control off")
		}
	}
	for _, req := range model.requests {
		var body struct{ Tools []toolDef }
		json.Unmarshal([]byte(req), &body)
		for _, d := range body.Tools {
			if d.Function.Name == "block_ip" {
				t.Errorf("block_ip was offered to the model")
			}
		}
	}
}
