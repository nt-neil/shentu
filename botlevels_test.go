package main

import (
	"bufio"
	"context"
	"encoding/base32"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestTOTP(t *testing.T) {
	// RFC 6238 test vector (SHA-1): T = 59 s → 94287082, of which the last 6 digits.
	if got := totpCode([]byte("12345678901234567890"), 1); got != "287082" {
		t.Errorf("totpCode = %s, want 287082", got)
	}
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))
	now := time.Unix(59, 0)
	step, ok := totpCheck(secret, "287082", 0, now)
	if !ok {
		t.Fatal("valid code refused")
	}
	if _, ok := totpCheck(secret, "287082", step, now); ok {
		t.Errorf("a code was accepted twice")
	}
	if _, ok := totpCheck(secret, "000000", 0, now); ok {
		t.Errorf("wrong code accepted")
	}
}

func levelBot(t *testing.T, model *hostileModel, levels [4]int) (*bot, *fakeTelegram) {
	b, tg := testBot(t, model, levels[0] >= 3)
	b.cfg.Bot.Interaction, b.cfg.Bot.Answers, b.cfg.Bot.Confirm, b.cfg.Bot.Protection = levels[0], levels[1], levels[2], levels[3]
	pairDirectly(t, b)
	return b, tg
}

func blockDecision(t *testing.T, b *bot) *logEntry {
	for i := 0; i < 150; i++ {
		for _, e := range auditLines(t, b.cfg.StateDir) {
			if e.Tool == "block_ip" {
				e := e
				return &e
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	return nil
}

// confirm = 1: Telegram only proposes; the action waits for `shentu bot approve`.
func TestBotConfirmOnServer(t *testing.T) {
	for _, approve := range []string{"n\n", "y\n"} {
		model := &hostileModel{replies: []string{call("block_ip", `{"ip":"203.0.113.9","reason":"x"}`), done}}
		b, tg := levelBot(t, model, [4]int{3, 4, 1, 2})
		b.handle(context.Background(), msg(pairedUser, pairedChat, "private", "block it"))
		var waiting bool
		for i := 0; i < 150 && !waiting; i++ {
			withBotState(b.cfg.StateDir, func(s *botState) error { waiting = s.Action != nil; return nil })
			time.Sleep(20 * time.Millisecond)
		}
		if !waiting {
			t.Fatal("no action waited for the server")
		}
		for _, s := range tg.sent() {
			if _, ok := s["reply_markup"]; ok {
				t.Errorf("confirm = 1 offered a Telegram button")
			}
		}
		var out strings.Builder
		botApprove(b.cfg, bufio.NewReader(strings.NewReader(approve)), &out)
		e := blockDecision(t, b)
		if e == nil || e.Confirmed != (approve == "y\n") {
			t.Errorf("approve %q: decision %+v", strings.TrimSpace(approve), e)
		}
	}
}

// confirm = 2: ✅ alone is not enough; the authenticator code is required.
func TestBotConfirmNeedsCode(t *testing.T) {
	model := &hostileModel{replies: []string{call("block_ip", `{"ip":"203.0.113.9","reason":"x"}`), done}}
	b, tg := levelBot(t, model, [4]int{3, 4, 2, 2})
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))
	withBotState(b.cfg.StateDir, func(s *botState) error { s.TOTPSecret = secret; return nil })
	ctx := context.Background()
	b.handle(ctx, msg(pairedUser, pairedChat, "private", "block it"))
	nonce := ""
	for i := 0; i < 150 && nonce == ""; i++ {
		for _, s := range tg.sent() {
			if rm, ok := s["reply_markup"].(map[string]any); ok {
				data := rm["inline_keyboard"].([]any)[0].([]any)[0].(map[string]any)["callback_data"].(string)
				nonce, _, _ = strings.Cut(data, ":")
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	var u tgUpdate
	u.Callback = &struct {
		ID      string     `json:"id"`
		From    tgUser     `json:"from"`
		Data    string     `json:"data"`
		Message *tgMessage `json:"message"`
	}{ID: "q", From: tgUser{ID: pairedUser}, Data: nonce + ":y", Message: msg(pairedUser, pairedChat, "private", "").Message}
	b.handle(ctx, u)
	time.Sleep(100 * time.Millisecond)
	for _, wrong := range []string{"000000", "111111", "222222"} {
		b.handle(ctx, msg(pairedUser, pairedChat, "private", wrong))
		time.Sleep(50 * time.Millisecond)
	}
	e := blockDecision(t, b)
	if e == nil || e.Confirmed {
		t.Errorf("✅ and three wrong codes must not run the action: %+v", e)
	}
}

// confirm = 4 runs at once, but it is still logged and the model is still told.
func TestBotConfirmNone(t *testing.T) {
	model := &hostileModel{replies: []string{call("block_ip", `{"ip":"203.0.113.9","reason":"x"}`), done}}
	b, tg := levelBot(t, model, [4]int{3, 4, 4, 2})
	b.handle(context.Background(), msg(pairedUser, pairedChat, "private", "block it"))
	e := blockDecision(t, b)
	if e == nil || !e.Confirmed {
		t.Errorf("confirm = 4 did not run: %+v", e)
	}
	for _, s := range tg.sent() {
		if _, ok := s["reply_markup"]; ok {
			t.Errorf("confirm = 4 still asked")
		}
	}
}

// answers = 1 and 2 are capped in code, whatever the model writes.
func TestBotAnswerCap(t *testing.T) {
	long := strings.Repeat("x", 5000)
	model := &hostileModel{replies: []string{`{"role":"assistant","content":"` + long + `"}`}}
	b, tg := levelBot(t, model, [4]int{2, 1, 2, 2})
	b.handle(context.Background(), msg(pairedUser, pairedChat, "private", "status?"))
	for i := 0; i < 150; i++ {
		for _, s := range tg.sent() {
			if txt, _ := s["text"].(string); strings.HasPrefix(txt, "xxx") {
				if n := len([]rune(txt)); n > 401 {
					t.Errorf("answers = 1 sent %d characters", n)
				}
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("no answer sent")
}

// /lockdown works for the paired user only, unpairs and pauses.
func TestBotLockdown(t *testing.T) {
	b, _ := levelBot(t, &hostileModel{replies: []string{done}}, [4]int{2, 2, 2, 2})
	b.handle(context.Background(), msg(2002, 2002, "private", "/lockdown"))
	var st botState
	withBotState(b.cfg.StateDir, func(s *botState) error { st = *s; return nil })
	if st.Paused != "" || st.UserID == 0 {
		t.Fatalf("a stranger's /lockdown took effect")
	}
	b.handle(context.Background(), msg(pairedUser, pairedChat, "private", "/lockdown"))
	withBotState(b.cfg.StateDir, func(s *botState) error { st = *s; return nil })
	if st.Paused == "" || st.UserID != 0 {
		t.Errorf("lockdown did not unpair and pause: %+v", st)
	}
}

// A 409 (someone else reads this bot's updates) pauses at protection 1–2, not at 3.
func TestBotTokenLeak(t *testing.T) {
	for prot, wantPause := range map[int]bool{2: true, 3: false} {
		b, _ := levelBot(t, nil, [4]int{2, 2, 2, prot})
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/getUpdates") {
				w.WriteHeader(409)
				w.Write([]byte(`{"ok":false,"description":"Conflict: terminated by other getUpdates request"}`))
				return
			}
			w.Write([]byte(`{"ok":true,"result":true}`))
		}))
		b.api, b.hc = srv.URL, srv.Client()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		b.run(ctx)
		cancel()
		srv.Close()
		var st botState
		withBotState(b.cfg.StateDir, func(s *botState) error { st = *s; return nil })
		if (st.Paused != "") != wantPause {
			t.Errorf("protection %d: paused = %q", prot, st.Paused)
		}
	}
}

// Interaction 1 reads nothing at all, and raising a level is logged.
func TestBotLevelsAtStart(t *testing.T) {
	b, tg := levelBot(t, nil, [4]int{1, 2, 2, 2})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	b.run(ctx)
	if len(tg.calls) != 0 {
		t.Errorf("interaction = 1 still called Telegram: %v", tg.calls)
	}
	b2, _ := levelBot(t, nil, [4]int{3, 3, 4, 3})
	b2.noteLevelChanges(context.Background())
	found := false
	for _, e := range auditLines(t, b2.cfg.StateDir) {
		found = found || e.Tool == "bot_levels"
	}
	if !found {
		t.Errorf("raised levels were not logged")
	}
}

func TestBotUnitHasNoNetAdmin(t *testing.T) {
	b, _ := os.ReadFile("packaging/shentu-bot.service")
	for _, l := range strings.Split(string(b), "\n") {
		if (strings.HasPrefix(l, "CapabilityBoundingSet=") || strings.HasPrefix(l, "AmbientCapabilities=")) && strings.Contains(l, "CAP_NET_ADMIN") {
			t.Errorf("the bot unit grants CAP_NET_ADMIN; only the setup drop-in for interaction 3-4 may")
		}
	}
}

// Wrong codes add up across requests: five in a row pause the bot.
func TestBotCodeFailuresPause(t *testing.T) {
	b, _ := levelBot(t, &hostileModel{replies: []string{done}}, [4]int{3, 4, 2, 2})
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))
	withBotState(b.cfg.StateDir, func(s *botState) error { s.TOTPSecret, s.CodeFails = secret, 3; return nil })
	ctx := context.Background()
	done := make(chan bool)
	go func() { done <- b.confirmCode(ctx, pairedChat) }()
	for _, c := range []string{"000000", "111111"} {
		for i := 0; i < 100; i++ {
			b.mu.Lock()
			w := b.codeWait
			b.mu.Unlock()
			if w != nil {
				w <- c
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if <-done {
		t.Fatal("wrong codes were accepted")
	}
	var st botState
	withBotState(b.cfg.StateDir, func(s *botState) error { st = *s; return nil })
	if st.Paused == "" {
		t.Errorf("five wrong codes in total did not pause the bot (fails = %d)", st.CodeFails)
	}
}
