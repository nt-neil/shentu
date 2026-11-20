package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// S-r3-C1: the 100% limit counts a log it could not read in full as used up.
func TestBudgetUsedStrict(t *testing.T) {
	state := t.TempDir()
	cfg := &Config{StateDir: state}
	cfg.Budget.MonthlyTokens = 1_000_000
	now := time.Now()
	ts := now.UTC().Format(time.RFC3339)
	small := `{"time":"` + ts + `","tool":"llm","in_tokens":10,"out_tokens":10}` + "\n"
	p := filepath.Join(state, "log.jsonl")
	os.WriteFile(p, []byte(small), 0o600)
	if u := budgetUsed(cfg, now); u <= 0 || u >= 1 {
		t.Fatalf("a readable log: %v", u)
	}
	long := `{"time":"` + ts + `","tool":"llm","in_tokens":900000,"error":"` + strings.Repeat("x", maxLogLine) + `"}` + "\n"
	os.WriteFile(p, []byte(small+long), 0o600)
	if u := budgetUsed(cfg, now); u < 1 {
		t.Errorf("a model call's line too long to read was taken as unused: %v", u)
	}
	a := &agent{cfg: cfg}
	if _, _, err := a.run(context.Background(), nil); !errors.Is(err, errBudget) {
		t.Errorf("run: %v", err)
	}
}

// S-r3-B1: bot.json says the service can act only while it runs.
func TestBotClearsCanActOnExit(t *testing.T) {
	old := netAdmin
	netAdmin = func() bool { return true }
	t.Cleanup(func() { netAdmin = old })
	b, _ := levelBot(t, nil, [4]int{3, 2, 3, 2})
	var seen atomic.Bool // no lock held around bot.json's: a handler may hold that one
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/getUpdates") {
			withBotState(b.cfg.StateDir, func(s *botState) error {
				if s.CanAct {
					seen.Store(true)
				}
				return nil
			})
		}
		w.Write([]byte(`{"ok":true,"result":[]}`))
	}))
	b.api, b.hc = srv.URL, srv.Client()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	b.run(ctx)
	srv.Close() // waits for a request still being answered
	if !seen.Load() {
		t.Error("bot.json did not say the running service can act")
	}
	var st botState
	withBotState(b.cfg.StateDir, func(s *botState) error { st = *s; return nil })
	if st.CanAct {
		t.Error("bot.json still says the service can act after it stopped")
	}
}
