package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nt-neil/shentu/tools"
)

// reserveOther makes another process's live reservation of n tokens.
func reserveOther(t *testing.T, cfg *Config, n int) {
	t.Helper()
	os.MkdirAll(cfg.StateDir, 0o700)
	if _, _, err := reserve(cfg, n, 0, time.Now()); err != nil {
		t.Fatal(err)
	}
}

func spend(t *testing.T, cfg *Config, n int) {
	t.Helper()
	os.MkdirAll(cfg.StateDir, 0o700)
	os.WriteFile(filepath.Join(cfg.StateDir, "log.jsonl"), []byte(`{"time":"`+time.Now().UTC().Format(time.RFC3339)+`","tool":"llm","in_tokens":`+strconv.Itoa(n)+"}\n"), 0o600)
}

// R1 N: in the chat, a stop only others' reservations make says so, with
// how much they hold and when it frees; the budget line says it too.
func TestBotBudgetReservedWords(t *testing.T) {
	b, tg := testBot(t, &hostileModel{replies: []string{done}}, false)
	pairDirectly(t, b)
	b.cfg.Budget.MonthlyTokens = 150_000
	spend(t, b.cfg, 40_000)
	reserveOther(t, b.cfg, dispatchTokenCap)
	b.handle(context.Background(), msg(pairedUser, pairedChat, "private", "status?"))
	answered(t, b)
	got := lastText(tg)
	k := kTokens(dispatchTokenCap)
	if !strings.Contains(got, k) || !strings.Contains(got, "17") || strings.Contains(got, b.t("budget_out")) {
		t.Errorf("reply: %q", got)
	}
	if !strings.Contains(got, k+" are reserved by dispatches in progress") && !strings.Contains(got, k+" 被進行中的派遣預留") {
		t.Errorf("budget line: %q", got)
	}
}

// R1 N: the month's own use at the limit is the plain budget stop.
func TestBotBudgetOutWords(t *testing.T) {
	b, tg := testBot(t, &hostileModel{replies: []string{done}}, false)
	pairDirectly(t, b)
	b.cfg.Budget.MonthlyTokens = 150_000
	spend(t, b.cfg, 150_000)
	b.handle(context.Background(), msg(pairedUser, pairedChat, "private", "status?"))
	answered(t, b)
	if got := lastText(tg); !strings.HasPrefix(got, b.t("budget_out")) {
		t.Errorf("reply: %q", got)
	}
}

// R1 N: a reservations file that cannot be trusted is named, with the fix.
func TestBotBudgetUnsureWords(t *testing.T) {
	b, tg := testBot(t, &hostileModel{replies: []string{done}}, false)
	pairDirectly(t, b)
	b.cfg.Budget.MonthlyTokens = 1_000_000
	os.MkdirAll(b.cfg.StateDir, 0o700)
	p := filepath.Join(b.cfg.StateDir, reservationsFile)
	bs, _ := json.Marshal(reservations{V: 1})
	os.WriteFile(p, bs, 0o644)
	os.Chmod(p, 0o644)
	b.handle(context.Background(), msg(pairedUser, pairedChat, "private", "status?"))
	answered(t, b)
	got := lastText(tg)
	if !strings.HasPrefix(got, b.t("budget_unsure")) || !strings.Contains(got, reservationsFile) || !strings.Contains(got, "move it aside") {
		t.Errorf("reply: %q", got)
	}
}

// R1 N: shentu chat gets the same words.
func TestChatBudgetReservedWords(t *testing.T) {
	cfg := &Config{}
	cfg.LLM.MaxSteps = 5
	tmp, _ := filepath.EvalSymlinks(t.TempDir())
	cfg.StateDir = filepath.Join(tmp, "state")
	cfg.Budget.MonthlyTokens = 150_000
	spend(t, cfg, 40_000)
	reserveOther(t, cfg, dispatchTokenCap)
	err := chat(context.Background(), cfg, &tools.Env{}, "status?")
	if err == nil || !strings.Contains(err.Error(), "reserved "+kTokens(dispatchTokenCap)+" tokens") || !strings.Contains(err.Error(), "17 minutes") {
		t.Errorf("chat: %v", err)
	}
}

// R1 S: the automatic check counts the others' reservations: it does not
// start (nor use a day's slot) when they leave no room for its cap.
func TestAutoBudgetCountsReservations(t *testing.T) {
	h := &hostileModel{replies: []string{done}}
	cfg, env, _ := autoSetup(t, h)
	cfg.Budget.MonthlyTokens = 300_000
	reserveOther(t, cfg, dispatchTokenCap*3/2) // 180k held: 180k + 120k is not under 80%
	now := time.Now()
	autoIncident(context.Background(), cfg, env, []autoCandidate{l3(1)}, now)
	if n := len(archived(t, cfg)); n != 0 || len(h.requests) != 0 {
		t.Fatalf("dispatched with others' reservations filling the room: %d records, %d model calls", n, len(h.requests))
	}
	if s := autoIncidentSection(cfg, now); !strings.Contains(s, "budget 1") {
		t.Errorf("daily report:\n%s", s)
	}
}

// Backlog: auto_incident with a monthly token limit under 150k can never
// start a check: the report says so (and the config load warns).
func TestAutoBudgetTooSmallWarned(t *testing.T) {
	h := &hostileModel{replies: []string{done}}
	cfg, _, _ := autoSetup(t, h)
	cfg.Budget.MonthlyTokens = 100_000
	if w := autoBudgetWarning(cfg); !strings.Contains(w, kTokens(autoMinTokens)) {
		t.Errorf("warning: %q", w)
	}
	if s := autoIncidentSection(cfg, time.Now()); !strings.Contains(s, "none will ever start") {
		t.Errorf("daily report:\n%s", s)
	}
	cfg.Budget.MonthlyTokens = 150_000
	if w := autoBudgetWarning(cfg); w != "" {
		t.Errorf("warned at 150k: %q", w)
	}
	cfg.Agents.AutoIncident = false
	cfg.Budget.MonthlyTokens = 100_000
	if w := autoBudgetWarning(cfg); w != "" {
		t.Errorf("warned with auto_incident off: %q", w)
	}
}
