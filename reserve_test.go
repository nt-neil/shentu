package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// reserveDispatch runs one dispatch of patrol under a monthly token limit
// with used tokens already spent, and returns the sub-agent requests and
// what the commander was told.
func reserveDispatch(t *testing.T, limit, used int, before func(cfg *Config)) (subs int, out string, cfg *Config) {
	t.Helper()
	h := &hostileModel{replies: []string{call("dispatch", `{"tasks":[{"role":"patrol"}]}`), answerMsg(`{"status":"complete","findings":[]}`), done}}
	a, state := dispatchAgent(t, h, nil, nil)
	a.cfg.Budget.MonthlyTokens = limit
	if used > 0 {
		os.WriteFile(filepath.Join(state, "log.jsonl"), []byte(`{"time":"`+time.Now().UTC().Format(time.RFC3339)+`","tool":"llm","in_tokens":`+strconv.Itoa(used)+"}\n"), 0o600)
	}
	if before != nil {
		before(a.cfg)
	}
	_, msgs, _ := a.run(context.Background(), []message{{Role: "user", Content: "go"}})
	for _, m := range msgs {
		if m.Role == "tool" {
			out += m.Content
		}
	}
	return len(subRequestsOf(h)), out, a.cfg
}

func liveReservations(t *testing.T, cfg *Config) []reservation {
	t.Helper()
	var items []reservation
	if err := withReservations(cfg, time.Now(), func(r *reservations) { items = append(items, r.Items...) }); err != nil {
		t.Fatal(err)
	}
	return items
}

// R1: what another dispatch has reserved is not room: at 40,000 of 150,000
// used with another's 120,000 reserved, no sub-agent calls the model.
func TestReserveOthersCount(t *testing.T) {
	var release func()
	subs, out, _ := reserveDispatch(t, 150_000, 40_000, func(cfg *Config) {
		var err error
		if _, release, err = reserve(cfg, dispatchTokenCap, 0, time.Now()); err != nil { // the other process
			t.Fatal(err)
		}
	})
	if subs != 0 || !strings.Contains(out, "budget") {
		t.Errorf("with another's reservation: %d sub-agent requests\n%s", subs, out)
	}
	release()
	if subs, _, _ := reserveDispatch(t, 150_000, 40_000, nil); subs == 0 {
		t.Error("with no other reservation the sub-agent did not run")
	}
}

// R1: a dispatch's reservation is released when it ends, and one a dead
// process left is not counted once it has expired.
func TestReserveReleasedAndExpired(t *testing.T) {
	subs, _, cfg := reserveDispatch(t, 1_000_000, 0, func(cfg *Config) {
		withReservations(cfg, time.Now(), func(r *reservations) {
			r.Items = append(r.Items, reservation{ID: "dead00000000", Tokens: 999_000, Expires: time.Now().Add(-time.Minute)})
		})
	})
	if subs == 0 {
		t.Error("an expired reservation stopped the dispatch")
	}
	if items := liveReservations(t, cfg); len(items) != 0 {
		t.Errorf("left after the dispatch: %+v", items)
	}
}

// R1: a reservations file that cannot be trusted stops the dispatch.
func TestReserveUntrusted(t *testing.T) {
	subs, out, _ := reserveDispatch(t, 1_000_000, 0, func(cfg *Config) {
		p := filepath.Join(cfg.StateDir, reservationsFile)
		b, _ := json.Marshal(reservations{V: 1})
		os.WriteFile(p, b, 0o644)
		os.Chmod(p, 0o644)
	})
	if subs != 0 || !strings.Contains(out, "budget") {
		t.Errorf("an untrusted reservations file: %d sub-agent requests\n%s", subs, out)
	}
}

// R1: reservations made at once from several goroutines all count.
func TestReserveConcurrent(t *testing.T) {
	state, _ := filepath.EvalSymlinks(t.TempDir())
	cfg := &Config{StateDir: state}
	cfg.Budget.MonthlyTokens = 10_000_000
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, err := reserve(cfg, 1000, 0.01, time.Now()); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if n, c, err := othersReserved(cfg, "", time.Now()); err != nil || n != 8000 || c < 0.0799 || c > 0.0801 {
		t.Errorf("reserved: %d %v %v", n, c, err)
	}
}

// R2: with [agents] prices, a dispatch at $15 per million tokens (up to
// $1.80) runs its sub-agents at once only when the month's cost limit has
// room for that: 0.10 spent of 1.50 is under half, but not room enough.
func TestReserveCostParallel(t *testing.T) {
	sub, _, _ := parallelDispatchWith(t, parallelOpts{external: true, limit: 1_000_000, tokens: 10, costLimit: 1.5, spent: 0.10, price: 0.0001, pricePerMTok: 15})
	if sub.most != 1 {
		t.Errorf("$1.80 of room needed, $1.40 left: %d at once", sub.most)
	}
	sub, _, _ = parallelDispatchWith(t, parallelOpts{external: true, limit: 1_000_000, tokens: 10, costLimit: 5, spent: 0.10, price: 0.0001, pricePerMTok: 15})
	if sub.most < 2 {
		t.Errorf("$1.80 of room needed, $4.90 left: %d at once", sub.most)
	}
}

// R2: what another dispatch may cost counts as spent for a model call.
func TestReserveOthersCost(t *testing.T) {
	var release func()
	subs, out, _ := reserveDispatch(t, 1_000_000, 0, func(cfg *Config) {
		cfg.Budget.MonthlyCost = 2
		var err error
		if _, release, err = reserve(cfg, 1000, 2.5, time.Now()); err != nil { // another dispatch that may cost $2.50
			t.Fatal(err)
		}
	})
	defer release()
	if subs != 0 || !strings.Contains(out, "budget") {
		t.Errorf("another's $2.50 against a $2 limit: %d sub-agent requests\n%s", subs, out)
	}
	priced := &Config{}
	priced.Agents.PricePerMTokIn, priced.Agents.PricePerMTokOut = 3, 15
	if c := dispatchCost(priced); c < 1.799 || c > 1.801 {
		t.Errorf("dispatchCost: %v", c)
	}
}
