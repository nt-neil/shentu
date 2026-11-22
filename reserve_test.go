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
// A run refused before it dispatched at all (the commander's own model call
// counts the others' reservations too) leaves its error in out.
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
	_, msgs, err := a.run(context.Background(), []message{{Role: "user", Content: "go"}})
	if err != nil {
		out = err.Error()
	}
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
		if _, release, err = reserve(cfg, dispatchTokenCap, time.Now()); err != nil { // the other process
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
			if _, _, err := reserve(cfg, 1000, time.Now()); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if n, err := othersReserved(cfg, "", time.Now()); err != nil || n != 8000 {
		t.Errorf("reserved: %d %v", n, err)
	}
}

// S-R-6: a reservation with negative tokens, which no dispatch writes, is
// not dropped quietly: the file is not trusted (fail closed), and the
// budget line says it cannot be read.
func TestReserveNegativeUntrusted(t *testing.T) {
	var cfg *Config
	subs, out, _ := reserveDispatch(t, 1_000_000, 0, func(c *Config) {
		cfg = c
		b, _ := json.Marshal(reservations{V: 1, Items: []reservation{{ID: "neg000000000", Tokens: -500_000, Expires: time.Now().Add(time.Hour)}}})
		os.WriteFile(filepath.Join(c.StateDir, reservationsFile), b, 0o600)
	})
	if subs != 0 || !strings.Contains(out, "negative reservation") {
		t.Errorf("a negative reservation: %d sub-agent requests\n%s", subs, out)
	}
	if l := budgetLine(cfg, time.Now(), false); !strings.Contains(l, "cannot be read") {
		t.Errorf("budget line: %q", l)
	}
}

// S-R-7: a sub-agent another dispatch's reservation stops (two dispatches
// at once, room for one) says so; the month is not used up.
func TestReserveSubStoppedByOthers(t *testing.T) {
	h := &hostileModel{replies: []string{answerMsg(`{"status":"complete","findings":[]}`)}}
	a, state := dispatchAgent(t, h, nil, nil)
	a.cfg.Budget.MonthlyTokens = 150_000
	os.WriteFile(filepath.Join(state, "log.jsonl"), []byte(`{"time":"`+time.Now().UTC().Format(time.RFC3339)+`","tool":"llm","in_tokens":40000}`+"\n"), 0o600)
	if _, _, err := reserve(a.cfg, dispatchTokenCap, time.Now()); err != nil { // the other dispatch, reserved after this one's commander checked
		t.Fatal(err)
	}
	tasks, err := parseTasks(json.RawMessage(`{"tasks":[{"role":"patrol"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	_, reports, _, _ := a.runDispatch(context.Background(), originChat, "", tasks)
	if len(reports) != 1 || !strings.Contains(reports[0].Reason, "reservations of other dispatches") || strings.Contains(reports[0].Reason, "is used up") {
		t.Errorf("reports: %+v", reports)
	}
	if n := len(subRequestsOf(h)); n != 0 {
		t.Errorf("the sub-agent called the model %d times", n)
	}
}
