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
	if _, _, err := reserve(a.cfg, dispatchTokenCap, 0, time.Now()); err != nil { // the other dispatch, reserved after this one's commander checked
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

// S-R-6 (R2): a negative cost is not trusted either.
func TestReserveNegativeCostUntrusted(t *testing.T) {
	subs, out, _ := reserveDispatch(t, 1_000_000, 0, func(c *Config) {
		b, _ := json.Marshal(reservations{V: 1, Items: []reservation{{ID: "neg000000001", Tokens: 1000, Cost: -5, Expires: time.Now().Add(time.Hour)}}})
		os.WriteFile(filepath.Join(c.StateDir, reservationsFile), b, 0o600)
	})
	if subs != 0 || !strings.Contains(out, "negative reservation") {
		t.Errorf("a negative cost: %d sub-agent requests\n%s", subs, out)
	}
}

// S-R-2: what another dispatch in progress has logged since its
// reservation started is in the month's use already; it is taken off its
// reservation, so near the limit the check no longer stops early. Its
// reservation never goes below 0, and one without its dispatch counts in full.
func TestReserveLessWhatItSpent(t *testing.T) {
	cfg := &Config{}
	tmp, _ := filepath.EvalSymlinks(t.TempDir())
	cfg.StateDir = tmp
	cfg.Budget.MonthlyTokens = 200_000
	now := time.Now()
	const other = "0123456789ab"
	if _, _, err := reserveFor(cfg, dispatchTokenCap, 0, other, now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	line := func(d string, n int, at time.Time) string {
		b, _ := json.Marshal(logEntry{Time: at, Actor: "sub:patrol", Tool: "llm", InTokens: n, Dispatch: d})
		return string(b) + "\n"
	}
	// 70k logged by the other dispatch since it started, 10k before it did, 5k by another.
	os.WriteFile(filepath.Join(tmp, "log.jsonl"), []byte(line(other, 70_000, now)+line(other, 10_000, now.Add(-time.Hour))+line("ffffffffffff", 5_000, now)), 0o600)
	u, err := usageWithOthers(cfg, "", now)
	if err != nil {
		t.Fatal(err)
	}
	if u.tokens != 85_000 || u.othersTokens != dispatchTokenCap-70_000 {
		t.Errorf("use %d, others hold %d; want 85000 and %d", u.tokens, u.othersTokens, dispatchTokenCap-70_000)
	}
	// 85k used + 50k held = 135k of 200k: a model call goes ahead (before
	// S-R-2, 85k + 120k = 205k stopped it).
	if err := budgetStop(cfg, now, ""); err != nil {
		t.Errorf("stopped though the others hold only the rest: %v", err)
	}
	// Spent past the cap: held 0, not less.
	os.WriteFile(filepath.Join(tmp, "log.jsonl"), []byte(line(other, 150_000, now)), 0o600)
	if u, _ := usageWithOthers(cfg, "", now); u.othersTokens != 0 || u.tokens != 150_000 {
		t.Errorf("past the cap: %+v", u)
	}
	// A reservation without its dispatch counts in full.
	if _, _, err := reserve(cfg, 30_000, 0, now); err != nil {
		t.Fatal(err)
	}
	if u, _ := usageWithOthers(cfg, "", now); u.othersTokens != 30_000 {
		t.Errorf("without a dispatch: %+v", u)
	}
}

// S-R-2: a reservation started in the future takes nothing off.
func TestReserveFutureStartCountsInFull(t *testing.T) {
	cfg := &Config{}
	tmp, _ := filepath.EvalSymlinks(t.TempDir())
	cfg.StateDir = tmp
	cfg.Budget.MonthlyTokens = 1_000_000
	now := time.Now()
	const other = "0123456789ab"
	withReservations(cfg, now, func(r *reservations) {
		r.Items = append(r.Items, reservation{ID: "fut000000000", Tokens: 100_000, Expires: now.Add(time.Hour), Dispatch: other, Started: now.Add(time.Hour)})
	})
	// A line dated after that start too (a clock set ahead, or a forged
	// time): still nothing is taken off a reservation that has not begun.
	b, _ := json.Marshal(logEntry{Time: now.Add(2 * time.Hour), Tool: "llm", InTokens: 60_000, Dispatch: other})
	os.WriteFile(filepath.Join(tmp, "log.jsonl"), append(b, '\n'), 0o600)
	if u, _ := usageWithOthers(cfg, "", now); u.othersTokens != 100_000 {
		t.Errorf("future start: %+v", u)
	}
}

// S-169-1: two reservations of different ids for one dispatch, which no
// dispatch writes, would have that dispatch's use taken off twice: the
// file is not trusted (fail closed), and the budget line says so.
func TestReserveSharedDispatchUntrusted(t *testing.T) {
	var cfg *Config
	subs, out, _ := reserveDispatch(t, 1_000_000, 0, func(c *Config) {
		cfg = c
		exp := time.Now().Add(time.Hour)
		b, _ := json.Marshal(reservations{V: 1, Items: []reservation{
			{ID: "aaa000000000", Tokens: 120_000, Expires: exp, Dispatch: "0123456789ab", Started: time.Now()},
			{ID: "bbb000000000", Tokens: 120_000, Expires: exp, Dispatch: "0123456789ab", Started: time.Now()},
		}})
		os.WriteFile(filepath.Join(c.StateDir, reservationsFile), b, 0o600)
	})
	if subs != 0 || !strings.Contains(out, "two reservations for one dispatch") {
		t.Errorf("two reservations for one dispatch: %d sub-agent requests\n%s", subs, out)
	}
	if l := budgetLine(cfg, time.Now(), false); !strings.Contains(l, "cannot be read") {
		t.Errorf("budget line: %q", l)
	}
}
