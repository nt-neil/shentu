package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"
)

// countingModel answers through next after delay and records the most
// requests it held at once.
type countingModel struct {
	next     http.Handler
	delay    time.Duration
	mu       sync.Mutex
	inflight int
	most     int
	total    int
}

func (c *countingModel) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	c.inflight++
	c.total++
	c.most = max(c.most, c.inflight)
	c.mu.Unlock()
	time.Sleep(c.delay)
	c.next.ServeHTTP(w, r)
	c.mu.Lock()
	c.inflight--
	c.mu.Unlock()
}

// parallelDispatch dispatches patrol, surface and attack to the sub-agents'
// own model (outside this host or not), which answers each call after
// 300ms reporting tokens each, under a monthly limit with used tokens
// already spent. It returns the model's counts, the reports and the
// progress steps.
func parallelDispatch(t *testing.T, external bool, limit, used, tokens int) (*countingModel, []subReport, []string) {
	t.Helper()
	oldExt, oldDial := agentsExternal, llmDial
	agentsExternal = func(string) bool { return external }
	llmDial = (&net.Dialer{}).DialContext
	t.Cleanup(func() { agentsExternal, llmDial = oldExt, oldDial })
	h := &hostileModel{replies: []string{call("dispatch", `{"tasks":[{"role":"patrol"},{"role":"surface"},{"role":"attack"}]}`), done}}
	a, state := dispatchAgent(t, h, nil, nil)
	if used > 0 {
		line := `{"time":"` + time.Now().UTC().Format(time.RFC3339) + `","tool":"llm","in_tokens":` + strconv.Itoa(used) + "}\n"
		os.WriteFile(filepath.Join(state, "log.jsonl"), []byte(line), 0o600)
	}
	sub := &countingModel{delay: 300 * time.Millisecond,
		next: &usageModel{hostileModel: &hostileModel{replies: []string{answerMsg(`{"status":"complete","findings":[]}`)}}, tokens: tokens}}
	srv := httptest.NewServer(sub)
	t.Cleanup(srv.Close)
	a.cfg.Agents.BaseURL, a.cfg.Agents.Model = srv.URL, "m"
	a.cfg.Budget.MonthlyTokens = limit
	var steps []string
	a.progress = func(s string) { steps = append(steps, s) } // not safe to call at once: -race says if it is
	a.run(context.Background(), []message{{Role: "user", Content: "go"}})
	return sub, lastReports(t, h), steps
}

// D: sub-agents on a model outside this host run at once, in the tasks'
// order in the reports.
func TestDispatchParallelExternal(t *testing.T) {
	sub, reps, steps := parallelDispatch(t, true, 1_000_000, 0, 10)
	if sub.most < 2 {
		t.Errorf("at most %d request at once: not run at once", sub.most)
	}
	if len(reps) != 3 || reps[0].Role != "patrol" || reps[1].Role != "surface" || reps[2].Role != "attack" {
		t.Errorf("reports: %+v", reps)
	}
	for _, r := range reps {
		if r.Status != "complete" {
			t.Errorf("report: %+v", r)
		}
	}
	if len(steps) < 4 { // dispatch, then sub:<role> for each
		t.Errorf("progress: %v", steps)
	}
}

// D: on this host's model they still run one after another.
func TestDispatchSequentialLocal(t *testing.T) {
	sub, reps, _ := parallelDispatch(t, false, 1_000_000, 0, 10)
	if sub.most != 1 || len(reps) != 3 {
		t.Errorf("at most %d at once, reports %+v", sub.most, reps)
	}
}

// N-D1: without room in the monthly limit for a whole dispatch, they take
// turns, and the limit stops those after the first, as it did before.
func TestDispatchParallelNeedsBudgetRoom(t *testing.T) {
	sub, reps, _ := parallelDispatch(t, true, 100_000, 99_000, 30_000)
	if sub.most != 1 || sub.total != 1 {
		t.Errorf("99%% of the limit used: %d at once, %d calls to the model", sub.most, sub.total)
	}
	stopped := 0
	for _, r := range reps {
		if r.Reason == "the monthly AI budget is used up" {
			stopped++
		}
	}
	if len(reps) != 3 || stopped != 2 {
		t.Errorf("reports: %+v", reps)
	}
}

// D: each sub-agent run at once gets an equal share of the dispatch's cap.
func TestDispatchParallelShare(t *testing.T) {
	for n, want := range map[int]int{2: subTokenCap, 3: subTokenCap} {
		if got := min(subTokenCap, dispatchTokenCap/n); got != want || got*n > dispatchTokenCap {
			t.Errorf("%d tasks: share %d", n, got)
		}
	}
}
