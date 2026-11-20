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
	return parallelDispatchWith(t, parallelOpts{external: external, limit: limit, used: used, tokens: tokens})
}

type parallelOpts struct {
	external         bool
	realHost         bool // agentsOnThisHost as it is (the test model is on 127.0.0.1)
	limit, used      int
	tokens           int
	costLimit, spent float64 // monthly_cost, and what this month already cost
	price            float64 // what each call costs
}

func parallelDispatchWith(t *testing.T, o parallelOpts) (*countingModel, []subReport, []string) {
	t.Helper()
	external, limit, used, tokens := o.external, o.limit, o.used, o.tokens
	oldExt, oldDial, oldHost := agentsExternal, llmDial, agentsOnThisHost
	agentsExternal = func(string) bool { return external }
	if !o.realHost {
		agentsOnThisHost = func(string) bool { return false }
	}
	llmDial = (&net.Dialer{}).DialContext
	t.Cleanup(func() { agentsExternal, llmDial, agentsOnThisHost = oldExt, oldDial, oldHost })
	h := &hostileModel{replies: []string{call("dispatch", `{"tasks":[{"role":"patrol"},{"role":"surface"},{"role":"attack"}]}`), done}}
	a, state := dispatchAgent(t, h, nil, nil)
	if used > 0 || o.spent > 0 {
		line := `{"time":"` + time.Now().UTC().Format(time.RFC3339) + `","tool":"llm","in_tokens":` + strconv.Itoa(used) +
			`,"cost":` + strconv.FormatFloat(o.spent, 'f', -1, 64) + "}\n"
		os.WriteFile(filepath.Join(state, "log.jsonl"), []byte(line), 0o600)
	}
	var next http.Handler = &usageModel{hostileModel: &hostileModel{replies: []string{answerMsg(`{"status":"complete","findings":[]}`)}}, tokens: tokens}
	if o.price > 0 {
		reply := answerMsg(`{"status":"complete","findings":[]}`)
		next = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"choices":[{"message":` + reply + `}],"usage":{"prompt_tokens":` + strconv.Itoa(tokens) + `},"price_charged":` + strconv.FormatFloat(o.price, 'f', -1, 64) + `}`))
		})
	}
	sub := &countingModel{delay: 300 * time.Millisecond, next: next}
	srv := httptest.NewServer(sub)
	t.Cleanup(srv.Close)
	a.cfg.Agents.BaseURL, a.cfg.Agents.Model = srv.URL, "m"
	a.cfg.Budget.MonthlyTokens = limit
	a.cfg.Budget.MonthlyCost = o.costLimit
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

// N-D-r2-1: with a cost limit, they run at once only under half of it; at
// 0.99 of 1.00 they take turns and the limit stops them after one call.
func TestDispatchParallelCostLimit(t *testing.T) {
	sub, reps, _ := parallelDispatchWith(t, parallelOpts{external: true, limit: 1_000_000, tokens: 10, costLimit: 1, spent: 0.99, price: 0.05})
	if sub.most != 1 || sub.total != 1 || len(reps) != 3 {
		t.Errorf("0.99 of 1.00 spent: %d at once, %d calls, reports %+v", sub.most, sub.total, reps)
	}
	sub, _, _ = parallelDispatchWith(t, parallelOpts{external: true, limit: 1_000_000, tokens: 10, costLimit: 100, spent: 1, price: 0.05})
	if sub.most < 2 {
		t.Errorf("1 of 100 spent: at most %d at once", sub.most)
	}
}

// A model outside this host by agentsExternal's literal reading, at an
// address of this host, still runs them in turn.
func TestDispatchParallelLocalAddress(t *testing.T) {
	sub, reps, _ := parallelDispatchWith(t, parallelOpts{external: true, realHost: true, limit: 1_000_000, tokens: 10})
	if sub.most != 1 || len(reps) != 3 {
		t.Errorf("a model on 127.0.0.1: %d at once, reports %d", sub.most, len(reps))
	}
}

func TestAgentsOnThisHost(t *testing.T) {
	cases := map[string]bool{
		"http://127.0.0.1:1": true, "http://127.1:1": true, "http://0x7f.1:1": true, "http://2130706433:1": true,
		"http://0177.0.0.1:1": true, "http://0.0.0.0:1": true, "http://0:1": true, "http://[::]:1": true, "http://[::1]:1": true,
		"http://localhost:1": true, "http://foo.localhost:1": true, "http://[::ffff:127.0.0.1]:1": true,
		"http://192.0.2.1:1": false, "http://198.51.100.7:1": false, "http://[2001:db8::1]:1": false, "http://8.8.8.8:1": false,
		"::bad": true,
	}
	if addrs, _ := net.InterfaceAddrs(); len(addrs) > 0 {
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && !n.IP.IsLoopback() && n.IP.To4() != nil {
				cases["http://"+n.IP.String()+":11434"] = true // this host's LAN address
				break
			}
		}
	}
	for u, want := range cases {
		if got := agentsOnThisHost(u); got != want {
			t.Errorf("%s: %v", u, got)
		}
	}
	for s, want := range map[string]string{"127.1": "127.0.0.1", "0x7f.0.1": "127.0.0.1", "10.1.2": "10.1.0.2", "3232235777": "192.168.1.1"} {
		if got := atonV4(s); got == nil || got.String() != want {
			t.Errorf("atonV4(%s) = %v", s, got)
		}
	}
	for _, s := range []string{"256.1", "1.2.3.4.5", "a.b", "", "1..2", "127.0.0.256"} {
		if got := atonV4(s); got != nil {
			t.Errorf("atonV4(%q) = %v", s, got)
		}
	}
}
