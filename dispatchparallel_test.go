package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// slowModel answers after delay, as a model elsewhere does.
type slowModel struct {
	*hostileModel
	delay time.Duration
}

func (s *slowModel) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	time.Sleep(s.delay)
	s.hostileModel.ServeHTTP(w, r)
}

// parallelDispatch dispatches three sub-agents to a model that takes 300ms a
// call, outside this host or not, and returns how long the run took, the
// reports and the progress steps.
func parallelDispatch(t *testing.T, external bool) (time.Duration, []subReport, []string) {
	t.Helper()
	oldExt, oldDial := agentsExternal, llmDial
	agentsExternal = func(string) bool { return external }
	llmDial = (&net.Dialer{}).DialContext
	t.Cleanup(func() { agentsExternal, llmDial = oldExt, oldDial })
	h := &hostileModel{replies: []string{call("dispatch", `{"tasks":[{"role":"patrol"},{"role":"surface"},{"role":"attack"}]}`), done}}
	a, _ := dispatchAgent(t, h, nil, nil)
	sub := &slowModel{hostileModel: &hostileModel{replies: []string{answerMsg(`{"status":"complete","findings":[]}`)}}, delay: 300 * time.Millisecond}
	srv := httptest.NewServer(sub)
	t.Cleanup(srv.Close)
	a.cfg.Agents.BaseURL, a.cfg.Agents.Model = srv.URL, "m"
	a.cfg.Budget.MonthlyTokens = 1_000_000
	var steps []string
	a.progress = func(s string) { steps = append(steps, s) } // not safe to call at once: -race says if it is
	start := time.Now()
	a.run(context.Background(), []message{{Role: "user", Content: "go"}})
	return time.Since(start), lastReports(t, h), steps
}

// D: sub-agents on a model outside this host run at once, in the tasks'
// order in the reports.
func TestDispatchParallelExternal(t *testing.T) {
	took, reps, steps := parallelDispatch(t, true)
	if took >= 800*time.Millisecond {
		t.Errorf("three 300ms sub-agents took %v: not run at once", took)
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
	took, reps, _ := parallelDispatch(t, false)
	if took < 900*time.Millisecond {
		t.Errorf("three 300ms sub-agents on this host's model took %v: run at once", took)
	}
	if len(reps) != 3 {
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
