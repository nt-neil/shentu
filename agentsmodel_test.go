package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestAgentsExternalDefault(t *testing.T) {
	for u, want := range map[string]bool{
		"http://127.0.0.1:11434/v1": false, "http://localhost:8080": false, "http://[::1]:1/v1": false,
		"https://api.example.com/v1": true, "::not a url": true,
	} {
		if got := agentsExternal(u); got != want {
			t.Errorf("%s: %v", u, got)
		}
	}
}

func TestAgentsLLMSettings(t *testing.T) {
	main := &llmClient{model: "main"}
	cfg := &Config{}
	if l, ext, err := agentsLLM(cfg, main); l != main || ext || err != nil {
		t.Errorf("unset: %v %v %v", l, ext, err)
	}
	cfg.Agents.BaseURL = "http://127.0.0.1:1/v1"
	if _, _, err := agentsLLM(cfg, main); err == nil {
		t.Error("base_url without model was taken")
	}
	cfg.Agents.Model = "m"
	cfg.Agents.APIKeyEnv = "SHENTU_TEST_AGENTS_KEY_UNSET"
	os.Unsetenv(cfg.Agents.APIKeyEnv)
	if _, _, err := agentsLLM(cfg, main); err == nil || !strings.Contains(err.Error(), "not set") {
		t.Errorf("an unset key variable: %v", err)
	}
}

// agentsServer is the sub-agents' own model: it records each request and
// its Authorization header.
type agentsServer struct {
	*hostileModel
	mu    sync.Mutex
	auths []string
}

func (s *agentsServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.auths = append(s.auths, r.Header.Get("Authorization"))
	s.mu.Unlock()
	s.hostileModel.ServeHTTP(w, r)
}

func externalDispatch(t *testing.T, budget bool) (a *agent, state, out string, sub *agentsServer, key string) {
	t.Helper()
	oldExt, oldDial := agentsExternal, llmDial
	agentsExternal = func(string) bool { return true } // the test server stands in for a provider elsewhere
	llmDial = (&net.Dialer{}).DialContext
	t.Cleanup(func() { agentsExternal, llmDial = oldExt, oldDial })

	h := &hostileModel{replies: []string{call("dispatch", `{"tasks":[{"role":"attack"}]}`), done}}
	a, state = dispatchAgent(t, h, nil, nil)
	logFile := filepath.Join(state, "auth.log")
	os.WriteFile(logFile, []byte("Failed password from 198.51.100.7 key "+fakeAWSKey+"\n"), 0o600)
	sub = &agentsServer{hostileModel: &hostileModel{replies: []string{
		call("log_search", `{"path":"`+logFile+`","pattern":"."}`),
		answerMsg(`{"status":"complete","findings":[{"severity":"high","kind":"ssh","summary":"brute force"}]}`),
	}}}
	srv := httptest.NewServer(sub)
	t.Cleanup(srv.Close)
	key = strings.Join([]string{"sk-test", "agents", "0123456789abcdef"}, "-")
	t.Setenv("SHENTU_TEST_AGENTS_KEY", key)
	a.cfg.Agents.BaseURL, a.cfg.Agents.Model, a.cfg.Agents.APIKeyEnv = srv.URL, "remote-model", "SHENTU_TEST_AGENTS_KEY"
	if budget {
		a.cfg.Budget.MonthlyTokens = 1_000_000
	}
	_, msgs, _ := a.run(context.Background(), []message{{Role: "user", Content: "go"}})
	for _, m := range msgs {
		if m.Role == "tool" && strings.Contains(m.Content, `"reports"`) {
			out = m.Content
		}
	}
	return a, state, out, sub, key
}

// F: a model outside this host is not used without a monthly budget, and
// nothing is sent to it.
func TestAgentsExternalNeedsBudget(t *testing.T) {
	a, _, out, sub, _ := externalDispatch(t, false)
	sub.mu.Lock()
	n := len(sub.auths)
	sub.mu.Unlock()
	if n != 0 {
		t.Errorf("%d requests reached the outside model without a budget", n)
	}
	if !strings.Contains(out, "monthly limit") || strings.Contains(out, externalNote) {
		t.Errorf("output: %s", out)
	}
	recs, _, err := newDispatchStore(a.cfg).Since(time.Now().Add(-time.Hour))
	if err != nil || len(recs) != 1 || recs[0].External || recs[0].Subs[0].Reason != reasonModelError {
		t.Errorf("record: %+v %v", recs, err)
	}
}

// F: with a budget, the sub-agents use their own model with its key; what
// they send is masked, the key is written nowhere, and the dispatch says
// it used a model outside this host.
func TestAgentsExternalUsed(t *testing.T) {
	a, state, out, sub, key := externalDispatch(t, true)
	sub.mu.Lock()
	auths, reqs := append([]string(nil), sub.auths...), append([]string(nil), sub.requests...)
	sub.mu.Unlock()
	if len(auths) != 2 || auths[0] != "Bearer "+key {
		t.Fatalf("requests to the sub-agents' model: %d, auth %q", len(auths), auths)
	}
	for _, r := range reqs {
		if strings.Contains(r, fakeAWSKey) {
			t.Error("an unmasked secret was sent to the outside model")
		}
		var body struct{ Model string }
		json.Unmarshal([]byte(r), &body)
		if body.Model != "remote-model" {
			t.Errorf("model %q", body.Model)
		}
	}
	if !strings.Contains(out, externalNote) {
		t.Errorf("the commander was not told: %s", out)
	}
	recs, _, err := newDispatchStore(a.cfg).Since(time.Now().Add(-time.Hour))
	if err != nil || len(recs) != 1 || !recs[0].External || recs[0].Subs[0].Status != statusComplete {
		t.Fatalf("record: %+v %v", recs, err)
	}
	if sec := dispatchDaily(a.cfg, time.Now()); !strings.Contains(sec, "1 used the sub-agents' model outside this host") {
		t.Errorf("daily: %s", sec)
	}
	filepath.Walk(state, func(p string, info os.FileInfo, err error) error {
		if err == nil && info.Mode().IsRegular() {
			if b, _ := os.ReadFile(p); strings.Contains(string(b), key) {
				t.Errorf("the key is in %s", p)
			}
		}
		return nil
	})
	if strings.Contains(out, key) {
		t.Error("the key is in the dispatch output")
	}
}
