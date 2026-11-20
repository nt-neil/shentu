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
		"http://127.0.0.1:11434/v1": false, "http://localhost:8080": false, "http://[::1]:1/v1": false, "http://127.0.0.2/v1": false,
		"http://LocalHost:1":         false,
		"https://api.example.com/v1": true, "::not a url": true,
		"http://192.168.1.5:11434/v1": true, "http://10.0.0.2:11434": true, // a LAN address, this host's own too
		"http://ollama.local:11434": true, "http://localhost.example.com": true, // a name: it can resolve anywhere
		"http://[::ffff:127.0.0.1]:1": false,
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
	mu        sync.Mutex
	auths     []string
	commander *hostileModel // the commander's model, for what it was sent
}

func (s *agentsServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.auths = append(s.auths, r.Header.Get("Authorization"))
	s.mu.Unlock()
	s.hostileModel.ServeHTTP(w, r)
}

func externalDispatch(t *testing.T, budget bool) (a *agent, state, out string, sub *agentsServer, key string) {
	return externalDispatchWith(t, budget, nil)
}

// externalDispatchWith is externalDispatch with handler, when set, as the
// outside model instead of one that answers.
func externalDispatchWith(t *testing.T, budget bool, handler func(http.ResponseWriter, *http.Request)) (a *agent, state, out string, sub *agentsServer, key string) {
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
	}}, commander: h}
	var srv *httptest.Server
	if handler != nil {
		srv = httptest.NewServer(http.HandlerFunc(handler))
	} else {
		srv = httptest.NewServer(sub)
	}
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

// N-F1: a cost limit alone is no limit for a provider that does not report
// cost, so an outside model needs monthly_tokens.
func TestAgentsExternalCostOnlyRefused(t *testing.T) {
	main := &llmClient{model: "main"}
	cfg := &Config{}
	cfg.Agents.BaseURL, cfg.Agents.Model = "https://api.example.com/v1", "m"
	cfg.Budget.MonthlyCost = 5
	if _, _, err := agentsLLM(cfg, main); err == nil || !strings.Contains(err.Error(), "monthly_tokens") {
		t.Errorf("monthly_cost alone: %v", err)
	}
	cfg.Budget.MonthlyTokens = 1_000_000
	if _, ext, err := agentsLLM(cfg, main); err != nil || !ext {
		t.Errorf("with monthly_tokens: %v %v", ext, err)
	}
}

// B-F1: a provider that echoes the key back in an error (text or JSON)
// does not get it into the state, the dispatch output or the commander's
// model, which may be another provider's.
func TestAgentsModelErrorKeyScrubbed(t *testing.T) {
	for name, body := range map[string]func(auth string) (string, string){
		"text": func(auth string) (string, string) { return "text/plain", "invalid api key " + auth },
		"json": func(auth string) (string, string) {
			return "application/json", `{"error":{"message":"bad key: ` + strings.TrimPrefix(auth, "Bearer ") + `"}}`
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, state, out, sub, key := externalDispatchWith(t, true, func(w http.ResponseWriter, r *http.Request) {
				ct, b := body(r.Header.Get("Authorization"))
				w.Header().Set("Content-Type", ct)
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte(b))
			})
			if out == "" || strings.Contains(out, key) {
				t.Errorf("dispatch output: %s", out)
			}
			found := false
			filepath.Walk(state, func(p string, info os.FileInfo, err error) error {
				if err == nil && info.Mode().IsRegular() {
					b, _ := os.ReadFile(p)
					if strings.Contains(string(b), key) {
						t.Errorf("the key is in %s", p)
					}
					found = found || strings.Contains(string(b), "[key]")
				}
				return nil
			})
			if !found {
				t.Error("no [key] in the state: the error was not logged as expected")
			}
			sub.commander.mu.Lock()
			defer sub.commander.mu.Unlock()
			if len(sub.commander.requests) < 2 {
				t.Errorf("the commander's model was asked %d times", len(sub.commander.requests))
			}
			for _, r := range sub.commander.requests {
				if strings.Contains(r, key) {
					t.Error("the key was sent to the commander's model")
				}
			}
		})
	}
}

// B-F1 for [llm] too: the commander's own key is scrubbed from its errors.
func TestLLMErrorKeyScrubbed(t *testing.T) {
	key := strings.Join([]string{"sk", "main", "fedcba9876543210"}, "-")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("no such key: " + r.Header.Get("Authorization") + strings.Repeat(" ", 280) + key))
	}))
	defer srv.Close()
	l := &llmClient{baseURL: srv.URL, apiKey: key, http: srv.Client()}
	_, err := l.chat(context.Background(), []message{{Role: "user", Content: "x"}}, nil)
	if err == nil || strings.Contains(err.Error(), key) || !strings.Contains(err.Error(), "[key]") {
		t.Errorf("error: %v", err)
	}
	// a key cut at the 300-byte limit leaves no part of it behind
	l2 := &llmClient{baseURL: srv.URL, apiKey: key, http: srv.Client()}
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(strings.Repeat("x", 295) + key))
	}))
	defer srv2.Close()
	l2.baseURL = srv2.URL
	_, err = l2.chat(context.Background(), []message{{Role: "user", Content: "x"}}, nil)
	if err == nil || strings.Contains(err.Error(), key[:5]) {
		t.Errorf("a cut key: %v", err)
	}
}
