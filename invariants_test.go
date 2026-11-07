package main

// Security invariants. Each test plays a hostile model: a fake LLM server that asks
// for exactly what an attacker who controls the model's output would want. They must
// keep passing whatever else changes; a change that breaks one is not mergeable.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/nt-neil/shentu/tools"
)

// hostileModel replays scripted replies and records every request body it gets.
type hostileModel struct {
	mu       sync.Mutex
	replies  []string // raw JSON message objects; the last one repeats
	requests []string
}

func (h *hostileModel) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	h.mu.Lock()
	n := len(h.requests)
	h.requests = append(h.requests, string(b))
	reply := h.replies[min(n, len(h.replies)-1)]
	h.mu.Unlock()
	w.Write([]byte(`{"choices":[{"message":` + reply + `}]}`))
}

func call(name, args string) string {
	b, _ := json.Marshal(map[string]any{"role": "assistant", "content": "", "tool_calls": []any{
		map[string]any{"id": "c1", "type": "function", "function": map[string]any{"name": name, "arguments": args}},
	}})
	return string(b)
}

const done = `{"role":"assistant","content":"done"}`

func hostileAgent(t *testing.T, h *hostileModel, actor string, allowControl bool, confirm func(string, string) bool) (*agent, string) {
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	cfg := &Config{}
	cfg.LLM.MaxSteps = 5
	state, _ := filepath.EvalSymlinks(t.TempDir()) // macOS: /var is a symlink to /private/var
	return &agent{
		cfg: cfg, llm: &llmClient{baseURL: srv.URL, http: srv.Client()},
		env: &tools.Env{LogPaths: []string{filepath.Join(state, "*.log")}}, skills: map[string]skill{},
		allowControl: allowControl, confirm: confirm, actor: actor, log: newAuditLog(state),
	}, state
}

func auditLines(t *testing.T, state string) []logEntry {
	b, _ := os.ReadFile(filepath.Join(state, "log.jsonl"))
	var out []logEntry
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var e logEntry
		if json.Unmarshal([]byte(l), &e) == nil && e.Tool != "" {
			out = append(out, e)
		}
	}
	return out
}

// Patrol runs unattended, so it must never see or run a control tool, whether the
// model asks for it with a native tool call or with JSON in its text.
func TestInvariantPatrolHasNoControlTools(t *testing.T) {
	h := &hostileModel{replies: []string{
		call("block_ip", `{"ip":"203.0.113.9","reason":"x"}`),
		`{"role":"assistant","content":"{\"name\": \"unblock_ip\", \"arguments\": {\"ip\": \"203.0.113.9\"}}"}`,
		done,
	}}
	a, state := hostileAgent(t, h, "patrol", false, func(string, string) bool {
		t.Fatal("patrol must never ask for confirmation")
		return true
	})
	if _, _, err := a.run(context.Background(), []message{{Role: "user", Content: "go"}}); err != nil {
		t.Fatal(err)
	}
	for _, req := range h.requests {
		var body struct{ Tools []toolDef }
		json.Unmarshal([]byte(req), &body)
		for _, d := range body.Tools {
			if tl, ok := tools.Find(d.Function.Name); ok && tl.Control {
				t.Errorf("control tool %s was offered to the patrol model", d.Function.Name)
			}
		}
	}
	for _, e := range auditLines(t, state) {
		if e.Tool == "block_ip" || e.Tool == "unblock_ip" {
			t.Errorf("patrol ran a control tool: %+v", e)
		}
	}
	for _, d := range a.toolDefs() {
		if tl, ok := tools.Find(d.Function.Name); ok && tl.Control {
			t.Errorf("patrol tool list contains %s", d.Function.Name)
		}
	}
}

// Every control tool in chat must show the exact command and run only after a yes.
func TestInvariantControlNeedsConfirmation(t *testing.T) {
	for _, tl := range tools.All() {
		if tl.Control && tl.Preview == nil {
			t.Errorf("control tool %s has no preview", tl.Name)
		}
	}
	h := &hostileModel{replies: []string{call("block_ip", `{"ip":"203.0.113.9","reason":"x"}`), done}}
	var shown string
	a, state := hostileAgent(t, h, "chat", true, func(_, preview string) bool {
		shown = preview
		return false // the operator says no
	})
	if _, _, err := a.run(context.Background(), []message{{Role: "user", Content: "go"}}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(shown, "nft add element") || !strings.Contains(shown, "203.0.113.9") {
		t.Errorf("operator was not shown the exact command: %q", shown)
	}
	for _, e := range auditLines(t, state) {
		if e.Tool == "block_ip" && (e.Confirmed || e.OK) {
			t.Errorf("block_ip ran without a yes: %+v", e)
		}
	}
	// No confirm function at all means no.
	h2 := &hostileModel{replies: []string{call("block_ip", `{"ip":"203.0.113.9","reason":"x"}`), done}}
	a2, state2 := hostileAgent(t, h2, "chat", true, nil)
	a2.run(context.Background(), []message{{Role: "user", Content: "go"}})
	for _, e := range auditLines(t, state2) {
		if e.Tool == "block_ip" && (e.Confirmed || e.OK) {
			t.Errorf("block_ip ran with no confirm function")
		}
	}
}

// Lockout targets are refused before the operator is even asked, so a tired "y"
// cannot cut the server off.
func TestInvariantLockoutRefusedBeforeConfirm(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "::1", "0.0.0.0", "10.0.0.0/8", "0.0.0.0/0", "203.0.113.0/24", "not-an-ip"} {
		h := &hostileModel{replies: []string{call("block_ip", `{"ip":"`+ip+`","reason":"x"}`), done}}
		a, _ := hostileAgent(t, h, "chat", true, func(string, string) bool {
			t.Errorf("operator was asked to block %s", ip)
			return true
		})
		a.run(context.Background(), []message{{Role: "user", Content: "go"}})
	}
}

// The model can only read log files the operator listed, whatever path it asks for.
func TestInvariantLogSearchStaysInAllowlist(t *testing.T) {
	for _, p := range []string{"/etc/shadow", "/etc/shentu/env", "/root/.ssh/id_ed25519", "../../etc/passwd"} {
		h := &hostileModel{replies: []string{call("log_search", `{"path":"`+p+`","pattern":"."}`), done}}
		a, state := hostileAgent(t, h, "chat", true, nil)
		a.run(context.Background(), []message{{Role: "user", Content: "go"}})
		for _, e := range auditLines(t, state) {
			if e.Tool == "log_search" && e.OK {
				t.Errorf("log_search read %s", p)
			}
		}
	}
}

// Secrets found by a tool are masked before they reach the model, and tool output
// is labelled untrusted.
func TestInvariantSecretsMaskedAndOutputUntrusted(t *testing.T) {
	h := &hostileModel{}
	a, state := hostileAgent(t, h, "chat", true, nil)
	logFile := filepath.Join(state, "app.log")
	os.WriteFile(logFile, []byte("login ok password=hunter2 key AKIAABCDEFGHIJKLMNOP\n"), 0o600)
	h.replies = []string{call("log_search", `{"path":"`+logFile+`","pattern":"login"}`), done}
	if _, _, err := a.run(context.Background(), []message{{Role: "user", Content: "go"}}); err != nil {
		t.Fatal(err)
	}
	if len(h.requests) < 2 {
		t.Fatalf("model got %d requests", len(h.requests))
	}
	second := h.requests[1]
	if strings.Contains(second, "hunter2") || strings.Contains(second, "AKIAABCDEFGHIJKLMNOP") {
		t.Errorf("a secret reached the model")
	}
	if !strings.Contains(second, `\"untrusted\":true`) {
		t.Errorf("tool output is not labelled untrusted")
	}
	if !strings.Contains(strings.ToLower(systemPrompt(&Config{}, nil)), "untrusted") {
		t.Errorf("system prompt no longer tells the model that tool output is untrusted")
	}
}

// The patrol service keeps its sandbox, so even a bug in Go code cannot let an
// unattended run change the firewall or the system.
func TestInvariantPatrolSandbox(t *testing.T) {
	for _, unit := range []string{"packaging/shentu-patrol.service", "packaging/shentu-daily.service"} {
		b, err := os.ReadFile(unit)
		if err != nil {
			t.Fatal(err)
		}
		s := string(b)
		for _, want := range []string{"ProtectSystem=strict", "NoNewPrivileges=yes", "CapabilityBoundingSet="} {
			if !strings.Contains(s, want) {
				t.Errorf("%s lost %s", unit, want)
			}
		}
		if strings.Contains(s, "CAP_NET_ADMIN") || strings.Contains(s, "CAP_SYS_ADMIN") {
			t.Errorf("%s grants a capability that can change the system", unit)
		}
	}
}

// One third-party dependency keeps the supply chain small.
func TestInvariantOneDependency(t *testing.T) {
	b, _ := os.ReadFile("go.mod")
	n := 0
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(l), "require"))
		if strings.Contains(l, "/") && strings.Contains(l, " v") && !strings.HasPrefix(l, "module") {
			n++
		}
	}
	if n != 1 {
		t.Errorf("go.mod has %d dependencies, want 1", n)
	}
}
