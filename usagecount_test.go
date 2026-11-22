package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// llmLines counts the model calls in the audit log, whoever made them.
func llmLines(t *testing.T, state string) map[string]int {
	t.Helper()
	f, err := os.Open(filepath.Join(state, "log.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	n := map[string]int{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var e logEntry
		if json.Unmarshal(sc.Bytes(), &e) == nil && e.Tool == "llm" {
			n[e.Actor]++
		}
	}
	return n
}

// The v0.5.3 real-bot acceptance: `shentu usage` showed 12 calls where the
// log held 15, the 3 of sub:incident left out. A real dispatch, then the
// usage command of the binary: every model call in the log is counted.
func TestUsageCountsSubAgents(t *testing.T) {
	if testing.Short() || runtime.GOOS == "windows" {
		t.Skip("builds the binary")
	}
	h := &hostileModel{replies: []string{call("dispatch", `{"tasks":[{"role":"patrol"}]}`), answerMsg(`{"status":"complete","findings":[]}`), done}}
	a, state := dispatchAgent(t, h, nil, nil)
	if _, _, err := a.run(context.Background(), []message{{Role: "user", Content: "go"}}); err != nil {
		t.Fatal(err)
	}
	byActor := llmLines(t, state)
	total := 0
	for _, n := range byActor {
		total += n
	}
	if byActor["sub:patrol"] == 0 || byActor["chat"] == 0 {
		t.Fatalf("the dispatch did not log both: %v", byActor)
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "shentu")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	cfgPath := filepath.Join(dir, "shentu.toml")
	os.WriteFile(cfgPath, []byte("state_dir = "+strconv.Quote(state)+"\n"), 0o600)
	cmd := exec.Command(bin, "usage")
	cmd.Env = append(os.Environ(), "SHENTU_CONFIG="+cfgPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("usage: %v\n%s", err, out)
	}
	if want := fmt.Sprintf("Today: %d calls", total); !strings.Contains(string(out), want) || !strings.Contains(string(out), fmt.Sprintf("sub-agents (dispatches): %d calls", byActor["sub:patrol"])) {
		t.Errorf("log %v, want %q:\n%s", byActor, want, out)
	}
}

// An actor the report has no name for is counted, on a line of its own.
func TestUsageCountsOtherActors(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	f, _ := os.OpenFile(filepath.Join(dir, "log.jsonl"), os.O_CREATE|os.O_WRONLY, 0o600)
	for _, e := range []logEntry{
		{Time: now, Actor: "bot", Tool: "llm", InTokens: 10},
		{Time: now, Actor: "sub:incident", Tool: "llm", InTokens: 20},
		{Time: now, Actor: "sub:patrol", Tool: "llm", InTokens: 30},
		{Time: now, Actor: "auto", Tool: "llm", InTokens: 40},
	} {
		b, _ := json.Marshal(e)
		f.Write(append(b, '\n'))
	}
	f.Close()
	r := usageReport(dir, now, true)
	for _, want := range []string{"今天：4 次，100／", "子 Agent（派遣）：2 次，50／", "其他：1 次，40／"} {
		if !strings.Contains(r, want) {
			t.Errorf("missing %q:\n%s", want, r)
		}
	}
}
