package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Over the monthly budget the model is not called; under it, it is.
func TestBudgetStopsModel(t *testing.T) {
	h := &hostileModel{replies: []string{done}}
	a, state := hostileAgent(t, h, "bot", false, nil)
	a.cfg.StateDir = state
	a.cfg.Budget.MonthlyTokens = 1000
	line := `{"time":"` + time.Now().UTC().Format(time.RFC3339) + `","actor":"bot","tool":"llm","ok":true,"in_tokens":600,"out_tokens":10,"reasoning_tokens":200}` + "\n"
	os.WriteFile(filepath.Join(state, "log.jsonl"), []byte(line), 0o600)
	if _, _, err := a.run(context.Background(), []message{{Role: "user", Content: "hi"}}); err != nil {
		t.Fatalf("under budget: %v", err)
	}
	if h.count() != 1 {
		t.Fatalf("model not called under budget")
	}
	f, _ := os.OpenFile(filepath.Join(state, "log.jsonl"), os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString(line)
	f.Close()
	if _, _, err := a.run(context.Background(), []message{{Role: "user", Content: "hi"}}); !errors.Is(err, errBudget) {
		t.Errorf("over budget: err = %v", err)
	}
	if h.count() != 1 {
		t.Errorf("model called over budget")
	}
	b, _ := os.ReadFile(filepath.Join(state, "budget.json"))
	if len(b) == 0 {
		t.Errorf("no budget alert recorded")
	}
	a.cfg.Budget.MonthlyTokens = 0
	if budgetUsed(a.cfg, time.Now()) != 0 || budgetLine(a.cfg, time.Now(), true) != "" {
		t.Errorf("no budget set, but one is reported")
	}
}
