package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestUsageReport(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 11, 7, 23, 0, 0, 0, time.Local)
	for _, e := range []logEntry{
		{Time: now.Add(-time.Hour), Actor: "bot", Tool: "llm", InTokens: 1000, OutTokens: 10, ReasonTokens: 200, Cost: 0.001},
		{Time: now.Add(-2 * time.Hour), Actor: "bot", Tool: "llm", InTokens: 2000, OutTokens: 20},
		{Time: now.AddDate(0, 0, -3), Actor: "patrol", Tool: "llm", InTokens: 500, Cost: 0.002},
		{Time: now.AddDate(0, 0, -40), Actor: "bot", Tool: "llm", InTokens: 9999},
		{Time: now.Add(-time.Hour), Actor: "bot", Tool: "ssh_logins"},
	} {
		b, _ := json.Marshal(e)
		f, _ := os.OpenFile(filepath.Join(dir, "log.jsonl"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		f.Write(append(b, '\n'))
		f.Close()
	}
	s := usageSummary(dir, now)
	if b := s[0]["bot"]; b == nil || b.Calls != 2 || b.In != 3000 || b.Reason != 200 || b.Priced != 1 {
		t.Errorf("today: %+v", s[0]["bot"])
	}
	if s[0]["patrol"] != nil || s[1]["patrol"] == nil || s[2]["bot"].Calls != 2 {
		t.Errorf("periods wrong: %+v %+v", s[1], s[2]["bot"])
	}
	r := usageReport(dir, now, true)
	if !strings.Contains(r, "今天：2 次") || !strings.Contains(r, "部分呼叫沒有報價") || !strings.Contains(r, "$0.0030") {
		t.Errorf("report:\n%s", r)
	}
}
