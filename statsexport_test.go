package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// G: `shentu dispatch stats --json`, the weekly summary's input, has a
// versioned form of known keys only, and nothing of the host: no address,
// dispatch id, trigger, path or host name, though the archive holds them.
func TestStatsExportForm(t *testing.T) {
	s := testStore(t)
	cfg := &Config{StateDir: filepath.Dir(s.dir)}
	now := time.Now()
	rec := testRecord(testDispatch, now) // proposals for 203.0.113.9 and 2001:db8:1:2::9
	trigger := triggerID("203.0.113.0/24|code@/srv/app.py:1|L3|v")
	rec.Origin, rec.Trigger = originAuto, trigger
	rec.Subs = append(rec.Subs, subRecord{Role: "attack", Status: statusIncomplete, Reason: reasonTokenCap, Steps: 3, TokensIn: 900})
	if err := s.Save(rec); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveFeedback(testDispatch, verdictFalsePos, now); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := statsReport(cfg, 7, true, &out, now); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	host, _ := os.Hostname()
	for _, secret := range []string{"203.0.113.9", "2001:db8", testDispatch, trigger, "/srv/app.py", cfg.StateDir, host} {
		if secret != "" && strings.Contains(got, secret) {
			t.Errorf("the export holds %q:\n%s", secret, got)
		}
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(out.Bytes(), &top); err != nil {
		t.Fatal(err)
	}
	if keys := sortedKeys(top); strings.Join(keys, ",") != "days,dispatches,roles,shentu,suggestions,unknown_field_lines,unreadable_lines,until,v" { // unknown_field_lines: in v1 before its first release (#197)
		t.Errorf("top keys: %v", keys)
	}
	var e statsExport
	json.Unmarshal(out.Bytes(), &e)
	if e.V != statsExportV || e.Until != now.UTC().Format("2006-01-02") || e.Days != 7 || e.Dispatches != 1 || len(e.Roles) != 2 || e.Suggestions == nil {
		t.Errorf("export: %+v", e)
	}
	var roles []map[string]json.RawMessage
	json.Unmarshal(top["roles"], &roles)
	for _, r := range roles {
		if keys := sortedKeys(r); strings.Join(keys, ",") != "complete,false_positive,proposals,reasons,refused,role,runs,steps,tokens,useful" {
			t.Errorf("role keys: %v", keys)
		}
	}
}

// G: with nothing archived the form is the same: empty lists, not null.
func TestStatsExportEmpty(t *testing.T) {
	s := testStore(t)
	cfg := &Config{StateDir: filepath.Dir(s.dir)}
	var out bytes.Buffer
	if err := statsReport(cfg, 7, true, &out, time.Now()); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); !strings.Contains(got, `"roles": []`) || !strings.Contains(got, `"suggestions": []`) || !strings.Contains(got, `"v": 1`) {
		t.Errorf("empty export:\n%s", got)
	}
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
