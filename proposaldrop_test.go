package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// proposalLog is the "proposals" audit entry of a dispatch's sub-agent.
type proposalLog struct {
	Written int               `json:"written"`
	Kept    int               `json:"kept"`
	Dropped []droppedProposal `json:"dropped"`
}

func proposalLogs(t *testing.T, state string) []proposalLog {
	t.Helper()
	var out []proposalLog
	for _, e := range auditLines(t, state) {
		if e.Tool != "proposals" {
			continue
		}
		var p proposalLog
		if err := json.Unmarshal([]byte(e.Args), &p); err != nil {
			t.Fatalf("proposals entry is not JSON: %q", e.Args)
		}
		out = append(out, p)
	}
	return out
}

// F-3: every proposal parseReport drops says why, in fixed words.
func TestParseReportDropReasons(t *testing.T) {
	cases := []struct{ role, prop, want string }{
		{"incident", `{"action":"propose_block_ip","ip":"203.0.113.0/24"}`, dropNetwork},
		{"incident", `{"action":"propose_block_ip","ip":"203.0.113.7, 203.0.113.8"}`, dropNotIP},
		{"incident", `{"action":"propose_block_ip","ip":""}`, dropNotIP},
		{"incident", `{"action":"block_ip","ip":"203.0.113.7"}`, dropAction},
		{"patrol", `{"action":"propose_block_ip","ip":"203.0.113.7"}`, dropRole},
	}
	for _, c := range cases {
		r := parseReport(c.role, `{"status":"complete","findings":[],"proposals":[`+c.prop+`]}`)
		if len(r.Proposals) != 0 || r.written != 1 || len(r.dropped) != 1 || r.dropped[0].Reason != c.want {
			t.Errorf("%s %s: kept %d, written %d, dropped %+v; want reason %s", c.role, c.prop, len(r.Proposals), r.written, r.dropped, c.want)
		}
	}
	var many []string
	for i := 0; i < maxSubagents*3+2; i++ {
		many = append(many, `{"action":"propose_block_ip","ip":"203.0.113.`+itoa(i+1)+`"}`)
	}
	r := parseReport("attack", `{"status":"complete","findings":[],"proposals":[`+strings.Join(many, ",")+`]}`)
	if len(r.Proposals) != maxSubagents*3 || len(r.dropped) != 2 || r.dropped[0].Reason != dropTooMany {
		t.Errorf("cap: kept %d dropped %+v", len(r.Proposals), r.dropped)
	}
	if r := parseReport("incident", "no JSON here"); r.written != -1 {
		t.Errorf("an unreadable report wrote %d proposals, want -1 (unknown)", r.written)
	}
	onPlatform(t, "darwin") // block_ip is Linux only: the attack role cannot propose here
	if r := parseReport("attack", `{"status":"complete","findings":[],"proposals":[`+many[0]+`]}`); len(r.dropped) != 1 || r.dropped[0].Reason != dropRole {
		t.Errorf("darwin attack proposal: %+v", r.dropped)
	}
}

// F-3, the VM's case: the automatic check's sub-agent writes the group's
// network. Before, the record said proposals 0 and nothing else did; now
// the audit log says it wrote one and why it was dropped, and the address
// it wrote right is kept.
func TestAutoDispatchDroppedProposalLogged(t *testing.T) {
	h := &hostileModel{replies: []string{answerMsg(`{"status":"complete","findings":[{"severity":"high","kind":"sqli","summary":"L3"}],` +
		`"proposals":[{"action":"propose_block_ip","ip":"203.0.1.0/24"},{"action":"propose_block_ip","ip":"203.0.1.7"}],"unchecked":[]}`)}}
	cfg, env, _ := autoSetup(t, h)
	if _, err := autoIncident(context.Background(), cfg, env, []autoCandidate{l3(1)}, time.Now()); err != nil {
		t.Fatal(err)
	}
	recs := archived(t, cfg)
	if len(recs) != 1 || len(recs[0].Subs) != 1 || len(recs[0].Subs[0].Proposals) != 1 {
		t.Fatalf("record: %+v", recs)
	}
	ps := proposalLogs(t, cfg.StateDir)
	if len(ps) != 1 || ps[0].Written != 2 || ps[0].Kept != 1 || len(ps[0].Dropped) != 1 ||
		ps[0].Dropped[0].Reason != dropNetwork || ps[0].Dropped[0].IP != "203.0.1.0/24" {
		t.Fatalf("proposals log: %+v", ps)
	}
}

// A report with no proposals says so: written 0, not silence.
func TestAutoDispatchNoProposalLogged(t *testing.T) {
	h := &hostileModel{replies: []string{answerMsg(`{"status":"complete","findings":[],"unchecked":[]}`)}}
	cfg, env, _ := autoSetup(t, h)
	if _, err := autoIncident(context.Background(), cfg, env, []autoCandidate{l3(1)}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if ps := proposalLogs(t, cfg.StateDir); len(ps) != 1 || ps[0].Written != 0 || ps[0].Kept != 0 || len(ps[0].Dropped) != 0 {
		t.Fatalf("proposals log: %+v", ps)
	}
}

// F-3: the roles that may propose are told when and how (one address per
// proposal); the automatic check says it comes from a verified L3 alert.
// The rule asks; the gate and the press are unchanged
// (TestInvariantProposalNeedsStrictConfirm).
func TestSubPromptProposalRule(t *testing.T) {
	cfg := &Config{Language: "English"}
	for _, role := range subRoleOrder {
		r, _, _ := roleFor(role, hostGOOS)
		p := subPrompt(cfg, role, r)
		if has := strings.Contains(p, "One proposal per IP address"); has != r.propose {
			t.Errorf("%s: proposal rule present %v, role proposes %v", role, has, r.propose)
		}
	}
	h := &hostileModel{replies: []string{answerMsg(`{"status":"complete","findings":[],"unchecked":[]}`)}}
	cfg2, env, _ := autoSetup(t, h)
	if _, err := autoIncident(context.Background(), cfg2, env, []autoCandidate{l3(1)}, time.Now()); err != nil {
		t.Fatal(err)
	}
	reqs := subRequests(h)
	if len(reqs) == 0 || !strings.Contains(reqs[0], "verified attack alert (level L3") {
		t.Errorf("the automatic check's question does not say L3")
	}
	if q := subQuestion(subTask{Role: "incident", IP: "203.0.113.7"}); strings.Contains(q, "L3") {
		t.Errorf("a dispatch call's question claims an alert: %q", q)
	}
	tasks, err := parseTasks(json.RawMessage(`{"tasks":[{"role":"incident","ip":"203.0.113.7","l3":true}]}`))
	if err == nil && tasks[0].l3 { // an unknown field may be refused outright; either way no l3
		t.Errorf("a dispatch call set l3: %v %+v", err, tasks)
	}
}
