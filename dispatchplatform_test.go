package main

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/nt-neil/shentu/tools"
)

// TestMain runs the dispatch tests as on Linux, the platform every role is
// written for, whatever this machine is; the platform tests switch it.
func TestMain(m *testing.M) {
	if hostGOOS != runtime.GOOS { // what the program runs with, before the tests change it
		fmt.Fprintf(os.Stderr, "hostGOOS is %q, not this platform's %q\n", hostGOOS, runtime.GOOS)
		os.Exit(1)
	}
	hostGOOS = "linux"
	os.Exit(m.Run())
}

func onPlatform(t *testing.T, goos string) {
	old := hostGOOS
	hostGOOS = goos
	t.Cleanup(func() { hostGOOS = old })
}

// subRequestsOf are the model requests the sub-agents made.
func subRequestsOf(h *hostileModel) []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []string
	for _, r := range h.requests {
		if strings.Contains(r, subMarker) {
			out = append(out, r)
		}
	}
	return out
}

// E: on Windows the attack role gets only the tools that work there, says
// which it could not use, and proposes nothing (no block_ip there).
func TestDispatchWindowsAttack(t *testing.T) {
	onPlatform(t, "windows")
	h := &hostileModel{replies: []string{
		call("dispatch", `{"tasks":[{"role":"attack"}]}`),
		answerMsg(`{"status":"complete","findings":[],"proposals":[{"action":"propose_block_ip","ip":"203.0.113.9"}]}`),
		done,
	}}
	a, _ := dispatchAgent(t, h, nil, nil)
	a.run(context.Background(), []message{{Role: "user", Content: "go"}})
	subs := subRequestsOf(h)
	if len(subs) != 1 {
		t.Fatalf("%d sub-agent requests", len(subs))
	}
	if strings.Contains(subs[0], `"name":"attack_attempts"`) || !strings.Contains(subs[0], `"name":"log_search"`) {
		t.Error("the Windows attack sub-agent was offered the wrong tools")
	}
	if strings.Contains(subs[0], "propose_block_ip") {
		t.Error("the Windows sub-agent was asked for proposals")
	}
	reps := lastReports(t, h)
	if len(reps) != 1 || len(reps[0].Proposals) != 0 || len(reps[0].Unchecked) == 0 || reps[0].Unchecked[0] != "attack_attempts: not available on Windows" {
		t.Errorf("report: %+v", reps)
	}
}

// E: on macOS only surface runs; patrol is not asked of the model at all
// and is reported incomplete, with the reason, as unsupported.
func TestDispatchMacOSRoles(t *testing.T) {
	onPlatform(t, "darwin")
	h := &hostileModel{replies: []string{
		call("dispatch", `{"tasks":[{"role":"patrol"},{"role":"surface"}]}`),
		answerMsg(`{"status":"complete","findings":[]}`),
		done,
	}}
	a, _ := dispatchAgent(t, h, nil, nil)
	a.run(context.Background(), []message{{Role: "user", Content: "go"}})
	subs := subRequestsOf(h)
	if len(subs) != 1 || !strings.Contains(subs[0], "a surface sub-agent") {
		t.Fatalf("sub-agent requests: %d", len(subs))
	}
	reps := lastReports(t, h)
	if len(reps) != 2 || reps[0].Status != "incomplete" || reps[0].Reason != "the patrol role is not available on macOS yet" ||
		reps[1].Status != "complete" {
		t.Errorf("reports: %+v", reps)
	}
	// N-E1: every tool of the closed role is listed, the supported ones as not run.
	if len(reps[0].Unchecked) != len(subRoles["patrol"].tools) {
		t.Errorf("unchecked: %v", reps[0].Unchecked)
	}
	want := map[string]bool{"processes: not available on macOS": false, "site_profile: not run: the patrol role is not available on macOS yet": false}
	for _, u := range reps[0].Unchecked {
		if _, ok := want[u]; ok {
			want[u] = true
		}
	}
	for u, ok := range want {
		if !ok {
			t.Errorf("unchecked lacks %q: %v", u, reps[0].Unchecked)
		}
	}
	recs, _, err := newDispatchStore(a.cfg).Since(time.Now().Add(-time.Hour))
	if err != nil || len(recs) != 1 || recs[0].Subs[0].Reason != reasonUnsupported {
		t.Errorf("record: %+v %v", recs, err)
	}
}

func TestToolsSupportedOn(t *testing.T) {
	for _, c := range []struct {
		name, goos string
		want       bool
	}{
		{"attack_attempts", "linux", true}, {"attack_attempts", "windows", false}, {"attack_attempts", "darwin", false},
		{"processes", "windows", true}, {"processes", "darwin", false}, {"listening_ports", "darwin", false},
		{"accounts_audit", "darwin", false}, {"log_search", "darwin", false}, {"package_vulns", "darwin", true},
		{"cert_expiry", "darwin", false}, // S-E2: Homebrew's certbot paths are not read yet
		{"block_ip", "windows", false}, {"block_ip", "darwin", false}, {"processes", "plan9", false},
	} {
		if got := tools.SupportedOn(c.name, c.goos); got != c.want {
			t.Errorf("%s on %s: %v", c.name, c.goos, got)
		}
	}
	for role := range subRoles {
		r, _, open := roleFor(role, "linux")
		if !open || len(r.tools) != len(subRoles[role].tools) || r.propose != subRoles[role].propose {
			t.Errorf("%s on Linux changed: %+v", role, r)
		}
	}
}

// S-E3: off Linux the automatic incident check is not made and takes no
// daily slot; the daily report says why.
func TestAutoDispatchOffLinux(t *testing.T) {
	for _, goos := range []string{"darwin", "windows"} {
		t.Run(goos, func(t *testing.T) {
			onPlatform(t, goos)
			h := &hostileModel{replies: []string{done}}
			cfg, env, out := autoSetup(t, h)
			now := time.Now()
			id, err := autoIncident(context.Background(), cfg, env, []autoCandidate{l3(1)}, now)
			if err != nil || id != "" {
				t.Fatalf("dispatched: %q %v", id, err)
			}
			st := readState(t, cfg)
			if len(st.Dispatches) != 0 || len(*out) != 0 || len(h.requests) != 0 {
				t.Errorf("slots %d, sent %d, model calls %d", len(st.Dispatches), len(*out), len(h.requests))
			}
			if sec := autoIncidentSection(cfg, now); !strings.Contains(sec, "platform 1") || !strings.Contains(sec, "Linux only") {
				t.Errorf("daily: %s", sec)
			}
		})
	}
}
