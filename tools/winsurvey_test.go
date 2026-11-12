package tools

import (
	"context"
	"strings"
	"testing"

	"github.com/nt-neil/shentu/hostenv"
)

// replayWindows makes windowsFacts collect from the recorded windows-2022 runner.
func replayWindows(t *testing.T) *hostenv.Facts {
	t.Helper()
	rp, err := hostenv.LoadReplay("../hostenv/testdata/windows/server2022-admin")
	if err != nil {
		t.Fatal(err)
	}
	f := hostenv.WindowsCollector{}.Collect(context.Background(), rp)
	old := windowsFacts
	windowsFacts = func(context.Context) *hostenv.Facts { return f }
	t.Cleanup(func() { windowsFacts = old })
	return f
}

func TestSurveyFromWindowsFacts(t *testing.T) {
	f := replayWindows(t)
	p := surveyFromFacts(f, &Env{})
	if !strings.Contains(p.OS, "Windows Server 2022") || !strings.HasPrefix(p.Kernel, "build 20348.") {
		t.Errorf("platform: %q %q", p.OS, p.Kernel)
	}
	if !strings.HasPrefix(p.Firewall, "Windows Firewall on:") {
		t.Errorf("firewall: %q", p.Firewall)
	}
	roles := map[string]string{}
	for _, s := range p.Services {
		roles[s.Name] = s.Role
	}
	if roles["lsass"] != "Windows (authentication)" || roles["system"] == "" {
		t.Errorf("services by process, .exe and case dropped: %v", roles)
	}
	if len(p.CronFiles) != len(f.Persistence.Value) || len(p.CronFiles) == 0 {
		t.Errorf("autostart entries as the cron baseline: %d of %d", len(p.CronFiles), len(f.Persistence.Value))
	}
	if strings.Join(p.LoginAccounts, ",") != "user1,user4" {
		t.Errorf("login accounts: %v", p.LoginAccounts)
	}
	keys := map[string]bool{}
	for _, r := range p.Risks {
		if keys[r.Key] {
			t.Errorf("duplicate risk key %q: patrol would drop all but one", r.Key)
		}
		keys[r.Key] = true
		if strings.HasPrefix(r.Key, uncheckedPrefix) && (r.Severity != "info" || !Unchecked(r)) {
			t.Errorf("a check that could not tell is listed, never pushed: %+v", r)
		}
	}

	// A new autostart entry since the baseline is drift.
	old := p
	old.CronFiles = old.CronFiles[1:]
	var found bool
	for _, r := range Drift(old, p) {
		found = found || r.Key == "drift:cron:"+p.CronFiles[0]
	}
	if !found {
		t.Error("a new autostart entry must show as drift")
	}
}

func TestPortsFromWindowsFacts(t *testing.T) {
	f := replayWindows(t)
	ports, err := portsFromFacts(f)
	if err != nil || len(ports) == 0 {
		t.Fatalf("ports: %v %v", len(ports), err)
	}
	for _, p := range ports {
		if p.PID != 0 && p.Process == "" {
			t.Errorf("owner name missing: %+v", p)
		}
	}
	f.Listeners = hostenv.Unknown[[]hostenv.Listener](hostenv.ReasonPermission, "denied")
	if _, err := portsFromFacts(f); err == nil {
		t.Error("an unknown socket table must be an error, not an empty baseline")
	}
}
