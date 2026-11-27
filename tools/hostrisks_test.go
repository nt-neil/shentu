package tools

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/nt-neil/shentu/hostenv"
)

// I-10: the survey says sudo with no password and a pending reboot, read
// through the host source.
func TestSurveySudoReboot(t *testing.T) {
	oldRun, oldRead, oldExists, oldApache := ngxRun, ngxRead, ngxExists, apacheVersion
	ngxRun = func(context.Context, []string) ([]byte, error) { return nil, os.ErrNotExist }
	ngxRead = func(string) ([]byte, error) { return nil, os.ErrNotExist }
	ngxExists = func(string) bool { return false }
	apacheVersion = func(context.Context) string { return "" }
	t.Cleanup(func() { ngxRun, ngxRead, ngxExists, apacheVersion = oldRun, oldRead, oldExists, oldApache })
	withHost(t, dirHost{scriptHost{memHost: memHost{
		"/etc/os-release":           "ID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"24.04\"\nPRETTY_NAME=\"Ubuntu 24.04.3 LTS\"\n",
		"/etc/sudoers":              "root ALL=(ALL:ALL) ALL\n@includedir /etc/sudoers.d\n",
		"/etc/sudoers.d/99-ops":     "admin ALL=(ALL) NOPASSWD:ALL\n",
		"/run/reboot-required":      "*** System restart required ***\n",
		"/run/reboot-required.pkgs": "linux-image-6.8.0-90-generic\n",
	}}})
	got := map[string]Risk{}
	for _, r := range Survey(context.Background(), &Env{}).Risks {
		got[r.Key] = r
	}
	if r := got["sudo:nopasswd"]; r.Severity != "warning" || !strings.Contains(r.Summary, "/etc/sudoers.d/99-ops: admin ALL=(ALL) NOPASSWD:ALL (every command, as any user)") {
		t.Errorf("sudo: %+v (risks %v)", r, got)
	}
	if r := got["reboot:pending"]; r.Severity != "warning" || !strings.Contains(r.Summary, "linux-image-6.8.0-90-generic") {
		t.Errorf("reboot: %+v (risks %v)", r, got)
	}
}

// sudo with no password for every command, by where it comes from: the
// cloud image's default user (cloud-init's default_user) in cloud-init's
// file is info (not pushed); anything else with ALL is a warning
// (N-274-1, N-274-2); commands only, info.
func TestSudoRisksBySource(t *testing.T) {
	sudo := func(files map[string]string) map[string]Risk {
		h := dirHost{scriptHost{memHost: memHost{
			"/etc/sudoers":         "root ALL=(ALL:ALL) ALL\n@includedir /etc/sudoers.d\n",
			"/etc/cloud/cloud.cfg": "system_info:\n  default_user:\n    name: ubuntu\n",
		}}}
		for p, c := range files {
			h.memHost[p] = c
		}
		got := map[string]Risk{}
		for _, r := range sudoRisks(hostenv.SudoNopasswd(h)) {
			got[r.Key] = r
		}
		return got
	}
	const ci = "/etc/sudoers.d/90-cloud-init-users"
	hdr := "# Created by cloud-init v. 24.1\n\n# User rules for ubuntu\n"
	for name, c := range map[string]struct {
		files map[string]string
		key   string
		sev   string
	}{
		"cloud-init, default user":     {map[string]string{ci: hdr + "ubuntu ALL=(ALL) NOPASSWD:ALL\n"}, "sudo:nopasswd:cloud-init", "info"},
		"the same in 99-custom":        {map[string]string{"/etc/sudoers.d/99-custom": hdr + "ubuntu ALL=(ALL) NOPASSWD:ALL\n"}, "sudo:nopasswd", "warning"},
		"copied to 91-deploy":          {map[string]string{"/etc/sudoers.d/91-deploy": hdr + "ubuntu ALL=(ALL) NOPASSWD:ALL\n"}, "sudo:nopasswd", "warning"},
		"cloud-init, not default_user": {map[string]string{ci: "eve ALL=(ALL) NOPASSWD:ALL\n"}, "sudo:nopasswd", "warning"},
		"cloud-init, %sudo":            {map[string]string{ci: "%sudo ALL=(ALL) NOPASSWD:ALL\n"}, "sudo:nopasswd", "warning"},
		"!authenticate":                {map[string]string{ci: "Defaults !authenticate\n"}, "sudo:nopasswd", "warning"},
		"ALL after a command":          {map[string]string{"/etc/sudoers.d/x": "bob ALL=(ALL) NOPASSWD: /bin/true, ALL\n"}, "sudo:nopasswd", "warning"},
		"ALL with its own run-as":      {map[string]string{"/etc/sudoers.d/x": "bob ALL=(ALL) NOPASSWD: /bin/ls, (root) ALL\n"}, "sudo:nopasswd", "warning"},
		"an alias of ALL":              {map[string]string{"/etc/sudoers.d/x": "Cmnd_Alias ANY = ALL\nbob ALL=(ALL) NOPASSWD: ANY\n"}, "sudo:nopasswd", "warning"},
		"PASSWD before ALL":            {map[string]string{"/etc/sudoers.d/x": "bob ALL=(ALL) NOPASSWD: /bin/ls, PASSWD: ALL\n"}, "sudo:nopasswd:some", "info"},
		"Defaults for one command":     {map[string]string{"/etc/sudoers.d/x": "Defaults!/bin/ls !authenticate\n"}, "sudo:nopasswd:some", "info"},
	} {
		got := sudo(c.files)
		if len(got) != 1 || got[c.key].Severity != c.sev {
			t.Errorf("%s: want %s (%s), got %+v", name, c.key, c.sev, got)
		}
	}
	// One file with both: the default user's rule info, eve's a warning.
	got := sudo(map[string]string{ci: "ubuntu ALL=(ALL) NOPASSWD:ALL\neve ALL=(ALL) NOPASSWD:ALL\n"})
	if got["sudo:nopasswd"].Severity != "warning" || !strings.Contains(got["sudo:nopasswd"].Summary, "eve ALL") || strings.Contains(got["sudo:nopasswd"].Summary, "ubuntu ALL") || got["sudo:nopasswd:cloud-init"].Severity != "info" {
		t.Errorf("eve added to cloud-init's file: %+v", got)
	}
	if r := sudo(map[string]string{ci: "ubuntu ALL=(ALL) NOPASSWD:ALL\n"})["sudo:nopasswd:cloud-init"]; !strings.Contains(r.Summary, "cloud-init's default user") || !strings.Contains(r.Summary, "safe only while that user can log in with a key alone") || !strings.Contains(r.Summary, "(every command, as any user)") {
		t.Errorf("cloud-init's text: %q", r.Summary)
	}
	// S-274-3: what it runs and as whom, as written.
	if r := sudo(map[string]string{"/etc/sudoers.d/x": "bob ALL=(deploy) NOPASSWD: ALL\n"})["sudo:nopasswd"]; !strings.Contains(r.Summary, "(every command, as deploy)") {
		t.Errorf("run as deploy: %q", r.Summary)
	}
	if r := sudo(map[string]string{"/etc/sudoers.d/x": "Defaults!/bin/ls !authenticate\n"})["sudo:nopasswd:some"]; !strings.Contains(r.Summary, "(only /bin/ls, as root)") {
		t.Errorf("Defaults for one command: %q", r.Summary)
	}
}

// Some commands only is info; what was not read is an unchecked risk.
func TestSudoRebootRisks(t *testing.T) {
	var rules []hostenv.SudoRule
	for _, f := range []string{"a", "b", "c", "d"} {
		rules = append(rules, hostenv.SudoRule{File: f, Line: "1", Cmds: []string{"/x"}})
	}
	r := sudoRisks(hostenv.SudoNoPass{Rules: rules, Unread: []string{"/etc/sudoers.d (permission denied)"}})
	if len(r) != 2 || r[0].Key != "sudo:nopasswd:some" || r[0].Severity != "info" || !strings.Contains(r[0].Summary, "a: 1 (only /x, as root); b: 1 (only /x, as root); c: 1 (only /x, as root) (and 1 more)") ||
		!Unchecked(r[1]) || NotYet(r[1]) || !strings.Contains(r[1].Summary, "run Shentu as root") {
		t.Errorf("%+v", r)
	}
	if r := rebootRisks(hostenv.RebootPending{Unread: "/boot (permission denied)"}); len(r) != 1 || r[0].Key != "unchecked:reboot" || !Unchecked(r[0]) {
		t.Errorf("%+v", r)
	}
	if r := append(sudoRisks(hostenv.SudoNoPass{}), rebootRisks(hostenv.RebootPending{})...); len(r) != 0 {
		t.Errorf("nothing to say: %+v", r)
	}
}
