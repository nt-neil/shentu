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
	if r := got["sudo:nopasswd"]; r.Severity != "warning" || !strings.Contains(r.Summary, "/etc/sudoers.d/99-ops: admin ALL=(ALL) NOPASSWD:ALL") {
		t.Errorf("sudo: %+v (risks %v)", r, got)
	}
	if r := got["reboot:pending"]; r.Severity != "warning" || !strings.Contains(r.Summary, "linux-image-6.8.0-90-generic") {
		t.Errorf("reboot: %+v (risks %v)", r, got)
	}
}

// sudo with no password for every command, by where it comes from: the
// cloud image's default user in cloud-init's file is info (not pushed);
// the same rule elsewhere, a group in cloud-init's file, or
// !authenticate is a warning.
func TestSudoRisksBySource(t *testing.T) {
	sudo := func(files map[string]string) map[string]Risk {
		h := dirHost{scriptHost{memHost: memHost{"/etc/sudoers": "root ALL=(ALL:ALL) ALL\n@includedir /etc/sudoers.d\n"}}}
		for p, c := range files {
			h.memHost[p] = c
		}
		got := map[string]Risk{}
		for _, r := range sudoRisks(hostenv.SudoNopasswd(h)) {
			got[r.Key] = r
		}
		return got
	}
	cloud := "# Created by cloud-init v. 24.1\n\n# User rules for ubuntu\nubuntu ALL=(ALL) NOPASSWD:ALL\n"
	for name, c := range map[string]struct {
		files map[string]string
		key   string
		sev   string
	}{
		"cloud-init, one user":  {map[string]string{"/etc/sudoers.d/90-cloud-init-users": cloud}, "sudo:nopasswd:cloud-init", "info"},
		"the same in 99-custom": {map[string]string{"/etc/sudoers.d/99-custom": "ubuntu ALL=(ALL) NOPASSWD:ALL\n"}, "sudo:nopasswd", "warning"},
		"cloud-init, %sudo":     {map[string]string{"/etc/sudoers.d/90-cloud-init-users": "%sudo ALL=(ALL) NOPASSWD:ALL\n"}, "sudo:nopasswd", "warning"},
		"!authenticate":         {map[string]string{"/etc/sudoers.d/90-cloud-init-users": "Defaults !authenticate\n"}, "sudo:nopasswd", "warning"},
	} {
		got := sudo(c.files)
		if len(got) != 1 || got[c.key].Severity != c.sev {
			t.Errorf("%s: want %s (%s), got %+v", name, c.key, c.sev, got)
		}
	}
	if r := sudo(map[string]string{"/etc/sudoers.d/90-cloud-init-users": cloud})["sudo:nopasswd:cloud-init"]; !strings.Contains(r.Summary, "cloud image's default user") || !strings.Contains(r.Summary, "safe only while that user can log in with a key alone") {
		t.Errorf("cloud-init's text: %q", r.Summary)
	}
}

// Some commands only is info; what was not read is an unchecked risk.
func TestSudoRebootRisks(t *testing.T) {
	rules := []hostenv.SudoRule{{File: "a", Line: "1"}, {File: "b", Line: "2"}, {File: "c", Line: "3"}, {File: "d", Line: "4"}}
	r := sudoRisks(hostenv.SudoNoPass{Rules: rules, Unread: []string{"/etc/sudoers.d (permission denied)"}})
	if len(r) != 2 || r[0].Key != "sudo:nopasswd:some" || r[0].Severity != "info" || !strings.Contains(r[0].Summary, "a: 1; b: 2; c: 3 (and 1 more)") ||
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
