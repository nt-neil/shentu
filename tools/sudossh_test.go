package tools

import (
	"os"
	"strings"
	"testing"

	"github.com/nt-neil/shentu/hostenv"
)

// denyHost is memHost with paths that cannot be read.
type denyHost struct {
	memHost
	deny map[string]bool
}

func (d denyHost) ReadFile(p string) ([]byte, error) {
	if d.deny[p] {
		return nil, os.ErrPermission
	}
	return d.memHost.ReadFile(p)
}

// t6: cloud-init's one-user NOPASSWD:ALL is a warning when sshd lets every
// user log in with a password: no Match block in any file, every file read,
// PasswordAuthentication yes or sshd's default on a known family. Through
// LinuxCollector.SSHD and the survey's sudo risks.
func TestCloudInitSudoWithSSHPassword(t *testing.T) {
	cloud := "ubuntu ALL=(ALL) NOPASSWD:ALL\n"
	risk := func(t *testing.T, sshd map[string]string, deny []string, family string) (string, string) {
		t.Helper()
		m := memHost{"/etc/sudoers": "@includedir /etc/sudoers.d\n", "/etc/sudoers.d/90-cloud-init-users": cloud,
			"/etc/cloud/cloud.cfg": "system_info:\n  default_user:\n    name: ubuntu\n"}
		for p, c := range sshd {
			m[p] = c
		}
		d := denyHost{memHost: m, deny: map[string]bool{}}
		for _, p := range deny {
			d.deny[p] = true
		}
		pw := sshPasswordLogin(linux.SSHD(d, "/etc/ssh/sshd_config").Value, family)
		for _, r := range sudoRisks(hostenv.SudoNopasswd(dirHost{scriptHost{memHost: m}}), pw) {
			if r.Key == "sudo:nopasswd:cloud-init" {
				return r.Severity, pw
			}
		}
		return "", pw
	}
	for _, c := range []struct {
		name   string
		sshd   map[string]string
		deny   []string
		family string
		want   string
	}{
		{"no Match, yes", map[string]string{"/etc/ssh/sshd_config": "PasswordAuthentication yes\n"}, nil, "debian", "warning"},
		{"no Match, the default on a known family", map[string]string{"/etc/ssh/sshd_config": "Port 22\n"}, nil, "debian", "warning"},
		{"no Match, the default on an unknown family", map[string]string{"/etc/ssh/sshd_config": "Port 22\n"}, nil, "", "info"},
		{"a Match block", map[string]string{"/etc/ssh/sshd_config": "PasswordAuthentication yes\nMatch User ubuntu\n  PasswordAuthentication no\n"}, nil, "debian", "info"},
		{"a Match in an included file", map[string]string{"/etc/ssh/sshd_config": "Include /etc/ssh/sshd_config.d/a.conf\nPasswordAuthentication yes\n",
			"/etc/ssh/sshd_config.d/a.conf": "Match User ubuntu\n  PasswordAuthentication no\n"}, nil, "debian", "info"},
		{"an Include not read (the setting before it)", map[string]string{"/etc/ssh/sshd_config": "PasswordAuthentication yes\nInclude /etc/ssh/sshd_config.d/a.conf\n",
			"/etc/ssh/sshd_config.d/a.conf": "Port 22\n"}, []string{"/etc/ssh/sshd_config.d/a.conf"}, "debian", "info"},
		{"an Include with a %-token", map[string]string{"/etc/ssh/sshd_config": "Include /etc/ssh/%h.conf\nPasswordAuthentication yes\n"}, nil, "debian", "info"},
		{"PasswordAuthentication no", map[string]string{"/etc/ssh/sshd_config": "PasswordAuthentication no\n"}, nil, "debian", "info"},
	} {
		sev, pw := risk(t, c.sshd, c.deny, c.family)
		if sev != c.want {
			t.Errorf("%s: %q (ssh password %s), want %q", c.name, sev, pw, c.want)
		}
	}
	// The warning says the two together.
	m := memHost{"/etc/sudoers": "@includedir /etc/sudoers.d\n", "/etc/sudoers.d/90-cloud-init-users": cloud,
		"/etc/cloud/cloud.cfg": "system_info:\n  default_user:\n    name: ubuntu\n"}
	for _, r := range sudoRisks(hostenv.SudoNopasswd(dirHost{scriptHost{memHost: m}}), "yes") {
		if r.Key == "sudo:nopasswd:cloud-init" && (!strings.Contains(r.Summary, "PasswordAuthentication yes") || !strings.Contains(r.Summary, "root at once")) {
			t.Errorf("the warning's text: %q", r.Summary)
		}
	}
}
