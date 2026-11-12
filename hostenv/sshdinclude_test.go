package hostenv

import (
	"strings"
	"testing"
)

// A Match in an included file ends that file only: settings after the
// Include in the main file still count (sshd restores the Match state).
// Only the main file's Match ends the global part.
func TestSSHDIncludeMatch(t *testing.T) {
	h := newFake(true)
	h.files[SSHDConfigPath] = "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin yes\nMatch User x\nPasswordAuthentication yes\n"
	h.files["/etc/ssh/sshd_config.d/a.conf"] = "X11Forwarding yes\nMatch Address 10.0.0.0/8\nPermitEmptyPasswords yes\n"
	o := LinuxCollector{}.SSHD(h, SSHDConfigPath)
	s := o.Value.Settings
	if s["permitrootlogin"] != "yes" || s["x11forwarding"] != "yes" || s["permitemptypasswords"] != "no" || s["passwordauthentication"] != "yes" && s["passwordauthentication"] != SSHDDefaults()["passwordauthentication"] {
		t.Errorf("settings %v", s)
	}
	if s["passwordauthentication"] != SSHDDefaults()["passwordauthentication"] {
		t.Errorf("the main file's Match block counted: %v", s["passwordauthentication"])
	}
	// Five levels of Include: the fifth is not read, and says so.
	for i := 1; i <= 6; i++ {
		h.files["/etc/ssh/n"+strings.Repeat("x", i)] = "Include /etc/ssh/n" + strings.Repeat("x", i+1) + "\n"
	}
	h.files[SSHDConfigPath] = "Include /etc/ssh/nx\n"
	if o = (LinuxCollector{}).SSHD(h, SSHDConfigPath); o.Status != StatusPartial || !strings.Contains(strings.Join(o.Value.Unread, ","), "nested more than 4 deep") {
		t.Errorf("deep Include: %s %v", o.Status, o.Value.Unread)
	}
}
