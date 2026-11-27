package hostenv

import (
	"strings"
	"testing"
)

// N-274-6: a fixture's sudoers files (/etc/sudoers, /etc/sudoers.d/*, and
// what they include from elsewhere) are masked by MaskSudoers; any other
// file with the same text by MaskSecrets.
func TestMaskerSudoersFiles(t *testing.T) {
	rule := "deploy ALL=NOPASSWD: /usr/bin/systemctl restart app\n"
	entries := []*entry{
		{Op: "file", Path: "/etc/sudoers", data: []byte("#include /opt/x/inc\n@includedir /etc/sudoers.d\n" + rule)},
		{Op: "file", Path: "/etc/sudoers.d/a", data: []byte(rule)},
		{Op: "file", Path: "/opt/x/inc", data: []byte(rule + "#include ../y/inc2\n")},
		{Op: "file", Path: "/opt/y/inc2", data: []byte(rule)},
		{Op: "file", Path: "/etc/app.conf", data: []byte(rule)},
		{Op: "file", Path: "/etc/sudoers.d/b.bak", data: []byte(rule)}, // in sudoers.d: masked as sudoers (sudo itself skips the name)
	}
	(&Masker{}).apply(entries)
	for _, e := range entries {
		kept := strings.Contains(string(e.data), "NOPASSWD: /usr/bin/systemctl")
		if want := e.Path != "/etc/app.conf"; kept != want {
			t.Errorf("%s: tag kept %v, want %v: %q", e.Path, kept, want, e.data)
		}
	}
}
