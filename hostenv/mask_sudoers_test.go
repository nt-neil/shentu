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
		{Op: "file", Path: "/etc/sudoers.d/b.bak", data: []byte(rule)}, // sudo skips a name with a dot (S-274-9)
		{Op: "file", Path: "/etc/sudoers.d/c~", data: []byte(rule)},
	}
	(&Masker{}).apply(entries)
	general := map[string]bool{"/etc/app.conf": true, "/etc/sudoers.d/b.bak": true, "/etc/sudoers.d/c~": true}
	for _, e := range entries {
		kept := strings.Contains(string(e.data), "NOPASSWD: /usr/bin/systemctl")
		if want := !general[e.Path]; kept != want {
			t.Errorf("%s: tag kept %v, want %v: %q", e.Path, kept, want, e.data)
		}
	}
}

// S-274-9: an includedir reads as sudo does (a name with a dot or ending
// in ~ skipped), and only sudo's four directives include: #includes is a
// comment.
func TestMaskerSudoersIncludedir(t *testing.T) {
	rule := "deploy ALL=NOPASSWD: /usr/bin/systemctl restart app\n"
	entries := []*entry{
		{Op: "file", Path: "/etc/sudoers", data: []byte("@includedir /etc\n#includes /etc/other.conf\n#includes /etc/other\n")},
		{Op: "file", Path: "/etc/app.conf", data: []byte(rule)},
		{Op: "file", Path: "/etc/my.cnf", data: []byte(rule)},
		{Op: "file", Path: "/etc/x~", data: []byte(rule)},
		{Op: "file", Path: "/etc/other.conf", data: []byte(rule)},
		{Op: "file", Path: "/etc/opsrules", data: []byte(rule)}, // no dot, in the includedir: sudoers
	}
	(&Masker{}).apply(entries)
	for _, e := range entries[1:] {
		kept := strings.Contains(string(e.data), "NOPASSWD: /usr/bin/systemctl")
		if want := e.Path == "/etc/opsrules"; kept != want {
			t.Errorf("%s: tag kept %v, want %v", e.Path, kept, want)
		}
	}
}
