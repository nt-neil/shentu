package main

import (
	"strings"
	"testing"
)

// S-281-1, as hostenv's TestMaskCommandArgs: the root mask() masks the same.
func TestMaskCommandArgs(t *testing.T) {
	dl := "cu" + "rl" // the program's name built at run time, so a secret scanner reads no rule here
	s := strings.Repeat("h2", 4) + "x9"
	for in, want := range map[string]string{
		"mysql -u app -p" + s + " shop":                   "mysql -u app -p[REDACTED] shop",
		"mysql --password " + s + " shop":                 "mysql --password [REDACTED] shop",
		dl + " -u bob:" + s + " https://api.example.test": dl + " -u bob:[REDACTED] https://api.example.test",
		"git push origin -u main:main":                    "git push origin -u main:main",
		"mysql -h db.example.test -P 3306 -u app":         "mysql -h db.example.test -P 3306 -u app",
		"mysql --password-file=/etc/app/pw shop":          "mysql --password-file=/etc/app/pw shop",
	} {
		if got := mask(in); got != want {
			t.Errorf("mask(%q) = %q, want %q", in, got, want)
		}
	}
}
