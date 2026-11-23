package tools

import (
	"context"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/nt-neil/shentu/hostenv"
)

// The PHP check reads the host source only: a PHP on the host read is
// reported, and the machine running the check (a CI runner with PHP 8.5
// installed) is never looked at. On v056-train 06eb505 it globbed, read and
// ran dpkg-query on the machine itself, so an empty replay got php8.5
// findings (TestSiteProfileEmptyHost on the runner).
func TestPHPHostSourceOnly(t *testing.T) {
	win := phpWindows
	t.Cleanup(func() { phpWindows = win })
	phpWindows = false
	bin := "\x7fELF\x02\x01\x01\x00padding\x00X-Powered-By: PHP/8.3.7\x00PHP_SELF\x00"
	h := dirHost{scriptHost{memHost: memHost{
		"/etc/os-release": "NAME=\"Example Linux\"\nID=debian\nVERSION_ID=\"12\"\n",
		"/usr/bin/php8.3": bin,
	}, cmds: map[string]hostenv.CmdResult{
		strings.Join(hostenv.DpkgSearchArgv("/usr/bin/php8.3"), " "): {Stdout: []byte("php8.3-cli: /usr/bin/php8.3\n")},
		strings.Join(hostenv.DpkgStatusArgv("php8.3-cli"), " "):      {Stdout: []byte("installed 8.3.7-1+example1")},
	}}}
	withHost(t, h)
	r := phpRisks(context.Background())
	// the package queries ran on the host read too: its package is named
	if a := phpFind(r, "php8.3:CVE-2026-129496"); a == nil || !strings.Contains(a.Summary, "/usr/bin/php8.3") ||
		!strings.Contains(a.Summary, "package php8.3-cli 8.3.7-1+example1") {
		t.Fatalf("PHP on the host read: %v", phpKeys(r))
	}
	// The host read has no PHP: nothing, whatever the machine running this has.
	withHost(t, dirHost{scriptHost{memHost: memHost{"/etc/os-release": "NAME=\"Example Linux\"\nID=debian\nVERSION_ID=\"12\"\n"}}})
	if r := phpRisks(context.Background()); len(r) != 0 {
		t.Errorf("no PHP on the host read, yet: %v", phpKeys(r))
	}
}

// The PHP check's own files touch the machine only through hostenv: no
// direct open, stat, listing, glob, link resolution or command.
func TestPHPNoDirectHostAccess(t *testing.T) {
	direct := regexp.MustCompile(`\bos\.(Open|OpenFile|ReadFile|Stat|Lstat|ReadDir|Readlink)\(|\bexec\.Command|\bfilepath\.(Glob|EvalSymlinks|WalkDir|Walk)\(`)
	for _, f := range []string{"php.go", "phpcgi_win.go"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for i, l := range strings.Split(string(b), "\n") {
			if direct.MatchString(l) && !strings.HasPrefix(strings.TrimSpace(l), "//") {
				t.Errorf("%s:%d reads the machine itself: %s", f, i+1, strings.TrimSpace(l))
			}
		}
	}
}
