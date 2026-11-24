package tools

import (
	"context"
	"go/parser"
	"go/token"
	"os"
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

// The PHP check's own files touch the machine only through hostenv: they
// import nothing that opens, stats, lists or runs on the machine itself
// (os.DirFS, ioutil and syscall.Open included).
func TestPHPNoDirectHostAccess(t *testing.T) {
	for _, f := range []string{"php.go", "phpcgi_win.go"} {
		pf, err := parser.ParseFile(token.NewFileSet(), f, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, im := range pf.Imports {
			switch p := strings.Trim(im.Path.Value, `"`); p {
			case "os", "os/exec", "io/ioutil", "syscall", "path/filepath", "golang.org/x/sys/unix", "golang.org/x/sys/windows":
				t.Errorf("%s imports %s: the machine running the check, not the host read", f, p)
			}
		}
	}
}

// winHost is a Windows host read (a replay, or another host's survey): only
// what the PHP check asks of it; anything else panics (nil WinSource).
type winHost struct {
	hostenv.WinSource
	files map[string]string
}

func (winHost) Info() hostenv.SourceInfo { return hostenv.SourceInfo{GOOS: "windows"} }
func (h winHost) ReadFile(p string) ([]byte, error) {
	if s, ok := h.files[p]; ok {
		return []byte(s), nil
	}
	return nil, os.ErrNotExist
}
func (winHost) ReadDir(string) ([]string, error)        { return nil, os.ErrNotExist }
func (winHost) Readlink(string) (string, error)         { return "", os.ErrNotExist }
func (winHost) Services() ([]hostenv.WinService, error) { return nil, nil }
func (winHost) Run(context.Context, []string) (hostenv.CmdResult, error) {
	return hostenv.CmdResult{}, os.ErrNotExist
}
func (h winHost) Lstat(p string) (hostenv.FileStat, error) {
	for f := range h.files {
		if f == p || strings.HasPrefix(f, p+`\`) {
			return hostenv.FileStat{}, nil
		}
	}
	return hostenv.FileStat{}, os.ErrNotExist
}
func (winHost) RegValues(key string) (map[string]hostenv.RegValue, error) {
	if key == hostenv.KeyCodePage {
		return map[string]hostenv.RegValue{"ACP": {Type: "SZ", String: "1252"}}, nil
	}
	return nil, os.ErrNotExist
}

// S-1 (#223 review): a Windows host read is read, not the machine running
// the check (winSource is always the live one): its IIS php-cgi is
// reported, and with none, nothing is.
func TestPHPWindowsReplay(t *testing.T) {
	win := phpWindows
	t.Cleanup(func() { phpWindows = win })
	phpWindows = false // Windows from the host read's own word
	cfg := "<configuration>\n<system.webServer>\n<fastCgi>\n" +
		"  <application fullPath=\"%SystemDrive%\\PHP\\php-cgi.exe\" />\n" +
		"</fastCgi>\n</system.webServer>\n</configuration>\n"
	withHost(t, winHost{files: map[string]string{
		`C:\Windows\System32\inetsrv\config\applicationHost.config`: cfg,
		`C:\PHP\php-cgi.exe`: "MZ\x00stub\x00",
		`C:\PHP\php8ts.dll`:  "MZ\x00X-Powered-By: PHP/8.3.7\x00",
	}})
	r := phpRisks(context.Background())
	if a := phpFind(r, "php8.3:CVE-2026-129538"); a == nil || !strings.Contains(a.Summary, `C:\PHP\php-cgi.exe`) {
		t.Fatalf("php-cgi on the Windows host read: %v", phpKeys(r))
	}
	withHost(t, winHost{files: map[string]string{}})
	if r := phpRisks(context.Background()); len(r) != 0 {
		t.Errorf("no PHP on the Windows host read, yet: %v", phpKeys(r))
	}
}
