package tools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nt-neil/shentu/hostenv"
)

// The Windows checks read the host read (hostSource), as the PHP check does:
// a Windows replay is read, and the machine running the check never is.
// Before, winSource was always the live machine, so on
// a Windows replay every one of them read the machine running the test.
// Everything here is made up at run time (example.test, 192.0.2.0/24).

// winRead is a Windows host read made in the test: what the Windows checks
// ask of it, every call recorded.
type winRead struct {
	files map[string]string
	calls *[]string
}

func newWinRead() winRead {
	cfg := "<configuration>\n<system.applicationHost>\n<sites>\n" +
		"<site name=\"example\" id=\"1\">\n<application path=\"/\">\n" +
		"<virtualDirectory path=\"/\" physicalPath=\"%SystemDrive%\\inetpub\\example\" />\n" +
		"</application>\n</site>\n</sites>\n</system.applicationHost>\n</configuration>\n"
	return winRead{files: map[string]string{
		`C:\Windows\System32\inetsrv\config\applicationHost.config`: cfg,
	}, calls: new([]string)}
}

func (w winRead) log(f string, a ...any) { *w.calls = append(*w.calls, fmt.Sprintf(f, a...)) }

func (w winRead) Info() hostenv.SourceInfo {
	return hostenv.SourceInfo{GOOS: "windows", GOARCH: "amd64", Elevated: true, RecordedAt: time.Date(2026, 11, 20, 8, 0, 0, 0, time.UTC)}
}
func (w winRead) ReadFile(p string) ([]byte, error) {
	w.log("ReadFile %s", p)
	if s, ok := w.files[p]; ok {
		if s == "\x00denied" {
			return nil, &fs.PathError{Op: "open", Path: p, Err: os.ErrPermission} // as Live
		}
		if len(s) > hostenv.MaxFileBytes { // as Live: the first MaxFileBytes, said cut
			return []byte(s[:hostenv.MaxFileBytes]), hostenv.ErrTruncated
		}
		return []byte(s), nil
	}
	return nil, os.ErrNotExist
}
func (w winRead) Stat(p string) (hostenv.FileStat, error) {
	w.log("Stat %s", p)
	if s, ok := w.files[p]; ok {
		if s == "\x00unrecorded" { // as Replay, asked what the fixture lacks
			return hostenv.FileStat{}, fmt.Errorf("%w: stat %s", hostenv.ErrNotRecorded, p)
		}
		return hostenv.FileStat{Mode: 0o644, Size: int64(len(s)), ModTime: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)}, nil
	}
	return hostenv.FileStat{}, os.ErrNotExist
}
func (w winRead) ReadDir(p string) ([]string, error) {
	w.log("ReadDir %s", p)
	return nil, os.ErrNotExist
}
func (w winRead) Readlink(p string) (string, error) {
	w.log("Readlink %s", p)
	return "", os.ErrNotExist
}
func (w winRead) Run(_ context.Context, argv []string) (hostenv.CmdResult, error) {
	w.log("Run %s", strings.Join(argv, " "))
	return hostenv.CmdResult{}, os.ErrNotExist
}
func (w winRead) RegValues(key string) (map[string]hostenv.RegValue, error) {
	w.log("RegValues %s", key)
	if key == hostenv.KeyCurrentVersion {
		return map[string]hostenv.RegValue{"SystemRoot": {Type: "SZ", String: `C:\Windows`}}, nil
	}
	return nil, os.ErrNotExist
}
func (w winRead) RegSubkeys(key string) ([]string, error) {
	w.log("RegSubkeys %s", key)
	return nil, os.ErrNotExist
}
func (w winRead) Services() ([]hostenv.WinService, error) {
	w.log("Services")
	return []hostenv.WinService{{Name: "W3SVC", StartType: "auto", State: "running", PID: 812}}, nil
}
func (w winRead) Processes() ([]hostenv.WinProcess, error) {
	w.log("Processes")
	return []hostenv.WinProcess{
		{PID: 812, PPID: 600, Name: "w3wp.exe", Exe: `C:\Windows\System32\inetsrv\w3wp.exe`, User: `IIS APPPOOL\example`},
		{PID: 4242, PPID: 812, Name: "cmd.exe", Exe: `C:\Windows\System32\cmd.exe`, User: `IIS APPPOOL\example`, Cmdline: "cmd.exe /c whoami"},
	}, nil
}
func (w winRead) Sockets() ([]hostenv.WinSocket, error) { w.log("Sockets"); return nil, nil }
func (w winRead) Users() ([]hostenv.WinUser, error) {
	w.log("Users")
	return []hostenv.WinUser{
		{Name: "Administrator", SID: "S-1-5-21-1-2-3-500"},
		{Name: "Guest", SID: "S-1-5-21-1-2-3-501", Disabled: true},
		{Name: "opsexample", SID: "S-1-5-21-1-2-3-1001"},
	}, nil
}
func (w winRead) GroupMembers(sid string) ([]string, error) {
	w.log("GroupMembers %s", sid)
	if sid == hostenv.SIDAdministrators {
		return []string{"S-1-5-21-1-2-3-500", "S-1-5-21-1-2-3-1001"}, nil
	}
	return nil, nil
}
func (w winRead) Tasks() ([]hostenv.WinTask, error) { w.log("Tasks"); return nil, nil }
func (w winRead) Events(channel, _ string, _ int) ([]hostenv.WinEvent, error) {
	w.log("Events %s", channel)
	if channel != "Security" {
		return nil, nil
	}
	return []hostenv.WinEvent{{Channel: "Security", ID: 4625, Time: "2026-11-20T07:00:00Z",
		Data: map[string]string{"IpAddress": "192.0.2.10", "TargetUserName": "admin"}}}, nil
}
func (w winRead) EachEventText(channel, _ string, _ int, f func(string) bool) error {
	w.log("EachEventText %s", channel)
	if channel == "Security" {
		f("2026-11-20T07:00:00Z Security 4625 IpAddress=192.0.2.10")
	}
	return nil
}
func (w winRead) WMI(ns, q string, _ []string) ([]map[string]any, error) {
	w.log("WMI %s %s", ns, q)
	return nil, os.ErrNotExist
}
func (w winRead) FirewallPolicy() (hostenv.WinFirewallPolicy, error) {
	w.log("FirewallPolicy")
	return hostenv.WinFirewallPolicy{}, os.ErrNotExist
}
func (w winRead) FileSecurity(p string) (hostenv.WinFileSecurity, error) {
	w.log("FileSecurity %s", p)
	return hostenv.WinFileSecurity{Owner: hostenv.SIDAdministrators, Writers: []string{"S-1-5-32-545"}}, nil
}

// winChecks runs every check that reads the Windows host, each one's result
// or error as JSON, in a fixed order.
func winChecks(t *testing.T) map[string]string {
	t.Helper()
	acl := webrootACL
	t.Cleanup(func() { webrootACL = acl })
	webrootACL = true
	out := map[string]string{}
	put := func(k string, v any, err error) {
		if err != nil {
			out[k] = "error: " + err.Error()
			return
		}
		b, jerr := json.Marshal(v)
		if jerr != nil {
			t.Fatal(jerr)
		}
		out[k] = string(b)
	}
	a, err := winAccountsAudit()
	put("accounts", a, err)
	p, err := winProcesses(true)
	put("processes", p, err)
	l, err := winLogonSummary(time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC), "")
	put("logons", l, err)
	s, err := winLogSearch("Security", "4625", 10)
	put("log_search", s, err)
	put("facts", windowsFacts(context.Background()), nil)
	roots, unread := iisWebRoots(winSource())
	put("iis_roots", [][]string{roots, unread}, nil)
	put("webroot_acl", webrootFindings(roots), nil)
	return out
}

// The checks read the Windows host read, not the machine running them.
// Fails on the base: winSource was the live machine.
func TestWinChecksReadHostSource(t *testing.T) {
	w := newWinRead()
	w.files[winAdminKeys] = "ssh-ed25519 AAAAexample1 ops@example.test\n# a comment\nssh-ed25519 AAAAexample2 ci@example.test\n"
	withHost(t, w)
	got := winChecks(t)
	for k, want := range map[string]string{
		"accounts":    `"administrators_authorized_keys":{"user":"Administrators","path":"C:\\ProgramData\\ssh\\administrators_authorized_keys"`,
		"processes":   `cmd.exe /c whoami`,
		"logons":      `192.0.2.10`,
		"log_search":  `IpAddress=192.0.2.10`,
		"iis_roots":   `C:\\inetpub\\example`,
		"webroot_acl": `S-1-5-32-545`,
	} {
		if !strings.Contains(got[k], want) {
			t.Errorf("%s from the host read: %s", k, got[k])
		}
	}
	if !strings.Contains(got["accounts"], `"keys":2`) {
		t.Errorf("the host read's two keys: %s", got["accounts"])
	}
	if roots, _ := WebRootsReport(); !slices.Contains(roots, `C:\inetpub\example`) {
		t.Errorf("web roots of a Windows host read: %q", roots)
	}
	if !slices.Contains(*w.calls, "Users") || !slices.Contains(*w.calls, "Processes") {
		t.Errorf("facts not collected from the host read: %q", *w.calls)
	}
	// The package check's Windows branch asks MSRC about the host read's build.
	*w.calls = nil
	hc := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("no network in this test")
	})}
	_, _, err := packageVulnsAll(context.Background(), hc, "")
	if err == nil || strings.Contains(err.Error(), "not a Windows source") {
		t.Errorf("MSRC check on the host read: %v", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// The machine running the check is never read on a host read: a key file
// at the same path on this machine is not the host read's, and a host read
// of another OS has no Windows host at all.
func TestWinChecksNeverReadTheMachine(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the decoy is a file named like the Windows path, in a temp folder")
	}
	t.Chdir(t.TempDir())
	// The machine's "key file": five keys, at the path as a relative name.
	if err := os.WriteFile(winAdminKeys, []byte(strings.Repeat("ssh-ed25519 AAAAdecoy local@example.test\n", 5)), 0o600); err != nil {
		t.Fatal(err)
	}
	withHost(t, newWinRead()) // no key file on the host read
	if a, err := winAccountsAudit(); err != nil || a.AdminKeys != nil {
		t.Errorf("the machine's key file read on a host read: %+v %v", a.AdminKeys, err)
	}
	w := newWinRead()
	w.files[winAdminKeys] = "ssh-ed25519 AAAAexample1 ops@example.test\n"
	withHost(t, w)
	if a, err := winAccountsAudit(); err != nil || a.AdminKeys == nil || a.AdminKeys.Keys != 1 {
		t.Errorf("the host read's one key: %+v %v", a.AdminKeys, err)
	}
	// A Linux host read: no Windows source; each check says so, reads nothing here.
	withHost(t, memHost{"/etc/os-release": "ID=debian\n"})
	got := winChecks(t)
	for _, k := range []string{"accounts", "processes", "logons", "log_search"} {
		if !strings.HasPrefix(got[k], "error: ") || strings.Contains(got[k], "decoy") {
			t.Errorf("%s on a Linux host read: %s", k, got[k])
		}
	}
	acl := webrootACL
	t.Cleanup(func() { webrootACL = acl })
	webrootACL = true
	if f := webrootFindings([]string{`C:\inetpub\example`}); len(f) != 1 || f[0].Kind != "webroot_acl_unknown" ||
		!strings.Contains(f[0].Detail, "not a Windows source") {
		t.Errorf("webroot ACL on a Linux host read: %+v", f)
	}
}

// The same Windows host read gives the same output whether the checks are
// handed it directly (winSource replaced, as before this change) or get it
// as the host read: nothing but the source changed. With SHENTU_WINDUMP
// set, the direct run is written there to compare with the base's.
func TestWinChecksSameOutput(t *testing.T) {
	direct := func() map[string]string {
		w := newWinRead()
		old := winSource
		t.Cleanup(func() { winSource = old })
		winSource = func() hostenv.Source { return w }
		withHost(t, w)
		defer func() { winSource = old }()
		return winChecks(t)
	}()
	if p := os.Getenv("SHENTU_WINDUMP"); p != "" {
		b, _ := json.MarshalIndent(direct, "", " ")
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	withHost(t, newWinRead())
	viaHost := winChecks(t)
	for k, v := range direct {
		if viaHost[k] != v {
			t.Errorf("%s differs:\n direct    %s\n host read %s", k, v, viaHost[k])
		}
	}
}

// A key file read in part (over 8 MiB) or not at all is said, never a
// count of 0 that reads as "no administrators' keys" (#241 review).
func TestWinAdminKeysUnreadSaid(t *testing.T) {
	line := "ssh-ed25519 AAAAexample ops@example.test\n"
	w := newWinRead()
	w.files[winAdminKeys] = strings.Repeat(line, hostenv.MaxFileBytes/len(line)+10)
	withHost(t, w)
	a, err := winAccountsAudit()
	if err != nil || a.AdminKeys == nil || a.AdminKeys.Keys < hostenv.MaxFileBytes/len(line)-1 ||
		!strings.Contains(a.Partial, winAdminKeys+" read in part (over 8 MiB)") {
		t.Errorf("a key file over 8 MiB: keys %+v, partial %q, %v", a.AdminKeys, a.Partial, err)
	}
	w = newWinRead()
	w.files[winAdminKeys] = "\x00denied"
	withHost(t, w)
	if a, err := winAccountsAudit(); err != nil || !strings.Contains(a.Partial, winAdminKeys+" could not be read (permission denied)") ||
		strings.Count(a.Partial, winAdminKeys) != 1 {
		t.Errorf("an unreadable key file, its path said once: %+v, partial %q, %v", a.AdminKeys, a.Partial, err)
	}
	// Not in the fixture: Replay's error names the path; it is said once.
	w = newWinRead()
	w.files[winAdminKeys] = "\x00unrecorded"
	withHost(t, w)
	if a, err := winAccountsAudit(); err != nil || !strings.Contains(a.Partial, winAdminKeys+" could not be checked (hostenv: not in fixture)") ||
		strings.Count(a.Partial, winAdminKeys) != 1 {
		t.Errorf("a key file not in the fixture, its path said once: partial %q, %v", a.Partial, err)
	}
	// A line past bufio's 64 KB default is a key, and the keys after it are counted.
	w = newWinRead()
	w.files[winAdminKeys] = "ssh-rsa AAAA" + strings.Repeat("B", 70<<10) + " big@example.test\n" + line
	withHost(t, w)
	if a, err := winAccountsAudit(); err != nil || a.AdminKeys == nil || a.AdminKeys.Keys != 2 || a.Partial != "" {
		t.Errorf("a key line over 64 KB: keys %+v, partial %q, %v", a.AdminKeys, a.Partial, err)
	}
	// A file saved with a UTF-8 BOM (Notepad): its first line, a comment, is no key.
	w = newWinRead()
	w.files[winAdminKeys] = "\ufeff# ops keys\n" + line
	withHost(t, w)
	if a, err := winAccountsAudit(); err != nil || a.AdminKeys == nil || a.AdminKeys.Keys != 1 {
		t.Errorf("a BOM before a comment: keys %+v, %v", a.AdminKeys, err)
	}
}

// A Windows host read (wherever the check runs) is surveyed as Windows
// (onWindows goes by the host source), and its profile says Apache there
// is not checked rather than skipping it quietly.
func TestSurveyWindowsApacheUnchecked(t *testing.T) {
	withHost(t, newWinRead())
	p := Survey(context.Background(), &Env{})
	if !slices.ContainsFunc(p.Risks, func(r Risk) bool { return r.Key == "unchecked:apache:windows" && strings.Contains(r.Summary, "CVE-2026-119618") }) {
		t.Errorf("risks %+v: no Apache-on-Windows not-checked line", p.Risks)
	}
}
