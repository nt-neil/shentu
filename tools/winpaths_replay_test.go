package tools

import (
	"testing"

	"github.com/nt-neil/shentu/hostenv"
)

func replayHost(t *testing.T, dir string) {
	t.Helper()
	acl := webrootACL
	webrootACL = webrootACLHost
	t.Cleanup(func() { webrootACL = acl })
	rp, err := hostenv.LoadReplay(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(SetHostSourceForTest(rp))
}

// v0.5.9 (plan t15): a Windows host's recording, replayed on any machine,
// has the IIS checks on and its paths read as Windows reads them: drive
// letters, "\", case folded. Fails on the base when run off Windows: the
// switches followed the machine's GOOS and the paths its filepath.
func TestWindowsReplayPaths(t *testing.T) {
	if !hostIsLive() {
		t.Fatal("the default host read is not the live machine")
	}
	replayHost(t, "../hostenv/testdata/windows/server2022-admin")
	if hostIsLive() {
		t.Fatal("a replay taken for the live machine")
	}
	if !aspAudit() || !foldPaths() || !webrootACL() || hostPaths().Sep != `\` {
		t.Fatalf("switches %v %v %v, sep %q", aspAudit(), foldPaths(), webrootACL(), hostPaths().Sep)
	}
	roots := []string{`C:\inetpub\wwwroot\`}
	for _, c := range []struct {
		name string
		got  bool
		want bool
	}{
		{"inside, other case", inside(`c:\InetPub\wwwroot\a.aspx`, roots[0]), true},
		{"inside, forward slashes", inside(`C:/inetpub/wwwroot/a.aspx`, roots[0]), true},
		{"a sibling folder", inside(`C:\inetpub\wwwrootx\a.aspx`, roots[0]), false},
		{"another drive", inside(`D:\inetpub\wwwroot\a.aspx`, roots[0]), false},
		{"a drive's root holds only itself", inside(`C:\x`, `C:\`), false},
		{"a drive's root is itself, any case", inside(`c:\`, `C:\`), true},
		{"served under the root", served(`C:\InetPub\WWWRoot\shell.aspx`, roots), true},
		{"served by a folder name, folded", served(`D:\sites\Public\x.aspx`, nil), true},
		{"not served", served(`D:\backup\x.aspx`, nil), false},
		{"upload folder under the root", uploadFolder(`C:\inetpub\wwwroot\Uploads\x.aspx`, roots), true},
		{"not an upload folder", uploadFolder(`C:\inetpub\wwwroot\bin\x.aspx`, roots), false},
		{"an ASP page", aspPage(`C:\inetpub\wwwroot\X.ASPX`), true},
	} {
		if c.got != c.want {
			t.Errorf("%s: %v, want %v", c.name, c.got, c.want)
		}
	}
}

// S-281-3: a Linux host's recording, replayed on any machine (Windows
// too), has the IIS checks off and its paths case-sensitive.
func TestLinuxReplayNoWindowsChecks(t *testing.T) {
	replayHost(t, "../hostenv/testdata/linux/al2023-root")
	if aspAudit() || foldPaths() || webrootACL() || hostPaths().Sep != "/" {
		t.Fatalf("switches %v %v %v, sep %q", aspAudit(), foldPaths(), webrootACL(), hostPaths().Sep)
	}
	if aspPage("/var/www/html/x.aspx") || inside("/var/www/HTML/x", "/var/www/html") {
		t.Error("a Linux host's paths read as Windows'")
	}
	if !served("/srv/site/public/x.php", nil) || served("/srv/site/Public/x.php", nil) {
		t.Error("folder names compared as Linux does: case kept")
	}
}
