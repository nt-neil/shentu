package checks

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nt-neil/shentu/hostenv"
)

func facts() *hostenv.Facts {
	return hostenv.NewFacts("test", "0", time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC))
}

func byCheck(fs []Finding, id string) []Finding {
	var out []Finding
	for _, f := range fs {
		if f.Check == id {
			out = append(out, f)
		}
	}
	return out
}

// A Facts nobody filled in must produce "cannot tell", not a clean result.
func TestUnknownFactsCannotTell(t *testing.T) {
	out := Run(facts())
	for _, id := range []string{"ssh.root_password_login", "persistence.ld_preload", "process.exe_deleted_or_temp", "rdp.no_nla"} {
		got := byCheck(out, id)
		if len(got) != 1 || got[0].Status != StatusCannotTell || got[0].Reason != string(hostenv.ReasonNotCollected) {
			t.Errorf("%s: %+v", id, got)
		}
	}
	for _, f := range out {
		if f.Status == StatusFail {
			t.Errorf("failed on unknown facts: %+v", f)
		}
	}
}

func TestFindings(t *testing.T) {
	f := facts()
	f.RemoteAccess.SSH = hostenv.OK(hostenv.SSHConfig{ConfigPath: "/etc/ssh/sshd_config",
		Settings: map[string]string{"permitrootlogin": "yes", "passwordauthentication": "yes"}})
	f.Persistence = hostenv.OK([]hostenv.PersistenceItem{{Kind: "ld_preload", Location: "/etc/ld.so.preload", Command: "/lib/x.so"}, {Kind: "cron"}})
	f.Processes = hostenv.Partial([]hostenv.Process{
		{PID: 1, Name: "init", ExeKnown: true, ExeExists: true, Exe: "/sbin/init"},
		{PID: 2, Name: "x", ExeKnown: true, ExeExists: true, Exe: "/tmp/x", InTemp: true},
		{PID: 3, Name: "y", ExeKnown: true, ExeExists: false, Exe: "/usr/bin/y"},
		{PID: 4, Name: "z"},
	}, hostenv.ReasonPermission, "1 hidden")
	f.RemoteAccess.RDP = hostenv.NotApplicable[hostenv.RDPConfig]()
	out := Run(f)
	if got := byCheck(out, "ssh.root_password_login"); len(got) != 1 || got[0].Status != StatusFail {
		t.Errorf("ssh %+v", got)
	}
	if got := byCheck(out, "persistence.ld_preload"); len(got) != 1 || got[0].Status != StatusFail {
		t.Errorf("ld_preload %+v", got)
	}
	got := byCheck(out, "process.exe_deleted_or_temp")
	if len(got) != 3 || got[2].Status != StatusCannotTell {
		t.Errorf("process %+v", got)
	}
	if got := byCheck(out, "rdp.no_nla"); len(got) != 0 {
		t.Errorf("rdp on a platform without RDP: %+v", got)
	}

	f.RemoteAccess.SSH = hostenv.Partial(hostenv.SSHConfig{Settings: map[string]string{"permitrootlogin": "unknown", "passwordauthentication": "unknown"}},
		hostenv.ReasonPermission, "")
	if got := byCheck(Run(f), "ssh.root_password_login"); len(got) != 1 || got[0].Status != StatusCannotTell {
		t.Errorf("ssh partial %+v", got)
	}
	f.RemoteAccess.RDP = hostenv.OK(hostenv.RDPConfig{Enabled: true, NLA: false, Port: 3389})
	if got := byCheck(Run(f), "rdp.no_nla"); len(got) != 1 || got[0].Status != StatusFail {
		t.Errorf("rdp %+v", got)
	}
}

// Checks read facts only: no OS access of their own.
func TestInvariantChecksDoNotTouchOS(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range f.Imports {
			switch strings.Trim(imp.Path.Value, `"`) {
			case "os", "os/exec", "syscall", "runtime", "io/fs", "path/filepath", "net/http":
				t.Errorf("%s imports %s; checks must read hostenv.Facts only", name, imp.Path.Value)
			}
		}
	}
}
