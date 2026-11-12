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
	for _, id := range []string{"ssh.settings", "persistence.ld_preload", "process.exe_deleted_or_temp", "rdp.no_nla",
		"accounts.extra_uid0", "listener.exposed_service", "process.miner", "process.shell_as_web_user", "ssh.shared_key",
		"firewall.disabled", "antimalware", "smb", "winrm.insecure", "auth.bruteforce"} {
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
	if got := byCheck(out, "ssh.root_login"); len(got) != 1 || got[0].Status != StatusFail {
		t.Errorf("ssh root %+v", got)
	}
	if got := byCheck(out, "ssh.password_auth"); len(got) != 1 {
		t.Errorf("ssh password %+v", got)
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
	if got := byCheck(Run(f), "ssh.settings"); len(got) != 1 || got[0].Status != StatusCannotTell {
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

func TestPatrolChecks(t *testing.T) {
	f := facts()
	f.Accounts = hostenv.OK([]hostenv.Account{{Name: "root", UID: "0"}, {Name: "toor", UID: "0"}, {Name: "web", UID: "33"}})
	f.Processes = hostenv.OK([]hostenv.Process{
		{PID: 10, Name: "redis-server", Exe: "/usr/bin/redis-server", ExeKnown: true, ExeExists: true},
		{PID: 11, Name: "kdevtmpfsi", Exe: "/var/tmp/kdevtmpfsi", ExeKnown: true, ExeExists: true, Cmdline: "kdevtmpfsi -o stratum+tcp://pool.example:3333"},
		{PID: 12, Name: "grep", Exe: "/usr/bin/grep", ExeKnown: true, ExeExists: true, Cmdline: "grep --donate-level x.log"},
		{PID: 13, Name: "bash", Exe: "/usr/bin/bash", ExeKnown: true, ExeExists: true, User: "www-data", Cmdline: "bash -i"},
		{PID: 14, Name: "cmd.exe", Exe: `C:\Windows\System32\cmd.exe`, ExeKnown: true, ExeExists: true, User: `IIS APPPOOL\DefaultAppPool`},
		{PID: 15, Name: "xmrig.exe", Exe: `C:\Users\Public\xmrig.exe`, ExeKnown: true, ExeExists: true},
	})
	f.Listeners = hostenv.OK([]hostenv.Listener{
		{Proto: "tcp", Addr: "0.0.0.0", Port: 6379, PID: 10, Process: "redis-server"},
		{Proto: "tcp6", Addr: "::", Port: 6379, PID: 10, Process: "redis-server"},
		{Proto: "tcp", Addr: "127.0.0.1", Port: 3306, Process: "mysqld"},
	})
	f.Persistence = hostenv.OK([]hostenv.PersistenceItem{
		{Kind: "authorized_key", Location: "/root/.ssh/authorized_keys", Detail: "ssh-ed25519 SHA256:aaa"},
		{Kind: "authorized_key", Location: "/home/a/.ssh/authorized_keys", Detail: "ssh-ed25519 SHA256:aaa"},
		{Kind: "authorized_key", Location: "/root/.ssh/authorized_keys", Detail: "ssh-ed25519 SHA256:bbb (with options)"},
		{Kind: "authorized_key", Location: "/home/b/.ssh/authorized_keys", Detail: "ssh-ed25519 SHA256:bbb"},
	})
	f.Firewall = hostenv.OK(hostenv.Firewall{Backend: "windows", Enabled: true, Profiles: map[string]bool{"Domain": true, "Public": false}})
	f.Antimalware = hostenv.OK(hostenv.Antimalware{Product: "Microsoft Defender", RealTime: false, SignatureAgeDays: 30,
		Exclusions: []string{`C:\`, `C:\inetpub\logs`, `C:\Windows\Temp\`}})
	f.RemoteAccess.SMB = hostenv.OK(hostenv.SMBConfig{SMB1Enabled: true, SigningRequired: false, WritableShares: []string{"public"}})
	f.RemoteAccess.WinRM = hostenv.OK(hostenv.WinRMConfig{Running: true, HTTPListener: true, AllowUnencrypted: true})
	f.AuthEvents = hostenv.OK(hostenv.AuthEvents{WindowHours: 24, FailedBySrc: map[string]int{"203.0.113.7": 300, "10.0.0.2": 3},
		Notable: []hostenv.AuthEvent{{Kind: "log_cleared", When: "2026-11-12T01:00:00Z"}}})
	out := Run(f)
	want := map[string]int{
		"accounts.extra_uid0": 1, "listener.exposed_service": 1, "process.miner": 2, "process.shell_as_web_user": 2,
		"ssh.shared_key": 1, "firewall.disabled": 1, "antimalware.realtime_off": 1, "antimalware.stale_signatures": 1,
		"antimalware.broad_exclusion": 2, "antimalware.exclusion": 1, "smb.v1_enabled": 1, "smb.signing_not_required": 1, "smb.everyone_writable": 1,
		"winrm.insecure": 1, "auth.bruteforce": 1, "auth.log_cleared": 1,
	}
	got := map[string]int{}
	for _, x := range out {
		if x.Status == StatusFail {
			got[x.Check]++
		}
	}
	for id, n := range want {
		if got[id] != n {
			t.Errorf("%s: %d findings, want %d", id, got[id], n)
		}
	}
	if e := byCheck(out, "listener.exposed_service"); len(e) == 1 && e[0].Evidence != "tcp/6379, tcp6/6379" {
		t.Errorf("exposed evidence %q", e[0].Evidence)
	}
	if e := byCheck(out, "ssh.shared_key"); len(e) == 1 && !strings.Contains(e[0].Evidence, "SHA256:aaa") {
		t.Errorf("shared key %+v", e)
	}
}

// On a platform where a fact does not exist, its checks stay silent.
func TestNotApplicableIsSilent(t *testing.T) {
	f := facts()
	f.RemoteAccess.RDP = hostenv.NotApplicable[hostenv.RDPConfig]()
	f.RemoteAccess.WinRM = hostenv.NotApplicable[hostenv.WinRMConfig]()
	f.Antimalware = hostenv.NotApplicable[hostenv.Antimalware]()
	for _, x := range Run(f) {
		switch x.Check {
		case "rdp.no_nla", "winrm.insecure", "antimalware":
			t.Errorf("not-applicable fact produced %+v", x)
		}
	}
}

func TestBroadExclusion(t *testing.T) {
	for x, want := range map[string]bool{
		`C:\`: true, `c:`: true, `*`: true, `C:\Windows\Temp\*`: true, `C:\Users\bob\AppData\Local\Temp`: true,
		`%TEMP%\x`: true, `C:/ProgramData/`: true, `C:\Users\Public\Downloads`: true, `ps1`: true, `*.exe`: true,
		`\\?\C:\`: true, `\\localhost\c$\Windows\Temp`: true, `C:\data\..\Windows`: true, `D:\Windows\System32`: true,
		`%SystemDrive%\`: true, `%ProgramFiles%`: true, `C:\PROGRA~1`: true, `C:\Users\Public\`: true,
		`\\server\share`: true, `\\?\GLOBALROOT\Device\HarddiskVolume1`: true, `\\localhost\admin$\Temp`: true,
		`C:\Windows. \System32`: true, `C:\*\Temp`: true, `C:\*.*`: true, `C:\W*\x`: true, `C:\Windows\System32\drivers`: true,
		`C:\Windows\...\System32`: true, `C:\Win*`: true, `C:\Windows\Sys*32`: true, `C:\?:\x`: true, `*.log`: false,
		`D:\data`: false, `C:\inetpub\logs`: false, `C:\ProgramData\Vendor\cache`: false, `sqlservr.exe`: false,
	} {
		if got := broadExclusion(x); got != want {
			t.Errorf("broadExclusion(%q) = %v, want %v", x, got, want)
		}
	}
}

// A partial fact is judged and its gap admitted.
func TestPartialAdmitsGap(t *testing.T) {
	f := facts()
	f.Firewall = hostenv.Partial(hostenv.Firewall{Backend: "windows", Enabled: true, Profiles: map[string]bool{"Domain": true}},
		hostenv.ReasonPermission, "some firewall profiles unreadable")
	f.Antimalware = hostenv.Partial(hostenv.Antimalware{Product: "Microsoft Defender", RealTime: true}, hostenv.ReasonPermission, "exclusions hidden")
	out := Run(f)
	for _, id := range []string{"firewall.disabled", "antimalware"} {
		got := byCheck(out, id)
		if len(got) != 1 || got[0].Status != StatusCannotTell || got[0].Reason != string(hostenv.ReasonPermission) {
			t.Errorf("%s: %+v", id, got)
		}
	}
}
