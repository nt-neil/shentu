package hostenv

// The macOS collector. Like the Linux one it only talks to a Source, so a
// macOS fixture replays on any machine. Everything is read-only and runs as
// whoever starts it: without root some facts are partial, never guessed.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

type DarwinCollector struct{}

func (DarwinCollector) Name() string { return "darwin" }

const (
	macSystemVersion = "/System/Library/CoreServices/SystemVersion.plist"
	socketfilterfw   = "/usr/libexec/ApplicationFirewall/socketfilterfw"
)

var (
	swVersArgv      = []string{"/usr/bin/sw_vers"}
	macSysctlArgv   = []string{"/usr/sbin/sysctl", "-n", "kern.osrelease", "hw.memsize", "vm.loadavg"}
	macPsArgv       = []string{"/bin/ps", "-axww", "-o", "pid=,ppid=,uid=,user=,etime=,comm="}
	macPsArgsArgv   = []string{"/bin/ps", "-axww", "-o", "pid=,args="}
	netstatTCPArgv  = []string{"/usr/sbin/netstat", "-anv", "-p", "tcp"}
	netstatUDPArgv  = []string{"/usr/sbin/netstat", "-anv", "-p", "udp"}
	lsofListenArgv  = []string{"/usr/sbin/lsof", "-nP", "-iTCP", "-sTCP:LISTEN", "-iUDP", "-FpcPnt"}
	alfStateArgv    = []string{socketfilterfw, "--getglobalstate"}
	alfBlockAllArgv = []string{socketfilterfw, "--getblockall"}
	alfStealthArgv  = []string{socketfilterfw, "--getstealthmode"}
	pfInfoArgv      = []string{"/sbin/pfctl", "-s", "info"}
	csrutilArgv     = []string{"/usr/bin/csrutil", "status"}
	spctlArgv       = []string{"/usr/sbin/spctl", "--status"}
	fdesetupArgv    = []string{"/usr/bin/fdesetup", "status"}
	dsclUIDArgv     = []string{"/usr/bin/dscl", ".", "-list", "/Users", "UniqueID"}
	dsclShellArgv   = []string{"/usr/bin/dscl", ".", "-list", "/Users", "UserShell"}
	dsclHomeArgv    = []string{"/usr/bin/dscl", ".", "-list", "/Users", "NFSHomeDirectory"}
	dsclAdminArgv   = []string{"/usr/bin/dscl", ".", "-read", "/Groups/admin", "GroupMembership"}
)

// Allowlist never holds system_profiler or ioreg: they print the serial
// number and the hardware UUID, which must never reach a fixture.
func (DarwinCollector) Allowlist() [][]string {
	return [][]string{swVersArgv, macSysctlArgv, macPsArgv, macPsArgsArgv, netstatTCPArgv, netstatUDPArgv,
		lsofListenArgv, alfStateArgv, alfBlockAllArgv, alfStealthArgv, pfInfoArgv, csrutilArgv, spctlArgv, fdesetupArgv,
		dsclUIDArgv, dsclShellArgv, dsclHomeArgv, dsclAdminArgv}
}

func (c DarwinCollector) Collect(ctx context.Context, src Source) *Facts {
	info := src.Info()
	f := NewFacts(c.Name(), CollectorVersion, info.RecordedAt)
	f.Privilege = OK(Privilege{Elevated: info.Elevated})
	var sysctl []string
	if r, err := src.Run(ctx, macSysctlArgv); err == nil && r.ExitCode == 0 {
		sysctl = strings.Split(strings.TrimSpace(string(r.Stdout)), "\n")
	}
	f.Platform = c.Platform(ctx, src, sysctl)
	f.Resources = macResources(sysctl)
	f.Packages = c.Packages(src, f.Platform.Value.Version)
	f.Accounts = c.Accounts(ctx, src)
	f.Processes = c.Processes(ctx, src, info.RecordedAt)
	f.Listeners = c.Listeners(ctx, src)
	if f.Processes.Known() { // full process names: netstat cuts them short
		names := map[int]string{}
		for _, p := range f.Processes.Value {
			names[p.PID] = p.Name
		}
		for i, l := range f.Listeners.Value {
			if n := names[l.PID]; n != "" {
				f.Listeners.Value[i].Process = n
			}
		}
	}
	f.Firewall = c.Firewall(ctx, src)
	f.Protections = c.Protections(ctx, src)
	f.Antimalware = c.XProtect(src, info.RecordedAt)
	f.RemoteAccess.SSH = LinuxCollector{}.SSHD(src, SSHDConfigPath) // same OpenSSH, same file
	f.SSHKeys = Unknown[[]AuthorizedKeyFile](f.Accounts.Reason, "accounts unknown")
	if f.Accounts.Known() {
		// System accounts ("_name") have no login shell and homes only
		// root may read; sshd lets none of them in.
		var login []Account
		for _, a := range f.Accounts.Value {
			if a.CanLogin || a.UID == "0" {
				login = append(login, a)
			}
		}
		f.SSHKeys = LinuxCollector{}.SSHKeyFiles(src, login)
	}
	var jobs []launchJob
	f.Services, jobs = c.Services(src, f.Accounts)
	f.Persistence = c.persistence(src, jobs, f.Services, f.SSHKeys)

	f.Patches = NotApplicable[[]Patch]() // macOS patches are the OS version and the app versions
	f.RemoteAccess.RDP = NotApplicable[RDPConfig]()
	f.RemoteAccess.WinRM = NotApplicable[WinRMConfig]()
	f.RemoteAccess.SMB = Unknown[SMBConfig](ReasonNotCollected, "macOS file sharing not collected yet")
	f.AuthEvents = Unknown[AuthEvents](ReasonNotCollected, "the unified log (log show) is not read yet")
	f.Web = Unknown[Web](ReasonNotCollected, "web servers on macOS not collected yet")
	return f
}

// Platform reads SystemVersion.plist, and sw_vers when the plist is missing.
func (DarwinCollector) Platform(ctx context.Context, src Source, sysctl []string) Obs[Platform] {
	p := Platform{OS: "darwin", Family: "macos", Distro: "macos", Arch: src.Info().GOARCH}
	if len(sysctl) > 0 {
		p.Kernel = sysctl[0]
	}
	var err error
	if b, rerr := src.ReadFile(macSystemVersion); rerr == nil {
		if v, perr := ParsePlist(b); perr == nil {
			d, _ := v.(map[string]any)
			p.Version, p.Build = PlistString(d, "ProductVersion"), PlistString(d, "ProductBuildVersion")
			p.PrettyName = PlistString(d, "ProductName")
		} else {
			err = perr
		}
	} else {
		err = rerr
	}
	if p.Version == "" {
		r, rerr := src.Run(ctx, swVersArgv)
		if rerr == nil && r.ExitCode == 0 {
			for _, l := range strings.Split(string(r.Stdout), "\n") {
				k, v, _ := strings.Cut(l, ":")
				switch strings.TrimSpace(k) {
				case "ProductName":
					p.PrettyName = strings.TrimSpace(v)
				case "ProductVersion":
					p.Version = strings.TrimSpace(v)
				case "BuildVersion":
					p.Build = strings.TrimSpace(v)
				}
			}
		} else if rerr != nil {
			err = rerr
		}
	}
	if p.PrettyName == "" {
		p.PrettyName = "macOS"
	}
	if p.Version == "" {
		return Obs[Platform]{Status: StatusPartial, Reason: Classify(err), Detail: "macOS version unknown", Value: p}
	}
	p.PrettyName += " " + p.Version
	if p.Build != "" {
		p.PrettyName += " (" + p.Build + ")"
	}
	return OK(p)
}

// macResources reads sysctl's hw.memsize and vm.loadavg ("{ 1.2 1.1 1.0 }").
// Available memory needs vm_stat and is left at 0 (not known).
func macResources(sysctl []string) Obs[Resources] {
	if len(sysctl) < 3 {
		return Unknown[Resources](ReasonCommandFailed, "sysctl gave no answer")
	}
	var r Resources
	r.MemTotalBytes, _ = strconv.ParseUint(strings.TrimSpace(sysctl[1]), 10, 64)
	if f := strings.Fields(strings.Trim(strings.TrimSpace(sysctl[2]), "{}")); len(f) > 0 {
		r.Load1, _ = strconv.ParseFloat(f[0], 64)
	}
	return OK(r)
}

// MacAppDirs hold application bundles; each .app's Info.plist names its version.
var MacAppDirs = []string{"/Applications", "/Applications/Utilities"}

// homebrewCellars are where Homebrew keeps one folder per formula and version
// (Apple silicon, then Intel), and its casks.
var (
	homebrewCellars = []string{"/opt/homebrew/Cellar", "/usr/local/Cellar"}
	homebrewCasks   = []string{"/opt/homebrew/Caskroom", "/usr/local/Caskroom"}
)

// Packages lists Homebrew formulae and casks from their folders and the
// applications in /Applications from their Info.plist. Package.Source says
// which: "homebrew", "homebrew-cask" or "app". Installer receipts (pkgutil)
// are not listed, so the set is partial.
func (DarwinCollector) Packages(src Source, osVersion string) Obs[PackageSet] {
	set := PackageSet{Manager: "macos"}
	if osVersion != "" {
		set.Feed = &PatchFeed{Kind: "apple", Release: strings.Split(osVersion, ".")[0], Upgrade: "softwareupdate --install --all"}
	}
	var unread []string
	note := func(p string, err error) {
		if err != nil && !missing(err) {
			unread = append(unread, p+" ("+string(Classify(err))+")")
		}
	}
	versions := func(root, source string) {
		names, err := src.ReadDir(root)
		note(root, err)
		for _, n := range names {
			vs, err := src.ReadDir(root + "/" + n)
			note(root+"/"+n, err)
			for _, v := range vs {
				if !strings.HasPrefix(v, ".") {
					set.Items = append(set.Items, Package{Name: n, Version: v, Source: source})
				}
			}
		}
	}
	for _, c := range homebrewCellars {
		versions(c, "homebrew")
	}
	for _, c := range homebrewCasks {
		versions(c, "homebrew-cask")
	}
	for _, dir := range MacAppDirs {
		names, err := src.ReadDir(dir)
		note(dir, err)
		for _, n := range names {
			if !strings.HasSuffix(n, ".app") {
				continue
			}
			p := dir + "/" + n + "/Contents/Info.plist"
			b, err := src.ReadFile(p)
			if err != nil {
				note(p, err)
				continue
			}
			v, err := ParsePlist(b)
			if err != nil {
				unread = append(unread, p+" (unparsable)")
				continue
			}
			d, _ := v.(map[string]any)
			pkg := Package{Name: strings.TrimSuffix(n, ".app"), Version: PlistString(d, "CFBundleShortVersionString"), Source: "app"}
			if pkg.Version == "" {
				pkg.Version = PlistString(d, "CFBundleVersion")
			}
			if id := PlistString(d, "CFBundleIdentifier"); id != "" {
				pkg.Name = id
			}
			set.Items = append(set.Items, pkg)
		}
	}
	sort.Slice(set.Items, func(i, j int) bool {
		a, b := set.Items[i], set.Items[j]
		if a.Source != b.Source {
			return a.Source < b.Source
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Version < b.Version
	})
	detail := "installer receipts (pkgutil) not listed"
	if len(unread) > 0 {
		detail += "; unread: " + strings.Join(unread, ", ")
	}
	return Partial(set, ReasonNotCollected, detail)
}

// Accounts come from Directory Services (dscl), read-only. Names starting
// with "_" are system accounts; a shell of false or nologin cannot log in.
func (DarwinCollector) Accounts(ctx context.Context, src Source) Obs[[]Account] {
	r, err := src.Run(ctx, dsclUIDArgv)
	if err != nil || r.ExitCode != 0 {
		return unknownFrom[[]Account]("dscl", cmdErr(err, r))
	}
	uids := dsclList(r.Stdout)
	var why []string // what dscl could not tell, and what is not read because of it
	col := func(argv []string, what string) map[string]string {
		r, err := src.Run(ctx, argv)
		if err != nil || r.ExitCode != 0 {
			why = append(why, what+" unknown ("+cmdErr(err, r).Error()+")")
			return nil
		}
		return dsclList(r.Stdout)
	}
	shells := col(dsclShellArgv, "shells")
	homes := col(dsclHomeArgv, "homes")
	admins := map[string]bool{}
	if r, err := src.Run(ctx, dsclAdminArgv); err == nil && r.ExitCode == 0 {
		_, list, _ := strings.Cut(string(r.Stdout), ":")
		for _, n := range strings.Fields(list) {
			admins[n] = true
		}
	} else {
		why = append(why, "admin members unknown ("+cmdErr(err, r).Error()+")")
	}
	var out []Account
	for name, uid := range uids {
		a := Account{Name: name, UID: uid, Shell: shells[name], Home: homes[name]} // a home may hold spaces
		a.CanLogin = !strings.HasPrefix(name, "_") && CanLoginShell(a.Shell)
		a.IsAdmin = uid == "0" || admins[name]
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	if len(why) > 0 {
		return Partial(out, ReasonCommandFailed, strings.Join(why, "; "))
	}
	return OK(out)
}

// dsclList reads "name   value" lines of dscl -list; the value is the rest
// of the line as written (a home path may hold spaces, even two in a row).
func dsclList(b []byte) map[string]string {
	m := map[string]string{}
	for _, l := range strings.Split(string(b), "\n") {
		name, rest, ok := strings.Cut(strings.TrimLeft(l, " \t"), " ")
		if ok && name != "" {
			if v := strings.TrimLeft(rest, " \t"); v != "" { // trailing spaces are part of a path
				m[name] = v
			}
		}
	}
	return m
}

func cmdErr(err error, r CmdResult) error {
	if err != nil {
		return err
	}
	return fmt.Errorf("exit %d: %s", r.ExitCode, CutString(strings.TrimSpace(r.Stderr), 200))
}

// Processes come from ps: the executable path (comm), the command line
// (args, masked) and the elapsed time, which gives the start time against
// the Source's clock, so a replay gives the same answer anywhere.
func (DarwinCollector) Processes(ctx context.Context, src Source, now time.Time) Obs[[]Process] {
	r, err := src.Run(ctx, macPsArgv)
	if err != nil || r.ExitCode != 0 {
		return unknownFrom[[]Process]("ps", cmdErr(err, r))
	}
	args := map[int]string{}
	argsWhy := "" // why some command lines are missing
	a, aerr := src.Run(ctx, macPsArgsArgv)
	switch {
	case aerr == nil && a.ExitCode == 0:
	case errors.Is(aerr, ErrTruncated) || errors.Is(aerr, ErrTimeout):
		argsWhy = "command lines cut short (" + aerr.Error() + ")" // what came is kept
	default:
		argsWhy = "command lines unknown (" + cmdErr(aerr, a).Error() + ")"
		a.Stdout = nil
	}
	if len(a.Stdout) > 0 {
		for _, l := range strings.Split(string(a.Stdout), "\n") {
			l = strings.TrimSpace(l)
			pid, rest, _ := strings.Cut(l, " ")
			if n, err := strconv.Atoi(pid); err == nil {
				args[n] = CutString(MaskSecrets(strings.TrimSpace(rest)), MaxCmdline)
			}
		}
	}
	var out []Process
	for _, l := range strings.Split(string(r.Stdout), "\n") {
		f := strings.Fields(l)
		if len(f) < 6 {
			continue
		}
		pid, e1 := strconv.Atoi(f[0])
		ppid, e2 := strconv.Atoi(f[1])
		if e1 != nil || e2 != nil {
			continue
		}
		// comm is the rest of the line after five fields; it may hold spaces.
		comm := strings.TrimSpace(l)
		for i := 0; i < 5; i++ {
			comm = strings.TrimSpace(comm[strings.IndexAny(comm, " \t"):])
		}
		p := Process{PID: pid, PPID: ppid, UID: f[2], User: f[3], Cmdline: args[pid], Name: path.Base(comm)}
		if strings.HasPrefix(comm, "/") {
			p.Exe, p.ExeKnown = comm, true
			_, serr := Stat(src, comm)
			p.ExeExists = serr == nil || errors.Is(serr, ErrNoStat)
			p.InTemp = MacInTempDir(comm)
		}
		if d, ok := parseEtime(f[4]); ok && !now.IsZero() {
			p.Started = now.Add(-d).UTC().Truncate(time.Second).Format(time.RFC3339)
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PID < out[j].PID })
	if argsWhy != "" {
		r := Classify(aerr)
		if r == "" {
			r = ReasonCommandFailed
		}
		return Partial(out, r, argsWhy)
	}
	return OK(out)
}

// MacInTempDir: world-writable temp folders, also under /private.
func MacInTempDir(exe string) bool {
	return InTempDir(strings.TrimPrefix(exe, "/private"))
}

// parseEtime reads ps's elapsed time, [[dd-]hh:]mm:ss.
func parseEtime(s string) (time.Duration, bool) {
	days := 0
	if d, rest, ok := strings.Cut(s, "-"); ok {
		n, err := strconv.Atoi(d)
		if err != nil {
			return 0, false
		}
		days, s = n, rest
	}
	parts := strings.Split(s, ":")
	if len(parts) < 2 || len(parts) > 3 {
		return 0, false
	}
	secs := 0
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return 0, false
		}
		secs = secs*60 + n
	}
	return time.Duration(days*86400+secs) * time.Second, true
}

// netstat -anv line: proto, queues, local, foreign, [state], counters, then
// "process:pid" (the name may hold spaces and is cut at 16 characters).
var netstatLine = regexp.MustCompile(`^(tcp[46]*|udp[46]*)\s+\d+\s+\d+\s+(\S+)\s+(\S+)\s+(?:([A-Z_0-9]+)\s+)?(?:\d+\s+){4}(.*):(\d+)\s+[0-9a-f]{5}\s`)

// Listeners are TCP sockets in LISTEN and unconnected UDP sockets, with the
// owning process netstat names (it sees every process's sockets). macOS can
// hide every Internet socket from netstat when a program, not a terminal,
// starts it; with not a single socket line, that is taken as hidden, never
// as "nothing listens", and lsof lists what this user's processes hold.
func (c DarwinCollector) Listeners(ctx context.Context, src Source) Obs[[]Listener] {
	var out []Listener
	seen := map[string]bool{}
	sockets := 0
	var cut []string // netstat runs cut at the output cap
	for _, argv := range [][]string{netstatTCPArgv, netstatUDPArgv} {
		r, err := src.Run(ctx, argv)
		switch {
		case errors.Is(err, ErrTruncated): // past the output cap: what was read is kept, and said
			cut = append(cut, strings.Join(argv, " "))
		case err != nil || r.ExitCode != 0:
			return unknownFrom[[]Listener]("netstat", cmdErr(err, r))
		}
		for _, l := range strings.Split(string(r.Stdout), "\n") {
			if strings.HasPrefix(l, "tcp") || strings.HasPrefix(l, "udp") {
				sockets++
			}
			m := netstatLine.FindStringSubmatch(l)
			if m == nil {
				continue
			}
			proto, local, foreign, state := m[1], m[2], m[3], m[4]
			if strings.HasPrefix(proto, "tcp") && state != "LISTEN" || strings.HasPrefix(proto, "udp") && foreign != "*.*" {
				continue
			}
			i := strings.LastIndexByte(local, '.')
			if i < 0 {
				continue
			}
			port, err := strconv.Atoi(local[i+1:])
			if err != nil {
				continue
			}
			addr := local[:i]
			if addr == "*" {
				addr = "0.0.0.0"
				if strings.HasSuffix(proto, "6") {
					addr = "::"
				}
			}
			base := proto[:3]
			if strings.HasSuffix(proto, "6") || strings.Contains(addr, ":") {
				base += "6"
			}
			pid, _ := strconv.Atoi(m[6])
			ln := Listener{Proto: base, Addr: addr, Port: port, PID: pid, Process: strings.TrimSpace(m[5])}
			k := fmt.Sprintf("%s %s %d %d", ln.Proto, ln.Addr, ln.Port, ln.PID)
			if !seen[k] {
				seen[k] = true
				out = append(out, ln)
			}
		}
	}
	if sockets == 0 {
		return c.lsofListeners(ctx, src)
	}
	sortListeners(out)
	if len(cut) > 0 {
		return Partial(out, ReasonTruncated, "output cut short: "+strings.Join(cut, ", "))
	}
	return OK(out)
}

// lsofListeners parses lsof -F output: p<pid>, c<command>, t<IPv4|IPv6>,
// P<TCP|UDP>, n<addr:port>. lsof sees only this user's processes unless
// run as root.
func (DarwinCollector) lsofListeners(ctx context.Context, src Source) Obs[[]Listener] {
	r, err := src.Run(ctx, lsofListenArgv)
	if err != nil || r.ExitCode > 1 { // 1: nothing matched
		return unknownFrom[[]Listener]("netstat showed no sockets, and lsof", cmdErr(err, r))
	}
	var out []Listener
	seen := map[string]bool{}
	pid, cmd, family, proto := 0, "", "", ""
	for _, l := range strings.Split(string(r.Stdout), "\n") {
		if l == "" {
			continue
		}
		v := l[1:]
		switch l[0] {
		case 'p':
			pid, _ = strconv.Atoi(v)
			cmd = ""
		case 'c':
			cmd = v
		case 't':
			family = v
		case 'P':
			proto = strings.ToLower(v)
		case 'n':
			if strings.Contains(v, "->") {
				continue
			}
			i := strings.LastIndexByte(v, ':')
			port, err := strconv.Atoi(v[i+1:])
			if i < 0 || err != nil {
				continue // "*:*": not bound to a port
			}
			addr := strings.Trim(v[:i], "[]")
			p := proto
			if family == "IPv6" {
				p += "6"
			}
			if addr == "*" {
				addr = "0.0.0.0"
				if family == "IPv6" {
					addr = "::"
				}
			}
			ln := Listener{Proto: p, Addr: addr, Port: port, PID: pid, Process: cmd}
			k := fmt.Sprintf("%s %s %d %d", ln.Proto, ln.Addr, ln.Port, ln.PID)
			if !seen[k] {
				seen[k] = true
				out = append(out, ln)
			}
		}
	}
	sortListeners(out)
	return Partial(out, ReasonPermission, "netstat showed no Internet sockets (macOS hides them from programs); "+
		"lsof lists only this user's processes")
}

func sortListeners(out []Listener) {
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		if a.Proto != b.Proto {
			return a.Proto < b.Proto
		}
		if a.Addr != b.Addr {
			return a.Addr < b.Addr
		}
		return a.PID < b.PID
	})
}

// Firewall is the application firewall (socketfilterfw) and pf. pf's state
// needs root; without it, extra.pf says so and the fact is partial.
func (DarwinCollector) Firewall(ctx context.Context, src Source) Obs[Firewall] {
	run := func(argv []string) (string, error) {
		r, err := src.Run(ctx, argv)
		if err != nil || r.ExitCode != 0 {
			return "", cmdErr(err, r)
		}
		return strings.TrimSpace(string(r.Stdout)), nil
	}
	state, err := run(alfStateArgv)
	if err != nil {
		return unknownFrom[Firewall]("socketfilterfw", err)
	}
	fw := Firewall{Backend: "socketfilterfw", Extra: map[string]string{}}
	fw.Enabled = strings.Contains(state, "enabled") || strings.Contains(state, "State = 1") || strings.Contains(state, "State = 2")
	blockAll := false
	if s, err := run(alfBlockAllArgv); err == nil {
		blockAll = strings.Contains(s, "enabled") && !strings.Contains(s, "disabled")
		fw.Extra["block_all"] = onOff(blockAll)
	}
	if s, err := run(alfStealthArgv); err == nil {
		fw.Extra["stealth"] = onOff(strings.Contains(s, " on") || strings.Contains(s, "enabled"))
	}
	switch {
	case !fw.Enabled:
		fw.DefaultInbound = "allow"
	case blockAll:
		fw.DefaultInbound = "block"
	default:
		fw.Extra["mode"] = "per application: signed software allowed, others asked"
	}
	// pf is noted only: enabled with no block rule it filters nothing, so it
	// does not make the host's firewall "enabled" (its rules need root).
	pf, perr := run(pfInfoArgv)
	switch {
	case perr == nil && strings.Contains(pf, "Status: Enabled"):
		fw.Extra["pf"] = "enabled (rules not read)"
	case perr == nil:
		fw.Extra["pf"] = "disabled"
	default:
		fw.Extra["pf"] = "unknown (needs root)"
	}
	return OK(fw)
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

// Protections are SIP (csrutil), Gatekeeper (spctl) and FileVault (fdesetup).
func (DarwinCollector) Protections(ctx context.Context, src Source) Obs[Protections] {
	var p Protections
	var failed, notes []string
	run := func(argv []string) (string, bool) { // each command once
		r, err := src.Run(ctx, argv)
		if err != nil || r.ExitCode != 0 {
			failed = append(failed, path.Base(argv[0]))
			return "", false
		}
		return string(r.Stdout), true
	}
	state := func(out string, ok bool, on, off, name string) string {
		low := strings.ToLower(out)
		switch {
		case !ok:
			return ""
		case strings.Contains(low, on):
			return "on"
		case strings.Contains(low, off):
			return "off"
		}
		failed = append(failed, name)
		return ""
	}
	csr, ok := run(csrutilArgv)
	if ok && strings.Contains(strings.ToLower(csr), "custom configuration") {
		// "enabled (Custom Configuration)" or "unknown (Custom Configuration)"
		// lists components; any one off is SIP partly off, so it is not "on".
		p.Integrity = "off"
		p.Extra = map[string]string{"sip": CutString(strings.Join(strings.Fields(csr), " "), 400)}
		notes = append(notes, "SIP is in a custom configuration (some protections off); see extra.sip")
	} else {
		p.Integrity = state(csr, ok, "status: enabled", "status: disabled", "csrutil")
	}
	sp, ok := run(spctlArgv)
	p.AppVerification = state(sp, ok, "assessments enabled", "assessments disabled", "spctl")
	fde, ok := run(fdesetupArgv)
	p.DiskEncryption = state(fde, ok, "filevault is on", "filevault is off", "fdesetup")
	if ok && strings.Contains(fde, "progress") {
		if p.Extra == nil {
			p.Extra = map[string]string{}
		}
		p.Extra["filevault"] = strings.TrimSpace(fde)
	}
	if len(failed) == 3 {
		return Unknown[Protections](ReasonCommandFailed, "no answer from "+strings.Join(failed, ", "))
	}
	if len(failed) > 0 {
		return Partial(p, ReasonCommandFailed, strings.Join(append(notes, "no answer from "+strings.Join(failed, ", ")), "; "))
	}
	return Obs[Protections]{Status: StatusOK, Detail: strings.Join(notes, "; "), Value: p}
}

// xprotectBundles: the copy XProtect updates itself (macOS 15 and later),
// then the one in the system volume.
var xprotectBundles = []string{
	"/private/var/protected/xprotect/XProtect.bundle/Contents/Info.plist",
	"/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist",
}

// XProtect is macOS's built-in malware scanner; it checks software when it
// first runs. Its age is that of the newest signature bundle.
func (DarwinCollector) XProtect(src Source, now time.Time) Obs[Antimalware] {
	var newest time.Time
	version := ""
	var lastErr error
	for _, p := range xprotectBundles {
		st, err := Stat(src, p)
		if err != nil {
			lastErr = err
			continue
		}
		if st.ModTime.After(newest) {
			newest = st.ModTime
			if b, err := src.ReadFile(p); err == nil {
				if v, err := ParsePlist(b); err == nil {
					d, _ := v.(map[string]any)
					version = PlistString(d, "CFBundleShortVersionString")
				}
			}
		}
	}
	if newest.IsZero() {
		return unknownFrom[Antimalware]("XProtect", lastErr)
	}
	// RealTime is assumed, not read: XProtect checks software when it first
	// runs and macOS has no switch to turn that off.
	a := Antimalware{Product: "XProtect", RealTime: true}
	if version != "" {
		a.Product += " " + version
	}
	if !now.IsZero() && now.After(newest) {
		a.SignatureAgeDays = int(now.Sub(newest).Hours() / 24)
	}
	return Obs[Antimalware]{Status: StatusOK, Detail: "real_time assumed: macOS gives no switch to turn XProtect off", Value: a}
}

// launchJob is one launchd property list outside /System.
type launchJob struct {
	path, label, program string
	exe                  string // Program, or ProgramArguments[0]: a path may hold spaces
	userName             string // UserName: whom a daemon runs as ("" root)
	scope                string // daemon, agent, user agent
	uid                  string // a user agent's owner, whose launchctl overrides apply
	runAtLoad, disabled  bool
	keepAlive            bool
}

// launchDirs are the launchd folders an administrator or installer writes;
// /System/Library is Apple's and sealed, so it is not reported.
var launchDirs = []struct{ dir, scope string }{
	{"/Library/LaunchDaemons", "daemon"},
	{"/Library/LaunchAgents", "agent"},
}

// Services are the launchd jobs outside /System: every account's
// ~/Library/LaunchAgents too. A job that runs at load or is kept alive
// starts "auto"; Disabled is "disabled"; the rest start on demand.
func (DarwinCollector) Services(src Source, accounts Obs[[]Account]) (Obs[[]Service], []launchJob) {
	type launchDir struct{ dir, scope, home, uid string }
	var dirs []launchDir
	for _, d := range launchDirs {
		dirs = append(dirs, launchDir{d.dir, d.scope, "", ""})
	}
	var jobs []launchJob
	var unread []string
	reason := Reason("")
	if !accounts.Known() { // dscl failed: whose homes to look in is not known
		unread = append(unread, "user LaunchAgents not read (accounts unknown: "+accounts.Detail+")")
		reason = accounts.Reason
	}
	for _, a := range accounts.Value { // every login account's agents, wherever its home is (root's /var/root too)
		switch {
		case !a.CanLogin:
		case strings.HasPrefix(a.Home, "/") && a.Home != "/":
			dirs = append(dirs, launchDir{strings.TrimSuffix(a.Home, "/") + "/Library/LaunchAgents", "user agent", strings.TrimSuffix(a.Home, "/"), a.UID})
		default:
			unread = append(unread, a.Name+"'s LaunchAgents not read (home unknown)")
		}
	}
	for _, d := range dirs {
		if d.home != "" { // a person's folder: never follow a link out of it, at any level below the home
			if l := linkBelow(src, d.home, d.dir); l != "" {
				unread = append(unread, d.dir+" (symlink_not_followed: "+l+")")
				continue
			}
		}
		names, err := src.ReadDir(d.dir)
		if err != nil {
			if !missing(err) {
				unread = append(unread, d.dir+" ("+string(Classify(err))+")")
				if reason == "" {
					reason = Classify(err)
				}
			}
			continue
		}
		sort.Strings(names)
		for _, n := range names {
			if !strings.HasSuffix(n, ".plist") {
				continue
			}
			p := d.dir + "/" + n
			j := launchJob{path: p, scope: d.scope, uid: d.uid, label: strings.TrimSuffix(n, ".plist")}
			b, err := ReadFileNoFollow(src, p)
			if err != nil {
				if !errors.Is(err, fs.ErrNotExist) {
					unread = append(unread, p+" ("+string(Classify(err))+")")
				}
				continue
			}
			if v, err := ParsePlist(b); err == nil {
				m, _ := v.(map[string]any)
				if l := PlistString(m, "Label"); l != "" {
					j.label = l
				}
				j.exe, j.userName = launchExe(m), PlistString(m, "UserName")
				if launchArgsOdd(m) {
					unread = append(unread, p+" (ProgramArguments holds non-string items)")
				}
				var cut bool
				if j.program, cut = launchProgram(m); cut {
					unread = append(unread, p+" (ProgramArguments cut at "+strconv.Itoa(maxLaunchArgs)+" arguments, "+strconv.Itoa(MaxCmdline)+" bytes)")
				}
				j.runAtLoad, _ = m["RunAtLoad"].(bool)
				j.disabled, _ = m["Disabled"].(bool)
				switch k := m["KeepAlive"].(type) {
				case bool:
					j.keepAlive = k
				case map[string]any:
					j.keepAlive = true // kept alive under conditions
				}
			} else {
				unread = append(unread, p+" (unparsable)")
			}
			jobs = append(jobs, j)
		}
	}
	// launchctl enable/disable keeps its choice apart from the plist: the
	// system domain's in disabled.plist (daemons), each user's in
	// disabled.<uid>.plist (that user's agents). A job turned off there
	// still has its plist's Disabled; a file that cannot be read is said.
	// An overrides file that cannot be read or parsed leaves the job's state
	// unknown: it is then never taken as disabled (launchctl may have turned
	// it on), and the file is listed in unread.
	type overrideSet struct {
		m     map[string]bool
		known bool
	}
	readOverrides := func(p string) overrideSet {
		b, err := src.ReadFile(p)
		if err != nil {
			if missing(err) {
				return overrideSet{known: true} // none set
			}
			unread = append(unread, p+" ("+string(Classify(err))+"): jobs turned on or off with launchctl are not known")
			return overrideSet{}
		}
		v, err := ParsePlist(b)
		if err != nil {
			unread = append(unread, p+" (unparsable)")
			return overrideSet{}
		}
		o := overrideSet{m: map[string]bool{}, known: true}
		m, _ := v.(map[string]any)
		for label, d := range m {
			if off, ok := d.(bool); ok {
				o.m[label] = off
			}
		}
		return o
	}
	// apply is a job's state under one domain's overrides: off or on.
	apply := func(o overrideSet, label string, plistOff bool) bool {
		if !o.known {
			return false
		}
		if off, ok := o.m[label]; ok {
			return off
		}
		return plistOff
	}
	system := readOverrides(launchOverrides)
	perUser := map[string]overrideSet{}
	userOv := func(uid string) overrideSet {
		o, ok := perUser[uid]
		if !ok {
			o = readOverrides(userOverrides(uid))
			perUser[uid] = o
		}
		return o
	}
	var loginUIDs []string // a global agent runs in each of their sessions
	for _, a := range accounts.Value {
		if a.CanLogin && a.UID != "" {
			loginUIDs = append(loginUIDs, a.UID)
		}
	}
	globalUnknown := false
	for i := range jobs {
		j := &jobs[i]
		switch {
		case j.scope == "daemon":
			j.disabled = apply(system, j.label, j.disabled)
		case j.uid != "": // a user agent: its owner's domain; never the system's
			j.disabled = apply(userOv(j.uid), j.label, j.disabled)
		case !accounts.Known(): // whose sessions run it is not known: never taken as off
			j.disabled, globalUnknown = false, true
		case len(loginUIDs) > 0: // a global agent: off only when off for every login account
			anyOn := false
			for _, uid := range loginUIDs {
				anyOn = anyOn || !apply(userOv(uid), j.label, j.disabled)
			}
			j.disabled = !anyOn
		}
	}
	if globalUnknown {
		unread = append(unread, "global agents' per-user overrides not checked (accounts unknown)")
	}
	var svcs []Service
	for _, j := range jobs {
		s := Service{Name: j.label, Exe: j.exe, StartMode: "manual"}
		switch {
		case j.disabled:
			s.StartMode = "disabled"
		case j.runAtLoad || j.keepAlive:
			s.StartMode = "auto"
		}
		if j.scope == "daemon" {
			s.RunAs = "root"
			if j.userName != "" {
				s.RunAs = j.userName
			}
		}
		svcs = append(svcs, s)
	}
	if len(unread) > 0 {
		if reason == "" {
			reason = ReasonPermission
		}
		return Partial(svcs, reason, "not fully read: "+strings.Join(unread, ", ")), jobs
	}
	return OK(svcs), jobs
}

// linkBelow is the first folder from below home down to dir that is a
// symbolic link ("" none): ~/Library or ~/Library/LaunchAgents pointing
// elsewhere would make a person's folder show another's files.
func linkBelow(src Source, home, dir string) string {
	rest, ok := strings.CutPrefix(dir, home+"/")
	if !ok {
		return ""
	}
	p := home
	for _, part := range strings.Split(rest, "/") {
		p += "/" + part
		if _, err := src.Readlink(p); err == nil {
			return p
		}
	}
	return ""
}

// maxLaunchArgs caps the ProgramArguments of a launchd job that are kept.
const maxLaunchArgs = 64

// launchProgram is the command a launchd job runs: Program, or its
// ProgramArguments joined, at most maxLaunchArgs arguments and MaxCmdline
// bytes; cut says some were left out. A plist can repeat one long string
// thousands of times by reference, so nothing is joined past the cap.
func launchProgram(m map[string]any) (prog string, cut bool) {
	program := PlistString(m, "Program")
	if len(program) > MaxCmdline {
		program, cut = CutString(program, MaxCmdline), true
	}
	args, _ := m["ProgramArguments"].([]any)
	var s []string
	size := len(program)
	for _, a := range args {
		t, ok := a.(string)
		if !ok {
			continue // launchd refuses such a job; launchArgsOdd says so
		}
		if len(s) == maxLaunchArgs || size+1+len(t) > MaxCmdline {
			if room := MaxCmdline - size - 1; len(s) < maxLaunchArgs && room > 0 {
				s = append(s, CutString(t, room))
			}
			cut = true
			break
		}
		s = append(s, t)
		size += 1 + len(t)
	}
	prog = program
	if prog == "" && len(s) > 0 {
		prog = s[0]
	}
	if len(s) > 1 {
		prog = strings.Join(s, " ")
		if program != "" && program != s[0] {
			prog = program + " " + strings.Join(s[1:], " ")
		}
	}
	return prog, cut
}

// launchOverrides is where launchctl enable/disable records its choice for
// the system domain's jobs, the daemons (label: true when turned off);
// userOverrides the file for one user's domain, that user's agents.
const launchOverrides = "/var/db/com.apple.xpc.launchd/disabled.plist"

func userOverrides(uid string) string {
	return "/var/db/com.apple.xpc.launchd/disabled." + uid + ".plist"
}

// launchArgsOdd says ProgramArguments holds something other than strings,
// which launchd does not run: what the job would do is not known.
func launchArgsOdd(m map[string]any) bool {
	args, ok := m["ProgramArguments"]
	if !ok {
		return false
	}
	list, ok := args.([]any)
	if !ok {
		return true
	}
	for _, a := range list {
		if _, ok := a.(string); !ok {
			return true
		}
	}
	return false
}

// launchExe is the executable of a launchd job: Program, or the first of
// ProgramArguments, whole (a path may hold spaces).
func launchExe(m map[string]any) string {
	if p := PlistString(m, "Program"); p != "" {
		return CutString(p, MaxCmdline)
	}
	if args, ok := m["ProgramArguments"].([]any); ok && len(args) > 0 {
		if s, ok := args[0].(string); ok {
			return CutString(s, MaxCmdline)
		}
	}
	return ""
}

// periodicLines are the lines of a file periodic(8) sources or runs as root
// (periodic.conf, daily.local): every line but blanks and plain comments, as
// written. Shell is not simulated: a comment counts as plain only when it
// starts with "#", holds no quote, $ or backtick, and the line before does
// not end in a backslash; everything else, plain assignments included, is
// listed.
func periodicLines(b []byte) []string {
	var out []string
	prevGoesOn := false
	for _, raw := range strings.Split(string(b), "\n") {
		// Only space and tab are blanks to the shell: \r, \v, \f or a
		// non-ASCII space before "#" make it no comment, so such a line,
		// and a blank-looking one holding them, is listed as written.
		l := strings.TrimLeft(raw, " \t")
		// In an unquoted heredoc a "#" line is data, and $( ) and backticks
		// in it run: a comment holding a quote, $ or backtick is listed.
		plainComment := strings.HasPrefix(l, "#") && !strings.ContainsAny(l, "\"'$`") && plainASCII(l) && !prevGoesOn
		prevGoesOn = strings.HasSuffix(raw, "\\")
		if l == "" && !prevGoesOn || plainComment {
			continue
		}
		out = append(out, strings.TrimRight(l, " \t"))
	}
	return out
}

// plainASCII says s holds only printable ASCII and tabs.
func plainASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < 0x20 && c != '\t') || c > 0x7e {
			return false
		}
	}
	return true
}

// ParsePeriodicConf is periodicLines for a periodic.conf.
func ParsePeriodicConf(b []byte) []string { return periodicLines(b) }

// stockPeriodicDefaults are the sha256 of the stock /etc/defaults/periodic.conf,
// its bytes exactly as published (LF line ends), from Apple's open source crontabs project
// (github.com/apple-oss-distributions/crontabs, files/periodic.conf):
// tags crontabs-63 to 64.60.1, 59.140.1, 52.80.1 to 59, 46.1 to 52. macOS 27
// has no such file.
var stockPeriodicDefaults = map[string]bool{
	"bab867ca902516f84c2b982be91209df3e559d78fcedafc7fe0aa9135f86ce68": true,
	"0ed01ee9b592cbe236f7cf697e0699fba2ebf16b771ded229a84546a798ab5f1": true,
	"ee479a7a0dd839c4a08e73d5a6fcffbe750bd47b82cf7c633ed20c5e63b8ed03": true,
	"16abe95b825a404a87e4b9ee31a45c59ec0143fa30483aa06854cfd70796727b": true,
}

// stockDefaults says b is a stock /etc/defaults/periodic.conf, whole.
func stockDefaults(b []byte) bool {
	sum := sha256.Sum256(b) // the bytes as read: a \r or any other change is not stock
	return stockPeriodicDefaults[hex.EncodeToString(sum[:])]
}

// localPeriodicDirs are the folders a local_periodic= line names.
func localPeriodicDirs(l string) []string { return assignedPaths(l, "local_periodic") }

// assignedPaths are the paths a "name=…" or "export name=…" line sets.
func assignedPaths(l, name string) []string {
	l = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(l), "export "))
	v, ok := strings.CutPrefix(l, name+"=")
	if !ok {
		return nil
	}
	return strings.Fields(strings.Trim(v, `"'`))
}

// periodicDirs hold scripts periodic(8) runs daily, weekly and monthly.
var periodicDirs = []string{"/etc/periodic/daily", "/etc/periodic/weekly", "/etc/periodic/monthly",
	"/usr/local/etc/periodic/daily", "/usr/local/etc/periodic/weekly", "/usr/local/etc/periodic/monthly"}

// persistence: launchd jobs, cron (the user crontabs need root), periodic
// scripts and periodic.conf, at jobs, security agent plugins, startup
// items, login and logout hooks, sudo rules and authorized keys. Login items
// live in the Background Task Management store, which Shentu does not parse
// (as root either): they are always listed as not read.
func (c DarwinCollector) persistence(src Source, jobs []launchJob, svcs Obs[[]Service], keys Obs[[]AuthorizedKeyFile]) Obs[[]PersistenceItem] {
	var out []PersistenceItem
	denied := []string{"login items (the Background Task Management store is not parsed)"}
	var notes []string // what was read and left out on purpose
	if svcs.Status == StatusPartial || !svcs.Known() {
		denied = append(denied, "launchd: "+svcs.Detail)
	}
	for _, j := range jobs {
		d := j.scope + " in " + path.Dir(j.path)
		switch {
		case j.disabled:
			d += "; disabled"
		case j.runAtLoad && j.keepAlive:
			d += "; runs at load, kept alive"
		case j.runAtLoad:
			d += "; runs at load"
		case j.keepAlive:
			d += "; kept alive"
		}
		out = append(out, PersistenceItem{Kind: "launchd", Location: j.path, Command: MaskSecrets(j.program), Detail: d})
	}
	cron := func(p string) {
		b, err := src.ReadFile(p)
		if err != nil {
			if !missing(err) {
				denied = append(denied, p)
			}
			return
		}
		for _, cmd := range ParseCron(b) {
			out = append(out, PersistenceItem{Kind: "cron", Location: p, Command: MaskSecrets(cmd)})
		}
	}
	cron("/etc/crontab")
	if names, err := src.ReadDir("/usr/lib/cron/tabs"); err == nil {
		sort.Strings(names)
		for _, n := range names {
			cron("/usr/lib/cron/tabs/" + n)
		}
	} else if !missing(err) {
		denied = append(denied, "/usr/lib/cron/tabs (user crontabs)")
	}
	for _, dir := range periodicDirs {
		names, err := src.ReadDir(dir)
		if err != nil {
			if !missing(err) {
				denied = append(denied, dir)
			}
			continue
		}
		sort.Strings(names)
		for _, n := range names {
			out = append(out, PersistenceItem{Kind: "cron", Location: dir + "/" + n, Detail: "periodic script, run " + path.Base(dir)})
		}
	}
	// periodic.conf is sourced by periodic(8) as root: every line is listed
	// (periodicLines). The stock defaults file, whole, is not: it is the same
	// on every Mac of a release; changed in any way, it is listed whole.
	var localPeriodic []string // folders local_periodic adds; their daily/weekly/monthly scripts run
	// periodic_conf_files names the files sourced after the defaults: the
	// usual two, and any other it is pointed at, read the same way.
	confFiles := []string{"/etc/defaults/periodic.conf", "/etc/periodic.conf", "/etc/periodic.conf.local"}
	for i := 0; i < len(confFiles) && i < 16; i++ {
		f := confFiles[i]
		b, err := src.ReadFile(f)
		if err != nil {
			if !missing(err) {
				denied = append(denied, f+" ("+string(Classify(err))+")")
			}
			continue
		}
		stock := f == "/etc/defaults/periodic.conf" && stockDefaults(b)
		if stock {
			notes = append(notes, f+": stock defaults")
		}
		for _, v := range periodicLines(b) {
			if !stock {
				out = append(out, PersistenceItem{Kind: "periodic_conf", Location: f, Command: MaskSecrets(v)})
			}
			localPeriodic = append(localPeriodic, localPeriodicDirs(v)...)
			for _, extra := range assignedPaths(v, "periodic_conf_files") {
				if strings.HasPrefix(extra, "/") && !slices.Contains(confFiles, path.Clean(extra)) {
					confFiles = append(confFiles, path.Clean(extra))
				}
			}
		}
	}
	for _, base := range localPeriodic {
		if !strings.HasPrefix(base, "/") || slices.Contains([]string{"/usr/local/etc/periodic", "/etc/periodic"}, path.Clean(base)) {
			continue // relative, or already read above
		}
		for _, iv := range []string{"daily", "weekly", "monthly"} {
			dir := path.Clean(base) + "/" + iv
			names, err := src.ReadDir(dir)
			if err != nil {
				if !missing(err) {
					denied = append(denied, dir+" ("+string(Classify(err))+")")
				}
				continue
			}
			sort.Strings(names)
			for _, n := range names {
				out = append(out, PersistenceItem{Kind: "cron", Location: dir + "/" + n, Detail: "periodic script (local_periodic), run " + iv})
			}
		}
	}
	for _, f := range []string{"/etc/daily.local", "/etc/weekly.local", "/etc/monthly.local"} { // run by periodic(8) as root
		if b, err := src.ReadFile(f); err == nil {
			for _, l := range periodicLines(b) { // a shell script, run as root
				out = append(out, PersistenceItem{Kind: "periodic_conf", Location: f, Command: MaskSecrets(l), Detail: "local periodic script, run " + strings.TrimSuffix(path.Base(f), ".local")})
			}
		} else if !missing(err) {
			denied = append(denied, f+" ("+string(Classify(err))+")")
		}
	}
	listDir := func(dir, kind, detail string, keep func(string) bool) {
		names, err := src.ReadDir(dir)
		if err != nil {
			if !missing(err) {
				denied = append(denied, dir+" ("+string(Classify(err))+")")
			}
			return
		}
		sort.Strings(names)
		for _, n := range names {
			if keep(n) {
				out = append(out, PersistenceItem{Kind: kind, Location: dir + "/" + n, Detail: detail})
			}
		}
	}
	notHidden := func(n string) bool { return !strings.HasPrefix(n, ".") }
	listDir("/usr/lib/cron/jobs", "at_job", "at(1) job", notHidden) // root only
	listDir("/Library/Security/SecurityAgentPlugins", "security_agent_plugin", "loaded by the login window's authorization", func(n string) bool { return strings.HasSuffix(n, ".bundle") })
	listDir("/Library/StartupItems", "startup_item", "legacy startup item, run at boot", notHidden)
	for _, f := range []string{"/Library/Preferences/com.apple.loginwindow.plist", "/var/root/Library/Preferences/com.apple.loginwindow.plist"} {
		b, err := src.ReadFile(f)
		if err != nil {
			if !missing(err) {
				denied = append(denied, f+" ("+string(Classify(err))+")")
			}
			continue
		}
		v, err := ParsePlist(b)
		if err != nil {
			denied = append(denied, f+" (unparsable)")
			continue
		}
		m, _ := v.(map[string]any)
		for _, k := range []string{"LoginHook", "LogoutHook"} {
			if cmd := PlistString(m, k); cmd != "" {
				out = append(out, PersistenceItem{Kind: "login_hook", Location: f, Command: MaskSecrets(cmd), Detail: k + ", run as root"})
			}
		}
	}
	rules, rs := LinuxCollector{}.SudoRules(src)
	for _, r := range rules {
		loc, cmd, _ := strings.Cut(r, ": ")
		out = append(out, PersistenceItem{Kind: "sudo_rule", Location: loc, Command: cmd})
	}
	if rs.Status == StatusPartial {
		denied = append(denied, rs.Detail)
	}
	out = append(out, authorizedKeyItems(keys.Value)...)
	if keys.Status == StatusPartial || !keys.Known() {
		denied = append(denied, "authorized_keys: "+keys.Detail)
	}
	detail := "not fully read: " + strings.Join(denied, ", ")
	if len(notes) > 0 {
		detail += "; " + strings.Join(notes, "; ")
	}
	return Partial(out, ReasonPermission, detail)
}
