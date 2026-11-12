package hostenv

// The Linux collector. The file name avoids the _linux suffix on purpose:
// it only talks to a Source, so it builds and replays everywhere.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"strconv"
	"strings"
	"time"
)

// LinuxCollector gathers hostfacts on Linux from /proc, /etc and the package
// database. It runs two commands at most (dpkg-query or rpm), both read-only.
type LinuxCollector struct{}

func (LinuxCollector) Name() string { return "linux" }

var (
	dpkgArgv = []string{"/usr/bin/dpkg-query", "-W", "-f", DpkgQueryFormat}
	rpmArgv  = []string{"/usr/bin/rpm", "-qa", "--qf", RpmQueryFormat}
)

func (LinuxCollector) Allowlist() [][]string { return [][]string{dpkgArgv, rpmArgv} }

func (c LinuxCollector) Collect(ctx context.Context, src Source) *Facts {
	info := src.Info()
	f := NewFacts(c.Name(), CollectorVersion, info.RecordedAt)
	f.Privilege = OK(Privilege{Elevated: info.Elevated})
	f.Resources = c.Resources(src)

	var osr map[string]string
	f.Platform, osr = c.Platform(src)
	f.Packages = c.packages(ctx, src, osr)
	pw, accounts := c.Accounts(src)
	f.Accounts = accounts
	procs, sockOwner := c.Processes(src, pw)
	f.Processes = procs
	f.Listeners = c.Listeners(src, sockOwner)
	if procs.Known() { // name each listener's process, so checks need no join
		names := map[int]string{}
		for _, p := range procs.Value {
			names[p.PID] = p.Name
		}
		for i := range f.Listeners.Value {
			f.Listeners.Value[i].Process = names[f.Listeners.Value[i].PID]
		}
	}
	f.RemoteAccess.SSH = c.ssh(src)
	f.Persistence = c.persistence(src, accounts)

	f.Patches = NotApplicable[[]Patch]() // Linux patches are package versions
	f.RemoteAccess.RDP = NotApplicable[RDPConfig]()
	f.RemoteAccess.WinRM = NotApplicable[WinRMConfig]()
	f.RemoteAccess.SMB = Unknown[SMBConfig](ReasonNotCollected, "samba not collected yet")
	f.Antimalware = NotApplicable[Antimalware]() // no built-in AV on Linux; ClamAV et al. come later as packages
	// Services, Firewall, AuthEvents and Web stay not_collected until the
	// tools/ logic moves here (Phase 1c, after v0.2.5 reaches main).
	return f
}

// Platform gathers the platform fact on its own, and returns the parsed
// os-release (nil when unreadable) for callers that need other keys.
func (LinuxCollector) Platform(src Source) (Obs[Platform], map[string]string) {
	p := Platform{OS: "linux", Arch: src.Info().GOARCH}
	b, err := src.ReadFile("/etc/os-release")
	if errors.Is(err, fs.ErrNotExist) {
		b, err = src.ReadFile("/usr/lib/os-release")
	}
	var osr map[string]string
	if err == nil {
		osr = ParseOSRelease(b)
		p.Distro, p.Version, p.PrettyName = osr["ID"], osr["VERSION_ID"], osr["PRETTY_NAME"]
		p.Family = LinuxFamily(osr["ID"], osr["ID_LIKE"])
	}
	if k, kerr := src.ReadFile("/proc/sys/kernel/osrelease"); kerr == nil {
		p.Kernel = strings.TrimSpace(string(k))
	}
	p.InContainer = inContainer(src)
	if err != nil {
		return Obs[Platform]{Status: StatusPartial, Reason: Classify(err), Detail: "os-release: " + err.Error(), Value: p}, nil
	}
	return OK(p), osr
}

func inContainer(src Source) bool {
	for _, marker := range []string{"/.dockerenv", "/run/.containerenv"} {
		if _, err := src.ReadFile(marker); err == nil {
			return true
		}
	}
	b, err := src.ReadFile("/proc/1/cgroup")
	if err != nil {
		return false
	}
	s := string(b)
	return strings.Contains(s, "docker") || strings.Contains(s, "kubepods") || strings.Contains(s, "containerd") || strings.Contains(s, "/lxc/")
}

func (LinuxCollector) packages(ctx context.Context, src Source, osr map[string]string) Obs[PackageSet] {
	if osr == nil {
		return Unknown[PackageSet](ReasonNotCollected, "no os-release, distribution unknown")
	}
	set := PackageSet{Ecosystem: OSVEcosystem(osr)}
	var items []Package
	var err error
	var res CmdResult
	switch LinuxFamily(osr["ID"], osr["ID_LIKE"]) {
	case "debian":
		set.Manager = "dpkg"
		if res, err = src.Run(ctx, dpkgArgv); err == nil && res.ExitCode == 0 {
			items = ParseDpkgQuery(res.Stdout)
		}
	case "rhel", "suse":
		set.Manager = "rpm"
		if res, err = src.Run(ctx, rpmArgv); err == nil && res.ExitCode == 0 {
			items = ParseRpmQA(res.Stdout)
		}
	case "alpine":
		set.Manager = "apk"
		var b []byte
		if b, err = src.ReadFile("/lib/apk/db/installed"); err == nil {
			items = ParseApkInstalled(b)
		}
	default:
		return Unknown[PackageSet](ReasonUnsupported, "package manager for "+osr["ID"]+" not supported yet")
	}
	switch {
	case err != nil:
		return unknownFrom[PackageSet](set.Manager, err)
	case res.ExitCode != 0:
		return Unknown[PackageSet](ReasonCommandFailed, fmt.Sprintf("%s exit %d: %s", set.Manager, res.ExitCode, firstLine(res.Stderr)))
	}
	set.Items = items
	return OK(set)
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(strings.TrimSpace(s), "\n")
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// Accounts reads /etc/passwd and /etc/group. names maps uid to the first
// account with it, so a backdoor that reuses UID 0 is not shown as the
// owner of root's processes and files.
func (LinuxCollector) Accounts(src Source) (names map[string]string, accounts Obs[[]Account]) {
	b, err := src.ReadFile("/etc/passwd")
	if err != nil {
		return nil, unknownFrom[[]Account]("/etc/passwd", err)
	}
	admins := map[string]bool{}
	gb, gerr := src.ReadFile("/etc/group")
	if gerr == nil {
		groups := ParseGroup(gb)
		for _, g := range AdminGroups {
			for _, u := range groups[g] {
				admins[u] = true
			}
		}
	}
	names = map[string]string{}
	var out []Account
	for _, e := range ParsePasswd(b) {
		if _, dup := names[e.UID]; !dup {
			names[e.UID] = e.Name
		}
		out = append(out, Account{Name: e.Name, UID: e.UID, Home: e.Home, Shell: e.Shell,
			CanLogin: CanLoginShell(e.Shell), IsAdmin: e.UID == "0" || admins[e.Name]})
	}
	if gerr != nil {
		return names, Partial(out, Classify(gerr), "/etc/group unreadable: admin group members unknown")
	}
	return names, OK(out)
}

func numeric(s string) bool {
	_, err := strconv.Atoi(s)
	return err == nil
}

// Processes walks /proc once and also returns socket inode -> pid for
// Listeners, so the walk is not repeated. users maps uid to name (nil: none).
func (LinuxCollector) Processes(src Source, users map[string]string) (Obs[[]Process], map[string]int) {
	owners := map[string]int{}
	names, err := src.ReadDir("/proc")
	if err != nil {
		return unknownFrom[[]Process]("/proc", err), owners
	}
	var out []Process
	hidden := 0
	for _, n := range names {
		if !numeric(n) {
			continue
		}
		pid, _ := strconv.Atoi(n)
		dir := "/proc/" + n
		sb, err := src.ReadFile(dir + "/status")
		if err != nil {
			continue // exited while we looked
		}
		st := ParseProcStatus(sb)
		p := Process{PID: pid, PPID: st.PPID, Name: st.Name, UID: st.UID, User: users[st.UID]}
		if cb, err := src.ReadFile(dir + "/comm"); err == nil {
			p.Name = strings.TrimSpace(string(cb)) // raw, as ps shows it; status escapes some bytes
		}
		if cb, err := src.ReadFile(dir + "/cmdline"); err == nil {
			p.Cmdline = ParseCmdline(cb)
		}
		if st, err := Stat(src, dir); err == nil {
			p.Started = st.ModTime.Format(time.RFC3339)
		}
		if sb, err := src.ReadFile(dir + "/stat"); err == nil {
			p.StartTicks, _ = ParseProcStartTicks(sb)
		}
		exe, err := src.Readlink(dir + "/exe")
		switch {
		case err == nil:
			p.ExeKnown, p.ExeExists = true, true
			if t, ok := strings.CutSuffix(exe, " (deleted)"); ok {
				exe, p.ExeExists = t, false
			}
			p.Exe, p.InTemp = exe, InTempDir(exe)
		case errors.Is(err, fs.ErrPermission):
			hidden++
		}
		// ENOENT on exe is a kernel thread: nothing to know.
		if fds, err := src.ReadDir(dir + "/fd"); err == nil {
			for _, fd := range fds {
				if t, err := src.Readlink(dir + "/fd/" + fd); err == nil && strings.HasPrefix(t, "socket:[") {
					owners[strings.TrimSuffix(strings.TrimPrefix(t, "socket:["), "]")] = pid
				}
			}
		}
		out = append(out, p)
	}
	if hidden > 0 { // even as root: hidepid, an LSM or a rootkit can hide them
		return Partial(out, ReasonPermission, fmt.Sprintf("%d processes' executables unreadable", hidden)), owners
	}
	return OK(out), owners
}

// Listeners reads /proc/net/{tcp,tcp6,udp,udp6}: TCP sockets in LISTEN and
// bound UDP sockets, one per proto/address/port, in table order. owners
// maps socket inode to pid (from Processes).
func (LinuxCollector) Listeners(src Source, owners map[string]int) Obs[[]Listener] {
	var out []Listener
	var firstErr error
	read, unowned := 0, 0
	seen := map[string]bool{}
	for _, proto := range []string{"tcp", "tcp6", "udp", "udp6"} {
		b, err := src.ReadFile("/proc/net/" + proto)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) && firstErr == nil { // no IPv6 is fine
				firstErr = err
			}
			continue
		}
		read++
		for _, e := range ParseProcNet(b) {
			if !e.IsListening(proto) {
				continue
			}
			l := Listener{Proto: proto, Addr: e.LocalIP.String(), Port: e.LocalPort, UID: e.UID}
			if pid, ok := owners[e.Inode]; ok {
				l.PID = pid
			} else if e.Inode != "0" {
				unowned++
			}
			// SO_REUSEPORT gives one row per socket: collapse rows of the
			// same owner, but keep a second process (or user) on the same
			// port visible, which is how a port gets hijacked.
			key := fmt.Sprintf("%s/%s/%d/%d/%s", proto, l.Addr, l.Port, l.PID, l.UID)
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, l)
		}
	}
	switch {
	case read == 0 && firstErr != nil:
		return unknownFrom[[]Listener]("/proc/net", firstErr)
	case read == 0:
		return Unknown[[]Listener](ReasonNotInstalled, "/proc/net tables missing")
	case unowned > 0 && !src.Info().Elevated:
		return Partial(out, ReasonPermission, fmt.Sprintf("owner of %d sockets not visible without root", unowned))
		// As root an ownerless socket belongs to the kernel (NFS, WireGuard):
		// PID stays 0, which checks read as "kernel", not as hidden.
	}
	return OK(out)
}

const sshdConfig = "/etc/ssh/sshd_config"

func (LinuxCollector) ssh(src Source) Obs[SSHConfig] {
	if _, err := src.ReadFile(sshdConfig); errors.Is(err, fs.ErrNotExist) {
		if names, derr := src.ReadDir("/usr/sbin"); derr == nil && !contains(names, "sshd") {
			return NotApplicable[SSHConfig]()
		}
	}
	cfg := SSHConfig{ConfigPath: sshdConfig, Settings: SSHDDefaults()}
	got := map[string]bool{}
	h := sha256.New()
	unknown := func(p string) {
		cfg.Unread = append(cfg.Unread, p)
		for k := range cfg.Settings {
			if !got[k] {
				cfg.Settings[k], got[k] = "unknown", true
			}
		}
	}
	var read func(p string, depth int) bool // false: stopped at Match
	read = func(p string, depth int) bool {
		if depth > 4 {
			return true
		}
		b, err := src.ReadFile(p)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				unknown(p)
			}
			return true
		}
		h.Write(b)
		dirs, sawMatch := ParseSSHDConfig(b)
		for _, d := range dirs {
			if d.Key == "include" {
				pat := d.Value
				if !strings.HasPrefix(pat, "/") {
					pat = path.Join(path.Dir(sshdConfig), pat)
				}
				dir, base := path.Split(pat)
				names, err := src.ReadDir(path.Clean(dir))
				if err != nil {
					if !errors.Is(err, fs.ErrNotExist) {
						unknown(path.Clean(dir))
					}
					continue
				}
				for _, n := range names { // already sorted, as sshd's glob is
					if ok, _ := path.Match(base, n); ok && !read(path.Join(dir, n), depth+1) {
						return false
					}
				}
				continue
			}
			if _, want := cfg.Settings[d.Key]; want && !got[d.Key] {
				cfg.Settings[d.Key], got[d.Key] = d.Value, true
			}
		}
		return !sawMatch
	}
	read(sshdConfig, 0)
	cfg.Hash = hex.EncodeToString(h.Sum(nil))[:16]
	if len(cfg.Unread) > 0 {
		return Partial(cfg, ReasonPermission, "some sshd config files unreadable; their settings are \"unknown\"")
	}
	return OK(cfg)
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// MaxPersistenceItems caps one category so a huge crontab cannot flood facts.
const MaxPersistenceItems = 500

func (LinuxCollector) persistence(src Source, accounts Obs[[]Account]) Obs[[]PersistenceItem] {
	var out []PersistenceItem
	var denied []string
	// note records every failure except "does not exist": a truncated,
	// unreadable or odd file is a place we could not fully look.
	note := func(p string, err error) {
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			denied = append(denied, p+" ("+string(Classify(err))+")")
		}
	}
	perKind := map[string]int{}
	dropped := 0
	add := func(it PersistenceItem) {
		if perKind[it.Kind] >= MaxPersistenceItems {
			dropped++
			return
		}
		perKind[it.Kind]++
		out = append(out, it)
	}
	// read returns what could be read; a truncated file is still parsed.
	read := func(p string) ([]byte, bool) {
		b, err := src.ReadFile(p)
		note(p, err)
		return b, err == nil || errors.Is(err, ErrTruncated)
	}
	cronFile := func(p string) {
		b, ok := read(p)
		if !ok {
			return
		}
		for _, cmd := range ParseCron(b) {
			add(PersistenceItem{Kind: "cron", Location: p, Command: MaskSecrets(cmd)})
		}
	}
	cronDir := func(dir string, skip ...string) {
		names, err := src.ReadDir(dir)
		if err != nil {
			note(dir, err)
			return
		}
		for _, n := range names {
			if !contains(skip, n) && !strings.HasPrefix(n, ".") {
				cronFile(dir + "/" + n)
			}
		}
	}
	cronFile("/etc/crontab")
	cronDir("/etc/cron.d")
	cronDir("/var/spool/cron", "crontabs", "atjobs", "atspool", "lastrun")
	cronDir("/var/spool/cron/crontabs")

	if b, ok := read("/etc/ld.so.preload"); ok {
		for _, l := range strings.Split(string(b), "\n") {
			if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
				add(PersistenceItem{Kind: "ld_preload", Location: "/etc/ld.so.preload", Command: l})
			}
		}
	}

	if b, ok := read("/etc/rc.local"); ok {
		for _, l := range ParseCron(b) { // same shape: non-comment lines
			if !strings.HasPrefix(l, "exit") {
				add(PersistenceItem{Kind: "rc_local", Location: "/etc/rc.local", Command: MaskSecrets(l)})
			}
		}
	}

	names, err := src.ReadDir("/etc/systemd/system")
	note("/etc/systemd/system", err)
	for _, n := range names {
		if !strings.HasSuffix(n, ".service") && !strings.HasSuffix(n, ".timer") {
			continue
		}
		p := "/etc/systemd/system/" + n
		b, ok := read(p)
		if !ok {
			continue
		}
		it := PersistenceItem{Kind: "systemd", Location: p}
		for _, l := range strings.Split(string(b), "\n") {
			if v, ok := strings.CutPrefix(strings.TrimSpace(l), "ExecStart="); ok {
				it.Command = MaskSecrets(v)
				break
			}
		}
		add(it)
	}

	if accounts.Known() {
		for _, a := range accounts.Value {
			if (!a.CanLogin && a.UID != "0") || a.Home == "" || a.Home == "/" {
				continue
			}
			for _, n := range []string{"authorized_keys", "authorized_keys2"} {
				// The user owns this path: never follow a link planted
				// there (it could point at /etc/shadow while we run as root).
				p := strings.TrimSuffix(a.Home, "/") + "/.ssh/" + n
				b, err := ReadFileNoFollow(src, p)
				note(p, err)
				if err != nil && !errors.Is(err, ErrTruncated) {
					continue
				}
				for _, k := range ParseAuthorizedKeys(b) {
					d := k.Type + " " + k.Fingerprint
					if k.Options {
						d += " (with options)"
					}
					add(PersistenceItem{Kind: "authorized_key", Location: p, Detail: d})
				}
			}
		}
	}
	switch {
	case dropped > 0:
		return Partial(out, ReasonTruncated, fmt.Sprintf("%d entries over the %d-per-kind cap dropped; unread: %s",
			dropped, MaxPersistenceItems, strings.Join(denied, ", ")))
	case len(denied) > 0:
		return Partial(out, ReasonPermission, "not fully read: "+strings.Join(denied, ", "))
	}
	return OK(out)
}
