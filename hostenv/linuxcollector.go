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
	"sort"
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

func (LinuxCollector) Allowlist() [][]string {
	return [][]string{dpkgArgv, rpmArgv, rpmQalArgv, nftListArgv, iptablesArgv, iptablesSbin, journalArgv, journalBinArgv, journalSockArgv, journalSockBinArgv}
}

func (c LinuxCollector) Collect(ctx context.Context, src Source) *Facts {
	info := src.Info()
	f := NewFacts(c.Name(), CollectorVersion, info.RecordedAt)
	f.Privilege = OK(Privilege{Elevated: info.Elevated})
	f.Resources = c.Resources(src)

	var osr map[string]string
	f.Platform, osr = c.Platform(src)
	var apkOwned map[string]bool // which OpenRC scripts apk installed (Alpine)
	f.Packages, apkOwned = c.packages(ctx, src, osr)
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
	f.Firewall = c.Firewall(ctx, src, procs.Value)
	f.AuthEvents = c.AuthEvents(ctx, src, info.RecordedAt, nil)
	f.Web = c.Web(src)
	f.SSHKeys = Unknown[[]AuthorizedKeyFile](accounts.Reason, "accounts unknown")
	if accounts.Known() {
		f.SSHKeys = c.SSHKeyFiles(src, accounts.Value)
	}
	f.Persistence = c.persistence(ctx, src, f.SSHKeys)
	if IsOpenRC(src) {
		svcs, items := c.OpenRCServices(src, apkOwned)
		f.Services = svcs
		if f.Persistence.Known() {
			f.Persistence.Value = append(f.Persistence.Value, items...)
			if apkOwned == nil && osr != nil && LinuxFamily(osr["ID"], osr["ID_LIKE"]) == "alpine" {
				// Without apk's database a script no package installed looks like any other: say so.
				if f.Persistence.Status == StatusOK {
					f.Persistence.Status, f.Persistence.Reason = StatusPartial, f.Packages.Reason
				}
				f.Persistence.Detail = strings.TrimPrefix(f.Persistence.Detail+"; which OpenRC scripts a package installed is unknown (apk database: "+f.Packages.Detail+")", "; ")
			}
			if svcs.Status != StatusOK { // what OpenRC could not read is missing from persistence too
				if f.Persistence.Status == StatusOK {
					f.Persistence.Status, f.Persistence.Reason = StatusPartial, svcs.Reason
				}
				f.Persistence.Detail = strings.TrimPrefix(f.Persistence.Detail+"; OpenRC "+svcs.Detail, "; ")
			}
		}
	}

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

// Packages lists installed packages with the distribution's own tool:
// dpkg-query, rpm -qa, or the apk database. osr is the parsed os-release.
func (c LinuxCollector) Packages(ctx context.Context, src Source, osr map[string]string) Obs[PackageSet] {
	set, _ := c.packages(ctx, src, osr)
	return set
}

// packages is Packages, and on Alpine which OpenRC scripts apk installed
// (nil: unknown), from the same single pass over apk's database.
func (LinuxCollector) packages(ctx context.Context, src Source, osr map[string]string) (Obs[PackageSet], map[string]bool) {
	if osr == nil {
		return Unknown[PackageSet](ReasonNotCollected, "no os-release, distribution unknown"), nil
	}
	var apkOwned map[string]bool
	feed := PatchFeedFor(osr)
	extrasErr, extrasReason := "", Reason("")
	if feed.Kind == "alas" && feed.Release == "2" {
		b, err := src.ReadFile(AL2ExtrasRepo)
		switch {
		case err == nil:
			feed.Repos = ParseAL2Extras(b)
		case !missing(err): // the topics' packages would go unchecked without a word
			extrasReason = Classify(err)
			extrasErr = AL2ExtrasRepo + " (" + string(extrasReason) + "): amazon-linux-extras topics not checked"
		}
	}
	set := PackageSet{Ecosystem: OSVEcosystem(osr)}
	if feed.Kind != "" {
		set.Feed = &feed
	}
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
		var owned map[string]bool
		if items, owned, err = ScanApkDB(src, isOpenRCScript); err == nil {
			apkOwned = owned
		}
	default:
		return Unknown[PackageSet](ReasonUnsupported, "package manager for "+osr["ID"]+" not supported yet"), nil
	}
	switch {
	case err != nil:
		return unknownFrom[PackageSet](set.Manager, err), nil
	case res.ExitCode != 0:
		return Unknown[PackageSet](ReasonCommandFailed, fmt.Sprintf("%s exit %d: %s", set.Manager, res.ExitCode, firstLine(res.Stderr))), nil
	}
	set.Items = items
	if extrasErr != "" {
		return Partial(set, extrasReason, "not fully read: "+extrasErr), apkOwned
	}
	return OK(set), apkOwned
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
		rows := 0
		err := ScanProcNet(src, proto, func(e ProcNetEntry) {
			rows++
			if !e.IsListening(proto) {
				return
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
				return
			}
			seen[key] = true
			out = append(out, l)
		})
		switch {
		case err == nil:
			read++
		case errors.Is(err, fs.ErrNotExist): // no IPv6 is fine
		default:
			if rows > 0 { // the rows before the error count; the fact is partial
				read++
			}
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	switch {
	case read == 0 && firstErr != nil:
		return unknownFrom[[]Listener]("/proc/net", firstErr)
	case read == 0:
		return Unknown[[]Listener](ReasonNotInstalled, "/proc/net tables missing")
	case firstErr != nil:
		return Partial(out, Classify(firstErr), "/proc/net not fully read: "+firstErr.Error())
	case unowned > 0 && !src.Info().Elevated:
		return Partial(out, ReasonPermission, fmt.Sprintf("owner of %d sockets not visible without root", unowned))
		// As root an ownerless socket belongs to the kernel (NFS, WireGuard):
		// PID stays 0, which checks read as "kernel", not as hidden.
	}
	return OK(out)
}

// SSHDConfigPath is where sshd reads its configuration.
const SSHDConfigPath = "/etc/ssh/sshd_config"

func (c LinuxCollector) ssh(src Source) Obs[SSHConfig] {
	if _, err := src.ReadFile(SSHDConfigPath); errors.Is(err, fs.ErrNotExist) {
		if names, derr := src.ReadDir("/usr/sbin"); derr == nil && !contains(names, "sshd") {
			return NotApplicable[SSHConfig]()
		}
	}
	return c.SSHD(src, SSHDConfigPath)
}

// SSHD reads the effective global sshd settings that matter for security,
// following Include in place (relative to the main file's folder, sorted
// as sshd's glob is); the first value wins, as in sshd, and a Match block
// ends the global part. A file or Include folder that cannot be read leaves
// every setting not set before it "unknown", and is listed in Unread as
// "path (why)". The hash covers every byte read, to notice any change.
func (LinuxCollector) SSHD(src Source, config string) Obs[SSHConfig] {
	cfg := SSHConfig{ConfigPath: config, Settings: SSHDDefaults()}
	got := map[string]bool{}
	h := sha256.New()
	reason := Reason("")
	unknown := func(p string, err error) {
		if reason == "" || Classify(err) == ReasonPermission {
			reason = Classify(err)
		}
		cfg.Unread = append(cfg.Unread, p+" ("+whyUnread(err)+")")
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
				unknown(p, err)
			}
			return true
		}
		h.Write(b)
		dirs, sawMatch := ParseSSHDConfig(b)
		for _, d := range dirs {
			if d.Key == "include" {
				pat := d.Value
				if !strings.HasPrefix(pat, "/") {
					pat = path.Join(path.Dir(config), pat)
				}
				// A folder that cannot be listed hides what it holds.
				if _, err := src.ReadDir(path.Dir(pat)); err != nil && !errors.Is(err, fs.ErrNotExist) {
					unknown(path.Dir(pat), err)
				}
				for _, inc := range Glob(src, pat) {
					if !read(inc, depth+1) {
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
	read(config, 0)
	cfg.Hash = hex.EncodeToString(h.Sum(nil))[:16]
	if len(cfg.Unread) > 0 {
		return Partial(cfg, reason, "some sshd config files unreadable; their settings are \"unknown\"")
	}
	return OK(cfg)
}

// whyUnread is the short reason a path could not be read: "permission
// denied", the system's own words ("is a directory"), or the error.
func whyUnread(err error) string {
	if errors.Is(err, fs.ErrPermission) {
		return "permission denied"
	}
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}
	return err.Error()
}

// exists reports whether p is there (an unreadable file still is).
func exists(src Source, p string) bool {
	_, err := Stat(src, p)
	if err == nil {
		return true
	}
	if !errors.Is(err, ErrNoStat) && !errors.Is(err, ErrNotRecorded) {
		return !errors.Is(err, fs.ErrNotExist)
	}
	if _, derr := src.ReadDir(p); derr == nil {
		return true
	}
	_, rerr := src.ReadFile(p)
	return !errors.Is(rerr, fs.ErrNotExist) && !errors.Is(rerr, ErrNotRecorded)
}

// Glob expands an absolute pattern through src, as filepath.Glob does
// (every component may hold *, ? or [...]); the result is sorted.
func Glob(src Source, pattern string) []string {
	paths := []string{"/"}
	for _, part := range strings.Split(strings.Trim(path.Clean(pattern), "/"), "/") {
		var next []string
		for _, d := range paths {
			if !strings.ContainsAny(part, "*?[\\") {
				next = append(next, path.Join(d, part))
				continue
			}
			names, _ := src.ReadDir(d)
			for _, n := range names {
				if ok, _ := path.Match(part, n); ok {
					next = append(next, path.Join(d, n))
				}
			}
		}
		paths = next
	}
	var out []string
	for _, p := range paths {
		// A dangling link matches too, as with filepath.Glob: its reader
		// says why it could not be read, rather than nothing at all.
		if _, lerr := src.Readlink(p); lerr == nil || exists(src, p) {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
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

func (c LinuxCollector) persistence(ctx context.Context, src Source, keys Obs[[]AuthorizedKeyFile]) Obs[[]PersistenceItem] {
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
	cronDir("/etc/crontabs") // busybox crond (Alpine)
	for _, it := range PeriodicScripts(src, note) {
		add(it)
	}

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

	for _, kf := range keys.Value {
		for _, l := range kf.Unparsed { // sshd ignores these, but never drop them silently
			add(PersistenceItem{Kind: "authorized_key_unparsed", Location: fmt.Sprintf("%s:%d", kf.Path, l),
				Detail: "neither a key nor a comment; check it is not a key written in another form"})
		}
		for _, k := range kf.Keys {
			d := k.Type + " " + k.Fingerprint
			if k.Options {
				d += " (with options)"
			}
			if k.CloudInitRefusal {
				d += " (cloud-init refusal)"
			}
			add(PersistenceItem{Kind: "authorized_key", Location: kf.Path, Detail: d})
		}
		if kf.OutsideHome {
			add(PersistenceItem{Kind: "authorized_keys_symlink", Location: kf.Path,
				Detail: "links to " + kf.SymlinkTarget + ", outside the home; sshd reads the keys there"})
		}
	}
	if keys.Status == StatusPartial || !keys.Known() {
		denied = append(denied, "authorized_keys: "+keys.Detail)
	}
	rules, rs := c.SudoRules(src)
	for _, r := range rules {
		loc, cmd, _ := strings.Cut(r, ": ")
		add(PersistenceItem{Kind: "sudo_rule", Location: loc, Command: cmd})
	}
	if rs.Status == StatusPartial {
		denied = append(denied, rs.Detail)
	}
	for _, f := range c.CronFiles(src) {
		add(PersistenceItem{Kind: "cron_file", Location: f})
	}
	for _, m := range c.UnpackagedPAM(src, RpmOwned(ctx, src)) {
		add(PersistenceItem{Kind: "pam_unpackaged", Location: m, Detail: "no package installed this PAM module"})
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
