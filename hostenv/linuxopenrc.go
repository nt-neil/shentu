package hostenv

// OpenRC (Alpine, Gentoo): services are scripts in /etc/init.d, enabled by
// a link in a runlevel folder; /etc/local.d/*.start runs at boot.

import (
	"path"
	"sort"
	"strings"
)

// OpenRCRunlevels are the runlevels OpenRC ships; a host may add its own
// folders under /etc/runlevels, and those count as well.
var OpenRCRunlevels = []string{"sysinit", "boot", "default", "nonetwork", "shutdown"}

// openRCScriptDirs hold service scripts: the system's, then the local ones.
var openRCScriptDirs = []string{"/etc/init.d", "/usr/local/etc/init.d"}

// isOpenRCScript: the files whose package apk's database is asked about.
func isOpenRCScript(p string) bool {
	for _, d := range openRCScriptDirs {
		if strings.HasPrefix(p, d+"/") {
			return true
		}
	}
	return false
}

// IsOpenRC reports an OpenRC host: runlevel folders and no systemd.
func IsOpenRC(src Source) bool {
	_, rl := src.ReadDir("/etc/runlevels")
	_, sd := src.ReadDir("/run/systemd/system")
	return rl == nil && sd != nil
}

// OpenRCServices lists the service scripts of /etc/init.d and
// /usr/local/etc/init.d; a service enabled in any runlevel (the shipped
// ones and any other folder in /etc/runlevels) starts "auto", the others
// "manual". A runlevel entry that is itself a runlevel stacks it; an entry
// with no script of that name is listed on its own, with where it links.
// /etc/inittab (busybox init) is listed too. owned is apk's file list
// (nil: unknown); a script no package installed is marked so. Anything
// that exists but cannot be read makes the services partial.
func (LinuxCollector) OpenRCServices(src Source, owned map[string]bool) (Obs[[]Service], []PersistenceItem) {
	var unread []string
	reason := Reason("")
	note := func(p string, err error) {
		if reason == "" {
			reason = Classify(err)
		}
		unread = append(unread, p+" ("+string(Classify(err))+")")
	}
	read := func(dir string) []string {
		names, err := src.ReadDir(dir)
		if err != nil && !missing(err) {
			note(dir, err)
		}
		return names
	}
	scripts := map[string]string{} // name -> path; /etc/init.d wins
	var order []string
	for _, d := range openRCScriptDirs {
		for _, n := range read(d) {
			if strings.HasPrefix(n, ".") || scripts[n] != "" {
				continue
			}
			scripts[n] = d + "/" + n
			order = append(order, n)
		}
	}
	if len(scripts) == 0 && len(unread) > 0 {
		return Unknown[[]Service](reason, "not read: "+strings.Join(unread, ", ")), nil
	}
	levels := append([]string(nil), OpenRCRunlevels...)
	for _, rl := range read("/etc/runlevels") {
		if !contains(levels, rl) && !strings.HasPrefix(rl, ".") {
			levels = append(levels, rl)
		}
	}
	enabled := map[string][]string{}
	var items []PersistenceItem
	for _, rl := range levels {
		for _, n := range read("/etc/runlevels/" + rl) {
			entry := "/etc/runlevels/" + rl + "/" + n
			switch {
			case stackedRunlevel(src, entry, n): // its services run here too
				items = append(items, PersistenceItem{Kind: "openrc", Location: entry, Detail: "runlevel " + rl + " stacks runlevel " + n})
			case scripts[n] == "":
				d := "enabled in " + rl + ", but no script " + n + " in " + strings.Join(openRCScriptDirs, " or ")
				if t, err := src.Readlink(entry); err == nil {
					d += "; links to " + t
				}
				items = append(items, PersistenceItem{Kind: "openrc", Location: entry, Detail: d})
			default:
				enabled[n] = append(enabled[n], rl)
			}
		}
	}
	var svcs []Service
	for _, n := range order {
		p := scripts[n]
		s := Service{Name: n, Exe: p, StartMode: "manual"}
		if rls := enabled[n]; len(rls) > 0 {
			s.StartMode = "auto"
			it := PersistenceItem{Kind: "openrc", Location: p, Detail: "enabled in " + strings.Join(rls, ", ")}
			if owned != nil && !owned[p] {
				it.Detail += "; no package installed this script"
			}
			items = append(items, it)
		}
		svcs = append(svcs, s)
	}
	for _, n := range read("/etc/local.d") {
		if strings.HasSuffix(n, ".start") || strings.HasSuffix(n, ".stop") {
			items = append(items, PersistenceItem{Kind: "local_d", Location: "/etc/local.d/" + n, Detail: "run by the local service at boot or shutdown"})
		}
	}
	if b, err := src.ReadFile("/etc/inittab"); err == nil {
		items = append(items, InittabEntries(b)...)
	} else if !missing(err) {
		note("/etc/inittab", err)
	}
	sort.Slice(svcs, func(i, j int) bool { return svcs[i].Name < svcs[j].Name })
	if len(unread) > 0 {
		return Partial(svcs, reason, "not fully read: "+strings.Join(unread, ", ")), items
	}
	return OK(svcs), items
}

// stackedRunlevel: entry (/etc/runlevels/<rl>/<n>) stacks runlevel n when it
// is, or links to, the folder /etc/runlevels/<n>. A script of the same name
// as a runlevel is a script, so it cannot pass for a stack and escape the
// "no package installed this script" mark.
func stackedRunlevel(src Source, entry, n string) bool {
	dir := "/etc/runlevels/" + n
	t, err := src.Readlink(entry)
	if err != nil {
		return false // a stack is made with a link (rc-update -s)
	}
	if !strings.HasPrefix(t, "/") {
		t = path.Join(path.Dir(entry), t)
	}
	if path.Clean(t) != dir {
		return false
	}
	_, err = src.ReadDir(dir)
	return err == nil
}

// InittabEntries are busybox init's lines "id:runlevels:action:process":
// each runs its process as root (at boot, or kept alive by respawn).
func InittabEntries(b []byte) []PersistenceItem {
	var out []PersistenceItem
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		f := strings.SplitN(l, ":", 4)
		if len(f) != 4 {
			continue
		}
		out = append(out, PersistenceItem{Kind: "inittab", Location: "/etc/inittab", Command: MaskSecrets(f[3]), Detail: f[2]})
	}
	return out
}

// PeriodicScripts are busybox crond's /etc/periodic/<interval>/ scripts
// (Alpine), run by the root crontab's run-parts lines.
func PeriodicScripts(src Source, note func(dir string, err error)) []PersistenceItem {
	var out []PersistenceItem
	for _, iv := range []string{"15min", "hourly", "daily", "weekly", "monthly"} {
		names, err := src.ReadDir("/etc/periodic/" + iv)
		note("/etc/periodic/"+iv, err) // a folder that is not there is fine; one not readable is said
		for _, n := range names {
			out = append(out, PersistenceItem{Kind: "cron", Location: "/etc/periodic/" + iv + "/" + n, Detail: "periodic script, run " + iv})
		}
	}
	return out
}
