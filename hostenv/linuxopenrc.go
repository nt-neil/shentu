package hostenv

// OpenRC (Alpine, Gentoo): services are scripts in /etc/init.d, enabled by
// a link in a runlevel folder; /etc/local.d/*.start runs at boot.

import (
	"sort"
	"strings"
)

// OpenRCRunlevels are the runlevels a service may be enabled in.
var OpenRCRunlevels = []string{"sysinit", "boot", "default", "nonetwork", "shutdown"}

// IsOpenRC reports an OpenRC host: runlevel folders and no systemd.
func IsOpenRC(src Source) bool {
	_, rl := src.ReadDir("/etc/runlevels")
	_, sd := src.ReadDir("/run/systemd/system")
	return rl == nil && sd != nil
}

// OpenRCServices lists /etc/init.d scripts; a service enabled in any
// runlevel starts "auto", the others "manual". owned is apk's file list
// (nil: unknown); a script no package installed is marked so.
func (LinuxCollector) OpenRCServices(src Source, owned map[string]bool) (Obs[[]Service], []PersistenceItem) {
	names, err := src.ReadDir("/etc/init.d")
	if err != nil {
		return unknownFrom[[]Service]("/etc/init.d", err), nil
	}
	enabled := map[string][]string{}
	for _, rl := range OpenRCRunlevels {
		links, _ := src.ReadDir("/etc/runlevels/" + rl)
		for _, n := range links {
			enabled[n] = append(enabled[n], rl)
		}
	}
	var svcs []Service
	var items []PersistenceItem
	for _, n := range names {
		if strings.HasPrefix(n, ".") {
			continue
		}
		p := "/etc/init.d/" + n
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
	local, _ := src.ReadDir("/etc/local.d")
	for _, n := range local {
		if strings.HasSuffix(n, ".start") || strings.HasSuffix(n, ".stop") {
			items = append(items, PersistenceItem{Kind: "local_d", Location: "/etc/local.d/" + n, Detail: "run by the local service at boot or shutdown"})
		}
	}
	sort.Slice(svcs, func(i, j int) bool { return svcs[i].Name < svcs[j].Name })
	return OK(svcs), items
}

// PeriodicScripts are busybox crond's /etc/periodic/<interval>/ scripts
// (Alpine), run by the root crontab's run-parts lines.
func PeriodicScripts(src Source) []PersistenceItem {
	var out []PersistenceItem
	for _, iv := range []string{"15min", "hourly", "daily", "weekly", "monthly"} {
		names, _ := src.ReadDir("/etc/periodic/" + iv)
		for _, n := range names {
			out = append(out, PersistenceItem{Kind: "cron", Location: "/etc/periodic/" + iv + "/" + n, Detail: "periodic script, run " + iv})
		}
	}
	return out
}
