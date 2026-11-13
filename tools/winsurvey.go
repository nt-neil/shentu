package tools

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/nt-neil/shentu/checks"
	"github.com/nt-neil/shentu/hostenv"
)

// On Windows, survey and the listening-port baseline come from hostenv's
// Windows facts and the checks package, not from the Linux readers (which
// find nothing there and would report an empty, clean-looking host).

// windowsFacts collects the Windows facts; tests replace it with a replay.
var windowsFacts = func(ctx context.Context) *hostenv.Facts {
	return hostenv.WindowsCollector{}.Collect(ctx, winSource())
}

// winRoles names the roles of common Windows server processes (".exe" and
// case dropped).
var winRoles = map[string]string{
	"w3wp": "web server (IIS)", "inetinfo": "web server (IIS)", "httpd": "web server", "nginx": "web server",
	"sqlservr": "database (SQL Server)", "mysqld": "database (MySQL)", "mariadbd": "database (MariaDB)",
	"postgres": "database (PostgreSQL)", "mongod": "database (MongoDB)", "redis-server": "cache (Redis)",
	"sshd": "remote access (OpenSSH)", "termservice": "remote access (RDP)", "lsass": "Windows (authentication)",
	"svchost": "Windows service host", "system": "Windows kernel (HTTP.sys, SMB)", "java": "app (Java)",
	"node": "app (Node.js)", "python": "app (Python)", "php-cgi": "app (PHP)", "dns": "DNS server",
}

// portsFromFacts is ListeningPorts from Windows facts: one owner per port.
func portsFromFacts(f *hostenv.Facts) ([]Port, error) {
	if !f.Listeners.Known() {
		// An unknown socket table must not become an empty baseline: every
		// port would look new on the next good run.
		return nil, errors.New("listening sockets unknown: " + f.Listeners.Detail)
	}
	exe := map[int]string{}
	for _, p := range f.Processes.Value {
		exe[p.PID] = p.Exe
	}
	var ports []Port
	seen := map[string]bool{}
	for _, l := range f.Listeners.Value {
		key := fmt.Sprintf("%s/%s/%d", l.Proto, l.Addr, l.Port)
		if seen[key] {
			continue
		}
		seen[key] = true
		ports = append(ports, Port{Proto: l.Proto, Addr: l.Addr, Port: l.Port, PID: l.PID, Process: l.Process, Exe: exe[l.PID], UID: l.UID})
	}
	sort.Slice(ports, func(i, j int) bool { return ports[i].Port < ports[j].Port })
	return ports, nil
}

// severityOf maps a check's severity onto patrol's.
func severityOf(s checks.Severity) string {
	switch s {
	case checks.SevHigh:
		return "critical"
	case checks.SevMedium, checks.SevLow:
		return "warning"
	}
	return "info"
}

// surveyFromFacts is Survey on Windows.
func surveyFromFacts(f *hostenv.Facts, env *Env) SiteProfile {
	p := SiteProfile{Time: time.Now().UTC(), OS: f.Platform.Value.PrettyName, Firewall: winFirewallSummary(f.Firewall)}
	if b := f.Platform.Value.Build; b != "" {
		p.Kernel = "build " + b
	}

	by := map[string]*Service{}
	if ports, err := portsFromFacts(f); err == nil {
		for _, pt := range ports {
			name := strings.TrimSuffix(strings.ToLower(pt.Process), ".exe")
			if name == "" {
				name = "unknown"
			}
			s := by[name]
			if s == nil {
				role := winRoles[name]
				if role == "" {
					role = "other"
				}
				s = &Service{Name: name, Role: role}
				by[name] = s
			}
			s.Ports = append(s.Ports, fmt.Sprintf("%s/%d", pt.Proto, pt.Port))
			if ip := net.ParseIP(pt.Addr); ip != nil && !ip.IsLoopback() {
				s.Public = true
			}
		}
	}
	for _, s := range by {
		sort.Strings(s.Ports)
		s.Ports = dedupe(s.Ports)
		p.Services = append(p.Services, *s)
	}
	sort.Slice(p.Services, func(i, j int) bool { return p.Services[i].Name < p.Services[j].Name })

	stacks := map[string]bool{}
	for _, l := range FindLockfiles(env.AppPaths) {
		stacks[l.Ecosystem] = true
		if len(p.Lockfiles) < 20 {
			p.Lockfiles = append(p.Lockfiles, l.Path)
		}
	}
	for s := range stacks {
		p.Stacks = append(p.Stacks, s)
	}
	sort.Strings(p.Stacks)

	if ssh := f.RemoteAccess.SSH; ssh.Known() {
		p.SSH, p.SSHHash = ssh.Value.Settings, ssh.Value.Hash
	}

	// Autostart entries (run keys, services, scheduled tasks, startup
	// folders, WMI subscriptions) play the part of cron files: Drift
	// reports a new one.
	for _, it := range f.Persistence.Value {
		p.CronFiles = append(p.CronFiles, it.Kind+" "+it.Location)
	}
	sort.Strings(p.CronFiles)
	for _, a := range f.Accounts.Value {
		if a.CanLogin && !a.Disabled {
			p.LoginAccounts = append(p.LoginAccounts, a.Name)
		}
	}
	sort.Strings(p.LoginAccounts)

	// One risk per check and title (a stable key for patrol's cooldown);
	// several findings of one kind share it, their evidence joined.
	at := map[string]int{}
	for _, x := range checks.Run(f) {
		r := Risk{x.Check + ":" + x.Title, severityOf(x.Severity), strings.TrimSpace(x.Title + " " + x.Evidence)}
		if x.Status == checks.StatusCannotTell {
			r = Risk{uncheckedPrefix + x.Check, "info", x.Title + " (" + x.Reason + ")"}
		}
		if i, ok := at[r.Key]; ok {
			if x.Evidence != "" {
				p.Risks[i].Summary += "; " + x.Evidence
			}
			continue
		}
		at[r.Key] = len(p.Risks)
		p.Risks = append(p.Risks, r)
	}
	return p
}

// winFirewallSummary says which Windows Firewall profiles are on.
func winFirewallSummary(o hostenv.Obs[hostenv.Firewall]) string {
	if !o.Known() {
		return "unknown"
	}
	var on, off []string
	for name, enabled := range o.Value.Profiles {
		if enabled {
			on = append(on, name)
		} else {
			off = append(off, name)
		}
	}
	sort.Strings(on)
	sort.Strings(off)
	s := "Windows Firewall"
	if len(on) > 0 {
		s += " on: " + strings.Join(on, ", ")
	}
	if len(off) > 0 {
		s += "; off: " + strings.Join(off, ", ")
	}
	if o.Value.DefaultInbound != "" {
		s += "; inbound by default: " + o.Value.DefaultInbound
	}
	return s
}
