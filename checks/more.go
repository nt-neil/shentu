package checks

import (
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"

	"github.com/nt-neil/shentu/hostenv"
)

// Checks that mirror today's patrol and survey items (tools/survey.go,
// tools/system.go, tools/persistence.go), plus the Windows items of the
// roadmap. Each reads facts only; a fact a platform does not have
// (not_applicable) produces nothing.

func init() {
	register(checkFunc{"accounts.extra_uid0", extraUID0})
	register(checkFunc{"listener.exposed_service", exposedService})
	register(checkFunc{"process.miner", miner})
	register(checkFunc{"process.shell_as_web_user", shellAsWebUser})
	register(checkFunc{"ssh.shared_key", sharedKey})
	register(checkFunc{"firewall.disabled", firewallDisabled})
	register(checkFunc{"antimalware", antimalware})
	register(checkFunc{"smb", smb})
	register(checkFunc{"winrm.insecure", winrm})
	register(checkFunc{"auth.bruteforce", bruteforce})
}

func extraUID0(f *hostenv.Facts) []Finding {
	o := f.Accounts
	if out := cannotTell("accounts.extra_uid0", "Accounts could not be read", o); out != nil {
		return out
	}
	var out []Finding
	for _, a := range o.Value {
		if a.UID == "0" && a.Name != "root" {
			out = append(out, Finding{Check: "accounts.extra_uid0", Status: StatusFail, Severity: SevHigh,
				Title: "An account other than root has UID 0", Evidence: a.Name})
		}
	}
	return out
}

// RiskyIfPublic are services that should never listen beyond loopback
// (tools/survey.go riskyIfPublic, plus their Windows names).
var RiskyIfPublic = map[string]bool{
	"mysqld": true, "mariadbd": true, "postgres": true, "mongod": true, "redis-server": true,
	"memcached": true, "rpcbind": true, "smbd": true,
	"mysqld.exe": true, "postgres.exe": true, "mongod.exe": true, "redis-server.exe": true, "memcached.exe": true,
}

func exposedService(f *hostenv.Facts) []Finding {
	o := f.Listeners
	if out := cannotTell("listener.exposed_service", "Listening ports could not be read", o); out != nil {
		return out
	}
	ports := map[string][]string{}
	for _, l := range o.Value {
		ip := net.ParseIP(l.Addr)
		if ip == nil || ip.IsLoopback() || !RiskyIfPublic[strings.ToLower(l.Process)] {
			continue
		}
		ports[l.Process] = append(ports[l.Process], fmt.Sprintf("%s/%d", l.Proto, l.Port))
	}
	var out []Finding
	for _, name := range sortedKeys(ports) {
		out = append(out, Finding{Check: "listener.exposed_service", Status: StatusFail, Severity: SevHigh,
			Title:    name + " listens on all interfaces; bind it to 127.0.0.1 or firewall it",
			Evidence: strings.Join(ports[name], ", ")})
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Miner signs, as in tools/system.go minerSigns.
var (
	minerArgs  = regexp.MustCompile(`(?i)\bstratum\+(tcp|ssl|tls)://|--donate-level\b|--randomx-|--cpu-max-threads-hint\b|(^|\s)-a\s+rx/0(\s|$)`)
	minerNames = map[string]bool{"xmrig": true, "xmr-stak": true, "xmr-stak-rx": true, "cpuminer": true, "minerd": true,
		"nbminer": true, "t-rex": true, "lolminer": true, "phoenixminer": true, "srbminer-multi": true}
	minerViewers = map[string]bool{"grep": true, "egrep": true, "fgrep": true, "zgrep": true, "ugrep": true, "rg": true,
		"ag": true, "less": true, "more": true, "cat": true, "head": true, "tail": true, "sed": true, "awk": true, "gawk": true,
		"vi": true, "vim": true, "nano": true, "journalctl": true}
)

// exeBase is the lower-case file name of an executable path in either
// spelling, without ".exe".
func exeBase(p string) string {
	p = strings.ReplaceAll(p, `\`, "/")
	return strings.TrimSuffix(strings.ToLower(p[strings.LastIndex(p, "/")+1:]), ".exe")
}

func exeDir(p string) string {
	p = strings.ReplaceAll(p, `\`, "/")
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[:i]
	}
	return ""
}

func isMiner(p hostenv.Process) bool {
	exe := p.Exe
	if exe == "" {
		exe = p.Name
	}
	base := exeBase(exe)
	if minerNames[base] {
		return true
	}
	// A system copy of grep showing miner options is someone searching for
	// one; a "grep" in /tmp or a deleted one is not.
	if d := exeDir(exe); p.ExeExists && minerViewers[base] && (d == "/usr/bin" || d == "/bin") {
		return false
	}
	return minerArgs.MatchString(p.Cmdline)
}

func miner(f *hostenv.Facts) []Finding {
	o := f.Processes
	if out := cannotTell("process.miner", "Processes could not be listed", o); out != nil {
		return out
	}
	var out []Finding
	for _, p := range o.Value {
		if isMiner(p) {
			out = append(out, Finding{Check: "process.miner", Status: StatusFail, Severity: SevHigh,
				Title: "A cryptominer is running", Evidence: fmt.Sprintf("pid %d %s %s", p.PID, p.Exe, p.Cmdline)})
		}
	}
	return out
}

// WebUsers are accounts web servers run as; IIS app pools are matched by
// prefix. Configurable later through [tools] web_users.
var WebUsers = map[string]bool{"www-data": true, "apache": true, "nginx": true, "http": true}

// Shells a web user has no business starting (tools/system.go shells, plus
// the Windows ones).
var Shells = map[string]bool{"sh": true, "bash": true, "dash": true, "zsh": true, "nc": true, "ncat": true, "socat": true,
	"python": true, "python3": true, "perl": true, "cmd": true, "powershell": true, "pwsh": true}

func isWebUser(u string) bool {
	return WebUsers[u] || strings.HasPrefix(strings.ToUpper(u), `IIS APPPOOL\`)
}

func shellAsWebUser(f *hostenv.Facts) []Finding {
	o := f.Processes
	if out := cannotTell("process.shell_as_web_user", "Processes could not be listed", o); out != nil {
		return out
	}
	var out []Finding
	for _, p := range o.Value {
		exe := p.Exe
		if exe == "" {
			exe = p.Name
		}
		if isWebUser(p.User) && Shells[exeBase(exe)] {
			out = append(out, Finding{Check: "process.shell_as_web_user", Status: StatusFail, Severity: SevHigh,
				Title:    "The web server's account is running a shell (likely a webshell)",
				Evidence: fmt.Sprintf("pid %d user %s %s", p.PID, p.User, p.Cmdline)})
		}
	}
	return out
}

// sharedKey flags one SSH key that unlocks several accounts. Keys with
// options are skipped: cloud-init copies the default user's key into
// root's file with a command= refusal.
func sharedKey(f *hostenv.Facts) []Finding {
	o := f.Persistence
	if out := cannotTell("ssh.shared_key", "authorized_keys could not be read", o); out != nil {
		return out
	}
	owners := map[string]map[string]bool{}
	for _, it := range o.Value {
		if it.Kind != "authorized_key" || strings.Contains(it.Detail, "(with options)") {
			continue
		}
		fields := strings.Fields(it.Detail)
		if len(fields) < 2 {
			continue
		}
		home := strings.TrimSuffix(it.Location[:max(0, strings.LastIndex(it.Location, "/.ssh/"))], "/")
		if owners[fields[1]] == nil {
			owners[fields[1]] = map[string]bool{}
		}
		owners[fields[1]][home] = true
	}
	var out []Finding
	for _, fp := range sortedKeys(owners) {
		if len(owners[fp]) > 1 {
			out = append(out, Finding{Check: "ssh.shared_key", Status: StatusFail, Severity: SevMedium,
				Title:    "One SSH key logs in to several accounts",
				Evidence: fp + ": " + strings.Join(sortedKeys(owners[fp]), ", ")})
		}
	}
	return out
}

func firewallDisabled(f *hostenv.Facts) []Finding {
	o := f.Firewall
	if out := cannotTell("firewall.disabled", "Firewall state could not be read", o); out != nil {
		return out
	}
	if !o.Known() {
		return nil
	}
	var off []string
	for _, name := range sortedKeys(o.Value.Profiles) {
		if !o.Value.Profiles[name] {
			off = append(off, name)
		}
	}
	switch {
	case !o.Value.Enabled:
		return []Finding{{Check: "firewall.disabled", Status: StatusFail, Severity: SevInfo,
			Title: "No host firewall is active; fine only if a cloud firewall covers this server", Evidence: o.Value.Backend}}
	case len(off) > 0:
		return []Finding{{Check: "firewall.disabled", Status: StatusFail, Severity: SevMedium,
			Title: "Windows Firewall is off for some profiles", Evidence: strings.Join(off, ", ")}}
	}
	return nil
}

// MaxSignatureAgeDays is how stale antivirus signatures may get.
const MaxSignatureAgeDays = 7

func antimalware(f *hostenv.Facts) []Finding {
	o := f.Antimalware
	if out := cannotTell("antimalware", "Antivirus state could not be read", o); out != nil {
		return out
	}
	if !o.Known() {
		return nil
	}
	var out []Finding
	if !o.Value.RealTime {
		out = append(out, Finding{Check: "antimalware.realtime_off", Status: StatusFail, Severity: SevHigh,
			Title: "Real-time antivirus protection is off", Evidence: o.Value.Product})
	}
	if o.Value.SignatureAgeDays > MaxSignatureAgeDays {
		out = append(out, Finding{Check: "antimalware.stale_signatures", Status: StatusFail, Severity: SevMedium,
			Title: "Antivirus signatures are out of date", Evidence: fmt.Sprintf("%s: %d days old", o.Value.Product, o.Value.SignatureAgeDays)})
	}
	for _, x := range o.Value.Exclusions {
		if broadExclusion(x) {
			out = append(out, Finding{Check: "antimalware.broad_exclusion", Status: StatusFail, Severity: SevHigh,
				Title: "Antivirus skips a whole drive or a temp folder", Evidence: x})
		}
	}
	return out
}

// broadExclusion: a drive root, or a folder malware is dropped into.
func broadExclusion(x string) bool {
	l := strings.ToLower(strings.TrimRight(strings.ReplaceAll(x, "/", `\`), `\`))
	if len(l) == 2 && l[1] == ':' {
		return true
	}
	for _, d := range []string{`\temp`, `\tmp`, `\appdata\local\temp`, `c:\users\public`, `c:\programdata`, `c:\windows`} {
		if strings.HasSuffix(l, d) || l == d {
			return true
		}
	}
	return l == "*" || l == "*.exe" || l == "*.dll" || l == "*.ps1"
}

func smb(f *hostenv.Facts) []Finding {
	o := f.RemoteAccess.SMB
	if out := cannotTell("smb", "SMB settings could not be read", o); out != nil {
		return out
	}
	if !o.Known() {
		return nil
	}
	var out []Finding
	if o.Value.SMB1Enabled {
		out = append(out, Finding{Check: "smb.v1_enabled", Status: StatusFail, Severity: SevHigh,
			Title: "SMBv1 is enabled (EternalBlue, WannaCry)"})
	}
	if !o.Value.SigningRequired {
		out = append(out, Finding{Check: "smb.signing_not_required", Status: StatusFail, Severity: SevMedium,
			Title: "SMB signing is not required (relay attacks)"})
	}
	for _, s := range o.Value.WritableShares {
		out = append(out, Finding{Check: "smb.everyone_writable", Status: StatusFail, Severity: SevHigh,
			Title: "A share is writable by everyone", Evidence: s})
	}
	return out
}

func winrm(f *hostenv.Facts) []Finding {
	o := f.RemoteAccess.WinRM
	if out := cannotTell("winrm.insecure", "WinRM settings could not be read", o); out != nil {
		return out
	}
	if !o.Known() || !o.Value.Running {
		return nil
	}
	var why []string
	if o.Value.HTTPListener && o.Value.AllowUnencrypted {
		why = append(why, "unencrypted HTTP allowed")
	}
	if o.Value.BasicAuth {
		why = append(why, "Basic authentication enabled")
	}
	if len(why) == 0 {
		return nil
	}
	return []Finding{{Check: "winrm.insecure", Status: StatusFail, Severity: SevHigh,
		Title: "WinRM accepts weak connections", Evidence: strings.Join(why, "; ")}}
}

// BruteforceThreshold is failed logins from one source within the window.
const BruteforceThreshold = 20

func bruteforce(f *hostenv.Facts) []Finding {
	o := f.AuthEvents
	if out := cannotTell("auth.bruteforce", "Login events could not be read", o); out != nil {
		return out
	}
	var out []Finding
	for _, src := range sortedKeys(o.Value.FailedBySrc) {
		if n := o.Value.FailedBySrc[src]; n >= BruteforceThreshold {
			out = append(out, Finding{Check: "auth.bruteforce", Status: StatusFail, Severity: SevMedium,
				Title:    "Repeated failed logins from one source",
				Evidence: fmt.Sprintf("%s: %d failures in %dh", src, n, o.Value.WindowHours)})
		}
	}
	for _, e := range o.Value.Notable {
		if e.Kind == "log_cleared" {
			out = append(out, Finding{Check: "auth.log_cleared", Status: StatusFail, Severity: SevHigh,
				Title: "The security log was cleared", Evidence: e.When + " " + e.Who})
		}
	}
	return out
}
