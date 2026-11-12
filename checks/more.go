package checks

import (
	"fmt"
	"net"
	"path"
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
	return append(out, partialNote("accounts.extra_uid0", "Some accounts could not be read", o)...)
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
	return append(out, partialNote("listener.exposed_service", "Some sockets could not be tied to a process", o)...)
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
	return append(out, partialNote("process.miner", "Some processes could not be inspected", o)...)
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
	return append(out, partialNote("process.shell_as_web_user", "Some processes could not be inspected", o)...)
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
	return append(out, partialNote("ssh.shared_key", "Some authorized_keys files could not be read", o)...)
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
	var out []Finding
	switch {
	case !o.Value.Enabled:
		out = append(out, Finding{Check: "firewall.disabled", Status: StatusFail, Severity: SevInfo,
			Title: "No host firewall is active; fine only if a cloud firewall covers this server", Evidence: o.Value.Backend})
	case len(off) > 0:
		out = append(out, Finding{Check: "firewall.disabled", Status: StatusFail, Severity: SevMedium,
			Title: "Windows Firewall is off for some profiles", Evidence: strings.Join(off, ", ")})
	}
	return append(out, partialNote("firewall.disabled", "Some firewall profiles could not be read", o)...)
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
	return append(out, partialNote("antimalware", "Some antivirus settings could not be read", o)...)
}

// broadExclusion: a drive root, a temp folder anywhere, a system or shared
// root on any drive, any path built on an environment variable, an 8.3
// short name (which can hide one), or a bare wildcard for a whole file
// type. The path is canonicalised first.
func broadExclusion(x string) bool {
	l := canonExclusion(x)
	if l == "" || l == "/" || (len(l) == 2 && l[1] == ':') {
		return true // "", "*", "C:", "\\?\C:\"
	}
	if strings.HasPrefix(l, "%") || strings.HasPrefix(l, "//") || strings.Contains(l, "globalroot") || strings.HasPrefix(l, "volume{") {
		return true // env vars, UNC, device and volume paths: fail closed, worth a look
	}
	segs := strings.Split(l, "/")
	for i, seg := range segs {
		if seg == "temp" || seg == "tmp" || seg == "downloads" || shortName.MatchString(seg) {
			return true
		}
		if i < len(segs)-1 && strings.ContainsAny(seg, "*?") {
			return true // a wildcard directory can stand for any root
		}
	}
	// System and shared roots, on whatever drive.
	rest := l
	if len(l) >= 2 && l[1] == ':' {
		rest = l[2:]
	}
	switch rest {
	case "/windows", "/windows/system32", "/windows/syswow64", "/users", "/users/public", "/programdata",
		"/program files", "/program files (x86)", "/perflogs":
		return true
	}
	for _, root := range []string{"/users/public/", "/windows/system32/", "/windows/syswow64/"} {
		if strings.HasPrefix(rest, root) {
			return true
		}
	}
	// Extensions (ExclusionExtension holds "ps1" or ".ps1") and wildcards.
	switch strings.TrimPrefix(strings.TrimPrefix(l, "*"), ".") {
	case "exe", "dll", "ps1", "bat", "cmd", "vbs", "js", "hta", "scr":
		return true
	}
	return false
}

var shortName = regexp.MustCompile(`~[0-9]`)

// canonExclusion lower-cases, uses "/", strips \\?\ and \\.\ prefixes,
// maps \\localhost\c$ and \\127.0.0.1\c$ to c:, resolves . and .., and
// drops trailing "/" and "/*".
func canonExclusion(x string) string {
	l := strings.ToLower(strings.TrimSpace(strings.ReplaceAll(x, `\`, "/")))
	for _, p := range []string{"//?/unc/", "//?/", "//./"} {
		if strings.HasPrefix(l, p) {
			l = strings.TrimPrefix(l, p)
			if p == "//?/unc/" {
				l = "//" + l
			}
			break
		}
	}
	for _, h := range []string{"//localhost/", "//127.0.0.1/", "//./"} {
		if rest, ok := strings.CutPrefix(l, h); ok {
			switch {
			case strings.HasPrefix(rest, "admin$"):
				l = "c:/windows" + strings.TrimPrefix(rest, "admin$")
			case len(rest) >= 2 && rest[1] == '$':
				l = rest[:1] + ":" + rest[2:]
			}
		}
	}
	// Win32 drops trailing dots and spaces from every component.
	segs := strings.Split(l, "/")
	for i, seg := range segs {
		if seg != "." && seg != ".." {
			segs[i] = strings.TrimRight(seg, ". ")
		}
	}
	l = strings.Join(segs, "/")
	for {
		t := l
		for _, suf := range []string{"*.*", "*.", "*", "/"} {
			t = strings.TrimSuffix(t, suf)
		}
		if t == l {
			break
		}
		l = t
	}
	if len(l) >= 2 && l[1] == ':' {
		if c := path.Clean("/" + l[2:]); c != "/" {
			return l[:2] + c
		}
		return l[:2]
	}
	if strings.HasPrefix(l, "//") {
		return l // UNC stays UNC; broadExclusion fails closed on it
	}
	if strings.HasPrefix(l, "/") {
		return path.Clean(l)
	}
	return l
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
	return append(out, partialNote("smb", "Some SMB settings could not be read", o)...)
}

func winrm(f *hostenv.Facts) []Finding {
	o := f.RemoteAccess.WinRM
	if out := cannotTell("winrm.insecure", "WinRM settings could not be read", o); out != nil {
		return out
	}
	if !o.Known() {
		return nil
	}
	note := partialNote("winrm.insecure", "Some WinRM settings could not be read", o)
	if !o.Value.Running {
		return note
	}
	var why []string
	if o.Value.HTTPListener && o.Value.AllowUnencrypted {
		why = append(why, "unencrypted HTTP allowed")
	}
	if o.Value.BasicAuth {
		why = append(why, "Basic authentication enabled")
	}
	if len(why) == 0 {
		return note
	}
	return append([]Finding{{Check: "winrm.insecure", Status: StatusFail, Severity: SevHigh,
		Title: "WinRM accepts weak connections", Evidence: strings.Join(why, "; ")}}, note...)
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
	return append(out, partialNote("auth.bruteforce", "Some login events could not be read", o)...)
}
