package tools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/nt-neil/shentu/hostenv"
)

var listeningPorts = Tool{
	Name:        "listening_ports",
	Description: "TCP and UDP ports this server listens on, with the owning process and its executable path.",
	Params:      schema(noParams),
	Run: func(ctx context.Context, env *Env, args json.RawMessage) (any, error) {
		return ListeningPorts()
	},
}

// Port is one listening socket.
type Port struct {
	Proto   string `json:"proto"`
	Addr    string `json:"addr"`
	Port    int    `json:"port"`
	PID     int    `json:"pid,omitempty"`
	Process string `json:"process,omitempty"`
	Exe     string `json:"exe,omitempty"`
	UID     string `json:"uid"`
}

// ListeningPorts lists TCP and UDP listening sockets from hostenv's
// listeners fact, each with its owning process and executable.
func ListeningPorts() ([]Port, error) {
	src := hostSource()
	procs, owners := linux.Processes(src, nil)
	byPID := map[int]hostenv.Process{}
	for _, p := range procs.Value {
		byPID[p.PID] = p
	}
	var ports []Port
	seen := map[string]bool{}
	for _, l := range linux.Listeners(src, owners).Value {
		key := fmt.Sprintf("%s/%s/%d", l.Proto, l.Addr, l.Port)
		if seen[key] { // the tool shows one owner per port, as before 1c
			continue
		}
		seen[key] = true
		p := Port{Proto: l.Proto, Addr: l.Addr, Port: l.Port, UID: l.UID}
		if l.PID != 0 {
			pr := byPID[l.PID]
			p.PID, p.Process, p.Exe = l.PID, pr.Name, rawExe(pr)
		}
		ports = append(ports, p)
	}
	sort.Slice(ports, func(i, j int) bool { return ports[i].Port < ports[j].Port })
	return ports, nil
}

// rawExe is the executable as /proc/PID/exe reads, " (deleted)" included.
func rawExe(p hostenv.Process) string {
	if !p.ExeKnown {
		return ""
	}
	if !p.ExeExists {
		return p.Exe + " (deleted)"
	}
	return p.Exe
}

// procNet is one /proc/net table through hostenv. complete is false when
// the table could not be read in full (cut short, or unreadable); a table
// that does not exist is complete. The rows read are still returned.
func procNet(proto string) (rows []hostenv.ProcNetEntry, complete bool) {
	err := hostenv.ScanProcNet(hostSource(), proto, func(e hostenv.ProcNetEntry) { rows = append(rows, e) })
	switch {
	case err == nil:
		return rows, true
	case errors.Is(err, fs.ErrNotExist): // no such table: no IPv6, or not Linux
		return nil, true
	}
	return rows, false
}

// SSHPeers returns the remote IPs of established connections to local port 22.
// block_ip refuses these so the operator never locks themselves out; the
// error says the connection table could not be read in full, and block_ip
// then refuses outright rather than risk the operator's own address.
func SSHPeers() (map[string]bool, error) {
	peers := map[string]bool{}
	complete := true
	for _, proto := range []string{"tcp", "tcp6"} {
		rows, ok := procNet(proto)
		complete = complete && ok
		for _, e := range rows {
			if e.State == "01" && e.LocalPort == 22 {
				peers[normIP(e.RemoteIP)] = true
			}
		}
	}
	if c := os.Getenv("SSH_CLIENT"); c != "" {
		peers[strings.Fields(c)[0]] = true
	}
	if !complete {
		return peers, errors.New("the TCP connection table could not be read in full, so active SSH sessions are not known")
	}
	return peers, nil
}

func normIP(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}

var processesTool = Tool{
	Name:        "processes",
	Description: "Running processes. By default only suspicious ones: executables in /tmp, /dev/shm or /var/tmp, deleted executables, shells started by web server users, and cryptominers (pool URLs, miner options or a known miner binary).",
	Params: schema(`{"type":"object","properties":{
		"all":{"type":"boolean","description":"list every process, not only suspicious ones"}}}`),
	Run: func(ctx context.Context, env *Env, args json.RawMessage) (any, error) {
		var a struct {
			All bool `json:"all"`
		}
		if err := decode(args, &a); err != nil {
			return nil, err
		}
		return Processes(a.All), nil
	},
}

// Proc is one process.
type Proc struct {
	PID     int      `json:"pid"`
	PPID    int      `json:"ppid"`
	User    string   `json:"user"`
	Comm    string   `json:"comm"`
	Exe     string   `json:"exe"`
	Cmdline string   `json:"cmdline"`
	Started string   `json:"started,omitempty"`
	Flags   []string `json:"flags,omitempty"`
}

var webUsers = map[string]bool{"www-data": true, "apache": true, "nginx": true, "http": true}

// SetWebUsers replaces the accounts that web servers and apps run as (config: [tools] web_users).
// A shell started by one of them is flagged.
func SetWebUsers(names []string) {
	if len(names) == 0 {
		return
	}
	m := map[string]bool{}
	for _, n := range names {
		m[n] = true
	}
	webUsers = m
}

var shells = map[string]bool{"sh": true, "bash": true, "dash": true, "zsh": true, "nc": true, "ncat": true, "socat": true, "python": true, "python3": true, "perl": true}

// Processes lists processes from hostenv's processes fact. With all=false
// only flagged processes are returned.
func Processes(all bool) []Proc {
	names := userNames()
	self := os.Getpid()
	procs, _ := linux.Processes(hostSource(), nil)
	var out []Proc
	var seen []Proc
	start := map[int]int64{} // clock ticks after boot
	for _, hp := range procs.Value {
		if hp.PID == self {
			continue
		}
		p := Proc{PID: hp.PID, PPID: hp.PPID, Comm: hp.Name, Exe: rawExe(hp), Cmdline: Cut(hp.Cmdline, 300), Started: hp.Started}
		if hp.UID != "" {
			p.User = names[hp.UID]
			if p.User == "" {
				p.User = hp.UID
			}
		}
		if hp.StartTicks > 0 {
			start[hp.PID] = hp.StartTicks
		}
		if strings.HasSuffix(p.Exe, " (deleted)") {
			p.Flags = append(p.Flags, "deleted_executable")
		}
		for _, dir := range []string{"/tmp/", "/dev/shm/", "/var/tmp/"} {
			if strings.HasPrefix(p.Exe, dir) {
				p.Flags = append(p.Flags, "runs_from_"+strings.Trim(dir, "/"))
			}
		}
		if minerSigns(p.Exe, p.Cmdline) {
			p.Flags = append(p.Flags, "miner")
		}
		if webUsers[p.User] && shells[filepath.Base(strings.TrimSuffix(p.Exe, " (deleted)"))] {
			p.Flags = append(p.Flags, "shell_as_web_user")
		}
		seen = append(seen, p)
	}
	for _, p := range unflagBootSurvivors(seen, start) {
		if all || len(p.Flags) > 0 {
			out = append(out, p)
		}
	}
	return out
}

// bootWindow bounds how soon after boot an initramfs process started: two
// minutes, in clock ticks (USER_HZ is 100 on Linux).
const bootWindow = 120 * 100

// A process started from the initramfs, before the boot switched to the real
// root file system, shows its executable as deleted once the initramfs is
// freed (plymouthd). It started before every process the real root started:
// before the earliest process, other than PID 1 and kernel threads, whose
// executable is still there. A process started after that whose executable
// was then deleted is flagged, whatever it is named; so is one started later
// than bootWindow after boot, should every early process have ended since.
func unflagBootSurvivors(ps []Proc, start map[int]int64) []Proc {
	first, ok := int64(0), false
	for _, p := range ps {
		t, has := start[p.PID]
		if p.PID == 1 || p.Exe == "" || strings.HasSuffix(p.Exe, " (deleted)") || !has {
			continue
		}
		if !ok || t < first {
			first, ok = t, true
		}
	}
	if !ok {
		return ps
	}
	for i, p := range ps {
		if t, has := start[p.PID]; has && t < first && t <= bootWindow && slices.Contains(p.Flags, "deleted_executable") {
			ps[i].Flags = slices.DeleteFunc(slices.Clone(p.Flags), func(f string) bool { return f == "deleted_executable" })
		}
	}
	return ps
}

// Cryptominer signs: a mining pool URL or miner-only options in the command line, or a known miner binary.
var (
	minerArgs  = regexp.MustCompile(`(?i)\bstratum\+(tcp|ssl|tls)://|--donate-level\b|--randomx-|--cpu-max-threads-hint\b|(^|\s)-a\s+rx/0(\s|$)`)
	minerNames = map[string]bool{"xmrig": true, "xmr-stak": true, "xmr-stak-rx": true, "cpuminer": true, "minerd": true,
		"nbminer": true, "t-rex": true, "lolminer": true, "phoenixminer": true, "srbminer-multi": true}
	// Tools that may show a miner's options as text, e.g. while someone searches for one.
	// Only the system's own copies count, so a miner renamed to /tmp/grep is still caught.
	minerViewers = map[string]bool{"grep": true, "egrep": true, "fgrep": true, "zgrep": true, "ugrep": true, "rg": true,
		"ag": true, "less": true, "more": true, "cat": true, "head": true, "tail": true, "sed": true, "awk": true, "gawk": true,
		"vi": true, "vim": true, "nano": true, "journalctl": true}
)

func minerSigns(exe, cmdline string) bool {
	deleted := strings.HasSuffix(exe, " (deleted)")
	exe = strings.TrimSuffix(exe, " (deleted)")
	base := strings.ToLower(filepath.Base(exe))
	if minerNames[base] {
		return true
	}
	if dir := filepath.Dir(exe); !deleted && minerViewers[base] && (dir == "/usr/bin" || dir == "/bin") {
		return false
	}
	return minerArgs.MatchString(cmdline)
}

// userNames maps uid to account name from hostenv's accounts fact; the
// first account with a uid wins.
func userNames() map[string]string {
	names, _ := linux.Accounts(hostSource())
	if names == nil {
		return map[string]string{}
	}
	return names
}

var accountsAudit = Tool{
	Name:        "accounts_audit",
	Description: "Accounts and persistence that matter for intrusion: extra UID 0 accounts, accounts with a login shell, sudo rules, authorized_keys files (key count and last change), one SSH key planted in several accounts (by fingerprint), libraries in /etc/ld.so.preload, and PAM modules that no package installed.",
	Params:      schema(noParams),
	Run: func(ctx context.Context, env *Env, args json.RawMessage) (any, error) {
		return AccountsAudit(), nil
	},
}

// KeyFile is one authorized_keys file.
type KeyFile struct {
	User     string    `json:"user"`
	Path     string    `json:"path"`
	Keys     int       `json:"keys"`
	Modified time.Time `json:"modified"`
	// Each key by the type written in it and its fingerprint (never the key).
	KeyList []KeyEntry `json:"key_list,omitempty"`
	// Lines that are neither a key nor a comment: sshd ignores them, but a
	// key written in a form not read here would hide among them.
	Unparsed []int `json:"unparsed_lines,omitempty"`
	// A link to a file outside the home: sshd reads the keys there.
	SymlinkOutsideHome string `json:"symlink_outside_home,omitempty"`
}

// KeyEntry is one key of an authorized_keys file.
type KeyEntry struct {
	Line        int    `json:"line"`
	Type        string `json:"type"`
	Fingerprint string `json:"fingerprint"`
}

// readKeyFile reads an authorized_keys file's keys and unparsed lines (hostenv).
func readKeyFile(b []byte) (keys []KeyEntry, unparsed []int) {
	ks, unparsed := hostenv.ParseAuthorizedKeys(b)
	for _, k := range ks {
		keys = append(keys, KeyEntry{k.Line, k.Type, k.Fingerprint})
	}
	return keys, unparsed
}

// Accounts is the result of AccountsAudit.
type Accounts struct {
	UID0          []string    `json:"uid0_accounts"`
	LoginAccounts []string    `json:"login_accounts"`
	SudoRules     []string    `json:"sudo_rules"`
	KeyFiles      []KeyFile   `json:"authorized_keys"`
	SharedKeys    []SharedKey `json:"keys_in_several_accounts,omitempty"`
	Preload       []string    `json:"ld_so_preload,omitempty"`
	UnpackagedPAM []string    `json:"pam_modules_not_from_a_package,omitempty"`
}

// AccountsAudit reads /etc/passwd, sudoers and authorized_keys.
func AccountsAudit() Accounts {
	var a Accounts
	_, accts := linux.Accounts(hostSource())
	for _, acct := range accts.Value {
		user := acct.Name
		if acct.UID == "0" {
			a.UID0 = append(a.UID0, user)
		}
		if acct.CanLogin {
			a.LoginAccounts = append(a.LoginAccounts, user)
		}
	}
	src := hostSource()
	for _, kf := range linux.SSHKeyFiles(src, accts.Value).Value {
		var keys []KeyEntry
		for _, k := range kf.Keys {
			keys = append(keys, KeyEntry{k.Line, k.Type, k.Fingerprint})
		}
		f := KeyFile{User: kf.User, Path: kf.Path, Keys: len(keys), Modified: kf.Modified, KeyList: keys, Unparsed: kf.Unparsed}
		if kf.OutsideHome {
			f.SymlinkOutsideHome = kf.SymlinkTarget
		}
		a.KeyFiles = append(a.KeyFiles, f)
	}
	a.SudoRules, _ = linux.SudoRules(src)
	a.SharedKeys = sharedKeys(a.KeyFiles)
	a.Preload = preloadEntries("/etc/ld.so.preload")
	a.UnpackagedPAM = unpackagedPAM()
	return a
}

// UIDOf returns the numeric UID of a user name from /etc/passwd.
func UIDOf(name string) (string, bool) {
	for uid, n := range userNames() {
		if n == name {
			return uid, true
		}
	}
	return "", false
}

// PeerUID returns the owner UID of the server side of an established local TCP
// connection, found by its exact 4-tuple in /proc/net/tcp{,6}.
func PeerUID(local, remote *net.TCPAddr) (string, bool) {
	for _, proto := range []string{"tcp", "tcp6"} {
		rows, _ := procNet(proto)
		for _, e := range rows {
			if e.LocalPort == remote.Port && e.RemotePort == local.Port &&
				e.LocalIP.Equal(remote.IP) && e.RemoteIP.Equal(local.IP) {
				return e.UID, true
			}
		}
	}
	return "", false
}
