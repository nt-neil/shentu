package tools

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
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

// ListeningPorts parses /proc/net/{tcp,tcp6,udp,udp6}.
func ListeningPorts() ([]Port, error) {
	owners := socketOwners()
	var ports []Port
	seen := map[string]bool{}
	for _, proto := range []string{"tcp", "tcp6", "udp", "udp6"} {
		for _, e := range readProcNet(proto) {
			// 0A = TCP_LISTEN; 07 = an unconnected (bound) UDP socket.
			if (strings.HasPrefix(proto, "tcp") && e.state != "0A") || (strings.HasPrefix(proto, "udp") && e.state != "07") {
				continue
			}
			p := Port{Proto: proto, Addr: e.localIP.String(), Port: e.localPort, UID: e.uid}
			if pid, ok := owners[e.inode]; ok {
				p.PID = pid
				p.Process = comm(pid)
				p.Exe, _ = os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
			}
			key := fmt.Sprintf("%s/%s/%d", proto, p.Addr, p.Port)
			if !seen[key] {
				seen[key] = true
				ports = append(ports, p)
			}
		}
	}
	sort.Slice(ports, func(i, j int) bool { return ports[i].Port < ports[j].Port })
	return ports, nil
}

type netEntry struct {
	localIP    net.IP
	localPort  int
	remoteIP   net.IP
	remotePort int
	state      string
	uid        string
	inode      string
}

func readProcNet(proto string) []netEntry {
	f, err := os.Open("/proc/net/" + proto)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []netEntry
	sc := bufio.NewScanner(f)
	sc.Scan() // header
	for sc.Scan() {
		fs := strings.Fields(sc.Text())
		if len(fs) < 10 {
			continue
		}
		lip, lport := parseHexAddr(fs[1])
		rip, rport := parseHexAddr(fs[2])
		out = append(out, netEntry{lip, lport, rip, rport, fs[3], fs[7], fs[9]})
	}
	return out
}

// parseHexAddr decodes "0100007F:0016" (little-endian 32-bit words) into an IP and port.
func parseHexAddr(s string) (net.IP, int) {
	host, port, ok := strings.Cut(s, ":")
	if !ok {
		return nil, 0
	}
	b, err := hex.DecodeString(host)
	if err != nil {
		return nil, 0
	}
	for i := 0; i+4 <= len(b); i += 4 {
		b[i], b[i+1], b[i+2], b[i+3] = b[i+3], b[i+2], b[i+1], b[i]
	}
	p, _ := strconv.ParseInt(port, 16, 32)
	return net.IP(b), int(p)
}

// socketOwners maps socket inode -> pid by scanning /proc/*/fd.
func socketOwners() map[string]int {
	owners := map[string]int{}
	for _, pid := range pids() {
		fds, _ := filepath.Glob(fmt.Sprintf("/proc/%d/fd/*", pid))
		for _, fd := range fds {
			link, err := os.Readlink(fd)
			if err == nil && strings.HasPrefix(link, "socket:[") {
				owners[strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")] = pid
			}
		}
	}
	return owners
}

func pids() []int {
	ents, _ := os.ReadDir("/proc")
	var out []int
	for _, e := range ents {
		if n, err := strconv.Atoi(e.Name()); err == nil {
			out = append(out, n)
		}
	}
	return out
}

func comm(pid int) string {
	b, _ := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	return strings.TrimSpace(string(b))
}

// SSHPeers returns the remote IPs of established connections to local port 22.
// block_ip refuses these so the operator never locks themselves out.
func SSHPeers() map[string]bool {
	peers := map[string]bool{}
	for _, proto := range []string{"tcp", "tcp6"} {
		for _, e := range readProcNet(proto) {
			if e.state == "01" && e.localPort == 22 {
				peers[normIP(e.remoteIP)] = true
			}
		}
	}
	if c := os.Getenv("SSH_CLIENT"); c != "" {
		peers[strings.Fields(c)[0]] = true
	}
	return peers
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

// Processes reads /proc. With all=false only flagged processes are returned.
func Processes(all bool) []Proc {
	names := userNames()
	self := os.Getpid()
	var out []Proc
	var seen []Proc
	start := map[int]int64{} // clock ticks after boot
	for _, pid := range pids() {
		if pid == self {
			continue
		}
		status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
		if err != nil {
			continue
		}
		p := Proc{PID: pid, Comm: comm(pid)}
		for _, line := range strings.Split(string(status), "\n") {
			if v, ok := strings.CutPrefix(line, "PPid:"); ok {
				p.PPID, _ = strconv.Atoi(strings.TrimSpace(v))
			}
			if v, ok := strings.CutPrefix(line, "Uid:"); ok {
				uid := strings.Fields(v)[0]
				p.User = names[uid]
				if p.User == "" {
					p.User = uid
				}
			}
		}
		p.Exe, _ = os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
		cmd, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		p.Cmdline = strings.TrimSpace(strings.ReplaceAll(string(cmd), "\x00", " "))
		if len(p.Cmdline) > 300 {
			p.Cmdline = Cut(p.Cmdline, 300)
		}
		if st, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); err == nil {
			p.Started = st.ModTime().Format(time.RFC3339)
		}
		if t, ok := procStart(pid); ok {
			start[pid] = t
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

// procStart is when the process started, in clock ticks after boot (field 22
// of /proc/PID/stat).
func procStart(pid int) (int64, bool) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, false
	}
	i := bytes.LastIndexByte(b, ')') // the name may hold spaces and parentheses
	if i < 0 {
		return 0, false
	}
	f := strings.Fields(string(b[i+1:]))
	if len(f) < 20 {
		return 0, false
	}
	t, err := strconv.ParseInt(f[19], 10, 64)
	return t, err == nil
}

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

func userNames() map[string]string {
	m := map[string]string{}
	b, _ := os.ReadFile("/etc/passwd")
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Split(line, ":")
		// The first name wins, so a backdoor account that reuses UID 0 is not shown as the owner of root's files.
		if len(f) < 3 {
			continue
		}
		if _, dup := m[f[2]]; !dup {
			m[f[2]] = f[0]
		}
	}
	return m
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
}

// KeyEntry is one key of an authorized_keys file.
type KeyEntry struct {
	Line        int    `json:"line"`
	Type        string `json:"type"`
	Fingerprint string `json:"fingerprint"`
}

// readKeyFile reads an authorized_keys file's keys and unparsed lines.
func readKeyFile(b []byte) (keys []KeyEntry, unparsed []int) {
	for i, l := range strings.Split(string(b), "\n") {
		t, fp, bad := parseKeyLine(l)
		switch {
		case fp != "":
			keys = append(keys, KeyEntry{i + 1, t, fp})
		case bad:
			unparsed = append(unparsed, i+1)
		}
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
	seenKeys := map[string]bool{}
	b, _ := os.ReadFile("/etc/passwd")
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Split(line, ":")
		if len(f) < 7 {
			continue
		}
		user, uid, home, shell := f[0], f[2], f[5], f[6]
		if uid == "0" {
			a.UID0 = append(a.UID0, user)
		}
		// RHEL's shutdown and halt accounts have the commands of those names as their shell.
		if base := filepath.Base(shell); !strings.HasSuffix(shell, "nologin") && base != "false" && base != "sync" && base != "shutdown" && base != "halt" {
			a.LoginAccounts = append(a.LoginAccounts, user)
		}
		for _, name := range []string{"authorized_keys", "authorized_keys2"} {
			p := filepath.Join(home, ".ssh", name)
			if seenKeys[p] { // accounts can share a home (RHEL: operator uses /root)
				continue
			}
			seenKeys[p] = true
			if st, err := os.Stat(p); err == nil {
				kb, _ := os.ReadFile(p)
				keys, bad := readKeyFile(kb)
				a.KeyFiles = append(a.KeyFiles, KeyFile{User: user, Path: p, Keys: len(keys), Modified: st.ModTime(), KeyList: keys, Unparsed: bad})
			}
		}
	}
	files, _ := filepath.Glob("/etc/sudoers.d/*")
	for _, f := range append([]string{"/etc/sudoers"}, files...) {
		sb, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, l := range strings.Split(string(sb), "\n") {
			l = strings.TrimSpace(l)
			if l != "" && !strings.HasPrefix(l, "#") && !strings.HasPrefix(l, "Defaults") && strings.Contains(l, "ALL") {
				a.SudoRules = append(a.SudoRules, f+": "+l)
			}
		}
	}
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
		for _, e := range readProcNet(proto) {
			if e.localPort == remote.Port && e.remotePort == local.Port &&
				e.localIP.Equal(remote.IP) && e.remoteIP.Equal(local.IP) {
				return e.uid, true
			}
		}
	}
	return "", false
}
