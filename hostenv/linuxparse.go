package hostenv

// Parsers for Linux sources. Pure functions, deliberately without a build
// tag (and the file name avoids the _linux suffix, which would add one), so
// they are tested on every platform against recorded fixtures.

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net"
	"strconv"
	"strings"
	"unicode/utf8"
)

// ParseOSRelease reads /etc/os-release KEY=value lines.
func ParseOSRelease(b []byte) map[string]string {
	m := map[string]string{}
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		if k, v, ok := strings.Cut(l, "="); ok {
			if uq, err := strconv.Unquote(v); err == nil {
				v = uq
			} else {
				v = strings.Trim(v, `"'`)
			}
			m[k] = v
		}
	}
	return m
}

// LinuxFamily folds an os-release ID and ID_LIKE into a family.
func LinuxFamily(id, idLike string) string {
	words := append([]string{id}, strings.Fields(idLike)...)
	for _, w := range words {
		switch w {
		case "debian", "ubuntu":
			return "debian"
		case "rhel", "fedora", "centos", "rocky", "almalinux", "amzn", "ol":
			return "rhel"
		case "alpine":
			return "alpine"
		case "suse", "opensuse", "sles", "opensuse-leap", "opensuse-tumbleweed":
			return "suse"
		case "arch", "manjaro":
			return "arch"
		}
	}
	return id
}

// OSVEcosystem names the OSV ecosystem for a distro, "" when OSV has none.
func OSVEcosystem(osr map[string]string) string {
	id, ver := osr["ID"], osr["VERSION_ID"]
	major := strings.Split(ver, ".")[0]
	switch id {
	case "debian":
		return "Debian:" + major
	case "ubuntu":
		eco := "Ubuntu:" + ver
		if strings.Contains(osr["VERSION"], "LTS") {
			eco += ":LTS"
		}
		return eco
	case "alpine":
		parts := strings.Split(ver, ".")
		return "Alpine:v" + strings.Join(parts[:min(2, len(parts))], ".")
	case "rocky":
		return "Rocky Linux:" + major
	case "almalinux":
		return "AlmaLinux:" + major
	}
	return ""
}

// ProcNetEntry is one row of /proc/net/{tcp,udp}{,6}.
type ProcNetEntry struct {
	LocalIP    net.IP
	LocalPort  int
	RemoteIP   net.IP
	RemotePort int
	State      string // hex, 0A = LISTEN for TCP
	UID        string
	Inode      string
}

// ParseProcNet reads one /proc/net table.
func ParseProcNet(b []byte) []ProcNetEntry {
	var out []ProcNetEntry
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	sc.Scan() // header
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 10 {
			continue
		}
		lip, lport := parseHexAddr(f[1])
		rip, rport := parseHexAddr(f[2])
		if lip == nil {
			continue
		}
		out = append(out, ProcNetEntry{lip, lport, rip, rport, f[3], f[7], f[9]})
	}
	return out
}

// parseHexAddr decodes "0100007F:0016" (little-endian 32-bit words).
func parseHexAddr(s string) (net.IP, int) {
	host, port, ok := strings.Cut(s, ":")
	if !ok {
		return nil, 0
	}
	b, err := hex.DecodeString(host)
	if err != nil || (len(b) != 4 && len(b) != 16) {
		return nil, 0
	}
	for i := 0; i+4 <= len(b); i += 4 {
		b[i], b[i+1], b[i+2], b[i+3] = b[i+3], b[i+2], b[i+1], b[i]
	}
	p, _ := strconv.ParseInt(port, 16, 32)
	return net.IP(b), int(p)
}

// IsListening reports whether a row is a listening socket: TCP LISTEN, or an
// unconnected UDP socket.
func (e ProcNetEntry) IsListening(proto string) bool {
	if strings.HasPrefix(proto, "tcp") {
		return e.State == "0A"
	}
	return e.State == "07" // TCP_CLOSE for UDP: bound, not connected
}

// DpkgQueryFormat is the -f argument the Linux collector passes to dpkg-query.
const DpkgQueryFormat = "${Package}\t${source:Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\n"

// ParseDpkgQuery reads DpkgQueryFormat output, keeping installed packages.
func ParseDpkgQuery(b []byte) []Package {
	var out []Package
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Split(l, "\t")
		if len(f) < 5 || f[0] == "" || !strings.HasPrefix(f[4], "ii") {
			continue
		}
		p := Package{Name: f[0], Version: f[2], Arch: f[3]}
		if f[1] != "" && f[1] != f[0] {
			p.Source = f[1]
		}
		out = append(out, p)
	}
	return out
}

// RpmQueryFormat is the --qf argument the Linux collector passes to rpm -qa.
const RpmQueryFormat = "%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\t%{ARCH}\n"

func ParseRpmQA(b []byte) []Package {
	var out []Package
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Split(l, "\t")
		if len(f) < 3 || f[0] == "" || f[0] == "gpg-pubkey" {
			continue
		}
		out = append(out, Package{Name: f[0], Version: f[1], Arch: f[2]})
	}
	return out
}

// ParseApkInstalled reads /lib/apk/db/installed.
func ParseApkInstalled(b []byte) []Package {
	var out []Package
	var p Package
	flush := func() {
		if p.Name != "" {
			out = append(out, p)
		}
		p = Package{}
	}
	for _, l := range strings.Split(string(b)+"\n\n", "\n") {
		switch {
		case l == "":
			flush()
		case strings.HasPrefix(l, "P:"):
			p.Name = l[2:]
		case strings.HasPrefix(l, "V:"):
			p.Version = l[2:]
		case strings.HasPrefix(l, "A:"):
			p.Arch = l[2:]
		case strings.HasPrefix(l, "o:"):
			if l[2:] != p.Name {
				p.Source = l[2:]
			}
		}
	}
	return out
}

// PasswdEntry is one /etc/passwd line.
type PasswdEntry struct{ Name, UID, GID, Home, Shell string }

func ParsePasswd(b []byte) []PasswdEntry {
	var out []PasswdEntry
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Split(l, ":")
		if len(f) != 7 || strings.HasPrefix(f[0], "#") || f[0] == "" {
			continue
		}
		out = append(out, PasswdEntry{f[0], f[2], f[3], f[5], f[6]})
	}
	return out
}

// ParseGroup maps group name to members from /etc/group.
func ParseGroup(b []byte) map[string][]string {
	m := map[string][]string{}
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Split(l, ":")
		if len(f) != 4 || f[0] == "" {
			continue
		}
		var mem []string
		for _, u := range strings.Split(f[3], ",") {
			if u = strings.TrimSpace(u); u != "" {
				mem = append(mem, u)
			}
		}
		m[f[0]] = mem
	}
	return m
}

// AdminGroups are the groups that grant root through the stock sudoers.
var AdminGroups = []string{"sudo", "wheel", "admin"}

// CanLoginShell is false for nologin and false shells, and for RHEL's
// sync, shutdown and halt accounts, whose shells are those commands. An
// empty shell is a login: login(1) and sshd use /bin/sh.
func CanLoginShell(shell string) bool {
	b := shell[strings.LastIndex(shell, "/")+1:]
	return !strings.HasSuffix(shell, "nologin") && b != "false" && b != "sync" && b != "halt" && b != "shutdown"
}

// SSHDDirective is one keyword line of sshd_config.
type SSHDDirective struct{ Key, Value string }

// ParseSSHDConfig returns the directives before the first Match block (which
// apply globally) and whether a Match block was reached. Include lines are
// returned as directives with Key "include"; the collector resolves them.
func ParseSSHDConfig(b []byte) (dirs []SSHDDirective, sawMatch bool) {
	for _, l := range strings.Split(string(b), "\n") {
		k, args := sshdLine(l)
		if k == "" || len(args) == 0 {
			continue
		}
		if k == "match" {
			return dirs, true
		}
		if k == "include" {
			for _, p := range args {
				dirs = append(dirs, SSHDDirective{"include", p})
			}
			continue
		}
		dirs = append(dirs, SSHDDirective{k, strings.ToLower(args[0])})
	}
	return dirs, false
}

// sshdLine tokenises one line the way sshd does: the keyword ends at
// whitespace or '=', one optional '=' may follow ("Key=Value",
// "Key = Value"), and arguments may be double-quoted.
func sshdLine(l string) (string, []string) {
	l = strings.TrimSpace(l)
	if l == "" || strings.HasPrefix(l, "#") {
		return "", nil
	}
	i := strings.IndexAny(l, " \t=")
	if i < 0 {
		return strings.ToLower(l), nil
	}
	key, rest := strings.ToLower(l[:i]), strings.TrimLeft(l[i:], " \t")
	if strings.HasPrefix(rest, "=") {
		rest = strings.TrimLeft(rest[1:], " \t")
	}
	var args []string
	for rest != "" {
		if rest[0] == '"' {
			end := strings.IndexByte(rest[1:], '"')
			if end < 0 {
				args = append(args, rest[1:])
				break
			}
			args = append(args, rest[1:1+end])
			rest = strings.TrimLeft(rest[2+end:], " \t")
			continue
		}
		if rest[0] == '#' {
			break
		}
		j := strings.IndexAny(rest, " \t")
		if j < 0 {
			args = append(args, rest)
			break
		}
		args = append(args, rest[:j])
		rest = strings.TrimLeft(rest[j:], " \t")
	}
	return key, args
}

// SSHDDefaults are OpenSSH's built-in values for the keys the checks read.
func SSHDDefaults() map[string]string {
	return map[string]string{"port": "22", "permitrootlogin": "prohibit-password", "passwordauthentication": "yes",
		"pubkeyauthentication": "yes", "permitemptypasswords": "no", "x11forwarding": "no"}
}

// ParseCron returns the command lines of a crontab (system crontabs carry a
// user column; the command is kept whole either way).
func ParseCron(b []byte) []string {
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		if k, _, ok := strings.Cut(l, "="); ok && !strings.ContainsAny(k, " \t*") {
			continue // VAR=value
		}
		out = append(out, l)
	}
	return out
}

// ProcStatus holds the /proc/<pid>/status fields the collector uses.
type ProcStatus struct {
	Name string
	PPID int
	UID  string // real uid
}

func ParseProcStatus(b []byte) ProcStatus {
	var s ProcStatus
	for _, l := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch k {
		case "Name":
			s.Name = v
		case "PPid":
			s.PPID, _ = strconv.Atoi(v)
		case "Uid":
			if f := strings.Fields(v); len(f) > 0 {
				s.UID = f[0]
			}
		}
	}
	return s
}

// MaxCmdline caps a recorded command line.
const MaxCmdline = 512

// ParseCmdline turns NUL-separated /proc/<pid>/cmdline into one masked
// line, cut at MaxCmdline bytes on a character boundary.
func ParseCmdline(b []byte) string {
	return CutString(MaskSecrets(strings.TrimSpace(strings.ReplaceAll(string(b), "\x00", " "))), MaxCmdline)
}

// CutString shortens s to at most n bytes without splitting a UTF-8
// character, adding "…" when it cuts (tools.Cut, shared).
func CutString(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "…"
}

// ParseProcStartTicks is field 22 of /proc/PID/stat: when the process
// started, in clock ticks after boot. The name field may hold spaces and
// parentheses, so fields count from the last ')'.
func ParseProcStartTicks(b []byte) (int64, bool) {
	i := strings.LastIndexByte(string(b), ')')
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

// TempDirs are world-writable places a binary has no business running from.
var TempDirs = []string{"/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/"}

func InTempDir(exe string) bool {
	for _, d := range TempDirs {
		if strings.HasPrefix(exe, d) {
			return true
		}
	}
	return false
}

// AuthorizedKey summarises one authorized_keys line without the key itself.
type AuthorizedKey struct {
	Type        string
	Fingerprint string // SHA256:... as ssh-keygen -l prints it
	Options     bool   // has options such as command="..."
}

func ParseAuthorizedKeys(b []byte) []AuthorizedKey {
	var out []AuthorizedKey
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		f := strings.Fields(l)
		for i := 0; i+1 < len(f); i++ {
			if isKeyType(f[i]) {
				k := AuthorizedKey{Type: f[i], Options: i > 0}
				if raw, err := base64.StdEncoding.DecodeString(f[i+1]); err == nil {
					sum := sha256.Sum256(raw)
					k.Fingerprint = "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
				} else {
					sum := sha256.Sum256([]byte(f[i+1]))
					k.Fingerprint = "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
				}
				out = append(out, k)
				break
			}
		}
	}
	return out
}

func isKeyType(s string) bool {
	return strings.HasPrefix(s, "ssh-") || strings.HasPrefix(s, "ecdsa-sha2-") || strings.HasPrefix(s, "sk-")
}
