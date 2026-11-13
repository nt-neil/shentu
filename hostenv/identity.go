package hostenv

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Masker removes what identifies a machine or a person from a recording
// before it can go into the repository: host names, user names, IP
// addresses, GECOS fields and SSH public key material. It is consistent:
// the same name or address always becomes the same placeholder, in contents
// and in paths alike, so a replay asks for /home/user1/... and finds it.
type Masker struct {
	Hosts []string // host names to replace (short and FQDN)
	Users []string // user names to replace
	// DropArgs records process command lines as the executable only: on a
	// person's machine the arguments hold anything (paths, URLs, a shell's
	// whole script).
	DropArgs bool

	repl   []pair
	ips    map[string]string
	nPriv  int
	nPub   int
	nV6    int
	nKey   int
	keys   map[string]string
	other  map[string]string // .local names, UUIDs, email addresses
	nOther map[string]int    // placeholders made, per format
	hw     map[string]string // MAC addresses, DUIDs, IAIDs
}

type pair struct {
	re *regexp.Regexp
	to string
	hw bool // the name itself holds a hardware-id shape (nas-00-11-22-33)
}

var (
	ipv4Re   = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	ipv6Re   = regexp.MustCompile(`(?i)\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b|(?i)\b(?:[0-9a-f]{1,4}:)+:(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4})*)?\b`)
	sshKeyRe = regexp.MustCompile(`\bAAAA[0-9A-Za-z+/]{16,}={0,3}`)
	akLineRe = regexp.MustCompile(`^(.*?\b(?:ssh-[a-z0-9-]+|ecdsa-sha2-[a-z0-9-]+|sk-[a-z0-9@.-]+))\s+(\S+)(?:\s+.*)?$`)
	// hwIDRe is a MAC address, a DHCPv6 DUID or an IAID (dhcpcd logs them),
	// all derived from the network card: four or more hex bytes joined by
	// ":" or "-", six or more unpadded ones (0:c:29:...), or Cisco's dotted
	// form. Times (12:34:56) have three groups and stay. Twelve bare hex
	// digits are not taken: hashes and ids everywhere have that shape.
	// One pattern per separator takes the whole run, so a mixed id
	// (00:0c:29:59:f:3f) is never cut short; hwID then checks its shape.
	// hwPaddedRe is four or more two-digit groups: inside a run that is not
	// an id as a whole (1:2:3:4:5), such a part is still masked.
	hwPaddedRe = regexp.MustCompile(`(?i)\b[0-9a-f]{2}(?::[0-9a-f]{2}){3,}\b|\b[0-9a-f]{2}(?:-[0-9a-f]{2}){3,}\b`)
	hwIDRe     = regexp.MustCompile(`(?i)\b[0-9a-f]{1,2}(?::[0-9a-f]{1,2}){3,}\b|\b[0-9a-f]{1,2}(?:-[0-9a-f]{1,2}){3,}\b|` +
		`\b[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}\b`)
	procNetRe = regexp.MustCompile(`\b([0-9A-F]{8}|[0-9A-F]{32}):([0-9A-F]{4})\b`)

	// Bonjour names (macOS hosts are "<name>.local"), UUIDs (hardware and
	// volume ids) and email addresses (Apple ID, iCloud) identify a machine
	// or a person whatever the user and host lists say.
	dotLocalRe = regexp.MustCompile(`\b[A-Za-z0-9][A-Za-z0-9.-]*\.local\b`)
	uuidRe     = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)
	// A path in a person's home names their projects and clients; only the
	// parts the collectors read keep their names.
	// The rest of a home path runs to the end of the field: a name may hold
	// spaces, commas, parentheses, "-", "=" or ":", and where it ends cannot
	// be told, so everything up to a line end, tab, quote, <, >, | or ; is
	// masked (masking too much beats leaking). homeToken is the narrower
	// path a kept location (homeKept) is cut to.
	homePathRe = regexp.MustCompile(`(/(?:Users|home)/(?:user\d+|Shared))/([^\n\t"'<>|;]+)`)
	maskedRe   = regexp.MustCompile(`^redacted\d+(/|$)`) // a path this mask already wrote
	homeToken  = regexp.MustCompile(`^[^\s"'<>|:;,=)]+`)
	emailRe    = regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b`)
)

// skipIP lists contents where dotted numbers are versions, not addresses.
func skipIP(e *entry) bool {
	if winSkipIP(e) {
		return true
	}
	if e.Op == "cmd" {
		b := strings.ToLower(baseName(e.Argv[0]))
		return b == "dpkg-query" || b == "rpm"
	}
	return e.Path == "/lib/apk/db/installed" || strings.HasSuffix(e.Path, "os-release")
}

// skipUser lists contents where a user-name match would mangle facts
// (a user called "rocky" on Rocky Linux).
func skipUser(e *entry) bool { return e.Op == "file" && strings.HasSuffix(e.Path, "os-release") }

func (m *Masker) init() {
	m.ips, m.keys, m.other, m.nOther = map[string]string{}, map[string]string{}, map[string]string{}, map[string]int{}
	add := func(names []string, prefix string) {
		seen := map[string]bool{}
		var list []string
		for _, n := range names {
			n = strings.TrimSpace(n)
			if n != "" && !seen[n] && n != "root" && n != "localhost" {
				seen[n] = true
				list = append(list, n)
			}
		}
		sort.Slice(list, func(i, j int) bool { return len(list[i]) > len(list[j]) }) // longest first: FQDN before short
		for i, n := range list {
			m.repl = append(m.repl, pair{regexp.MustCompile(`\b` + regexp.QuoteMeta(n) + `\b`), fmt.Sprintf("%s%d", prefix, i+1), hwIDRe.MatchString(n)})
		}
	}
	add(m.Hosts, "host")
	add(m.Users, "user")
}

func (m *Masker) apply(entries []*entry) []*entry {
	m.Users = append(m.Users, winMaskPrep(entries)...)
	m.init()
	if m.DropArgs {
		dropArgs(entries)
	}
	// Deterministic placeholder order: walk entries sorted by key.
	sort.Slice(entries, func(i, j int) bool { return entries[i].key() < entries[j].key() })
	for _, e := range entries {
		e.Path = m.text(e.Path, !winSkipIP(e), true)
		for i := range e.Argv {
			e.Argv[i] = m.text(e.Argv[i], true, true)
		}
		for i := range e.Names {
			e.Names[i] = m.text(e.Names[i], true, true)
		}
		e.Target = m.text(e.Target, true, true)
		e.Stderr = m.text(e.Stderr, true, true)
		if strings.HasPrefix(e.Err, "other:") {
			e.Err = m.text(e.Err, true, true)
		}
		if e.data == nil {
			continue
		}
		s := string(e.data)
		switch {
		case strings.HasPrefix(e.Path, "/proc/net/"):
			s = m.procNet(s)
		case e.Path == "/etc/passwd":
			s = clearGECOS(s)
		case strings.HasSuffix(e.Path, "authorized_keys") || strings.HasSuffix(e.Path, "authorized_keys2"):
			s = m.authorizedKeys(s)
		case e.Op == "cmd" && baseName(e.Argv[0]) == "lsof" && strings.Contains(strings.Join(e.Argv, " "), "-F"):
			s = m.lsofFields(s) // "n192.0.2.1:22": the field letter hides the address from \b
		}
		s = m.text(s, !skipIP(e), !skipUser(e))
		e.data = []byte(s)
	}
	return entries
}

func (m *Masker) text(s string, ips, users bool) string {
	if s == "" {
		return s
	}
	s = MaskSecrets(s)
	s = maskMachineSIDs(s)
	s = sshKeyRe.ReplaceAllStringFunc(s, m.key)
	s = emailRe.ReplaceAllStringFunc(s, func(t string) string {
		if notEmail(t) {
			return t
		}
		return m.same(t, "user%d@example.com")
	})
	s = uuidRe.ReplaceAllStringFunc(s, func(t string) string { return m.same(strings.ToUpper(t), "00000000-0000-0000-0000-%012d") })
	// Names that hold an id's shape go first, whole; then the ids, so a
	// short name (f3) can no longer split one; then the other names.
	names := func(hw bool) {
		for _, p := range m.repl {
			if p.hw == hw && (users || !strings.HasPrefix(p.to, "user")) {
				s = p.re.ReplaceAllString(s, p.to)
			}
		}
	}
	names(true)
	s = m.hwIDs(s, ips)
	names(false)
	s = m.dotLocal(s)
	if users {
		s = homePathRe.ReplaceAllStringFunc(s, m.homePath)
	}
	if ips {
		s = ipv4Re.ReplaceAllStringFunc(s, func(t string) string {
			ip := net.ParseIP(t)
			if ip == nil {
				return t
			}
			return m.ip(ip).String()
		})
		s = ipv6Re.ReplaceAllStringFunc(s, func(t string) string {
			ip := net.ParseIP(t)
			if ip == nil || ip.To4() != nil || hwShaped(t) {
				return t
			}
			return m.ip(ip).String()
		})
	}
	return s
}

// notEmail: names shaped like addresses that are not, such as OpenSSH's
// algorithm names (aes256-gcm@openssh.com) and versioned file names
// (com.example.db@2.plist).
func notEmail(t string) bool {
	_, domain, _ := strings.Cut(t, "@")
	domain = strings.ToLower(domain)
	switch domain {
	case "openssh.com", "libssh.org", "ssh.com", "example.com":
		return true
	}
	return versionedFile.MatchString(domain)
}

// versionedFile is "17.plist", "9.7.log": a version, then a file extension.
var versionedFile = regexp.MustCompile(`^\d+(?:\.\d+)*\.(?:plist|service|conf|json|log|pid|err|sock|txt)$`)

// homeKept are the paths below a home that collectors read by name.
var homeKept = []string{".ssh", "Library/LaunchAgents"}

// homePath keeps /Users/user1/.ssh/... and /Users/user1/Library/LaunchAgents/...,
// and turns any other path below a masked home into /Users/user1/redactedN.
func (m *Masker) homePath(t string) string {
	sm := homePathRe.FindStringSubmatch(t)
	home, rest := sm[1], sm[2]
	keep := func(tok string) string { // a kept path, then the rest masked again
		after := rest[len(tok):]
		// A file name may go on past a space ("authorized keys"): that part
		// is masked up to an option or another path.
		tail := ""
		if len(after) > 1 && after[0] == ' ' && !strings.ContainsRune("/-( ", rune(after[1])) {
			end := len(after)
			for i := 1; i+1 < len(after); i++ {
				if after[i] == ' ' && (after[i+1] == '/' || after[i+1] == '-') {
					end = i
					break
				}
			}
			tail = " " + m.same(strings.TrimRight(after[1:end], " "), "redacted%d")
			after = after[end:]
		}
		return home + "/" + tok + tail + homePathRe.ReplaceAllStringFunc(after, m.homePath)
	}
	tok := homeToken.FindString(rest)
	for _, k := range homeKept {
		if tok == k || strings.HasPrefix(tok, k+"/") {
			return keep(tok)
		}
	}
	if maskedRe.MatchString(tok) {
		return keep(tok)
	}
	trail := rest[len(strings.TrimRight(rest, " ")):] // spaces before a delimiter stay
	return home + "/" + m.same(strings.TrimRight(rest, " "), "redacted%d") + trail
}

// dropArgs cuts command lines down to the executable: /proc/<pid>/cmdline
// to its first field, and "ps -o pid=,args=" to the path "ps -o comm=" gave
// for that pid (an executable path may hold spaces, so args cannot be split).
func dropArgs(entries []*entry) {
	comm := map[string]string{}
	for _, e := range entries {
		if e.Op == "cmd" && baseName(e.Argv[0]) == "ps" && strings.Contains(strings.Join(e.Argv, " "), "comm=") {
			for _, l := range strings.Split(string(e.data), "\n") {
				f := strings.Fields(l)
				if len(f) >= 6 {
					c := strings.TrimSpace(l)
					for i := 0; i < 5; i++ {
						c = strings.TrimSpace(c[strings.IndexAny(c, " \t"):])
					}
					comm[f[0]] = c
				}
			}
		}
	}
	for _, e := range entries {
		switch {
		case e.Op == "file" && strings.HasPrefix(e.Path, "/proc/") && strings.HasSuffix(e.Path, "/cmdline") && e.data != nil:
			first, _, _ := strings.Cut(string(e.data), "\x00")
			e.data = []byte(first)
		case e.Op == "cmd" && baseName(e.Argv[0]) == "ps" && strings.Contains(strings.Join(e.Argv, " "), "args="):
			var out []string
			for _, l := range strings.Split(string(e.data), "\n") {
				pid, _, _ := strings.Cut(strings.TrimSpace(l), " ")
				if pid != "" {
					out = append(out, fmt.Sprintf("%5s %s", pid, comm[pid]))
				}
			}
			e.data = []byte(strings.Join(out, "\n") + "\n")
		}
	}
}

// lsofFields masks lsof -F output one field at a time, after its letter.
func (m *Masker) lsofFields(s string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		if len(l) > 1 {
			lines[i] = l[:1] + m.text(l[1:], true, true)
		}
	}
	return strings.Join(lines, "\n")
}

// dotLocal masks Bonjour host names, but not file names such as
// /etc/rc.local: a name inside a path (after "/" or ".", or before "/")
// stays, unless it follows "//", where a URL names its host.
func (m *Masker) dotLocal(s string) string {
	var b strings.Builder
	last := 0
	for _, ix := range dotLocalRe.FindAllStringIndex(s, -1) {
		i, j := ix[0], ix[1]
		url := i > 1 && s[i-2:i] == "//"
		if !url && (i > 0 && (s[i-1] == '/' || s[i-1] == '.') || j < len(s) && s[j] == '/') {
			continue
		}
		b.WriteString(s[last:i])
		b.WriteString(m.same(strings.ToLower(s[i:j]), "localhost%d.local"))
		last = j
	}
	if last == 0 {
		return s
	}
	b.WriteString(s[last:])
	return b.String()
}

// same gives every distinct value one numbered placeholder, the same
// wherever it appears; a placeholder maps to itself.
func (m *Masker) same(v, format string) string {
	if r, ok := m.other[v]; ok {
		return r
	}
	m.nOther[format]++
	r := fmt.Sprintf(format, m.nOther[format])
	m.other[v], m.other[r] = r, r
	return r
}

// hwIDs masks the hardware ids in s (hwIDRe). A match inside an IPv6
// address is handled here, not left to a later step: with ips the whole
// address is masked as one right away, without it stays as it is. An MD5
// fingerprint stays; an IPv4 address written with dashes (ip-10-20-30-40)
// is masked as an address when ips is set, in the same dashed form.
func (m *Masker) hwIDs(s string, ips bool) string {
	var b strings.Builder
	last := 0
	for _, loc := range hwIDRe.FindAllStringIndex(s, -1) {
		i, j := loc[0], loc[1]
		if i < last {
			continue // inside an address already written out
		}
		t := s[i:j]
		var repl string
		if a, z, ip := ipv6Around(s, i, j); ip != nil {
			if !ips {
				continue
			}
			b.WriteString(s[last:a])
			b.WriteString(m.ip(ip).String())
			last = z
			continue
		}
		switch {
		case strings.Contains(t, ":") && i >= 4 && strings.EqualFold(s[i-4:i], "MD5:"):
			continue // a key fingerprint
		case dashedIPv4(t) != nil:
			if !ips {
				continue
			}
			repl = strings.ReplaceAll(m.ip(dashedIPv4(t)).String(), ".", "-")
		default:
			repl = m.hwID(t)
		}
		b.WriteString(s[last:i])
		b.WriteString(repl)
		last = j
	}
	b.WriteString(s[last:])
	return b.String()
}

// ipv6Around returns the IPv6 address a hwIDRe match s[i:j] is part of:
// the run of hex digits and colons around it, when that run is longer than
// the match, has "::" or a group of three or four digits, and parses. So
// "HWaddr:00:0c:29:59:f3:3f" is still a MAC.
func ipv6Around(s string, i, j int) (a, z int, ip net.IP) {
	if !strings.Contains(s[i:j], ":") {
		return 0, 0, nil
	}
	a, z = i, j
	for a > 0 && (s[a-1] == ':' || isHex(s[a-1])) {
		a--
	}
	for z < len(s) && (s[z] == ':' || isHex(s[z])) {
		z++
	}
	for a < i && s[a] == ':' && (a+1 >= len(s) || s[a+1] != ':') {
		a++ // a lone colon before the address belongs to the text around it
	}
	for z > j && s[z-1] == ':' && (z < 2 || s[z-2] != ':') {
		z--
	}
	run := s[a:z]
	if run == s[i:j] {
		return 0, 0, nil
	}
	long := strings.Contains(run, "::")
	for _, g := range strings.Split(run, ":") {
		long = long || len(g) >= 3
	}
	if ip = net.ParseIP(run); !long || ip == nil || ip.To4() != nil {
		return 0, 0, nil
	}
	return a, z, ip
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// dashedIPv4 is the address of four dashed decimal numbers up to 255
// (ip-10-20-30-40), or nil.
func dashedIPv4(t string) net.IP {
	g := strings.Split(t, "-")
	if len(g) != 4 {
		return nil
	}
	for _, x := range g {
		if n, err := strconv.Atoi(x); err != nil || n > 255 || len(x) > 3 {
			return nil
		}
	}
	return net.ParseIP(strings.Join(g, ".")).To4()
}

// hwShaped: two-digit groups only, no "::" - part of a MAC or DUID, which
// hwIDRe has handled, not an IPv6 address.
func hwShaped(t string) bool {
	if strings.Contains(t, "::") {
		return false
	}
	for _, g := range strings.Split(t, ":") {
		if len(g) != 2 {
			return false
		}
	}
	return true
}

// hwID replaces a hardware-derived id with one of the same shape: as many
// bytes, the same separator, 02 first (locally administered) and a counter
// last, the same id always the same placeholder.
func (m *Masker) hwID(id string) string {
	if m.hw == nil {
		m.hw = map[string]string{}
	}
	sep := ":"
	switch {
	case strings.Contains(id, "-"):
		sep = "-"
	case strings.Contains(id, "."):
		sep = "."
	}
	// One key for one id however it is written: lower case, each group padded.
	groups := strings.Split(strings.ToLower(id), sep)
	unpadded := false
	for i, g := range groups {
		if sep != "." && len(g) == 1 {
			groups[i] = "0" + g
			unpadded = true
		}
	}
	if unpadded && len(groups) < 6 { // 1:2:3:4 is not a hardware id, but a padded part of it may be
		return hwPaddedRe.ReplaceAllStringFunc(id, m.hwID)
	}
	k := strings.Join(groups, ":")
	if v, ok := m.hw[k]; ok {
		if sep == "-" { // the placeholder keeps the id's own separator
			return strings.ReplaceAll(v, ":", "-")
		}
		return v
	}
	if v, ok := m.hw[id]; ok { // a placeholder
		return v
	}
	n := len(groups)
	if sep == "." { // Cisco: three groups of two bytes
		n = 6
		sep = ":"
	}
	parts := make([]string, n)
	for i := range parts {
		parts[i] = "00"
	}
	parts[0] = "02"
	c := len(m.hw)/2 + 1
	parts[n-1] = fmt.Sprintf("%02x", c&0xff)
	if n > 2 {
		parts[n-2] = fmt.Sprintf("%02x", (c>>8)&0xff)
	}
	v := strings.Join(parts, ":")
	m.hw[k], m.hw[v] = v, v
	if sep == "-" {
		d := strings.ReplaceAll(v, ":", "-")
		m.hw[d] = d
		return d
	}
	return v
}

func (m *Masker) key(k string) string {
	if v, ok := m.keys[k]; ok {
		return v
	}
	m.nKey++
	// A valid blob of the same key type (sshd and ParseKeyLine accept it,
	// so replay still sees a key of that type) whose key part says what it
	// is: it cannot be mistaken for a real key.
	typ := "ssh-ed25519"
	if raw, err := base64.StdEncoding.DecodeString(k); err == nil {
		if n := len(raw); n >= 4 {
			l := int(binary.BigEndian.Uint32(raw))
			if l > 0 && l <= 64 && 4+l <= n && fullKeyType(string(raw[4:4+l])) {
				typ = string(raw[4 : 4+l])
			}
		}
	}
	v := base64.StdEncoding.EncodeToString(sshBlob(typ, fmt.Sprintf("shentu-redacted-key-%08d", m.nKey)))
	m.keys[k] = v
	m.keys[v] = v
	return v
}

// ip keeps the class of an address (loopback, any, private, public, link
// local) and replaces the rest with documentation ranges.
func (m *Masker) ip(ip net.IP) net.IP {
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() || ip.Equal(net.IPv4bcast) {
		return ip
	}
	k := ip.String()
	if v, ok := m.ips[k]; ok {
		return net.ParseIP(v)
	}
	var out net.IP
	if v4 := ip.To4(); v4 != nil {
		switch {
		case ip.IsLinkLocalUnicast():
			out = v4
		case ip.IsPrivate():
			m.nPriv++
			out = net.IPv4(10, 0, byte(m.nPriv>>8), byte(m.nPriv))
		default:
			m.nPub++
			out = net.IPv4(198, 51, byte(100+m.nPub>>8), byte(m.nPub))
		}
	} else {
		m.nV6++
		prefix := "2001:db8::"
		switch {
		case ip.IsLinkLocalUnicast():
			prefix = "fe80::"
		case ip.IsPrivate():
			prefix = "fd00::"
		}
		out = net.ParseIP(fmt.Sprintf("%s%x", prefix, m.nV6))
	}
	m.ips[k] = out.String()
	m.ips[out.String()] = out.String() // masking twice changes nothing
	return out
}

// procNet rewrites the little-endian hex addresses in /proc/net/{tcp,udp}{,6}.
func (m *Masker) procNet(s string) string {
	return procNetRe.ReplaceAllStringFunc(s, func(t string) string {
		h, port, _ := strings.Cut(t, ":")
		ip, _ := parseHexAddr(h + ":" + port)
		if ip == nil {
			return t
		}
		return encodeHexAddr(m.ip(ip)) + ":" + port
	})
}

func encodeHexAddr(ip net.IP) string {
	b := ip.To4()
	if b == nil {
		b = ip.To16()
	}
	b = append([]byte(nil), b...)
	for i := 0; i+4 <= len(b); i += 4 {
		b[i], b[i+1], b[i+2], b[i+3] = b[i+3], b[i+2], b[i+1], b[i]
	}
	return strings.ToUpper(hex.EncodeToString(b))
}

// clearGECOS empties the comment field, which often holds a real name.
func clearGECOS(s string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		f := strings.Split(l, ":")
		if len(f) == 7 {
			f[4] = ""
			lines[i] = strings.Join(f, ":")
		}
	}
	return strings.Join(lines, "\n")
}

// authorizedKeys keeps options and key type, replaces the key, drops the
// comment (usually user@laptop).
func (m *Masker) authorizedKeys(s string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		if sub := akLineRe.FindStringSubmatch(l); sub != nil {
			lines[i] = sub[1] + " " + m.key(sub[2])
		}
	}
	return strings.Join(lines, "\n")
}

// sshBlob is a public key blob: the type and the key as length-prefixed
// strings.
func sshBlob(keyType, key string) []byte {
	var b []byte
	for _, f := range []string{keyType, key} {
		b = binary.BigEndian.AppendUint32(b, uint32(len(f)))
		b = append(b, f...)
	}
	return b
}
