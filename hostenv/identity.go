package hostenv

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"regexp"
	"sort"
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

	repl  []pair
	ips   map[string]string
	nPriv int
	nPub  int
	nV6   int
	nKey  int
	keys  map[string]string
	hw    map[string]string // MAC addresses, DUIDs, IAIDs

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
)

// skipIP lists contents where dotted numbers are versions, not addresses.
func skipIP(e *entry) bool {
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
	m.ips, m.keys = map[string]string{}, map[string]string{}
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
	m.init()
	// Deterministic placeholder order: walk entries sorted by key.
	sort.Slice(entries, func(i, j int) bool { return entries[i].key() < entries[j].key() })
	for _, e := range entries {
		e.Path = m.text(e.Path, true, true)
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
	s = sshKeyRe.ReplaceAllStringFunc(s, m.key)
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
	s = hwIDRe.ReplaceAllStringFunc(s, m.hwID)
	names(false)
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
