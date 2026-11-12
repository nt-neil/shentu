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
}

type pair struct {
	re *regexp.Regexp
	to string
}

var (
	ipv4Re    = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	ipv6Re    = regexp.MustCompile(`(?i)\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b|(?i)\b(?:[0-9a-f]{1,4}:)+:(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4})*)?\b`)
	sshKeyRe  = regexp.MustCompile(`\bAAAA[0-9A-Za-z+/]{16,}={0,3}`)
	akLineRe  = regexp.MustCompile(`^(.*?\b(?:ssh-[a-z0-9-]+|ecdsa-sha2-[a-z0-9-]+|sk-[a-z0-9@.-]+))\s+(\S+)(?:\s+.*)?$`)
	procNetRe = regexp.MustCompile(`\b([0-9A-F]{8}|[0-9A-F]{32}):([0-9A-F]{4})\b`)
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
			m.repl = append(m.repl, pair{regexp.MustCompile(`\b` + regexp.QuoteMeta(n) + `\b`), fmt.Sprintf("%s%d", prefix, i+1)})
		}
	}
	add(m.Hosts, "host")
	add(m.Users, "user")
}

func (m *Masker) apply(entries []*entry) []*entry {
	m.Users = append(m.Users, winMaskPrep(entries)...)
	m.init()
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
	for _, p := range m.repl {
		if !users && strings.HasPrefix(p.to, "user") {
			continue
		}
		s = p.re.ReplaceAllString(s, p.to)
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
			if ip == nil || ip.To4() != nil {
				return t
			}
			return m.ip(ip).String()
		})
	}
	return s
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
