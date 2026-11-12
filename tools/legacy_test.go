//go:build unix

package tools

// Phase 1c zero-diff harness: the pre-migration implementations, kept here
// verbatim (test-only), run against the same recorded inputs as the new
// hostenv path. A category is migrated when both agree on every fixture.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/nt-neil/shentu/hostenv"
)

// fixtures replays every Linux fixture of hostenv/testdata.
func fixtures(t *testing.T) map[string]*hostenv.Replay {
	dirs, _ := filepath.Glob(filepath.Join("..", "hostenv", "testdata", "linux", "*", "manifest.json"))
	if len(dirs) == 0 {
		t.Skip("no hostenv fixtures")
	}
	out := map[string]*hostenv.Replay{}
	for _, m := range dirs {
		rp, err := hostenv.LoadReplay(filepath.Dir(m))
		if err != nil {
			t.Fatal(err)
		}
		out[filepath.Base(filepath.Dir(m))] = rp
	}
	return out
}

// withHost points the tools at src for one test.
func withHost(t *testing.T, src hostenv.Source) {
	old := hostSource
	hostSource = func() hostenv.Source { return src }
	t.Cleanup(func() { hostSource = old })
}

// legacyOSRelease is tools/vulns.go osRelease before 1c.
func legacyOSRelease(b []byte) map[string]string {
	m := map[string]string{}
	for _, l := range strings.Split(string(b), "\n") {
		if k, v, ok := strings.Cut(l, "="); ok {
			m[k] = strings.Trim(v, `"`)
		}
	}
	return m
}

func TestLegacyPlatform(t *testing.T) {
	for name, rp := range fixtures(t) {
		withHost(t, rp)
		raw, err := rp.ReadFile("/etc/os-release")
		if err != nil {
			t.Fatal(err)
		}
		kernel, _ := rp.ReadFile("/proc/sys/kernel/osrelease")
		want := legacyOSRelease(raw)
		plat, got := hostPlatform()
		for _, k := range []string{"ID", "VERSION_ID", "VERSION", "PRETTY_NAME", "ID_LIKE"} {
			if got[k] != want[k] {
				t.Errorf("%s %s: %q, legacy %q", name, k, got[k], want[k])
			}
		}
		if plat.PrettyName != want["PRETTY_NAME"] || plat.Kernel != strings.TrimSpace(string(kernel)) {
			t.Errorf("%s: platform %+v", name, plat)
		}
	}
}

// commOverlay answers /proc/PID/comm from /proc/PID/status when a fixture
// predates comm being recorded, so legacy and new code see the same name.
type commOverlay struct{ hostenv.Source }

func (c commOverlay) ReadFile(p string) ([]byte, error) {
	b, err := c.Source.ReadFile(p)
	if rest, ok := strings.CutPrefix(p, "/proc/"); ok && strings.HasSuffix(rest, "/comm") && errors.Is(err, hostenv.ErrNotRecorded) {
		st, serr := c.Source.ReadFile(strings.TrimSuffix(p, "comm") + "status")
		if serr != nil {
			return nil, serr
		}
		return []byte(hostenv.ParseProcStatus(st).Name + "\n"), nil
	}
	return b, err
}

// legacyListeningPorts is tools/system.go ListeningPorts before 1c, with
// os.* replaced by the same reads through src.
func legacyListeningPorts(src hostenv.Source) []Port {
	type netEntry struct {
		localIP           net.IP
		localPort         int
		state, uid, inode string
	}
	parseHexAddr := func(s string) (net.IP, int) {
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
	readProcNet := func(proto string) []netEntry {
		b, err := src.ReadFile("/proc/net/" + proto)
		if err != nil {
			return nil
		}
		var out []netEntry
		sc := bufio.NewScanner(strings.NewReader(string(b)))
		sc.Scan()
		for sc.Scan() {
			fs := strings.Fields(sc.Text())
			if len(fs) < 10 {
				continue
			}
			lip, lport := parseHexAddr(fs[1])
			out = append(out, netEntry{lip, lport, fs[3], fs[7], fs[9]})
		}
		return out
	}
	var pids []int
	names, _ := src.ReadDir("/proc")
	for _, n := range names {
		if v, err := strconv.Atoi(n); err == nil {
			pids = append(pids, v)
		}
	}
	comm := func(pid int) string {
		b, _ := src.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
		return strings.TrimSpace(string(b))
	}
	owners := map[string]int{}
	for _, pid := range pids {
		fds, _ := src.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
		for _, fd := range fds {
			link, err := src.Readlink(fmt.Sprintf("/proc/%d/fd/%s", pid, fd))
			if err == nil && strings.HasPrefix(link, "socket:[") {
				owners[strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")] = pid
			}
		}
	}
	var ports []Port
	seen := map[string]bool{}
	for _, proto := range []string{"tcp", "tcp6", "udp", "udp6"} {
		for _, e := range readProcNet(proto) {
			if (strings.HasPrefix(proto, "tcp") && e.state != "0A") || (strings.HasPrefix(proto, "udp") && e.state != "07") {
				continue
			}
			p := Port{Proto: proto, Addr: e.localIP.String(), Port: e.localPort, UID: e.uid}
			if pid, ok := owners[e.inode]; ok {
				p.PID = pid
				p.Process = comm(pid)
				p.Exe, _ = src.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
			}
			key := fmt.Sprintf("%s/%s/%d", proto, p.Addr, p.Port)
			if !seen[key] {
				seen[key] = true
				ports = append(ports, p)
			}
		}
	}
	sort.Slice(ports, func(i, j int) bool { return ports[i].Port < ports[j].Port })
	return ports
}

func TestLegacyListeners(t *testing.T) {
	for name, rp := range fixtures(t) {
		src := commOverlay{rp}
		withHost(t, src)
		got, _ := ListeningPorts()
		want := legacyListeningPorts(src)
		if len(want) == 0 {
			t.Fatalf("%s: legacy found no ports", name)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s:\n got %+v\nwant %+v", name, got, want)
		}
	}
}

// legacyProcesses is tools/system.go Processes before 1c, I/O through src.
func legacyProcesses(src hostenv.Source, all bool) []Proc {
	names := map[string]string{}
	pw, _ := src.ReadFile("/etc/passwd")
	for _, line := range strings.Split(string(pw), "\n") {
		f := strings.Split(line, ":")
		if len(f) < 3 {
			continue
		}
		if _, dup := names[f[2]]; !dup {
			names[f[2]] = f[0]
		}
	}
	procStart := func(pid int) (int64, bool) {
		b, err := src.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if err != nil {
			return 0, false
		}
		i := bytes.LastIndexByte(b, ')')
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
	self := os.Getpid()
	var out, seen []Proc
	start := map[int]int64{}
	ents, _ := src.ReadDir("/proc")
	for _, e := range ents {
		pid, err := strconv.Atoi(e)
		if err != nil || pid == self {
			continue
		}
		status, err := src.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
		if err != nil {
			continue
		}
		cb, _ := src.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
		p := Proc{PID: pid, Comm: strings.TrimSpace(string(cb))}
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
		p.Exe, _ = src.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
		cmd, _ := src.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		p.Cmdline = strings.TrimSpace(strings.ReplaceAll(string(cmd), "\x00", " "))
		if len(p.Cmdline) > 300 {
			p.Cmdline = Cut(p.Cmdline, 300)
		}
		if st, err := hostenv.Stat(src, fmt.Sprintf("/proc/%d", pid)); err == nil {
			p.Started = st.ModTime.Format(time.RFC3339)
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

func TestLegacyProcesses(t *testing.T) {
	for name, rp := range fixtures(t) {
		src := commOverlay{rp}
		withHost(t, src)
		for _, all := range []bool{true, false} {
			got, want := Processes(all), legacyProcesses(src, all)
			if all && len(want) < 50 {
				t.Fatalf("%s: legacy saw only %d processes", name, len(want))
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("%s all=%v: %d vs legacy %d processes", name, all, len(got), len(want))
				for i := range min(len(got), len(want)) {
					if !reflect.DeepEqual(got[i], want[i]) {
						t.Errorf(" first diff:\n got %+v\nwant %+v", got[i], want[i])
						break
					}
				}
			}
		}
	}
}

// block_ip must refuse when the connection table was cut short: the
// operator's SSH session could be in the part not read.
func TestSSHPeersFailClosed(t *testing.T) {
	withHost(t, truncatedNet{})
	if _, err := SSHPeers(); err == nil {
		t.Fatal("SSHPeers reported a complete table")
	}
	if _, err := blockIP.Preview(json.RawMessage(`{"ip":"203.0.113.7","reason":"x"}`)); err == nil || !strings.Contains(err.Error(), "could not be read in full") {
		t.Errorf("block_ip did not refuse: %v", err)
	}
}

type truncatedNet struct{ hostenv.Source }

func (truncatedNet) Info() hostenv.SourceInfo { return hostenv.SourceInfo{GOOS: "linux"} }
func (truncatedNet) ReadFile(p string) ([]byte, error) {
	if p == "/proc/net/tcp" {
		return []byte("  sl  local_address rem_address   st\n"), hostenv.ErrTruncated
	}
	return nil, os.ErrNotExist
}

// legacyAccounts is the passwd part of AccountsAudit, and userNames, before 1c.
func legacyAccounts(src hostenv.Source) (uid0, login []string, names map[string]string) {
	b, _ := src.ReadFile("/etc/passwd")
	names = map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Split(line, ":")
		if len(f) >= 3 {
			if _, dup := names[f[2]]; !dup {
				names[f[2]] = f[0]
			}
		}
		if len(f) < 7 {
			continue
		}
		user, uid, shell := f[0], f[2], f[6]
		if uid == "0" {
			uid0 = append(uid0, user)
		}
		if base := filepath.Base(shell); !strings.HasSuffix(shell, "nologin") && base != "false" && base != "sync" && base != "shutdown" && base != "halt" {
			login = append(login, user)
		}
	}
	return uid0, login, names
}

func TestLegacyAccounts(t *testing.T) {
	for name, rp := range fixtures(t) {
		withHost(t, rp)
		uid0, login, names := legacyAccounts(rp)
		a := AccountsAudit()
		if !reflect.DeepEqual(a.UID0, uid0) || !reflect.DeepEqual(a.LoginAccounts, login) || len(login) == 0 {
			t.Errorf("%s: uid0 %v / %v, login %v / %v", name, a.UID0, uid0, a.LoginAccounts, login)
		}
		if got := userNames(); !reflect.DeepEqual(got, names) {
			t.Errorf("%s: userNames differ", name)
		}
	}
	// Edge cases the fixtures lack: an empty shell logs in (/bin/sh), and
	// a second UID 0 account does not take root's name.
	h := memHost{"/etc/passwd": "root:x:0:0::/root:/bin/bash\ntoor:x:0:0::/root:\nsvc:x:5:5::/:/usr/sbin/nologin\n"}
	withHost(t, h)
	uid0, login, names := legacyAccounts(h)
	a := AccountsAudit()
	if !reflect.DeepEqual(a.UID0, uid0) || !reflect.DeepEqual(a.LoginAccounts, login) || userNames()["0"] != names["0"] {
		t.Errorf("edge: %v %v / %v %v", a.UID0, a.LoginAccounts, uid0, login)
	}
	// N5: odd lines (an eighth field, a comment, a blank, a short line).
	h = memHost{"/etc/passwd": "root:x:0:0::/root:/bin/bash\nhide:x:0:0::/root:/bin/sh:extra\n# c\n\nshort:x:9\nops:x:1000:1000::/home/ops:/bin/zsh\n"}
	withHost(t, h)
	uid0, login, _ = legacyAccounts(h)
	if a := AccountsAudit(); !reflect.DeepEqual(a.UID0, uid0) || !reflect.DeepEqual(a.LoginAccounts, login) || len(uid0) != 2 {
		t.Errorf("odd lines: %v %v / %v %v", a.UID0, a.LoginAccounts, uid0, login)
	}
}

// memHost is a tiny file-only Source for edge cases.
type memHost map[string]string

func (memHost) Info() hostenv.SourceInfo { return hostenv.SourceInfo{GOOS: "linux"} }
func (m memHost) ReadFile(p string) ([]byte, error) {
	if s, ok := m[p]; ok {
		return []byte(s), nil
	}
	return nil, os.ErrNotExist
}
func (memHost) ReadDir(string) ([]string, error) { return nil, os.ErrNotExist }
func (memHost) Readlink(string) (string, error)  { return "", os.ErrNotExist }
func (memHost) Run(context.Context, []string) (hostenv.CmdResult, error) {
	return hostenv.CmdResult{}, os.ErrNotExist
}

// legacyPackages is installedPackages before 1c, run on the same package
// data: the fixtures hold the new dpkg-query/rpm output, which carries
// every field the old format printed, so it is cut back to the old
// columns first and parsed the old way.
func legacyPackages(src hostenv.Source) (string, []pkg) {
	b, _ := src.ReadFile("/etc/os-release")
	osr := legacyOSRelease(b)
	id, ver := osr["ID"], osr["VERSION_ID"]
	parseTSV := func(s string, keep func([]string) bool) []pkg {
		var out []pkg
		sc := bufio.NewScanner(strings.NewReader(s))
		for sc.Scan() {
			f := strings.Split(sc.Text(), "\t")
			if len(f) < 2 || f[0] == "" || (keep != nil && !keep(f)) {
				continue
			}
			out = append(out, pkg{f[0], f[1]})
		}
		return out
	}
	recorded := func(argv []string, cols ...int) string {
		res, err := src.Run(context.Background(), argv)
		if err != nil {
			return ""
		}
		var lines []string
		for _, l := range strings.Split(string(res.Stdout), "\n") {
			f := strings.Split(l, "\t")
			var keep []string
			for _, c := range cols {
				if c < len(f) {
					keep = append(keep, f[c])
				}
			}
			lines = append(lines, strings.Join(keep, "\t"))
		}
		return strings.Join(lines, "\n")
	}
	switch id {
	case "ubuntu", "debian":
		eco := "Debian:" + strings.Split(ver, ".")[0]
		if id == "ubuntu" {
			eco = "Ubuntu:" + ver
			if strings.Contains(osr["VERSION"], "LTS") {
				eco += ":LTS"
			}
		}
		// old -f: ${source:Package}\t${Version}\t${db:Status-Abbrev}; dpkg prints
		// the binary name for ${source:Package} when there is no source.
		out := recorded([]string{"/usr/bin/dpkg-query", "-W", "-f", hostenv.DpkgQueryFormat}, 1, 2, 4)
		var fixed []string
		full := recorded([]string{"/usr/bin/dpkg-query", "-W", "-f", hostenv.DpkgQueryFormat}, 0)
		names := strings.Split(full, "\n")
		for i, l := range strings.Split(out, "\n") {
			if strings.HasPrefix(l, "\t") && i < len(names) {
				l = names[i] + l
			}
			fixed = append(fixed, l)
		}
		return eco, uniq(parseTSV(strings.Join(fixed, "\n"), func(f []string) bool { return len(f) > 2 && strings.HasPrefix(f[2], "ii") }))
	case "rocky", "almalinux":
		eco := map[string]string{"rocky": "Rocky Linux", "almalinux": "AlmaLinux"}[id] + ":" + strings.Split(ver, ".")[0]
		return eco, uniq(parseTSV(recorded([]string{"/usr/bin/rpm", "-qa", "--qf", hostenv.RpmQueryFormat}, 0, 1), nil))
	}
	return "", nil
}

func TestLegacyPackages(t *testing.T) {
	for name, rp := range fixtures(t) {
		withHost(t, rp)
		eco, pkgs, err := installedPackages(context.Background())
		weco, want := legacyPackages(rp)
		if err != nil || eco != weco || len(want) < 100 || !reflect.DeepEqual(pkgs, want) {
			t.Errorf("%s: eco %q/%q, %d/%d packages, err %v", name, eco, weco, len(pkgs), len(want), err)
		}
	}
}

// legacyParseKeyLine and legacyReadKeyFile are tools/persistence.go and
// tools/system.go of v0.2.5 (d4a8ea9), verbatim.
func legacyParseKeyLine(line string) (keyType, fp string, unparsed bool) {
	short := map[string]bool{"rsa": true, "dsa": true, "ecdsa": true, "ed25519": true, "ecdsa-sk": true, "ed25519-sk": true,
		"xmss": true, "rsa-cert": true, "dsa-cert": true, "ecdsa-cert": true, "ed25519-cert": true, "ecdsa-sk-cert": true,
		"ed25519-sk-cert": true, "xmss-cert": true}
	full := func(t string) bool {
		return strings.HasPrefix(t, "ssh-") || strings.HasPrefix(t, "ecdsa-") || strings.HasPrefix(t, "sk-")
	}
	name := func(t string) bool { return full(strings.ToLower(t)) || short[strings.ToLower(t)] }
	keyAt := func(s string) (string, string) {
		f := strings.Fields(s)
		if len(f) < 2 || !name(f[0]) {
			return "", ""
		}
		blob, err := base64.StdEncoding.DecodeString(f[1])
		if err != nil || len(blob) < 16 {
			return "", ""
		}
		n := int(binary.BigEndian.Uint32(blob))
		if n <= 0 || n > 64 || 4+n > len(blob) {
			return "", ""
		}
		kt := string(blob[4 : 4+n])
		if !full(kt) {
			return "", ""
		}
		sum := sha256.Sum256(blob)
		return kt, "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
	}
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", "", false
	}
	if t, fp := keyAt(line); fp != "" {
		return t, fp, false
	}
	quoted := false
	i := 0
	for ; i < len(line) && (quoted || (line[i] != ' ' && line[i] != '\t')); i++ {
		if line[i] == '\\' && i+1 < len(line) && line[i+1] == '"' {
			i++
		} else if line[i] == '"' {
			quoted = !quoted
		}
	}
	if t, fp := keyAt(strings.TrimSpace(line[i:])); fp != "" {
		return t, fp, false
	}
	return "", "", true
}

func legacyReadKeyFile(b []byte) (keys []KeyEntry, unparsed []int) {
	for i, l := range strings.Split(string(b), "\n") {
		t, fp, bad := legacyParseKeyLine(l)
		switch {
		case fp != "":
			keys = append(keys, KeyEntry{i + 1, t, fp})
		case bad:
			unparsed = append(unparsed, i+1)
		}
	}
	return keys, unparsed
}

// legacyAuditAt is AccountsAudit's key-file and sudoers parts and survey's
// cronFiles before 1c, with every absolute path read under root.
func legacyAuditAt(root string) (keys []KeyFile, sudo, cron []string) {
	at := func(p string) string { return filepath.Join(root, p) }
	seenKeys := map[string]bool{}
	b, _ := os.ReadFile(at("/etc/passwd"))
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Split(line, ":")
		if len(f) < 7 {
			continue
		}
		user, home := f[0], f[5]
		for _, name := range []string{"authorized_keys", "authorized_keys2"} {
			p := filepath.Join(home, ".ssh", name)
			if seenKeys[p] {
				continue
			}
			seenKeys[p] = true
			if st, err := os.Stat(at(p)); err == nil {
				kb, _ := os.ReadFile(at(p))
				ks, bad := legacyReadKeyFile(kb)
				keys = append(keys, KeyFile{User: user, Path: p, Keys: len(ks), Modified: st.ModTime(), KeyList: ks, Unparsed: bad})
			}
		}
	}
	files, _ := filepath.Glob(at("/etc/sudoers.d/*"))
	for _, f := range append([]string{at("/etc/sudoers")}, files...) {
		sb, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, l := range strings.Split(string(sb), "\n") {
			l = strings.TrimSpace(l)
			if l != "" && !strings.HasPrefix(l, "#") && !strings.HasPrefix(l, "Defaults") && strings.Contains(l, "ALL") {
				sudo = append(sudo, strings.TrimPrefix(f, root)+": "+l)
			}
		}
	}
	for _, pat := range []string{"/etc/crontab", "/etc/cron.d/*", "/var/spool/cron/crontabs/*", "/var/spool/cron/*"} {
		fs, _ := filepath.Glob(at(pat))
		for _, f := range fs {
			if st, err := os.Stat(f); err == nil && st.Mode().IsRegular() {
				cron = append(cron, strings.TrimPrefix(f, root))
			}
		}
	}
	sort.Strings(cron)
	return keys, sudo, cron
}

func TestLegacyPersistenceTree(t *testing.T) {
	root := t.TempDir()
	w := func(p, body string) {
		os.MkdirAll(filepath.Dir(filepath.Join(root, p)), 0o755)
		if err := os.WriteFile(filepath.Join(root, p), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	k1, k2 := fakeKey(t), fakeKey(t)
	w("/etc/passwd", "root:x:0:0::/root:/bin/bash\noperator:x:11:0::/root:/sbin/nologin\nwww-data:x:33:33::/var/www:/usr/sbin/nologin\nann:x:1000:1000::/home/ann:/bin/bash\n")
	w("/root/.ssh/authorized_keys", k1+" a\n# c\n"+k2+"\n")
	w("/var/www/.ssh/authorized_keys", k2+" planted\n") // a nologin account: still counted
	w("/home/ann/.ssh/authorized_keys2", "\n"+k1+"\n")
	w("/etc/sudoers", "Defaults env_reset\nroot ALL=(ALL:ALL) ALL\n%sudo ALL=(ALL) ALL\n# x ALL\n")
	w("/etc/sudoers.d/90-cloud", "ann ALL=(ALL) NOPASSWD:ALL\n")
	w("/etc/sudoers.d/.hidden", "www-data ALL=(ALL) NOPASSWD: ALL\n")
	w("/etc/crontab", "* * * * * root x\n")
	w("/etc/cron.d/backup", "")
	w("/var/spool/cron/crontabs/ann", "* * * * * y\n")
	w("/var/spool/cron/.x", "z\n")

	live, _ := hostenv.NewLive(nil)
	live.Remap = map[string]string{"/": root}
	withHost(t, live)
	keys, sudo, cron := legacyAuditAt(root)
	a := AccountsAudit()
	if len(keys) != 3 || !reflect.DeepEqual(a.KeyFiles, keys) {
		t.Errorf("key files:\n got %+v\nwant %+v", a.KeyFiles, keys)
	}
	if len(sudo) != 4 || !reflect.DeepEqual(a.SudoRules, sudo) {
		t.Errorf("sudo:\n got %q\nwant %q", a.SudoRules, sudo)
	}
	if got := cronFiles(); len(cron) != 4 || !reflect.DeepEqual(got, cron) {
		t.Errorf("cron:\n got %q\nwant %q", got, cron)
	}
	if len(a.SharedKeys) != 2 {
		t.Errorf("shared keys %+v", a.SharedKeys)
	}
}

// legacySSHD is sshdSettings before 1c (as of f9264fd), I/O through src.
func legacySSHD(src hostenv.Source, config string) (map[string]string, string, []string) {
	legacyFields := func(line string) []string {
		line = strings.TrimSpace(line)
		i := strings.IndexAny(line, " \t=")
		if i < 0 {
			return []string{line}
		}
		rest := strings.TrimLeft(line[i:], " \t")
		if strings.HasPrefix(rest, "=") {
			rest = rest[1:]
		}
		return append([]string{line[:i]}, strings.Fields(rest)...)
	}
	want := map[string]string{"port": "22", "permitrootlogin": "prohibit-password", "passwordauthentication": "yes",
		"pubkeyauthentication": "yes", "permitemptypasswords": "no", "x11forwarding": "no"}
	got := map[string]bool{}
	h := sha256.New()
	var unread []string
	unknown := func(path string, err error) {
		why := err.Error()
		if errors.Is(err, fs.ErrPermission) {
			why = "permission denied"
		} else if pe := (*fs.PathError)(nil); errors.As(err, &pe) {
			why = pe.Err.Error()
		}
		unread = append(unread, path+" ("+why+")")
		for k := range want {
			if !got[k] {
				want[k], got[k] = "unknown", true
			}
		}
	}
	var read func(path string, depth int) bool
	read = func(path string, depth int) bool {
		if depth > 4 {
			return true
		}
		b, err := src.ReadFile(path)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				unknown(path, err)
			}
			return true
		}
		h.Write(b)
		for _, line := range strings.Split(string(b), "\n") {
			f := legacyFields(line)
			if len(f) < 2 || strings.HasPrefix(f[0], "#") {
				continue
			}
			key := strings.ToLower(f[0])
			if key == "match" {
				return false
			}
			if key == "include" {
				for _, pat := range f[1:] {
					if !strings.HasPrefix(pat, "/") {
						pat = filepath.Join(filepath.Dir(config), pat)
					}
					if _, err := src.ReadDir(filepath.Dir(pat)); err != nil && !errors.Is(err, fs.ErrNotExist) {
						unknown(filepath.Dir(pat), err)
					}
					files := hostenv.Glob(src, pat) // filepath.Glob through src
					for _, inc := range files {
						if !read(inc, depth+1) {
							return false
						}
					}
				}
				continue
			}
			if _, ok := want[key]; ok && !got[key] {
				want[key], got[key] = strings.ToLower(f[1]), true
			}
		}
		return true
	}
	read(config, 0)
	return want, hex.EncodeToString(h.Sum(nil))[:16], unread
}

func TestLegacySSHD(t *testing.T) {
	for name, rp := range fixtures(t) {
		withHost(t, rp)
		ws, wh, wu := legacySSHD(rp, "/etc/ssh/sshd_config")
		gs, gh, gu := sshdSettings()
		if !reflect.DeepEqual(gs, ws) || gh != wh || !reflect.DeepEqual(gu, wu) {
			t.Errorf("%s:\n got %v %s %q\nwant %v %s %q", name, gs, gh, gu, ws, wh, wu)
		}
		if strings.HasSuffix(name, "-user") != (len(wu) > 0) {
			t.Logf("%s: unread %q", name, wu)
		}
	}
}

// scriptHost is a Source with files, links and canned command results.
type scriptHost struct {
	memHost
	cmds map[string]hostenv.CmdResult
	stat map[string]bool
}

func (h scriptHost) Run(_ context.Context, argv []string) (hostenv.CmdResult, error) {
	if r, ok := h.cmds[strings.Join(argv, " ")]; ok {
		return r, nil
	}
	return hostenv.CmdResult{}, os.ErrNotExist
}
func (h scriptHost) Stat(p string) (hostenv.FileStat, error) {
	if h.stat[p] {
		return hostenv.FileStat{}, nil
	}
	if _, ok := h.memHost[p]; ok {
		return hostenv.FileStat{}, nil
	}
	return hostenv.FileStat{}, os.ErrNotExist
}

// legacyFirewall is survey's firewall() before 1c; "err != nil" of exec is
// a missing binary (ErrNotFound) or a non-zero exit, as here.
func legacyFirewall(h scriptHost, running []string) string {
	if b, err := h.ReadFile("/etc/ufw/ufw.conf"); err == nil && strings.Contains(string(b), "ENABLED=yes") {
		return "ufw (enabled)"
	}
	for _, p := range running {
		if p == "firewalld" {
			return "firewalld (running)"
		}
	}
	run := func(argv string) (string, bool, bool) { // out, ok, notFound
		r, err := h.Run(context.Background(), strings.Fields(argv))
		return string(r.Stdout), err == nil && r.ExitCode == 0, err != nil
	}
	if out, ok, notFound := run("/usr/sbin/nft list ruleset"); ok {
		if chains := strings.Count(out, "chain "); chains > 0 {
			return fmt.Sprintf("nftables (%d chains)", chains)
		}
	} else if !notFound {
		enabled := false
		for _, d := range []string{"/etc/systemd/system/multi-user.target.wants", "/etc/systemd/system/sysinit.target.wants"} {
			if h.stat[d+"/nftables.service"] {
				enabled = true
			}
		}
		if enabled {
			for _, c := range []string{"/etc/nftables.conf", "/etc/sysconfig/nftables.conf"} {
				if b, err := h.ReadFile(c); err == nil {
					return fmt.Sprintf("nftables (enabled at boot, %d chains in %s; live rules: ask in chat)", strings.Count(string(b), "chain "), c)
				}
			}
			return "nftables (enabled at boot; live rules: ask in chat)"
		}
		return "no firewall enabled at boot (nftables.service is off); rules added at runtime cannot be read here, ask in chat"
	}
	if out, ok, _ := run("/usr/sbin/iptables -S"); ok && strings.Count(out, "\n") > 3 {
		return "iptables rules present"
	}
	return "none detected"
}

func TestLegacyFirewall(t *testing.T) {
	ok := func(out string) hostenv.CmdResult { return hostenv.CmdResult{Stdout: []byte(out)} }
	denied := hostenv.CmdResult{ExitCode: 1, Stderr: "Operation not permitted"}
	nft, ipt := "/usr/sbin/nft list ruleset", "/usr/sbin/iptables -S"
	cases := map[string]struct {
		h       scriptHost
		running []string
	}{
		"ufw":           {scriptHost{memHost: memHost{"/etc/ufw/ufw.conf": "ENABLED=yes\n"}}, nil},
		"ufw off":       {scriptHost{memHost: memHost{"/etc/ufw/ufw.conf": "ENABLED=no\n"}}, nil},
		"firewalld":     {scriptHost{memHost: memHost{}}, []string{"sshd", "firewalld"}},
		"nft live":      {scriptHost{memHost: memHost{}, cmds: map[string]hostenv.CmdResult{nft: ok("table inet f {\n chain input {\n }\n chain output {\n }\n}\n")}}, nil},
		"nft empty":     {scriptHost{memHost: memHost{}, cmds: map[string]hostenv.CmdResult{nft: ok(""), ipt: ok("-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n-A INPUT -j DROP\n")}}, nil},
		"nft boot":      {scriptHost{memHost: memHost{"/etc/nftables.conf": "chain a\nchain b\nchain c\n"}, cmds: map[string]hostenv.CmdResult{nft: denied}, stat: map[string]bool{"/etc/systemd/system/sysinit.target.wants/nftables.service": true}}, nil},
		"nft boot conf": {scriptHost{memHost: memHost{}, cmds: map[string]hostenv.CmdResult{nft: denied}, stat: map[string]bool{"/etc/systemd/system/multi-user.target.wants/nftables.service": true}}, nil},
		"nft boot off":  {scriptHost{memHost: memHost{}, cmds: map[string]hostenv.CmdResult{nft: denied}}, nil},
		"iptables":      {scriptHost{memHost: memHost{}, cmds: map[string]hostenv.CmdResult{ipt: ok("-P INPUT DROP\n-P FORWARD DROP\n-P OUTPUT ACCEPT\n-A INPUT -i lo -j ACCEPT\n")}}, nil},
		"none":          {scriptHost{memHost: memHost{}, cmds: map[string]hostenv.CmdResult{ipt: denied}}, nil},
	}
	for name, c := range cases {
		var procs []hostenv.Process
		for _, n := range c.running {
			procs = append(procs, hostenv.Process{Name: n})
		}
		got := linux.Firewall(context.Background(), c.h, procs).Value.Extra["summary"]
		if want := legacyFirewall(c.h, c.running); got != want {
			t.Errorf("%s: %q, legacy %q", name, got, want)
		}
	}
}

// legacySSHAggregate is SSHSummary's grouping before 1c (the regexes are
// the same strings, so they are taken from the parsing it feeds).
func legacySSHAggregate(lines []string, since time.Time, onlyIP string) []SSHSource {
	prefix := `^(?:\S+|\w{3} +\d+ \d\d:\d\d:\d\d) \S+ sshd(?:-session)?\[\d+\]: `
	reF := regexp.MustCompile(prefix + `Failed (?:password|publickey|keyboard-interactive/pam|none) for (?:invalid user )?(.*) from (\S+) port \d+(?: ssh2)?(?: \[preauth\])?\s*$`)
	reI := regexp.MustCompile(prefix + `Invalid user (.*) from (\S+) port \d+(?: \[preauth\])?\s*$`)
	reA := regexp.MustCompile(prefix + `Accepted (\S+) for (\S+) from (\S+) port \d+ ssh2(?:: .*)?$`)
	parse := func(line string) (time.Time, bool) {
		if i := strings.IndexByte(line, ' '); i > 0 {
			for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05-0700"} {
				if t, err := time.Parse(layout, line[:i]); err == nil {
					return t, true
				}
			}
		}
		if len(line) >= 15 {
			t, err := time.ParseInLocation("Jan _2 15:04:05", line[:15], time.Local)
			if err == nil {
				now := time.Now()
				t = t.AddDate(now.Year(), 0, 0)
				if t.After(now.Add(24 * time.Hour)) {
					t = t.AddDate(-1, 0, 0)
				}
				return t, true
			}
		}
		return time.Time{}, false
	}
	by := map[string]*SSHSource{}
	users := map[string]map[string]map[string]bool{}
	for _, l := range lines {
		ts, ok := parse(l)
		if !ok || ts.Before(since) {
			continue
		}
		var ip, user, kind string
		if m := reF.FindStringSubmatch(l); m != nil {
			user, ip, kind = m[1], m[2], "failed"
		} else if m := reI.FindStringSubmatch(l); m != nil {
			user, ip, kind = m[1], m[2], "invalid"
		} else if m := reA.FindStringSubmatch(l); m != nil {
			user, ip, kind = m[2], m[3], "accepted"
		} else {
			continue
		}
		if net.ParseIP(ip) == nil {
			continue
		}
		if strings.Contains(user, " from ") || strings.Contains(user, ": ") {
			user = "[crafted user name]"
		}
		if len(user) > 64 {
			user = Cut(user, 64)
		}
		if onlyIP != "" && ip != onlyIP {
			continue
		}
		s := by[ip]
		if s == nil {
			s = &SSHSource{IP: ip, First: ts}
			by[ip] = s
			users[ip] = map[string]map[string]bool{"failed": {}, "invalid": {}, "accepted": {}}
		}
		switch kind {
		case "failed":
			s.Failed++
		case "invalid":
			s.InvalidUser++
		case "accepted":
			s.Accepted++
		}
		if ts.Before(s.First) {
			s.First = ts
		}
		if ts.After(s.Last) {
			s.Last = ts
		}
		if len(users[ip][kind]) < 20 {
			users[ip][kind][user] = true
		}
	}
	list := []SSHSource{}
	for ip, s := range by {
		names := func(kind string) []string {
			var l []string
			for u := range users[ip][kind] {
				l = append(l, u)
			}
			sort.Strings(l)
			return l
		}
		s.FailedUsers, s.InvalidUsers, s.AcceptedUsers = names("failed"), names("invalid"), names("accepted")
		list = append(list, *s)
	}
	return list
}

func TestLegacySSHLogins(t *testing.T) {
	now := time.Now()
	iso := func(d time.Duration) string { return now.Add(d).UTC().Format("2006-01-02T15:04:05.000000-07:00") }
	var lines []string
	for i := range 300 { // more than 50 sources and more than 20 names, ties included
		lines = append(lines,
			fmt.Sprintf("%s vm sshd[%d]: Failed password for invalid user u%d from 203.0.%d.%d port 4000 ssh2", iso(-time.Duration(i)*time.Minute), i, i, i%7, i%60),
			fmt.Sprintf("%s vm sshd[%d]: Invalid user n%d from 198.51.100.%d port 22 [preauth]", now.Add(-time.Duration(i)*time.Second).Format("Jan _2 15:04:05"), i, i, i%3),
		)
	}
	lines = append(lines,
		iso(-time.Hour)+" vm sshd[1]: Accepted publickey for ops from 192.0.2.10 port 5000 ssh2: ED25519 SHA256:x",
		iso(-time.Hour)+" vm sshd[2]: Invalid user x from 192.0.2.10 port 1 from 203.0.113.50 port 2222",
		iso(-time.Hour)+" vm sshd-session[3]: Failed password for "+strings.Repeat("é", 40)+" from 192.0.2.30 port 1 ssh2",
		iso(-30*time.Hour)+" vm sshd[4]: Failed password for root from 203.0.113.99 port 1 ssh2",
		// N6: masking must not change a count; only the names output are masked.
		iso(-time.Hour)+" vm sshd[5]: Invalid user -----BEGIN OPENSSH "+"PRIVATE KEY----- from 192.0.2.40 port 22",
		iso(-time.Hour)+" vm sshd[6]: Failed password for invalid user tok"+"en=abcdefgh from 192.0.2.40 port 22 ssh2",
	)
	since := now.Add(-24 * time.Hour)
	// The whole path: a log file, ScanAuthLogs, the aggregate, masked output.
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "auth.log"), []byte(strings.Join(lines, "\n")+"\n"), 0o600)
	noCmds, _ := hostenv.NewRunner(nil) // no journalctl: the text log is read, as v0.2.5 did
	live := &hostenv.Live{Runner: noCmds, Remap: map[string]string{"/var/log": dir}}
	for _, only := range []string{"", "192.0.2.10", "192.0.2.40"} {
		want := legacySSHAggregate(lines, since, only)
		for i := range want { // v0.2.5 output names as read; now they are masked
			for _, l := range []*[]string{&want[i].FailedUsers, &want[i].InvalidUsers, &want[i].AcceptedUsers} {
				for j := range *l {
					(*l)[j] = hostenv.MaskSecrets((*l)[j])
				}
				sort.Strings(*l)
			}
		}
		var agg *hostenv.SSHLogins
		src, verified, err := linux.ScanAuthLogs(context.Background(), live, []string{"/var/log/auth.log"}, since, func() func(string) {
			agg = hostenv.NewSSHLogins(since, now, only)
			return agg.Add
		})
		if err != nil {
			t.Fatal(src, err)
		}
		// Expected difference from v0.2.5: the same events, but a text log
		// is now marked unverified (journald comes first since v0.3.0).
		if verified || !strings.HasPrefix(src, "/var/log/auth.log (unverified: journald unavailable") {
			t.Errorf("source %q verified %v", src, verified)
		}
		got := agg.Result()
		if only == "192.0.2.40" {
			if len(got) != 1 || got[0].Failed+got[0].InvalidUser != 2 || strings.Contains(fmt.Sprint(got), "abcdefgh") || strings.Contains(fmt.Sprint(got), "BEGIN OPENSSH") {
				t.Errorf("masked names changed the count, or a name went out unmasked: %+v", got)
			}
		}
		// The legacy order of equal counts was map order; compare by IP, and
		// check the new list is the legacy one cut at the same 50.
		sortIP := func(l []SSHSource) { sort.Slice(l, func(i, j int) bool { return l[i].IP < l[j].IP }) }
		total := func(s SSHSource) int { return s.Failed + s.InvalidUser }
		sort.SliceStable(want, func(i, j int) bool { return total(want[i]) > total(want[j]) })
		if len(want) > 50 {
			cut := total(want[49])
			var keep []SSHSource
			for _, s := range want {
				if total(s) > cut {
					keep = append(keep, s)
				}
			}
			for _, s := range got {
				if total(s) == cut {
					keep = append(keep, s) // which ties make the cut was undefined before
				}
			}
			want = keep[:50]
		}
		sortIP(want)
		g := append([]SSHSource(nil), got...)
		sortIP(g)
		if !reflect.DeepEqual(g, want) {
			t.Errorf("only=%q: %d sources vs legacy %d", only, len(g), len(want))
		}
	}
}

// legacyWebRootsAt is webRootsFrom of v0.2.5 (d4a8ea9), with the
// configuration root and owner as parameters (the package variables there).
func legacyWebRootsAt(globs []string, confRoot string, owner uint32) (out, unreadable []string) {
	nginxRoot := regexp.MustCompile(`(?m)^\s*root\s+["']?([^"';\s]+)`)
	apacheRoot := regexp.MustCompile(`(?mi)^\s*DocumentRoot\s+["']?([^"'\s]+)`)
	errWhy := func(err error) string {
		if pe := (*fs.PathError)(nil); errors.As(err, &pe) {
			return pe.Err.Error()
		}
		return err.Error()
	}
	read := func(p string) ([]byte, string) {
		li, err := os.Lstat(p)
		if err != nil {
			return nil, errWhy(err)
		}
		target := p
		if li.Mode()&os.ModeSymlink != 0 {
			if target, err = filepath.EvalSymlinks(p); err != nil {
				return nil, "symlink: " + errWhy(err)
			}
			if !insideAny(target, []string{confRoot}) {
				return nil, "symlink to " + target + ", outside " + confRoot
			}
			st, err := os.Lstat(target)
			if err != nil {
				return nil, errWhy(err)
			}
			sys, ok := st.Sys().(*syscall.Stat_t)
			switch {
			case !st.Mode().IsRegular():
				return nil, "symlink to " + target + ", not a regular file"
			case !ok || sys.Uid != owner:
				return nil, "symlink to " + target + ", not owned by root"
			case st.Mode().Perm()&0o022 != 0:
				return nil, "symlink to " + target + ", writable by others than its owner"
			}
			li = st
		}
		b, ok := readSmallRegular(target, 1<<20, li)
		if !ok {
			return nil, "not a regular file of at most 1 MiB, or changed while read"
		}
		return b, ""
	}
	seen := map[string]bool{}
	for _, g := range globs {
		files, _ := filepath.Glob(g)
		for _, f := range files {
			b, why := read(f)
			if why != "" {
				unreadable = append(unreadable, f+" ("+why+")")
				continue
			}
			for _, re := range []*regexp.Regexp{nginxRoot, apacheRoot} {
				for _, m := range re.FindAllSubmatch(b, -1) {
					p := filepath.Clean(string(m[1]))
					if strings.HasPrefix(p, "/") && !strings.Contains(p, "$") && !seen[p] {
						seen[p] = true
						out = append(out, p)
					}
				}
			}
		}
	}
	sort.Strings(out)
	return out, unreadable
}

func TestLegacyWebRoots(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	etc := filepath.Join(root, "etc")
	other, _ := filepath.EvalSymlinks(t.TempDir())
	w := func(p, body string, mode os.FileMode) {
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte(body), mode)
		os.Chmod(p, mode)
	}
	w(filepath.Join(etc, "nginx/nginx.conf"), "http {\n  root /usr/share/nginx/html;\n}\n", 0o644)
	w(filepath.Join(etc, "nginx/sites-available/shop"), "server {\n  root /var/www/shop/public;\n}\n", 0o644)
	os.MkdirAll(filepath.Join(etc, "nginx/sites-enabled"), 0o755)
	os.Symlink("../sites-available/shop", filepath.Join(etc, "nginx/sites-enabled/shop")) // Debian: a link
	w(filepath.Join(etc, "nginx/sites-enabled/blog"), "server {\n  root \"/var/www/blog\";\n  # root /old;\n  root $document_root;\n  root relative/path;\n}\n", 0o644)
	w(filepath.Join(etc, "nginx/sites-available/open"), "server {\n root /var/www/open;\n}\n", 0o666)
	os.Symlink("../sites-available/open", filepath.Join(etc, "nginx/sites-enabled/open"))
	w(filepath.Join(other, "evil"), "server {\n root /var/www/evil;\n}\n", 0o644)
	os.Symlink(filepath.Join(other, "evil"), filepath.Join(etc, "nginx/sites-enabled/evil"))
	os.Symlink("loop2", filepath.Join(etc, "nginx/sites-enabled/loop1"))
	os.Symlink("loop1", filepath.Join(etc, "nginx/sites-enabled/loop2"))
	os.Symlink("../sites-available/gone", filepath.Join(etc, "nginx/sites-enabled/broken")) // dangling: listed, as v0.2.5 did
	w(filepath.Join(etc, "nginx/conf.d/big.conf"), "root /var/www/big;\n"+strings.Repeat("#\n", 600000), 0o644)
	w(filepath.Join(etc, "nginx/conf.d/api.conf"), "server { root /srv/api; }\nroot /var/www/blog;\n", 0o644)
	w(filepath.Join(etc, "apache2/sites-enabled/000-default.conf"), "<VirtualHost *:80>\n\tDocumentRoot /var/www/html\n</VirtualHost>\n", 0o644)
	w(filepath.Join(etc, "httpd/conf.d/ssl.conf"), "documentroot '/var/www/ssl'\n", 0o644)
	var globs []string
	for _, g := range hostenv.DefaultWebConf.Globs {
		globs = append(globs, filepath.Join(root, g))
	}
	owner := uint32(os.Getuid()) // the test's user stands for root
	wantRoots, wantUnread := legacyWebRootsAt(globs, etc, owner)
	r, o := webConfRoot, webConfOwner
	defer func() { webConfRoot, webConfOwner = r, o }()
	webConfRoot, webConfOwner = etc, owner
	gotRoots, gotUnread := webRootsFrom(globs)
	if len(wantRoots) < 5 || !reflect.DeepEqual(gotRoots, wantRoots) {
		t.Errorf("web roots:\n got %q\nwant %q", gotRoots, wantRoots)
	}
	if len(wantUnread) < 4 || !reflect.DeepEqual(gotUnread, wantUnread) {
		t.Errorf("unreadable:\n got %q\nwant %q", gotUnread, wantUnread)
	}
}
