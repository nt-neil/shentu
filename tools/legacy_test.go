package tools

// Phase 1c zero-diff harness: the pre-migration implementations, kept here
// verbatim (test-only), run against the same recorded inputs as the new
// hostenv path. A category is migrated when both agree on every fixture.

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

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
