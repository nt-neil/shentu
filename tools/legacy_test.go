package tools

// Phase 1c zero-diff harness: the pre-migration implementations, kept here
// verbatim (test-only), run against the same recorded inputs as the new
// hostenv path. A category is migrated when both agree on every fixture.

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
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
