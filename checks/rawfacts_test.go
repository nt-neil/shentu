package checks

import (
	"context"
	"encoding/json"
	"io/fs"
	"strings"
	"testing"

	"github.com/nt-neil/shentu/hostenv"
)

// liveLike answers as a live host does: Run masked (stdout and stderr, as
// Runner.Run), RunUnmasked as written.
type liveLike struct {
	goos  string
	cmds  map[string]string
	files map[string]string
}

func (l liveLike) Info() hostenv.SourceInfo { return hostenv.SourceInfo{GOOS: l.goos, GOARCH: "arm64"} }
func (l liveLike) ReadFile(p string) ([]byte, error) {
	if s, ok := l.files[p]; ok {
		return []byte(s), nil
	}
	return nil, &fs.PathError{Op: "open", Path: p, Err: fs.ErrNotExist}
}
func (l liveLike) ReadDir(p string) ([]string, error) {
	return nil, &fs.PathError{Op: "open", Path: p, Err: fs.ErrNotExist}
}
func (l liveLike) Readlink(p string) (string, error) {
	return "", &fs.PathError{Op: "readlink", Path: p, Err: fs.ErrNotExist}
}
func (l liveLike) RunUnmasked(_ context.Context, argv []string) (hostenv.CmdResult, error) {
	if s, ok := l.cmds[strings.Join(argv, " ")]; ok {
		return hostenv.CmdResult{Stdout: []byte(s)}, nil
	}
	return hostenv.CmdResult{}, &fs.PathError{Op: "exec", Path: argv[0], Err: fs.ErrNotExist}
}
func (l liveLike) Run(ctx context.Context, argv []string) (hostenv.CmdResult, error) {
	r, err := l.RunUnmasked(ctx, argv)
	r.Stdout, r.Stderr = []byte(hostenv.MaskSecrets(string(r.Stdout))), hostenv.MaskSecrets(r.Stderr)
	return r, err
}

// N-293-1: the collectors parse commands' output as written, and every field
// they keep is masked: the facts (the saved profile, onboard, hostfacts) and
// the checks' evidence hold no secret from the output.
func TestRawOutputFactsMasked(t *testing.T) {
	val := "hunter2" + "x9"
	pw := "password=" + val
	mac := liveLike{goos: "darwin", cmds: map[string]string{
		"/usr/sbin/sysctl -n kern.osrelease hw.memsize vm.loadavg": "24.1.0 " + pw + "\n17179869184\n{ 1.0 1.0 1.0 }\n",
		"/usr/bin/sw_vers": "ProductName:\tmacOS " + pw + "\nProductVersion:\t15.1\nBuildVersion:\t24B83\n",
		"/bin/ps -axww -o pid=,ppid=,uid=,user=,etime=,comm=": "  10 1 501 alice 01:00 /tmp/app " + pw + "\n" +
			"  11 1 501 alice 01:00 /tmp/-----BEGIN " + "RSA PRIVATE KEY-----/xmrig\n", // a miner known by its name only
		"/bin/ps -axww -o pid=,args=":                         "  10 /tmp/app " + pw + " -o stratum+tcp://pool.example.test:3333\n",
		"/usr/bin/dscl . -list /Users UniqueID":               "alice 501\n",
		"/usr/bin/dscl . -list /Users UserShell":              "alice /bin/zsh\n",
		"/usr/bin/dscl . -list /Users NFSHomeDirectory":       "alice /Users/alice " + pw + "\n",
		"/usr/bin/dscl . -read /Groups/admin GroupMembership": "GroupMembership: alice\n",
		"/usr/sbin/lsof -nP -iTCP -sTCP:LISTEN -iUDP -FpcPnt": "p10\ncapp " + pw + "\nf3\ntIPv4\nPTCP\nn*:8080\n",
		"/usr/bin/csrutil status":                             "System Integrity Protection status: enabled (Custom Configuration).\n\nConfiguration:\n\tKernel " + pw + "\n",
		"/usr/bin/fdesetup status":                            "Encryption in progress: " + pw + "\n",
		"/usr/sbin/netstat -anv -p tcp":                       "Active Internet connections (including servers)\n",
		"/usr/sbin/netstat -anv -p udp":                       "Active Internet connections (including servers)\n",
	}}
	f := hostenv.DarwinCollector{}.Collect(context.Background(), mac)
	b, _ := json.Marshal(f)
	if strings.Contains(string(b), val) {
		t.Errorf("macOS facts hold the output's secret: %s", b)
	}
	if !strings.Contains(string(b), "/tmp/app password=[REDACTED]") {
		t.Errorf("ps's process not in the facts: %s", b)
	}
	for _, fd := range Run(f) {
		if strings.Contains(fd.Evidence, val) || strings.Contains(fd.Title, val) {
			t.Errorf("evidence holds the secret: %+v", fd)
		}
	}
	if m := byCheck(Run(f), "process.miner"); len(m) != 2 || m[0].Status != StatusFail {
		t.Errorf("the miner, judged as written, not found: %+v", m)
	}
	// The listeners as lsof gives them (netstat shows no socket), before the
	// process list names them.
	ls := hostenv.DarwinCollector{}.Listeners(context.Background(), mac)
	b, _ = json.Marshal(ls)
	if strings.Contains(string(b), val) || !strings.Contains(string(b), "8080") {
		t.Errorf("lsof's listeners: %s", b)
	}
	deb := liveLike{goos: "linux", files: map[string]string{"/etc/os-release": "ID=debian\nVERSION_ID=12\n"}, cmds: map[string]string{
		"/usr/bin/dpkg-query -W -f " + hostenv.DpkgQueryFormat: "app\t\t1.0 " + pw + "\tamd64\tii \n" + "half\t\t2.0 " + pw + "\tamd64\tiF \n",
	}}
	ps := hostenv.LinuxCollector{}.Packages(context.Background(), deb, map[string]string{"ID": "debian", "VERSION_ID": "12"})
	b, _ = json.Marshal(ps)
	if strings.Contains(string(b), val) || !strings.Contains(string(b), `"app"`) {
		t.Errorf("Linux packages: %s", b)
	}
}
