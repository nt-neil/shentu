package hostenv

import (
	"context"
	"errors"
	"net"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

func mustIP(s string) net.IP { return net.ParseIP(s) }

func TestRunnerRefuses(t *testing.T) {
	for _, argv := range [][]string{
		{},
		{"dpkg-query", "-W"},              // relative
		{"/bin/sh", "-c", "id"},           // shell
		{"/usr/bin/env", "id"},            // indirection
		{"/usr/bin/python3.12", "-c", ""}, // interpreter
		{`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, "-Command", "Get-HotFix"},
		{`C:\Windows\System32\cmd.exe`, "/c", "dir"},
	} {
		if _, err := NewRunner([][]string{argv}); !errors.Is(err, ErrNotAllowed) {
			t.Errorf("NewRunner(%q) = %v, want ErrNotAllowed", argv, err)
		}
	}
	r, err := NewRunner([][]string{{"/usr/bin/dpkg-query", "-W"}, {`C:\Windows\System32\reg.exe`, "query", `HKLM\X`}})
	if err != nil {
		t.Fatal(err)
	}
	if r.Allowed([]string{"/usr/bin/dpkg-query", "-W", "-f", "x"}) || !r.Allowed([]string{"/usr/bin/dpkg-query", "-W"}) {
		t.Error("allowlist must match the exact argv")
	}
	if _, err := r.Run(context.Background(), []string{"/usr/bin/id"}); !errors.Is(err, ErrNotAllowed) {
		t.Errorf("Run outside allowlist: %v", err)
	}
	var zero *Runner
	if zero.Allowed([]string{"/usr/bin/id"}) {
		t.Error("nil runner allowed a command")
	}
}

func unixOnly(t *testing.T, bins ...string) {
	if runtime.GOOS == "windows" {
		t.Skip("unix commands")
	}
	for _, b := range bins {
		if _, err := os.Stat(b); err != nil {
			t.Skip(b + " missing")
		}
	}
}

func TestRunnerTimeout(t *testing.T) {
	unixOnly(t, "/bin/sleep")
	argv := []string{"/bin/sleep", "5"}
	r, _ := NewRunner([][]string{argv})
	r.Timeout = 200 * time.Millisecond
	start := time.Now()
	_, err := r.Run(context.Background(), argv)
	if !errors.Is(err, ErrTimeout) || Classify(err) != ReasonTimeout {
		t.Errorf("err %v", err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("timeout took %v", d)
	}
}

func TestRunnerOutputCapAndEnv(t *testing.T) {
	unixOnly(t, "/bin/dd", "/usr/bin/printenv", "/bin/echo")
	dd := []string{"/bin/dd", "if=/dev/zero", "bs=1024", "count=256"}
	pe := []string{"/usr/bin/printenv"}
	echo := []string{"/bin/echo", "api_key=" + fakeSecret(), "ghp_" + strings.Repeat("a", 36)}
	r, _ := NewRunner([][]string{dd, pe, echo})
	r.MaxStdout = 1000
	res, err := r.Run(context.Background(), dd)
	if !errors.Is(err, ErrTruncated) || !res.Truncated || len(res.Stdout) != 1000 {
		t.Errorf("cap: err=%v truncated=%v len=%d", err, res.Truncated, len(res.Stdout))
	}

	t.Setenv("SHENTU_TEST_TOKEN", "should-not-leak")
	res, err = r.Run(context.Background(), pe)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(res.Stdout), "SHENTU_TEST_TOKEN") || !strings.Contains(string(res.Stdout), "LC_ALL=C") {
		t.Errorf("environment not fixed:\n%s", res.Stdout)
	}

	res, err = r.Run(context.Background(), echo)
	if err != nil || strings.Contains(string(res.Stdout), fakeSecret()) || strings.Contains(string(res.Stdout), "ghp_aaaa") {
		t.Errorf("output not masked: %q %v", res.Stdout, err)
	}
}

func TestRunnerExitCodeIsNotError(t *testing.T) {
	unixOnly(t, "/usr/bin/false")
	argv := []string{"/usr/bin/false"}
	r, _ := NewRunner([][]string{argv})
	res, err := r.Run(context.Background(), argv)
	if err != nil || res.ExitCode == 0 {
		t.Errorf("false: %+v %v", res, err)
	}
}

// Every collector's allowlist must pass the same rules NewRunner enforces.
func TestCollectorAllowlists(t *testing.T) {
	for _, goos := range []string{"linux", "windows", "darwin", "freebsd"} {
		if _, err := NewRunner(ForOS(goos).Allowlist()); err != nil {
			t.Errorf("%s allowlist: %v", goos, err)
		}
	}
}

func TestRunnerSlots(t *testing.T) {
	r, err := NewRunner([][]string{journalArgv})
	if err != nil {
		t.Fatal(err)
	}
	ok := append([]string(nil), journalArgv...)
	ok[6] = "2026-11-12 03:00:00"
	bad := append([]string(nil), journalArgv...)
	bad[6] = "2026-11-12 03:00:00; rm -rf /"
	if !r.Allowed(ok) || r.Allowed(bad) || r.Allowed(journalArgv[:6]) {
		t.Error("a time slot must take exactly one time value")
	}
}
