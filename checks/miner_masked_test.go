package checks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nt-neil/shentu/hostenv"
)

// N-286-1: a renamed miner whose options follow a mysql -p' or --password '
// that the secret mask takes whole is still found: the collector keeps the
// command line as written for the check, and the evidence stays masked.
// Product path: /proc on disk, LinuxCollector.Processes, Run.
func TestMinerBehindMaskedPassword(t *testing.T) {
	pool := "stratum+tcp://pool.example.test:3333"
	for _, argv := range [][]string{
		{"/tmp/kworker", "mysql", "-px;--url=" + pool + ";--donate-level=1"},
		{"/tmp/kworker", "mysql", "-p'", "-o", pool, "--donate-level", "1", "'"},
		{"/tmp/kworker", "--password", "'", "-o", pool, "'"},
	} {
		root := t.TempDir()
		dir := filepath.Join(root, "proc", "4242")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		os.WriteFile(filepath.Join(dir, "status"), []byte("Name:\tkworker\nPPid:\t1\nUid:\t1000\t1000\t1000\t1000\n"), 0o600)
		os.WriteFile(filepath.Join(dir, "comm"), []byte("kworker\n"), 0o600)
		os.WriteFile(filepath.Join(dir, "cmdline"), []byte(strings.Join(argv, "\x00")+"\x00"), 0o600)
		if err := os.Symlink("/tmp/kworker", filepath.Join(dir, "exe")); err != nil {
			t.Skip("no symlinks here:", err)
		}
		src := &hostenv.Live{Remap: map[string]string{"/proc": filepath.Join(root, "proc")}}
		f := facts()
		f.Processes, _ = hostenv.LinuxCollector{}.Processes(src, nil)
		if len(f.Processes.Value) != 1 {
			t.Fatalf("%q: processes %+v", argv, f.Processes)
		}
		if p := f.Processes.Value[0]; !strings.Contains(p.Cmdline, "[REDACTED]") {
			t.Errorf("%q: the output's command line is not masked: %q", argv, p.Cmdline)
		}
		got := byCheck(Run(f), "process.miner")
		if len(got) != 1 || got[0].Status != StatusFail {
			t.Errorf("%q: miner not found: %+v", argv, got)
			continue
		}
		if !strings.Contains(got[0].Evidence, "[REDACTED]") {
			t.Errorf("%q: evidence not masked: %q", argv, got[0].Evidence)
		}
	}
}
