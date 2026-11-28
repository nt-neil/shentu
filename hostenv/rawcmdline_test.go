package hostenv

import (
	"context"
	"strings"
	"testing"
	"time"
)

// N-286-1: ps's command lines reach checks as written (RawCmdline) and
// output masked (Cmdline); a recording of them is masked.
func TestDarwinProcessesRawCmdline(t *testing.T) {
	pool := "stratum+tcp://pool.example.test:3333"
	line := "/tmp/kworker mysql -p' -o " + pool + " --donate-level 1 '"
	ps := "  11 1 501 alice 01:00 /tmp/kworker\n"
	src := fakeMac{cmds: map[string]string{key(macPsArgv): ps, key(macPsArgsArgv): "  11 " + line + "\n"}}
	rec := NewRecorder(src)
	o := DarwinCollector{}.Processes(context.Background(), rec, time.Now())
	if len(o.Value) != 1 {
		t.Fatalf("processes: %+v", o)
	}
	p := o.Value[0]
	if p.RawCmdline != line || p.MatchCmdline() != line {
		t.Errorf("as written: %q", p.RawCmdline)
	}
	if !strings.Contains(p.Cmdline, "[REDACTED]") || strings.Contains(p.Cmdline, pool) {
		t.Errorf("output not masked: %q", p.Cmdline)
	}
	e := rec.got[(&entry{Op: "cmd", Argv: macPsArgsArgv}).key()]
	if e == nil || strings.Contains(string(e.data), pool) || !strings.Contains(string(e.data), "[REDACTED]") {
		t.Errorf("recording not masked: %+v", e)
	}
	// A fixture read back has only the masked line: checks match that.
	if q := (Process{Cmdline: "x -p[REDACTED]"}); q.MatchCmdline() != q.Cmdline {
		t.Error("no RawCmdline: the masked one")
	}
}

// The raw command line on Linux is the NUL-joined argv, uncut to 512.
func TestParseRawCmdline(t *testing.T) {
	long := strings.Repeat("a", 600) + " --donate-level 1"
	b := []byte("/tmp/x\x00mysql\x00-p'\x00" + long + "\x00'\x00")
	if got := ParseRawCmdline(b); got != "/tmp/x mysql -p' "+long+" '" {
		t.Errorf("raw %q", got)
	}
	if got := ParseCmdline(b); strings.Contains(got, "--donate-level") || len(got) > MaxCmdline+len("…") {
		t.Errorf("masked %q", got)
	}
}
