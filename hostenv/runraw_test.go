package hostenv

import (
	"context"
	"runtime"
	"strings"
	"testing"
	"time"
)

// prodMac answers commands as a live host does: Run masked (Runner.Run),
// RunUnmasked as written.
type prodMac struct{ fakeMac }

func (p prodMac) Run(ctx context.Context, argv []string) (CmdResult, error) {
	r, err := p.fakeMac.Run(ctx, argv)
	r.Stdout, r.Stderr = []byte(MaskSecrets(string(r.Stdout))), MaskSecrets(r.Stderr) // as Runner.Run (S-293-1)
	return r, err
}
func (p prodMac) RunUnmasked(ctx context.Context, argv []string) (CmdResult, error) {
	return p.fakeMac.Run(ctx, argv)
}

func keyBegin() string { return "-----BEGIN " + "RSA PRIVATE KEY-----" } // built at run time

// Inventory item 2: a command's output is parsed as written. An unclosed
// key BEGIN in one process's path masked the rest of ps's output away, and
// the processes after it (a miner) were not listed.
func TestDarwinProcessesAfterAKeyMarker(t *testing.T) {
	pool := "stratum+tcp://pool.example.test:3333"
	ps := "  10 1 0 root 01:00 /tmp/" + keyBegin() + "\n  11 1 501 alice 01:00 /tmp/kworker\n"
	args := "  10 /tmp/x\n  11 /tmp/kworker -o " + pool + "\n"
	src := prodMac{fakeMac{cmds: map[string]string{key(macPsArgv): ps, key(macPsArgsArgv): args}}}
	o := DarwinCollector{}.Processes(context.Background(), src, time.Now())
	if len(o.Value) != 2 || o.Value[1].PID != 11 || !strings.Contains(o.Value[1].MatchCmdline(), pool) {
		t.Errorf("the processes after a key marker: %+v", o.Value)
	}
}

// An unclosed key BEGIN in an iptables rule's comment masked the rules
// after it, and the firewall read as "none detected".
func TestLinuxFirewallRuleCommentKeyMarker(t *testing.T) {
	rules := "-P INPUT DROP\n-A INPUT -m comment --comment \"" + keyBegin() + "\" -j ACCEPT\n" +
		"-A INPUT -p tcp --dport 22 -j ACCEPT\n-A INPUT -p tcp --dport 80 -j ACCEPT\n-A INPUT -p tcp --dport 443 -j ACCEPT\n"
	src := prodMac{fakeMac{cmds: map[string]string{key(iptablesArgv): rules}}}
	fw := LinuxCollector{}.Firewall(context.Background(), src, nil)
	if !fw.Value.Enabled || fw.Value.Backend != "iptables" {
		t.Errorf("iptables rules after a key marker: %+v", fw)
	}
}

// Runner.RunUnmasked gives a real command's output as written; Run masks it.
func TestRunnerRunUnmasked(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no /bin/echo")
	}
	argv := []string{"/bin/echo", "a password=hunter2x9 b"}
	r, err := NewRunner([][]string{argv})
	if err != nil {
		t.Fatal(err)
	}
	m, err := r.Run(context.Background(), argv)
	if err != nil || strings.Contains(string(m.Stdout), "hunter2x9") {
		t.Errorf("Run: %q %v", m.Stdout, err)
	}
	u, err := r.RunUnmasked(context.Background(), argv)
	if err != nil || !strings.Contains(string(u.Stdout), "password=hunter2x9") {
		t.Errorf("RunUnmasked: %q %v", u.Stdout, err)
	}
}
