//go:build darwin

package tools

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
)

// B-055m-1 on the macOS the test runs on (the CI macos job): a socket this
// test listens on is in listening_ports, with this process's pid, whichever
// way macOS lets it be read (netstat, or lsof when netstat hides it).
// Nothing is recorded: the answer is only checked for that one socket.
func TestMacListeningPortsLive(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	port := l.Addr().(*net.TCPAddr).Port
	// S-214-1: when netstat, run as the tool runs it, shows this process any
	// socket line, the list must be netstat's own and whole: ok, no line
	// left unread, no lsof; partial only for owners netstat or ps cannot
	// name (S-214-2). When it shows none (macOS hides them from a program
	// that is not a terminal's, e.g. this ad-hoc signed test binary on
	// macOS 27), lsof's partial list is what there is.
	visible := 0
	for _, argv := range [][]string{{"/usr/sbin/netstat", "-anv", "-p", "tcp"}, {"/usr/sbin/netstat", "-anv", "-p", "udp"}} {
		r, err := hostSource().Run(context.Background(), argv)
		if err != nil {
			t.Fatalf("%q: %v", argv, err)
		}
		for _, line := range strings.Split(string(r.Stdout), "\n") {
			if strings.HasPrefix(line, "tcp") || strings.HasPrefix(line, "udp") {
				visible++
			}
		}
	}
	t.Logf("netstat socket lines visible to this process: %d", visible)
	out, err := runTool(t, "listening_ports", `{}`)
	if err != nil {
		t.Fatalf("listening_ports: %v", err)
	}
	ports, ok := out.([]Port)
	if m, isMap := out.(map[string]any); isMap {
		ports, ok = m["ports"].([]Port)
		t.Logf("partial: %v", m["partial"])
		why := fmt.Sprint(m["partial"])
		if visible > 0 && (strings.Contains(why, "not understood") || strings.Contains(why, "lsof") ||
			!strings.Contains(why, "without a process name") && !strings.Contains(why, "no owner (pid 0)")) {
			t.Errorf("netstat shows %d socket lines, but the list is not netstat's own and whole: %s", visible, why)
		}
	}
	if !ok {
		t.Fatalf("not a list: %T", out)
	}
	for _, p := range ports {
		if p.Port == port && p.PID == os.Getpid() {
			return
		}
	}
	t.Errorf("127.0.0.1:%d (pid %d) is not among %d listening ports", port, os.Getpid(), len(ports))
}
