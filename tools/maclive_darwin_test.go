//go:build darwin

package tools

import (
	"net"
	"os"
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
	out, err := runTool(t, "listening_ports", `{}`)
	if err != nil {
		t.Fatalf("listening_ports: %v", err)
	}
	ports, ok := out.([]Port)
	if m, isMap := out.(map[string]any); isMap {
		ports, ok = m["ports"].([]Port)
		t.Logf("partial: %v", m["partial"])
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
