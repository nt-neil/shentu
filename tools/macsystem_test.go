package tools

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/nt-neil/shentu/hostenv"
)

func macFixture(t *testing.T) {
	t.Helper()
	rp, err := hostenv.LoadReplay("../hostenv/testdata/darwin/macos27-synthetic-user")
	if err != nil {
		t.Fatal(err)
	}
	withHost(t, rp)
}

func runTool(t *testing.T, name, args string) (any, error) {
	t.Helper()
	tool, ok := Find(name)
	if !ok {
		t.Fatalf("no tool %s", name)
	}
	return tool.Run(context.Background(), &Env{}, json.RawMessage(args))
}

// M0: on macOS (the synthetic fixture, wherever the test runs) the
// listening ports come from the darwin collector: launchd on *:22,
// mDNSResponder on *:5353 and exampledb on 127.0.0.1:7777, with owners.
func TestMacListeningPorts(t *testing.T) {
	macFixture(t)
	out, err := runTool(t, "listening_ports", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	ports, ok := out.([]Port)
	if !ok {
		t.Fatalf("not a list: %T %v", out, out)
	}
	want := map[int]string{22: "launchd", 5353: "mDNSResponder", 7777: "exampledb"}
	if len(ports) != len(want) {
		t.Fatalf("ports: %+v", ports)
	}
	for _, p := range ports {
		if want[p.Port] != p.Process || p.PID == 0 {
			t.Errorf("port %d: %+v", p.Port, p)
		}
	}
	if ps, err := ListeningPorts(); err != nil || len(ps) != 3 { // the baseline's and the survey's
		t.Errorf("ListeningPorts: %v %v", ps, err)
	}
}

// M0: processes on macOS: all of them with all, users from ps.
func TestMacProcesses(t *testing.T) {
	macFixture(t)
	out, err := runTool(t, "processes", `{"all":true}`)
	if err != nil {
		t.Fatal(err)
	}
	procs, ok := out.([]Proc)
	if !ok || len(procs) < 4 {
		t.Fatalf("processes: %T %v", out, out)
	}
	users := map[string]string{}
	for _, p := range procs {
		users[p.Comm] = p.User
	}
	if users["launchd"] != "root" || users["exampledb"] == "" {
		t.Errorf("users: %v", users)
	}
	if out, err := runTool(t, "processes", `{}`); err != nil || len(out.([]Proc)) != 0 {
		t.Errorf("suspicious on a clean synthetic host: %v %v", out, err)
	}
}

// M0: on a macOS host where nothing can be read, the tools say so (an
// error), never an empty list that looks like a quiet host.
func TestMacPortsProcessesUnknown(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(`{"format":"`+hostenv.FixtureFormat+`","info":{"goos":"darwin","goarch":"arm64"},"entries":[]}`), 0o600)
	os.Mkdir(filepath.Join(dir, "blobs"), 0o700)
	rp, err := hostenv.LoadReplay(dir)
	if err != nil {
		t.Fatal(err)
	}
	withHost(t, rp)
	for _, name := range []string{"listening_ports", "processes"} {
		if out, err := runTool(t, name, `{}`); err == nil {
			t.Errorf("%s on an unreadable macOS host: %v, no error", name, out)
		}
	}
	if _, err := ListeningPorts(); err == nil {
		t.Error("ListeningPorts on an unreadable macOS host: no error")
	}
}

// M0: a partial socket table (lsof, this user's processes only) is said
// beside the ports, and is an error for the baseline (it would make ports
// look closed, then new).
func TestMacPortsPartial(t *testing.T) {
	macFixture(t)
	old := macListeners
	macListeners = func(context.Context) hostenv.Obs[[]hostenv.Listener] {
		return hostenv.Partial([]hostenv.Listener{{Proto: "tcp", Addr: "127.0.0.1", Port: 7777, PID: 812, Process: "exampledb"}}, hostenv.ReasonPermission, "netstat showed no socket; lsof sees this user's only")
	}
	t.Cleanup(func() { macListeners = old })
	out, err := runTool(t, "listening_ports", `{}`)
	m, ok := out.(map[string]any)
	if err != nil || !ok || m["partial"] == "" || len(m["ports"].([]Port)) != 1 {
		t.Errorf("partial: %v %v", out, err)
	}
	if _, err := ListeningPorts(); err == nil {
		t.Error("ListeningPorts with a partial table: no error")
	}
}

// M0: a shell started by macOS's web user is flagged.
func TestMacProcessesWebShell(t *testing.T) {
	macFixture(t)
	old := macProcList
	macProcList = func(context.Context) hostenv.Obs[[]hostenv.Process] {
		return hostenv.OK([]hostenv.Process{{PID: 4242, PPID: 300, Name: "sh", Exe: "/bin/sh", ExeKnown: true, ExeExists: true, User: "_www"}})
	}
	t.Cleanup(func() { macProcList = old })
	out, err := runTool(t, "processes", `{}`)
	procs, _ := out.([]Proc)
	if err != nil || len(procs) != 1 || len(procs[0].Flags) != 1 || procs[0].Flags[0] != "shell_as_web_user" {
		t.Errorf("web shell: %v %v", out, err)
	}
}
