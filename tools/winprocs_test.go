package tools

import (
	"strings"
	"testing"

	"github.com/nt-neil/shentu/hostenv"
)

func TestWinProcesses(t *testing.T) {
	old := winProcList
	t.Cleanup(func() { winProcList = old })
	procs := []hostenv.Process{
		{PID: 4, Name: "System"},
		{PID: 800, PPID: 4, Name: "w3wp.exe", Exe: `C:\Windows\System32\inetsrv\w3wp.exe`, ExeKnown: true, ExeExists: true},
		{PID: 801, PPID: 800, Name: "cmd.exe", Exe: `C:\Windows\System32\cmd.exe`, ExeKnown: true, ExeExists: true, Cmdline: "cmd /c whoami"},
		{PID: 900, PPID: 4, Name: "XMRig.exe", Exe: `C:\Users\Public\XMRig.exe`, ExeKnown: true, ExeExists: true},
		{PID: 901, PPID: 4, Name: "upd.exe", Exe: `C:\Users\a\AppData\Local\Temp\upd.exe`, ExeKnown: true, ExeExists: false, InTemp: true},
		{PID: 902, PPID: 4, Name: "cmd.exe", Exe: `C:\Windows\System32\cmd.exe`, ExeKnown: true, ExeExists: true}, // not under IIS
	}
	winProcList = func() hostenv.Obs[[]hostenv.Process] { return hostenv.OK(procs) }
	got, err := winProcesses(false)
	if err != nil {
		t.Fatal(err)
	}
	flags := map[int]string{}
	for _, p := range got {
		flags[p.PID] = strings.Join(p.Flags, ",")
	}
	want := map[int]string{801: "shell_under_web_server", 900: "miner", 901: "deleted_executable,runs_from_temp"}
	if len(flags) != len(want) {
		t.Errorf("suspicious only: %v", flags)
	}
	for pid, f := range want {
		if flags[pid] != f {
			t.Errorf("pid %d: flags %q, want %q", pid, flags[pid], f)
		}
	}
	if all, _ := winProcesses(true); len(all) != len(procs) {
		t.Errorf("all: %d of %d", len(all), len(procs))
	}
	winProcList = func() hostenv.Obs[[]hostenv.Process] {
		return hostenv.Unknown[[]hostenv.Process](hostenv.ReasonPermission, "denied")
	}
	if out, err := winProcesses(false); err == nil || out != nil {
		t.Error("an unreadable process list must be an error, never an empty list")
	}
}
