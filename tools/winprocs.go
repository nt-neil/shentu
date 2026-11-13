package tools

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/nt-neil/shentu/hostenv"
)

// winProcList reads the Windows process list; tests replace it.
var winProcList = func() hostenv.Obs[[]hostenv.Process] {
	return hostenv.WindowsCollector{}.Processes(winSource())
}

// winShells are interpreters a web server should never start (a webshell
// running commands under w3wp.exe).
var winShells = map[string]bool{"cmd.exe": true, "powershell.exe": true, "pwsh.exe": true, "cscript.exe": true,
	"wscript.exe": true, "mshta.exe": true, "rundll32.exe": true, "certutil.exe": true, "bitsadmin.exe": true}

// winProcesses is the processes tool on Windows: by default only the
// suspicious ones, flagged as on Linux where the sign is the same.
func winProcesses(all bool) ([]Proc, error) {
	o := winProcList()
	if !o.Known() {
		return nil, errors.New("the Windows process list could not be read: " + o.Detail)
	}
	self := os.Getpid()
	name := map[int]string{}
	for _, p := range o.Value {
		name[p.PID] = strings.ToLower(p.Name)
	}
	out := []Proc{}
	for _, hp := range o.Value {
		if hp.PID == self {
			continue
		}
		p := Proc{PID: hp.PID, PPID: hp.PPID, User: hp.User, Comm: hp.Name, Exe: hp.Exe, Cmdline: Cut(hp.Cmdline, 300), Started: hp.Started}
		if hp.ExeKnown && !hp.ExeExists {
			p.Flags = append(p.Flags, "deleted_executable")
		}
		if hp.InTemp {
			p.Flags = append(p.Flags, "runs_from_temp")
		}
		base := strings.TrimSuffix(strings.ToLower(filepath.Base(strings.ReplaceAll(hp.Exe, `\`, "/"))), ".exe")
		if minerNames[base] || minerArgs.MatchString(hp.Cmdline) {
			p.Flags = append(p.Flags, "miner")
		}
		if winShells[strings.ToLower(hp.Name)] && name[hp.PPID] == "w3wp.exe" {
			p.Flags = append(p.Flags, "shell_under_web_server")
		}
		if all || len(p.Flags) > 0 {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PID < out[j].PID })
	return out, nil
}
