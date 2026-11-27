package tools

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/nt-neil/shentu/hostenv"
)

// On macOS, listening_ports and processes come from hostenv's darwin
// collector (netstat or lsof, and ps: no root needed), not the Linux
// readers, which read /proc and find nothing there: an empty list that
// would look like a quiet host (phase 5, M0). An unknown read is an error;
// a partial one (lsof sees only this user's processes when netstat shows
// no socket) says so beside what it found.

// onMac is whether the host the tools read is macOS: the host source's OS,
// so a replayed macOS fixture is judged as macOS wherever it runs.
func onMac() bool { return hostSource().Info().GOOS == "darwin" }

// onWindows is whether the host the tools read is Windows, as onMac: a
// replayed Linux or macOS fixture is read as that OS on a Windows machine,
// and a Windows one as Windows anywhere.
func onWindows() bool { return hostSource().Info().GOOS == "windows" }

// macListeners and macProcList read the macOS listeners and processes;
// tests replace them.
var (
	macListeners = func(ctx context.Context) hostenv.Obs[[]hostenv.Listener] {
		return hostenv.DarwinCollector{}.Listeners(ctx, hostSource())
	}
	macProcList = func(ctx context.Context) hostenv.Obs[[]hostenv.Process] {
		return hostenv.DarwinCollector{}.Processes(ctx, hostSource(), time.Now())
	}
)

// macPorts is ListeningPorts on macOS, with the reason when it is partial.
func macPorts(ctx context.Context) (ports []Port, partial string, err error) {
	ls := macListeners(ctx)
	if !ls.Known() {
		return nil, "", errors.New("the listening sockets could not be read on macOS: " + ls.Detail)
	}
	exe := map[int]string{}
	if ps := macProcList(ctx); ps.Known() {
		for _, p := range ps.Value {
			exe[p.PID] = p.Exe
		}
	}
	seen := map[string]bool{}
	ports = []Port{}
	for _, l := range ls.Value {
		key := fmt.Sprintf("%s/%s/%d", l.Proto, l.Addr, l.Port)
		if seen[key] { // one owner per port, as on Linux
			continue
		}
		seen[key] = true
		ports = append(ports, Port{Proto: l.Proto, Addr: l.Addr, Port: l.Port, PID: l.PID, Process: l.Process, Exe: exe[l.PID], UID: l.UID})
	}
	sort.Slice(ports, func(i, j int) bool { return ports[i].Port < ports[j].Port })
	if ls.Status == hostenv.StatusPartial {
		partial = fmt.Sprintf("only part of the sockets could be seen (%s): %s", ls.Reason, ls.Detail)
	}
	return ports, partial, nil
}

// macWebUsers are the accounts macOS's own web servers run as, beside the
// configured ones.
var macWebUsers = map[string]bool{"_www": true}

// macProcesses is the processes tool on macOS: by default only the
// suspicious ones, flagged as on Linux where the sign is the same. A
// process's start is ps's elapsed time; there is no boot tick to tell an
// early-boot process from a later one, so none is unflagged for it.
func macProcesses(ctx context.Context, all bool) (procs []Proc, partial string, err error) {
	o := macProcList(ctx)
	if !o.Known() {
		return nil, "", errors.New("the process list could not be read on macOS: " + o.Detail)
	}
	self := os.Getpid()
	procs = []Proc{}
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
		if minerSigns(p.Exe, p.Cmdline) {
			p.Flags = append(p.Flags, "miner")
		}
		if (webUsers[p.User] || macWebUsers[p.User]) && shells[filepath.Base(p.Exe)] {
			p.Flags = append(p.Flags, "shell_as_web_user")
		}
		if all || len(p.Flags) > 0 {
			procs = append(procs, p)
		}
	}
	sort.Slice(procs, func(i, j int) bool { return procs[i].PID < procs[j].PID })
	if o.Status == hostenv.StatusPartial {
		partial = fmt.Sprintf("some processes could not be fully read (%s): %s", o.Reason, o.Detail)
	}
	return procs, partial, nil
}

// withPartial is a list as a tool returns it: the list itself, or, when
// it is partial, an object with the list and why, so the model is told.
func withPartial(key string, list any, partial string) any {
	if partial == "" {
		return list
	}
	return map[string]any{key: list, "partial": partial}
}

// macPortsStrict is ListeningPorts on macOS for the patrol's baseline and
// the survey: a partial socket table is an error there, as an unknown one
// (every port missing from it would look closed, then new).
func macPortsStrict(ctx context.Context) ([]Port, error) {
	ports, partial, err := macPorts(ctx)
	if err == nil && partial != "" {
		err = errors.New("listening sockets partly unknown on macOS: " + strings.TrimPrefix(partial, "only "))
	}
	if err != nil {
		return nil, err
	}
	return ports, nil
}
