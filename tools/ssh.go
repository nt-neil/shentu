package tools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"runtime"
	"strings"
	"time"

	"github.com/nt-neil/shentu/hostenv"
)

var sshLogins = Tool{
	Name: "ssh_logins",
	Description: "SSH login attempts grouped by source IP: failed passwords, invalid users and successful logins. Use it to spot brute force and to check whether an attacking IP ever got in. " +
		"verified is false when the events come from text logs, which anyone on the host can write to: then never block_ip on these counts alone, check them first (journalctl -u ssh, the IP's other traffic). " +
		"complete is false when a log was cut short or unreadable (error says why): the counts are a lower bound. " +
		"source names what was read (journald, or the log files and why journald was not used); note says when low-activity sources were not tracked.",
	Params: schema(`{"type":"object","properties":{
		"since_hours":{"type":"number","description":"look back this many hours (default 24, at most 720: as far as block_ip's login check looks)"},
		"ip":{"type":"string","description":"only this source IP"}}}`),
	Run: func(ctx context.Context, env *Env, args json.RawMessage) (any, error) {
		var a struct {
			SinceHours float64 `json:"since_hours"`
			IP         string  `json:"ip"`
		}
		if err := decode(args, &a); err != nil {
			return nil, err
		}
		// No further back than block_ip's login check: what it cannot see must
		// not be shown as evidence for a block.
		h := min(a.SinceHours, loginGateWindow.Hours())
		return SSHSummary(ctx, env, hoursAgo(h, 24), a.IP)
	},
}

// SSHSource is the per-IP summary (hostenv.SSHSource).
type SSHSource = hostenv.SSHSource

// SSHSummary reads auth logs (or journald when there are none) and groups events by IP,
// streaming through hostenv: memory does not grow with the logs.
func SSHSummary(ctx context.Context, env *Env, since time.Time, onlyIP string) (map[string]any, error) {
	if runtime.GOOS == "windows" {
		return winLogonSummary(since, onlyIP)
	}
	var aggs []*hostenv.SSHLogins
	now := time.Now()
	source, verified, err := linux.ScanAuthLogs(ctx, hostSource(), env.LogPaths, since, func() func(string) {
		a := hostenv.NewSSHLogins(since, now, onlyIP)
		aggs = append(aggs, a)
		return a.Add
	})
	sources, evicted := hostenv.MaxLogins(aggs...)
	// verified is false for text logs: anyone on the host can write sshd lines there.
	// complete is false when a log was cut short or could not be read, or
	// when an empty journal had no text log to confirm it: the counts are
	// then a lower bound.
	complete := err == nil && (verified || !strings.HasPrefix(source, "journald"))
	out := map[string]any{"source": source, "verified": verified, "complete": complete, "since": since, "sources": sources}
	if runtime.GOOS == "darwin" && errors.Is(err, hostenv.ErrNotAllowed) {
		// No journalctl and no text auth log: macOS keeps sshd's events in
		// its unified log, which Shentu does not read. Root would not help.
		out["source"] = "none: Shentu has no sshd log source on macOS (it reads journald and the text auth logs, which macOS does not keep)"
		out["unsupported"] = true
		err = nil
	}
	if err != nil {
		out["error"] = err.Error()
	}
	// permission: a log was not read for want of rights (a text log root
	// can read, a journal hiding the system's entries): root would read it.
	if errors.Is(err, fs.ErrPermission) || strings.Contains(source, string(hostenv.ReasonPermission)) {
		out["permission"] = true
	}
	if n := evicted; n > 0 {
		out["note"] = fmt.Sprintf("%d low-activity sources were not tracked (more than %d sources)", n, hostenv.MaxTrackedSources)
	}
	return out, nil
}
