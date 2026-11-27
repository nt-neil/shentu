package tools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"strconv"
	"strings"
	"time"

	"github.com/nt-neil/shentu/hostenv"
)

var sshLogins = Tool{
	Name: "ssh_logins",
	Description: "SSH login attempts grouped by source IP: failed passwords, invalid users and successful logins. Use it to spot brute force and to check whether an attacking IP ever got in. " +
		"verified is false when the events come from text logs, which anyone on the host can write to: then never block_ip on these counts alone, check them first (journalctl -u ssh, the IP's other traffic). " +
		"complete is false when a log was cut short or unreadable (error says why): the counts are a lower bound. " +
		"On macOS the events come from its unified log, which only root and the admin group can read (permission says when that stopped it); only sshd's own events logged by root are counted (verified), and source says how many others were left out and why. " +
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

// scanAuthLogs reads the SSH events (a test's seam): journald or the text
// auth logs, and on macOS its unified log (M0).
var scanAuthLogs = func(ctx context.Context, src hostenv.Source, logPaths []string, since time.Time, sink func() func(string)) (string, bool, error) {
	if src.Info().GOOS == "darwin" {
		return hostenv.DarwinCollector{}.ScanAuthLogs(ctx, src, since, sink)
	}
	return linux.ScanAuthLogs(ctx, src, logPaths, since, sink)
}

// journalAll: journald shows this process every unit's entries: root, or
// a member of systemd-journal or adm (a test's seam).
var journalAll = func() bool {
	if os.Geteuid() == 0 {
		return true
	}
	gids, err := os.Getgroups()
	if err != nil {
		return false
	}
	for _, id := range append(gids, os.Getegid()) {
		if g, err := user.LookupGroupId(strconv.Itoa(id)); err == nil && (g.Name == "systemd-journal" || g.Name == "adm") {
			return true
		}
	}
	return false
}

// SSHSource is the per-IP summary (hostenv.SSHSource).
type SSHSource = hostenv.SSHSource

// SSHSummary reads auth logs (or journald when there are none) and groups events by IP,
// streaming through hostenv: memory does not grow with the logs.
func SSHSummary(ctx context.Context, env *Env, since time.Time, onlyIP string) (map[string]any, error) {
	if onWindows() {
		return winLogonSummary(since, onlyIP)
	}
	var aggs []*hostenv.SSHLogins
	now := time.Now()
	source, verified, err := scanAuthLogs(ctx, hostSource(), env.LogPaths, since, func() func(string) {
		a := hostenv.NewSSHLogins(since, now, onlyIP)
		aggs = append(aggs, a)
		return a.Add
	})
	sources, evicted := hostenv.MaxLogins(aggs...)
	// verified is false for text logs: anyone on the host can write sshd lines there.
	// complete is false when a log was cut short or could not be read, or
	// when an empty journal had no text log to confirm it: the counts are
	// then a lower bound.
	// A user outside systemd-journal and adm is shown only what it may see
	// of journald, with no error: a lower bound too, root would read it
	// all (VM acceptance of adff9e6, N1).
	journald := strings.HasPrefix(source, "journald")
	partial := journald && !journalAll()
	complete := err == nil && (verified || !journald) && !partial
	if partial {
		source += " (only part of it: this user is neither root nor in systemd-journal or adm)"
	}
	out := map[string]any{"source": source, "verified": verified, "complete": complete, "since": since, "sources": sources}
	if err != nil {
		out["error"] = err.Error()
	}
	// permission: a log was not read for want of rights (a text log root
	// can read, a journal hiding the system's entries): root would read it.
	if partial || errors.Is(err, fs.ErrPermission) || strings.Contains(source, string(hostenv.ReasonPermission)) {
		out["permission"] = true
	}
	if n := evicted; n > 0 {
		out["note"] = fmt.Sprintf("%d low-activity sources were not tracked (more than %d sources)", n, hostenv.MaxTrackedSources)
	}
	return out, nil
}
