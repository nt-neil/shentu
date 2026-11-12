package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"time"

	"github.com/nt-neil/shentu/hostenv"
)

var sshLogins = Tool{
	Name: "ssh_logins",
	Description: "SSH login attempts grouped by source IP: failed passwords, invalid users and successful logins. Use it to spot brute force and to check whether an attacking IP ever got in. " +
		"verified is false when the events come from text logs, which anyone on the host can write to: then never block_ip on these counts alone, check them first (journalctl -u ssh, the IP's other traffic). " +
		"complete is false when a log was cut short or unreadable (error says why): the counts are a lower bound.",
	Params: schema(`{"type":"object","properties":{
		"since_hours":{"type":"number","description":"look back this many hours (default 24)"},
		"ip":{"type":"string","description":"only this source IP"}}}`),
	Run: func(ctx context.Context, env *Env, args json.RawMessage) (any, error) {
		var a struct {
			SinceHours float64 `json:"since_hours"`
			IP         string  `json:"ip"`
		}
		if err := decode(args, &a); err != nil {
			return nil, err
		}
		return SSHSummary(ctx, env, hoursAgo(a.SinceHours, 24), a.IP)
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
	// complete is false when a log was cut short or could not be read: the counts are then a lower bound.
	out := map[string]any{"source": source, "verified": verified, "complete": err == nil, "since": since, "sources": sources}
	if err != nil {
		out["error"] = err.Error()
	}
	if n := evicted; n > 0 {
		out["note"] = fmt.Sprintf("%d low-activity sources were not tracked (more than %d sources)", n, hostenv.MaxTrackedSources)
	}
	return out, nil
}
