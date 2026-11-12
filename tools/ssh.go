package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/nt-neil/shentu/hostenv"
)

var sshLogins = Tool{
	Name:        "ssh_logins",
	Description: "SSH login attempts grouped by source IP: failed passwords, invalid users and successful logins. Use it to spot brute force and to check whether an attacking IP ever got in.",
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
	var agg *hostenv.SSHLogins
	now := time.Now()
	source, _, _ := linux.ScanAuthLogs(ctx, hostSource(), env.LogPaths, since, func() func(string) {
		agg = hostenv.NewSSHLogins(since, now, onlyIP)
		return agg.Add
	})
	out := map[string]any{"source": source, "since": since, "sources": agg.Result()}
	if n := agg.Evicted(); n > 0 {
		out["note"] = fmt.Sprintf("%d low-activity sources were not tracked (more than %d sources)", n, hostenv.MaxTrackedSources)
	}
	return out, nil
}
