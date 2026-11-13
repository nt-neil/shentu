// Package tools holds the security tools the LLM can call.
package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
	"unicode/utf8"
)

// Env is what tools need from the configuration.
type Env struct {
	LogPaths    []string
	WatchPaths  []string
	CertTargets []string
	AppPaths    []string
	NotifyURL   string
	HTTP        *http.Client
}

// Tool is one function the LLM can call.
type Tool struct {
	Name        string
	Description string
	Params      json.RawMessage // JSON Schema of the arguments
	// Control tools change the system. They only run after a human confirms Preview.
	Control bool
	Preview func(args json.RawMessage) (string, error)
	Run     func(ctx context.Context, env *Env, args json.RawMessage) (any, error)
}

// All returns every tool.
func All() []Tool {
	return guardWindows([]Tool{
		sshLogins, listeningPorts, processesTool, accountsAudit,
		packageVulns, appVulns, appCodeAudit, siteProfile, fileChanges, certExpiry, logSearch,
		blockIP, unblockIP, notifyTool,
	})
}

// Find returns the tool with the given name.
func Find(name string) (Tool, bool) {
	for _, t := range All() {
		if t.Name == name {
			return t, true
		}
	}
	return Tool{}, false
}

func schema(s string) json.RawMessage { return json.RawMessage(s) }

const noParams = `{"type":"object","properties":{}}`

// decode unmarshals args into v; empty args are fine.
func decode(args json.RawMessage, v any) error {
	if len(args) == 0 || string(args) == "null" {
		return nil
	}
	if err := json.Unmarshal(args, v); err != nil {
		return fmt.Errorf("invalid arguments: %w", err)
	}
	return nil
}

func hoursAgo(h float64, def float64) time.Time {
	if h <= 0 {
		h = def
	}
	return time.Now().Add(-time.Duration(h * float64(time.Hour)))
}

// Cut shortens s to at most n bytes without splitting a UTF-8 character, adding "…" when it cuts.
func Cut(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "…"
}
