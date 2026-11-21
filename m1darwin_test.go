package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nt-neil/shentu/tools"
)

// Phase 5, M1 (plan f98c3c): the sub-agent side of macOS patrol and
// incident, written before the platform line's tools read macOS. Until
// roleFor opens a role on darwin the per-tool test skips, saying why; once
// it opens, every tool of the role must give data or say it could not
// (an error), never an empty result that looks clean.

// toolData is, for a tool whose result is an object, the fields that hold
// what it read (N-173-1): the others (time, os, kernel, source, limit, a
// path, a caveat that is always there) are there whatever it read. A tool
// whose result is a list (listening_ports, processes, cert_expiry) is
// judged by the list.
var toolData = map[string][]string{
	// Not firewall (N-173r2-1): on macOS it is the Linux reader's summary of
	// what it could not read ("no firewall enabled at boot (nftables...")
	// until M0 reads pf and the application firewall; never empty.
	// tools.TestSiteProfileEmptyHost keeps these empty on a host where
	// nothing can be read: keep the two lists in step.
	"site_profile":    {"services", "app_stacks", "lock_files", "ssh", "containers", "cron_files", "login_accounts", "risks"},
	"accounts_audit":  {"uid0_accounts", "login_accounts", "sudo_rules", "authorized_keys", "keys_in_several_accounts", "ld_so_preload", "pam_modules_not_from_a_package"},
	"file_changes":    {"files"},
	"ssh_logins":      {"sources"},
	"attack_attempts": {"groups"},
	"log_search":      {"matches"},
}

// metaFields are never what a tool read, for a tool not in toolData.
var metaFields = map[string]bool{"time": true, "os": true, "kernel": true, "source": true, "limit": true, "since": true, "path": true, "roots": true, "untrusted": true}

// saysWhy are fields by which a tool says it could not (fully) read:
// explicit, not a clean-looking result.
var saysWhy = []string{"note", "error", "unsupported", "permission", "partial"}

// looksClean is a tool's result with nothing read in it: null, an empty
// list, or an object whose data fields (toolData, else all but metaFields)
// are all empty, false or zero, with nothing saying why. That is what an
// unread platform returns, and what reads as "all is well" to a model.
func looksClean(tool string, b []byte) bool {
	var v any
	if json.Unmarshal(b, &v) != nil {
		return false
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return emptyValue(v)
	}
	for _, k := range saysWhy {
		if !emptyValue(obj[k]) {
			return false
		}
	}
	if fields, ok := toolData[tool]; ok {
		for _, k := range fields {
			if !emptyValue(obj[k]) {
				return false
			}
		}
		return true
	}
	for k, f := range obj {
		if !metaFields[k] && !emptyValue(f) {
			return false
		}
	}
	return true
}

// shape is what a test may print of a result: its size, never its keys or
// values (an account or a process name is this host's).
func shape(b []byte) string {
	var v any
	json.Unmarshal(b, &v)
	switch x := v.(type) {
	case []any:
		return fmt.Sprintf("a list of %d, %d bytes", len(x), len(b))
	case map[string]any:
		return fmt.Sprintf("an object of %d fields, %d bytes", len(x), len(b))
	}
	return fmt.Sprintf("%d bytes", len(b))
}

func emptyValue(v any) bool {
	switch x := v.(type) {
	case nil:
		return true
	case bool:
		return !x
	case float64:
		return x == 0
	case string:
		return x == ""
	case []any:
		return len(x) == 0
	case map[string]any:
		for _, f := range x {
			if !emptyValue(f) {
				return false
			}
		}
		return true
	}
	return false
}

func TestM1LooksClean(t *testing.T) {
	for _, c := range []struct{ tool, out string }{
		{"processes", `null`}, {"processes", `[]`}, {"x", `{}`},
		{"x", `{"ports":[],"source":"lsof"}`}, // a source is not data (N-173-1)
		{"site_profile", `{"time":"2026-11-22T00:00:00Z","os":"darwin","kernel":"25.0","services":[],"ssh_config_hash":"ab"}`},
		{"attack_attempts", `{"groups":[],"within_hours":24,"untrusted":"samples are written by the senders"}`},
		// N-173r-1, N-173r2-1: what Survey gives on macOS for the firewall, a
		// summary of what the Linux reader could not read, is not data.
		{"site_profile", `{"time":"t","os":"darwin","kernel":"25.0","firewall":"no firewall enabled at boot (nftables.service is off); rules added at runtime cannot be read here, ask in chat","services":[]}`},
		{"site_profile", `{"time":"t","os":"darwin","kernel":"25.0","firewall":"none detected"}`},
		{"x", `{"a":{"b":[]}}`},
	} {
		if !looksClean(c.tool, []byte(c.out)) {
			t.Errorf("%s %s: not seen as clean-looking", c.tool, c.out)
		}
	}
	for _, c := range []struct{ tool, out string }{
		{"processes", `[{"pid":1}]`},
		{"x", `{"ports":[],"note":"could not read the table"}`},
		{"ssh_logins", `{"sources":[],"unsupported":true}`},
		{"site_profile", `{"time":"t","os":"darwin","services":[{"name":"sshd"}]}`},
		{"x", `{"total":3}`},
	} {
		if looksClean(c.tool, []byte(c.out)) {
			t.Errorf("%s %s: seen as clean-looking", c.tool, c.out)
		}
	}
	if s := shape([]byte(`{"alice":1,"bob":2}`)); strings.Contains(s, "alice") || !strings.Contains(s, "2 fields") {
		t.Errorf("shape: %q", s)
	}
}

// The gate as it stands: on macOS only surface is open. Opening patrol or
// incident is M1's step (m1-enable), done on purpose: this test changes
// with it. Every role is listed, in subRoleOrder, and only those
// (S-173-3).
func TestM1DarwinGate(t *testing.T) {
	want := map[string]bool{"patrol": false, "surface": true, "attack": false, "incident": false}
	if len(subRoleOrder) != len(subRoles) || len(want) != len(subRoles) {
		t.Fatalf("roles: order %v, %d defined, %d expected here", subRoleOrder, len(subRoles), len(want))
	}
	for _, role := range subRoleOrder {
		w, ok := want[role]
		if _, defined := subRoles[role]; !ok || !defined {
			t.Errorf("%s: in the order but not defined or not expected here", role)
			continue
		}
		if _, _, open := roleFor(role, "darwin"); open != w {
			t.Errorf("%s on macOS: open %v, want %v", role, open, w)
		}
	}
}

// needsSetting is the setting a tool reads from: when the product's
// configuration leaves it empty here, an empty result is "not set", not a
// clean-looking one (S-173-2).
var needsSetting = map[string]func(*tools.Env) bool{
	"cert_expiry":  func(e *tools.Env) bool { return len(e.CertTargets) > 0 },
	"log_search":   func(e *tools.Env) bool { return len(e.LogPaths) > 0 },
	"file_changes": func(e *tools.Env) bool { return len(e.WatchPaths) > 0 },
}

// productEnv is the Env the sub-agents get: the one main makes (envFor)
// from the configuration as loaded, with its defaults (S-173-2).
func productEnv(t *testing.T) *tools.Env {
	t.Helper()
	p := filepath.Join(t.TempDir(), "shentu.toml")
	os.WriteFile(p, []byte("state_dir = "+strconv.Quote(t.TempDir())+"\n"), 0o600)
	cfg, err := loadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	return envFor(cfg)
}

// Each tool a macOS role runs gives data or says why not, never a
// clean-looking empty result (runs on macOS, the CI macos job).
func TestM1DarwinToolsReadThePlatform(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("runs on macOS (the CI macos job)")
	}
	env := productEnv(t)
	for _, role := range []string{"patrol", "incident"} {
		t.Run(role, func(t *testing.T) {
			r, missing, open := roleFor(role, "darwin")
			// SHENTU_M1_PROBE=1 runs every tool of a closed role (S-173-1),
			// the ones not marked for macOS too, and logs only whether each
			// looks clean and its shape (never its output: it is this host's).
			probe := !open && os.Getenv("SHENTU_M1_PROBE") == "1"
			if !open && !probe {
				t.Skipf("M1: %s is closed on macOS until the platform line's tools read macOS (plan f98c3c, m1-enable); not available there: %v", role, missing)
			}
			if open && len(r.tools) == 0 {
				t.Fatalf("%s is open on macOS with no tool that works there", role)
			}
			names := r.tools
			if probe {
				names = subRoles[role].tools
			}
			for _, name := range names {
				tool, ok := tools.Find(name)
				if !ok {
					t.Errorf("%s: no such tool", name)
					continue
				}
				ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
				out, err := tool.Run(ctx, env, json.RawMessage(`{}`))
				cancel()
				b, _ := json.Marshal(out)
				set, needs := needsSetting[name]
				switch {
				case err != nil && probe:
					t.Logf("%s: error (explicit)", name)
				case err != nil: // said it could not: explicit
				case needs && !set(env) && looksClean(name, b):
					t.Logf("%s: its setting is empty in the default configuration; not judged", name)
				case probe:
					t.Logf("%s: supported %v, looks clean %v, %s", name, tools.SupportedOn(name, "darwin"), looksClean(name, b), shape(b))
				case looksClean(name, b):
					t.Errorf("%s on macOS gave an empty result that looks clean (%s)", name, shape(b))
				}
			}
		})
	}
}
