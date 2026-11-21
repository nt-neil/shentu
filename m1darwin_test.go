package main

import (
	"context"
	"encoding/json"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/nt-neil/shentu/tools"
)

// Phase 5, M1 (plan f98c3c): the sub-agent side of macOS patrol and
// incident, written before the platform line's tools read macOS. Until
// roleFor opens a role on darwin the per-tool test skips, saying why; once
// it opens, every tool of the role must give data or say it could not
// (an error), never an empty result that looks clean.

// looksClean is a tool result with nothing in it: null, an empty list or
// object, or an object (at any depth) whose every field is empty, false or
// zero. That is what an unread platform returns, and what reads as "all
// is well" to a model.
func looksClean(b []byte) bool {
	var v any
	if json.Unmarshal(b, &v) != nil {
		return false
	}
	return emptyValue(v)
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
	for _, c := range []string{`null`, `[]`, `{}`, `{"ports":[]}`, `{"ports":[],"total":0,"complete":false}`, `{"a":{"b":[]}}`} {
		if !looksClean([]byte(c)) {
			t.Errorf("%s: not seen as clean-looking", c)
		}
	}
	for _, c := range []string{`[{"port":22}]`, `{"ports":[],"note":"could not read the table"}`, `{"total":3}`, `{"complete":true}`} {
		if looksClean([]byte(c)) {
			t.Errorf("%s: seen as clean-looking", c)
		}
	}
}

// The gate as it stands: on macOS only surface is open. Opening patrol or
// incident is M1's step (m1-enable), done on purpose: this test changes
// with it.
func TestM1DarwinGate(t *testing.T) {
	for role, want := range map[string]bool{"surface": true, "patrol": false, "incident": false, "attack": false} {
		if _, _, open := roleFor(role, "darwin"); open != want {
			t.Errorf("%s on macOS: open %v, want %v", role, open, want)
		}
	}
}

// Each tool a macOS role runs gives data or an error, never a
// clean-looking empty result (runs on macOS, the CI macos job).
func TestM1DarwinToolsReadThePlatform(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("runs on macOS (the CI macos job)")
	}
	for _, role := range []string{"patrol", "incident"} {
		t.Run(role, func(t *testing.T) {
			r, missing, open := roleFor(role, "darwin")
			// SHENTU_M1_PROBE=1 runs a closed role's tools too and only logs
			// which look clean and how long their output is (never the output:
			// it is this host's), to show the platform line what is left.
			probe := !open && os.Getenv("SHENTU_M1_PROBE") == "1"
			if !open && !probe {
				t.Skipf("M1: %s is closed on macOS until the platform line's tools read macOS (plan f98c3c, m1-enable); not available there: %v", role, missing)
			}
			for _, name := range r.tools {
				tool, ok := tools.Find(name)
				if !ok {
					t.Errorf("%s: no such tool", name)
					continue
				}
				ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
				out, err := tool.Run(ctx, &tools.Env{}, json.RawMessage(`{}`))
				cancel()
				if err != nil {
					if probe {
						t.Logf("%s: error (explicit)", name)
					}
					continue // said it could not: explicit
				}
				b, _ := json.Marshal(out)
				switch {
				case probe:
					t.Logf("%s: looks clean %v, %d bytes", name, looksClean(b), len(b))
				case looksClean(b):
					t.Errorf("%s on macOS gave an empty result that looks clean: %s", name, b)
				}
			}
		})
	}
}
