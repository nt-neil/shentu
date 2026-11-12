package tools

import (
	"context"
	"strings"
	"testing"
)

func TestLinuxOnlyToolsErrorOnWindows(t *testing.T) {
	old := unsupportedHere
	unsupportedHere = true
	t.Cleanup(func() { unsupportedHere = old })
	names := map[string]bool{}
	for _, tl := range All() {
		names[tl.Name] = true
		if !windowsUnsupported[tl.Name] {
			continue
		}
		out, err := tl.Run(context.Background(), &Env{}, nil)
		if err == nil || out != nil || !strings.Contains(err.Error(), "not supported on Windows") {
			t.Errorf("%s on Windows: %v, %v; want an error, never an empty result", tl.Name, out, err)
		}
		if tl.Preview != nil {
			if _, err := tl.Preview(nil); err == nil {
				t.Errorf("%s preview on Windows must refuse too", tl.Name)
			}
		}
	}
	for n := range windowsUnsupported {
		if !names[n] {
			t.Errorf("%s is listed as Linux-only but is no tool: the guard would silently miss it", n)
		}
	}
	unsupportedHere = false
	for _, tl := range All() {
		if tl.Name == "processes" {
			if _, err := tl.Run(context.Background(), &Env{}, nil); err != nil && strings.Contains(err.Error(), "not supported on Windows") {
				t.Error("Unix tools must stay as they are")
			}
		}
	}
}
