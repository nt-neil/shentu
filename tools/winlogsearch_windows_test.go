//go:build windows

package tools

import "testing"

// The runner's own System log, through the live event reader.
func TestWinLogSearchLive(t *testing.T) {
	out, err := winLogSearch("System", ".", 5)
	if err != nil {
		t.Fatal(err)
	}
	if m, _ := out["matches"].([]string); len(m) == 0 {
		t.Error("the System log of a running runner has events")
	}
}
