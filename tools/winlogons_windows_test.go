//go:build windows

package tools

import (
	"testing"
	"time"
)

// The runner's real Security log: readable elevated, with the XPath accepted.
func TestWinLogonSummaryLive(t *testing.T) {
	out, err := winLogonSummary(time.Now().Add(-24*time.Hour), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%d sources in the last 24 hours", len(out["sources"].([]SSHSource)))
}
