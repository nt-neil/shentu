package tools

import (
	"os"
	"testing"
)

// TestMain runs block_ip as on Linux, whatever this machine is, and without
// reusing loginCheck's answers: the tests swap the log readers between
// checks of one address. Nor is the login index kept, which would read this
// host's journal. The platform, memo and index tests switch them back.
func TestMain(m *testing.M) {
	HostGOOS = "linux"
	loginMemoTTL = 0
	KeepLoginIndex = false
	os.Exit(m.Run())
}
