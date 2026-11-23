package tools

import (
	"os"
	"testing"
)

// TestMain runs block_ip as on Linux, whatever this machine is, and without
// reusing loginCheck's answers: the tests swap the log readers between
// checks of one address. The platform and memo tests switch them back.
func TestMain(m *testing.M) {
	HostGOOS = "linux"
	loginMemoTTL = 0
	os.Exit(m.Run())
}
