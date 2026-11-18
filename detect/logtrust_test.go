package detect

import (
	"testing"

	"github.com/nt-neil/shentu/hostenv"
)

// A log judged to be a server account's (hostenv.WebAccounts.ServerUIDs)
// stays verified while the file opened is still that account's; another
// owner, or a server account's file judged as root's, is not.
func TestOpenedServerOwner(t *testing.T) {
	const id = "1:2"
	rows := []struct {
		uid, judged int
		want        bool
	}{
		{999, 999, true},
		{rootUID, 999, true},
		{999, 0, false},
		{1000, 999, false},
	}
	for _, r := range rows {
		ok, _ := opened(hostenv.FileStat{Mode: 0o640, UID: r.uid, ID: id}, id, r.judged)
		if ok != r.want {
			t.Errorf("owner %d judged %d: %v, want %v", r.uid, r.judged, ok, r.want)
		}
	}
	if ok, _ := opened(hostenv.FileStat{Mode: 0o660, UID: 999, ID: id}, id, 999); ok {
		t.Errorf("group-writable file opened as verified")
	}
}
