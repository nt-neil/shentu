package hostenv

import (
	"fmt"
	"testing"
)

// S-305-3: Missed keeps maxMissed requests and counts the rest.
func TestReplayMissedBounded(t *testing.T) {
	rp := &Replay{byK: map[string]*entry{}}
	for i := range maxMissed + 5 {
		rp.ReadFile(fmt.Sprintf("/x/%d", i))
	}
	m := rp.Missed()
	if len(m) != maxMissed+1 || m[0] != "file /x/0" || m[maxMissed] != "... and 5 more" {
		t.Errorf("%d entries, first %q, last %q", len(m), m[0], m[len(m)-1])
	}
}
