package tools

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/nt-neil/shentu/hostenv"
)

// The patrol's refresh reads on past a read cut short by its time
// (JournalTimeout), each read saved, until it has read the whole journal:
// a flood of an hour is caught up in one patrol, and the check after it
// reads only from the end.
func TestRefreshLoginIndexCatchesUp(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	j := &fakeJournal{hangAfter: 2} // every read gives two entries, then runs out of time
	for i := 7; i > 0; i-- {
		j.failed(now.Add(-time.Duration(i)*time.Minute), "203.0.113.10")
	}
	withIndex(t, j, &now)
	old := hostenv.JournalTimeout
	hostenv.JournalTimeout = 100 * time.Millisecond
	t.Cleanup(func() { hostenv.JournalTimeout = old })
	RefreshLoginIndex(context.Background())
	if n := len(j.reads); n < 4 {
		t.Errorf("%d reads: %q; want the patrol to read on until it caught up", n, j.reads)
	}
	j.mu.Lock()
	j.hangAfter = 0
	j.mu.Unlock()
	if v, _, err := check("203.0.113.10"); !v {
		t.Fatalf("check: %v", err)
	}
	if r := j.reads[len(j.reads)-1]; r != "cursor "+j.cursorN(7) {
		t.Errorf("the check's read: %q, want from the last entry", r)
	}
}

// A flood of new addresses past maxIndexAddrs does not walk every kept
// address per event (prune, while full, once an hour of events): read at
// the speed of the rest, not slower the more addresses there are.
func TestLoginIndexOverflowFloodCost(t *testing.T) {
	old := maxIndexAddrs
	maxIndexAddrs = 20000
	t.Cleanup(func() { maxIndexAddrs = old })
	now := time.Now()
	x := &loginIndex{Version: loginIndexVersion, From: now.Add(-loginGateWindow), Addrs: map[string]*loginIndexAddr{}}
	start := time.Now()
	for i := 0; i < 120000; i++ {
		x.add(fmt.Sprintf("198.18.%d.%d", i/256%256, i%256), now.Add(time.Duration(i)*time.Millisecond), false)
	}
	if len(x.Addrs) != maxIndexAddrs || x.OverflowLast.IsZero() {
		t.Fatalf("kept %d, overflow %v", len(x.Addrs), x.OverflowLast)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("120000 events past a full index took %v", d) // each walking 20000 kept addresses: minutes
	}
}
