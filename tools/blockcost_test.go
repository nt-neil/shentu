package tools

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// countLogins makes loginSummary count its reads: sshd's own logins from
// ip, so the check would let the block through.
func countLogins(t *testing.T, ip string) *atomic.Int32 {
	t.Helper()
	var n atomic.Int32
	oldS, oldT, oldJ := loginSummary, textLogins, sshdJournal
	t.Cleanup(func() { loginSummary, textLogins, sshdJournal = oldS, oldT, oldJ })
	textLogins = func(*Env, string) (int, []string, []string) { return 0, nil, nil }
	loginSummary = func(ctx context.Context, _ *Env, _ time.Time, _ string) (map[string]any, error) {
		n.Add(1)
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return map[string]any{"complete": true, "verified": true, "source": "journald", "sources": []SSHSource{{IP: ip, Failed: 9}}}, nil
	}
	sshdJournal = func(context.Context, time.Time, time.Time, string) (SSHSource, error) {
		return SSHSource{IP: ip, Failed: 9}, nil
	}
	return &n
}

func onBlockPlatform(t *testing.T, goos string) {
	old := HostGOOS
	HostGOOS = goos
	t.Cleanup(func() { HostGOOS = old })
}

func memoFor(t *testing.T, ttl time.Duration) *time.Time {
	oldT, oldN := loginMemoTTL, memoNow
	loginMemoMu.Lock()
	loginMemo = map[string]loginMemoEntry{} // nothing an earlier test kept
	loginMemoMu.Unlock()
	now := time.Now()
	loginMemoTTL, memoNow = ttl, func() time.Time { return now }
	t.Cleanup(func() {
		loginMemoTTL, memoNow = oldT, oldN
		loginMemoMu.Lock()
		loginMemo = map[string]loginMemoEntry{}
		loginMemoMu.Unlock()
	})
	return &now
}

// S-186-5: where block_ip cannot run (macOS, Windows) it is refused as
// unsupported before any check: no month of the unified log is read for it,
// from Telegram (RemoteBlockCheck, the precheck) or the server's terminal.
func TestBlockIPUnsupportedBeforeGate(t *testing.T) {
	for _, goos := range []string{"darwin", "windows"} {
		onBlockPlatform(t, goos)
		gateState(t)
		n := countLogins(t, "203.0.113.12")
		ip := net.ParseIP("203.0.113.12")
		if _, code, _ := RemoteBlockCheck(context.Background(), &Env{}, ip); code != BlockUnsupported {
			t.Errorf("%s: RemoteBlockCheck code %q", goos, code)
		}
		args := ProposalBlockArgs(ip)
		if _, err := blockIP.Preview(args); codeOf(err) != BlockUnsupported {
			t.Errorf("%s: Preview %v", goos, err)
		}
		if _, err := blockIP.Run(context.Background(), &Env{}, args); codeOf(err) != BlockUnsupported {
			t.Errorf("%s: Run %v", goos, err)
		}
		if n.Load() != 0 {
			t.Errorf("%s: the logins were read %d times for a block that cannot run", goos, n.Load())
		}
	}
	onBlockPlatform(t, "linux") // the same address passes on Linux: the refusal was the platform's
	gateState(t)
	countLogins(t, "203.0.113.12")
	if _, code, err := RemoteBlockCheck(context.Background(), &Env{}, net.ParseIP("203.0.113.12")); code != BlockOK {
		t.Errorf("linux: %q %v", code, err)
	}
}

// One dispatch's read-only checks of an address read its logins once;
// block_ip's Run reads again; an expired answer is read again.
func TestLoginCheckMemo(t *testing.T) {
	gateState(t)
	n := countLogins(t, "203.0.113.12")
	now := memoFor(t, 2*time.Minute)
	ip := net.ParseIP("203.0.113.12")
	for i := 0; i < 3; i++ { // the archive, the buttons, a precheck
		if _, code, err := RemoteBlockCheck(context.Background(), &Env{}, ip); code != BlockOK {
			t.Fatalf("check %d: %q %v", i, code, err)
		}
	}
	if n.Load() != 1 {
		t.Errorf("three checks of one address read its logins %d times, want 1", n.Load())
	}
	if _, code, _ := RemoteBlockCheck(context.Background(), &Env{}, net.ParseIP("203.0.113.13")); code == BlockOK || n.Load() != 3 { // the day, then the month: none from it
		t.Errorf("another address: %q, reads %d", code, n.Load())
	}
	if err := blockGate(context.Background(), &Env{Remote: true}, ip, false); err != nil || n.Load() != 4 {
		t.Errorf("block_ip's own gate (Run) did not read again: %v, reads %d", err, n.Load())
	}
	*now = now.Add(2 * time.Minute)
	RemoteBlockCheck(context.Background(), &Env{}, ip)
	if n.Load() != 5 {
		t.Errorf("an answer past its time was reused: reads %d", n.Load())
	}
}

// A check its context cut short is refused as timeout and not kept.
func TestLoginCheckTimeout(t *testing.T) {
	gateState(t)
	n := countLogins(t, "203.0.113.12")
	memoFor(t, 2*time.Minute)
	ip := net.ParseIP("203.0.113.12")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, code, _ := RemoteBlockCheck(ctx, &Env{}, ip); code != BlockTimeout {
		t.Errorf("cut short: %q", code)
	}
	if _, code, err := RemoteBlockCheck(context.Background(), &Env{}, ip); code != BlockOK || n.Load() != 2 {
		t.Errorf("the cut-short answer was kept: %q %v, reads %d", code, err, n.Load())
	}
}
