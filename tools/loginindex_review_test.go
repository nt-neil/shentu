package tools

import (
	"context"
	"errors"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nt-neil/shentu/hostenv"
)

// The login index's rule (#213 review): it answers at least as strictly as
// reading the whole window, and is no stricter for what the whole read
// cannot see either. These tests reach the index only through loginCheck,
// the fake journalctl and the index file.

// sshdOwn: sshd itself wrote it (_COMM sshd or sshd-session, _UID 0).
func sshdOwn(comm string, uid int) bool {
	return uid == 0 && (comm == "sshd" || comm == "sshd-session")
}

// shortISO is the line journalctl -o short-iso writes for e ("" for an
// entry with no message, which it gives no sshd line).
func (e fakeEntry) shortISO() string {
	if e.noMsg {
		return ""
	}
	return e.at.UTC().Format(time.RFC3339) + " h sshd[812]: " + e.msg
}

// wholeRead makes loginSummary and sshdJournal read j as the whole read
// does (SSHSummary over short-iso lines, SSHDJournalLines over sshd's own),
// so a check with the index off is the whole read of the same journal.
func wholeRead(t *testing.T, j *fakeJournal, now time.Time) {
	t.Helper()
	lines := func(own bool) []fakeEntry {
		j.mu.Lock()
		defer j.mu.Unlock()
		var out []fakeEntry
		for _, e := range j.entries {
			if !own || sshdOwn(e.comm, e.uid) {
				out = append(out, e)
			}
		}
		return out
	}
	tooLong := func(es []fakeEntry, since, until time.Time) bool {
		for _, e := range es {
			if !e.at.Before(since) && !e.at.After(until) && len(e.shortISO()) >= hostenv.MaxLineBytes {
				return true
			}
		}
		return false
	}
	loginSummary = func(_ context.Context, _ *Env, since time.Time, want string) (map[string]any, error) {
		if tooLong(lines(false), since, now) { // the read stops at a line past MaxLineBytes: reported in r
			return map[string]any{"complete": false, "verified": true, "source": "journald", "error": "token too long", "sources": []SSHSource{}}, nil
		}
		c := hostenv.NewSSHLogins(since, now, want)
		for _, e := range lines(false) {
			if l := e.shortISO(); l != "" {
				c.Add(l)
			}
		}
		list, _ := hostenv.MaxLogins(c)
		return map[string]any{"complete": true, "verified": true, "source": "journald", "sources": list}, nil
	}
	sshdJournal = func(_ context.Context, since, until time.Time, ip string) (SSHSource, error) {
		if tooLong(lines(true), since, until) {
			return SSHSource{}, errors.New("token too long")
		}
		c := hostenv.NewSSHLogins(since, until, ip)
		for _, e := range lines(true) {
			if l := e.shortISO(); l != "" && !e.at.After(until) {
				c.Add(l)
			}
		}
		list, _ := hostenv.MaxLogins(c)
		for _, s := range list {
			if hostenv.CanonicalIP(s.IP) == hostenv.CanonicalIP(ip) {
				return s, nil
			}
		}
		return SSHSource{IP: ip}, nil
	}
}

func indexFile(t *testing.T, dir string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, LoginIndexFile))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// N-213-1, S-213-1: the journal vacuumed past the index's cursor. journalctl
// takes the cursor without an error and starts at the nearest entry; the
// index reads from there, that first entry after the gap included (a
// forged event there is seen), notes it, and answers for an address with no
// events as before, not as unreadable. An address whose events were all
// vacuumed is not seen, as the whole read (which cannot see them) says.
func TestLoginIndexJournalRotated(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	j := &fakeJournal{}
	j.failed(now.Add(-3*time.Hour), "203.0.113.10")
	j.failed(now.Add(-150*time.Minute), "203.0.113.20")
	dir, _ := withIndex(t, j, &now)
	if v, _, err := check("203.0.113.10"); !v {
		t.Fatalf("first check: %v", err)
	}
	last := j.cursorN(j.seq)
	j.vacuum(j.seq) // every entry so far, the cursor's with them
	j.forged(now.Add(-2*time.Hour), "203.0.113.10")
	j.failed(now.Add(-time.Hour), "203.0.113.10")
	if v, code, err := check("203.0.113.10"); v || code != BlockUnverified {
		t.Errorf("a forged event first after the gap: verified %v, %q (%v); want unverified", v, code, err)
	}
	if r := j.reads[len(j.reads)-1]; r != "cursor "+last {
		t.Errorf("read: %q, want from the saved cursor, its entry included", r)
	}
	if v, code, err := check("203.0.113.30"); v || code != BlockOK {
		t.Errorf("no events, after the rotation: verified %v, %q (%v); want as before", v, code, err)
	}
	if v, code, err := check("203.0.113.20"); v || code != BlockOK {
		t.Errorf("an address only in what was vacuumed: verified %v, %q (%v); want not seen, as the whole read", v, code, err)
	}
	if f := indexFile(t, dir); !strings.Contains(f, "moved on past the index") {
		t.Errorf("no note of the rotation: %s", f)
	}
}

// S-213-2: a saved cursor that is not one (cut short) is dropped and the
// read goes on by time from its entry; it is not saved back, and the whole
// window is not read on every check.
func TestLoginIndexBadCursor(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	j := &fakeJournal{}
	j.failed(now.Add(-time.Hour), "203.0.113.10")
	dir, whole := withIndex(t, j, &now)
	bad := `{"version":1,"cursor":"s=0123456789abcdef","cursor_time":"` + now.Add(-2*time.Hour).Format(time.RFC3339) +
		`","from":"` + now.Add(-loginGateWindow).Format(time.RFC3339) + `","read_at":"` + now.Format(time.RFC3339) + `","addrs":{}}`
	os.WriteFile(filepath.Join(dir, LoginIndexFile), []byte(bad), 0o600)
	for i := 0; i < 2; i++ {
		if v, code, err := check("203.0.113.10"); !v || code != BlockOK {
			t.Errorf("check %d: verified %v, %q (%v)", i, v, code, err)
		}
	}
	if *whole != 0 {
		t.Errorf("the whole window was read %d times", *whole)
	}
	if f := indexFile(t, dir); strings.Contains(f, `"s=0123456789abcdef"`) || !strings.Contains(f, j.cursorN(j.seq)) {
		t.Errorf("the bad cursor kept: %s", f)
	}
	if len(j.reads) == 0 || j.reads[0] != "since "+now.Add(-2*time.Hour).UTC().Format(time.RFC3339) {
		t.Errorf("reads: %q, want by time from the cursor's entry first", j.reads)
	}
}

// N-213-3: an address saved as null is dropped, not a panic.
func TestLoginIndexNullAddr(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	j := &fakeJournal{}
	j.failed(now.Add(-time.Hour), "203.0.113.10")
	dir, _ := withIndex(t, j, &now)
	if v, _, err := check("203.0.113.10"); !v {
		t.Fatalf("first check: %v", err)
	}
	f := indexFile(t, dir)
	f = strings.Replace(f, `"addrs":{`, `"addrs":{"203.0.113.71":null,`, 1)
	os.WriteFile(filepath.Join(dir, LoginIndexFile), []byte(f), 0o600)
	if v, code, err := check("203.0.113.71"); v || code != BlockOK {
		t.Errorf("a null address: verified %v, %q (%v)", v, code, err)
	}
	if v, _, err := check("203.0.113.10"); !v {
		t.Errorf("the rest of the index: %v", err)
	}
	if f := indexFile(t, dir); strings.Contains(f, "null") {
		t.Errorf("null saved back: %s", f)
	}
}

// N-213-2, S-213-4: an entry is read whole up to the line the whole read
// takes (1 MiB): a forged event with a 70 KB user name counts against its
// address only, as the whole read counts it; an entry with no message is
// no event, as for the whole read. Only an entry past that line, which the
// whole read fails on (state_error), whoever wrote it, makes a window
// holding it unverified, for every address.
func TestLoginIndexUnreadableEntry(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	long := "Failed password for invalid user " + strings.Repeat("x", 70<<10) + " from 203.0.113.10 port 22 ssh2"
	huge := "Failed password for invalid user " + strings.Repeat("x", 1<<20) + " from 203.0.113.10 port 22 ssh2"
	for _, c := range []struct {
		name    string
		entries []fakeEntry
		ip      string
		v       bool
		refused bool
	}{
		{"70 KB forged, then own: its address", []fakeEntry{{at: now.Add(-2 * time.Hour), comm: "logger", uid: 1000, msg: long}}, "203.0.113.10", false, true},
		{"70 KB forged: another address", []fakeEntry{{at: now.Add(-2 * time.Hour), comm: "logger", uid: 1000, msg: long}}, "203.0.113.14", false, false},
		{"no message, not sshd's", []fakeEntry{{at: now.Add(-2 * time.Hour), comm: "logger", uid: 1000, noMsg: true}}, "203.0.113.12", false, false},
		{"over 1 MiB, forged", []fakeEntry{{at: now.Add(-2 * time.Hour), comm: "logger", uid: 1000, msg: huge}}, "203.0.113.12", false, true},
		{"over 1 MiB, sshd's own", []fakeEntry{{at: now.Add(-2 * time.Hour), comm: "sshd", uid: 0, msg: huge}}, "203.0.113.12", false, true},
		{"70 KB, sshd's own", []fakeEntry{{at: now.Add(-2 * time.Hour), comm: "sshd", uid: 0, msg: long}}, "203.0.113.13", true, false},
	} {
		j := &fakeJournal{}
		for _, e := range c.entries {
			j.addEntry(e)
		}
		j.failed(now.Add(-time.Hour), "203.0.113.10")
		j.failed(now.Add(-time.Hour), "203.0.113.13")
		withIndex(t, j, &now)
		wholeRead(t, j, now)
		iv, icode, ierr := check(c.ip)
		KeepLoginIndex = false
		wv, wcode, werr := check(c.ip)
		for _, r := range []struct {
			who  string
			v    bool
			code BlockCode
			err  error
		}{{"index", iv, icode, ierr}, {"whole read", wv, wcode, werr}} {
			if r.v != c.v || (r.code != BlockOK) != c.refused {
				t.Errorf("%s, %s: verified %v, %q (%v); want verified %v, refused %v", c.name, r.who, r.v, r.code, r.err, c.v, c.refused)
			}
		}
	}
}

// S-213-3: the journal vacuumed entries older than the cursor's, which is
// still there: an address whose events were all among them is not seen,
// as the whole read (which no longer has them) says.
func TestLoginIndexVacuumedBehindCursor(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	j := &fakeJournal{}
	j.failed(now.Add(-100*time.Hour), "203.0.113.20")
	j.failed(now.Add(-time.Hour), "203.0.113.10")
	withIndex(t, j, &now)
	if v, _, err := check("203.0.113.10"); !v {
		t.Fatalf("first check: %v", err)
	}
	j.vacuum(1) // the 100-hour-old entry; the cursor's (the last) stays
	if v, code, err := check("203.0.113.20"); v || code != BlockOK {
		t.Errorf("vacuumed behind the cursor: verified %v, %q (%v); want not seen", v, code, err)
	}
	wholeRead(t, j, now)
	KeepLoginIndex = false
	if v, code, _ := check("203.0.113.20"); v || code != BlockOK {
		t.Errorf("the whole read: verified %v, %q", v, code)
	}
}

// The index against the whole read, over random journals (fixed seed):
// the two answer alike, as strictly (verified, nothing against it, or
// refused), for every address. The journals hold sshd's own events and
// forged ones (another program, or sshd not as root), the same address
// written as IPv4 and as ::ffff:, entries that are no events, 70 KB entries
// (both read them) and entries over 1 MiB (both refuse for the window that
// holds one); in a third of them the index is built first and the journal
// then vacuumed from its oldest entry, the cursor's entry or not.
func TestLoginIndexAgreesWithWholeRead(t *testing.T) {
	rng := rand.New(rand.NewSource(20261123))
	ips := []string{"203.0.113.10", "2001:db8::7", "203.0.113.11"}
	writers := []struct {
		comm string
		uid  int
	}{{"sshd", 0}, {"sshd-session", 0}, {"logger", 1000}, {"sshd", 1000}, {"logger", 0}}
	kinds := []string{"Failed password for root from %s port 22 ssh2", "Invalid user admin from %s port 22", "Accepted publickey for ops from %s port 22 ssh2"}
	// strictness: verified 0, nothing against it 1, refused 2
	rank := func(v bool, code BlockCode) int {
		switch {
		case v && code == BlockOK:
			return 0
		case code == BlockOK:
			return 1
		}
		return 2
	}
	now := time.Now().Truncate(time.Second)
	differ, vacuumed := 0, 0
	for n := 0; n < 300; n++ {
		j := &fakeJournal{}
		for k := rng.Intn(8); k > 0; k-- {
			// whole hours and a half: never within minutes of a window's edge
			at := now.Add(-time.Duration(rng.Intn(800))*time.Hour - 30*time.Minute)
			w := writers[rng.Intn(len(writers))]
			ip := ips[rng.Intn(len(ips))]
			if rng.Intn(4) == 0 {
				ip = "::ffff:" + ips[0]
			}
			msg := strings.Replace(kinds[rng.Intn(len(kinds))], "%s", ip, 1)
			switch rng.Intn(20) {
			case 0, 1:
				msg = "Failed password for invalid user " + strings.Repeat("y", 70<<10) + " from " + ip + " port 22 ssh2"
			case 2:
				msg = "Failed password for invalid user " + strings.Repeat("z", 1<<20) + " from " + ip + " port 22 ssh2"
			case 3, 4:
				msg = "Server listening on 0.0.0.0 port 22."
			}
			j.add(at, w.comm, w.uid, msg)
		}
		j.inTimeOrder()
		withIndex(t, j, &now)
		wholeRead(t, j, now)
		if len(j.entries) > 0 && rng.Intn(3) == 0 {
			check(ips[0]) // the index built, then the oldest entries vacuumed
			j.vacuum(1 + rng.Intn(len(j.entries)))
			vacuumed++
		}
		for _, ip := range ips {
			KeepLoginIndex = true
			iv, icode, ierr := check(ip)
			KeepLoginIndex = false
			wv, wcode, werr := check(ip)
			if rank(iv, icode) != rank(wv, wcode) {
				differ++
				if differ <= 5 {
					t.Errorf("journal %d, %s: index %v %q (%v), whole read %v %q (%v)", n, ip, iv, icode, ierr, wv, wcode, werr)
				}
			}
		}
	}
	if differ > 0 {
		t.Errorf("%d answers differ", differ)
	}
	if vacuumed < 50 {
		t.Errorf("only %d journals vacuumed", vacuumed)
	}
}
