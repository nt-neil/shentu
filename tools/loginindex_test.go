package tools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nt-neil/shentu/hostenv"
)

// fakeJournal answers journalctl's reads of sshd's units as journalctl
// does: only an argv the Linux allowlist takes (hostenv.ErrNotAllowed
// otherwise, as the live runner), -o json with __CURSOR and
// __REALTIME_TIMESTAMP first, --since a time, and a cursor as journalctl
// seeks one: a well-formed cursor whose entry is gone is no error, the read
// starts at the nearest entry after it; --cursor reads from there,
// --after-cursor skips one entry more (the cursor's, or the first after the
// gap: sd_journal_next_skip(j, 2)); with neither, from the first entry.
type fakeJournal struct {
	mu      sync.Mutex
	entries []fakeEntry
	reads   []string // "since <time>", "cursor <c>" or "after <c>", one per read
	seq     int
	// sid is the seqnum_id of the entries added from now on ("" the
	// fixtures' one): a journal made anew.
	sid string
	// hangAfter: a read gives this many entries, then waits for its
	// context to end (a read cut short); 0: no wait.
	hangAfter int
}

type fakeEntry struct {
	seq   int
	sid   string
	at    time.Time
	comm  string
	uid   int
	msg   string
	noMsg bool // MESSAGE null
}

func (j *fakeJournal) cursorN(n int) string {
	sid := j.sid
	if sid == "" {
		sid = "0123456789abcdef0123456789abcdef"
	}
	return fmt.Sprintf("s=%s;i=%x;b=0123456789abcdef0123456789abcdef;m=%x;t=%x;x=%x", sid, n, n, n, n)
}

// seqOf is the entry number a cursor names (its i=).
func seqOf(c string) int {
	_, rest, _ := strings.Cut(c, ";i=")
	hex, _, _ := strings.Cut(rest, ";")
	n, _ := strconv.ParseInt(hex, 16, 64)
	return int(n)
}

// add appends an entry by comm (uid 0 unless forged by a user) with the
// tag sshd.
func (j *fakeJournal) add(at time.Time, comm string, uid int, msg string) {
	j.addEntry(fakeEntry{at: at, comm: comm, uid: uid, msg: msg})
}

func (j *fakeJournal) addEntry(e fakeEntry) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.seq++
	e.seq, e.sid = j.seq, j.sid
	j.entries = append(j.entries, e)
}

// inTimeOrder puts the entries in time order and numbers them so, as
// journald keeps a journal (an entry added out of order is a fixture's).
func (j *fakeJournal) inTimeOrder() {
	j.mu.Lock()
	defer j.mu.Unlock()
	sort.SliceStable(j.entries, func(a, b int) bool { return j.entries[a].at.Before(j.entries[b].at) })
	for i := range j.entries {
		j.entries[i].seq = i + 1
	}
	j.seq = len(j.entries)
}

// vacuum drops the entries up to entry n, as journalctl --vacuum-* does.
func (j *fakeJournal) vacuum(n int) {
	j.mu.Lock()
	defer j.mu.Unlock()
	k := 0
	for k < len(j.entries) && j.entries[k].seq <= n {
		k++
	}
	j.entries = j.entries[k:]
}

func (j *fakeJournal) failed(at time.Time, ip string) {
	j.add(at, "sshd", 0, "Failed password for root from "+ip+" port 22 ssh2")
}
func (j *fakeJournal) forged(at time.Time, ip string) {
	j.add(at, "logger", 1000, "Failed password for root from "+ip+" port 22 ssh2")
}

func (j *fakeJournal) Info() hostenv.SourceInfo         { return hostenv.SourceInfo{GOOS: "linux"} }
func (j *fakeJournal) ReadFile(string) ([]byte, error)  { return nil, fs.ErrNotExist }
func (j *fakeJournal) ReadDir(string) ([]string, error) { return nil, fs.ErrNotExist }
func (j *fakeJournal) Readlink(string) (string, error)  { return "", fs.ErrNotExist }
func (j *fakeJournal) Run(context.Context, []string) (hostenv.CmdResult, error) {
	return hostenv.CmdResult{}, errors.New("not used: reads stream")
}

var linuxRunner, _ = hostenv.NewRunner(hostenv.LinuxCollector{}.Allowlist())

// jsonLine is the entry as journalctl -o json writes it.
func (e fakeEntry) jsonLine() string {
	msg := []byte("null")
	if !e.noMsg {
		msg, _ = json.Marshal(e.msg)
	}
	comm, _ := json.Marshal(e.comm)
	return fmt.Sprintf(`{"__CURSOR":"%s","__REALTIME_TIMESTAMP":"%d","_SYSTEMD_UNIT":"ssh.service","_UID":"%d","_PID":"812","_COMM":%s,"SYSLOG_IDENTIFIER":"sshd","MESSAGE":%s}`,
		(&fakeJournal{sid: e.sid}).cursorN(e.seq), e.at.UnixMicro(), e.uid, comm, msg)
}

func (j *fakeJournal) RunLinesCut(ctx context.Context, argv []string, max int, fn func(string, bool)) (hostenv.CmdResult, error) {
	if !linuxRunner.Allowed(argv) {
		return hostenv.CmdResult{}, fmt.Errorf("%w: %q", hostenv.ErrNotAllowed, argv)
	}
	if !strings.Contains(strings.Join(argv, " "), "-u ssh -u sshd -u ssh@* -u sshd@*") {
		return hostenv.CmdResult{}, fmt.Errorf("unexpected command %q", argv)
	}
	j.mu.Lock()
	var out []fakeEntry
	if !strings.Contains(strings.Join(argv, " "), "--since") && !strings.Contains(strings.Join(argv, " "), "cursor") {
		out = append(out, j.entries...) // from the first entry (where the journal starts): not counted as a read
	}
	for i, a := range argv {
		switch a {
		case "--since":
			since, err := time.Parse("2006-01-02 15:04:05 MST", argv[i+1])
			if err != nil {
				j.mu.Unlock()
				return hostenv.CmdResult{}, err
			}
			j.reads = append(j.reads, "since "+since.UTC().Format(time.RFC3339))
			for _, e := range j.entries {
				if !e.at.Before(since) {
					out = append(out, e)
				}
			}
		case "--cursor", "--after-cursor":
			word := map[string]string{"--cursor": "cursor ", "--after-cursor": "after "}[a]
			j.reads = append(j.reads, word+argv[i+1])
			want := seqOf(argv[i+1])
			k := 0 // the nearest entry from the cursor's place on
			for k < len(j.entries) && j.entries[k].seq < want {
				k++
			}
			if a == "--after-cursor" {
				k++ // skip one: the cursor's entry, or the first after the gap
			}
			if k < len(j.entries) {
				out = append(out, j.entries[k:]...)
			}
		}
	}
	hang := j.hangAfter
	j.mu.Unlock()
	for n, e := range out {
		if hang > 0 && n == hang {
			<-ctx.Done()
			return hostenv.CmdResult{}, ctx.Err()
		}
		l := e.jsonLine()
		if len(l) > max {
			fn(l[:max], true)
			continue
		}
		fn(l, false)
	}
	return hostenv.CmdResult{}, nil
}

// withIndex keeps the login index in a new state directory over j, at now;
// reading the whole window (loginSummary, sshdJournal) counts in whole.
func withIndex(t *testing.T, j *fakeJournal, now *time.Time) (dir string, whole *int) {
	t.Helper()
	dir = t.TempDir()
	oldDir, oldKeep, oldAll, oldNow, oldSrc := attackStateDir, KeepLoginIndex, journalAll, indexNow, hostSource
	oldS, oldT, oldJ := loginSummary, textLogins, sshdJournal
	t.Cleanup(func() {
		attackStateDir, KeepLoginIndex, journalAll, indexNow, hostSource = oldDir, oldKeep, oldAll, oldNow, oldSrc
		loginSummary, textLogins, sshdJournal = oldS, oldT, oldJ
	})
	attackStateDir, KeepLoginIndex = dir, true
	journalAll = func() bool { return true }
	indexNow = func() time.Time { return *now }
	hostSource = func() hostenv.Source { return j }
	whole = new(int)
	loginSummary = func(context.Context, *Env, time.Time, string) (map[string]any, error) {
		*whole++
		return map[string]any{"complete": true, "verified": true, "source": "journald", "sources": []SSHSource{}}, nil
	}
	sshdJournal = func(context.Context, time.Time, time.Time, string) (SSHSource, error) {
		*whole++
		return SSHSource{}, nil
	}
	textLogins = func(*Env, string) (int, []string, []string) { return 0, nil, nil }
	return dir, whole
}

func check(ip string) (bool, BlockCode, error) {
	v, err := loginCheck(context.Background(), &Env{}, net.ParseIP(ip))
	return v, codeOf(err), err
}

// The login index answers as the whole read does: an address whose events
// in the window sshd itself wrote, one with an event another program wrote
// in sshd's unit, the window (the day, else 720h) as loginCheckRead takes
// it, one with no events; without reading the whole window again.
func TestLoginIndexAnswers(t *testing.T) {
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	j := &fakeJournal{}
	j.failed(now.Add(-time.Hour), "203.0.113.10")
	j.failed(now.Add(-2*time.Hour), "203.0.113.11")
	j.forged(now.Add(-3*time.Hour), "203.0.113.11")
	j.failed(now.Add(-48*time.Hour), "203.0.113.12")
	j.forged(now.Add(-30*time.Hour), "203.0.113.12") // in 720h, the window when the day has none
	j.failed(now.Add(-time.Hour), "203.0.113.13")
	j.forged(now.Add(-30*time.Hour), "203.0.113.13") // before the day, which is the window
	j.add(now.Add(-time.Hour), "sshd", 0, "Server listening on 0.0.0.0 port 22.")
	j.inTimeOrder()
	dir, whole := withIndex(t, j, &now)
	for _, c := range []struct {
		ip       string
		verified bool
		code     BlockCode
	}{
		{"203.0.113.10", true, BlockOK},
		{"203.0.113.11", false, BlockUnverified},
		{"203.0.113.12", false, BlockUnverified},
		{"203.0.113.13", true, BlockOK},
		{"203.0.113.14", false, BlockOK},
		{"::ffff:203.0.113.10", true, BlockOK},
	} {
		if v, code, err := check(c.ip); v != c.verified || code != c.code {
			t.Errorf("%s: verified %v, %q (%v); want %v, %q", c.ip, v, code, err, c.verified, c.code)
		}
	}
	if *whole != 0 {
		t.Errorf("the whole window was read %d times", *whole)
	}
	want := "since " + now.Add(-loginGateWindow).Format(time.RFC3339)
	if len(j.reads) == 0 || j.reads[0] != want {
		t.Errorf("first read: %q, want %q", j.reads, want)
	}
	for _, r := range j.reads[1:] {
		if !strings.HasPrefix(r, "cursor ") {
			t.Errorf("a later read not from the cursor: %q", r)
		}
	}
	st, err := os.Stat(filepath.Join(dir, LoginIndexFile))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("index file: %v %v", st, err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, LoginIndexFile))
	if !strings.Contains(string(b), `"version":1`) || !strings.Contains(string(b), j.cursorN(j.seq)) {
		t.Errorf("index file: %s", b)
	}
}

// A check reads on from where the last stopped: a forged event that came
// since is seen.
func TestLoginIndexReadsOn(t *testing.T) {
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	j := &fakeJournal{}
	j.failed(now.Add(-time.Hour), "203.0.113.10")
	withIndex(t, j, &now)
	if v, _, err := check("203.0.113.10"); !v {
		t.Fatalf("first check: %v", err)
	}
	last := j.cursorN(j.seq)
	now = now.Add(10 * time.Minute)
	j.forged(now.Add(-time.Minute), "203.0.113.10")
	if v, code, _ := check("203.0.113.10"); v || code != BlockUnverified {
		t.Errorf("after a forged event: verified %v, %q", v, code)
	}
	if r := j.reads[len(j.reads)-1]; r != "cursor "+last {
		t.Errorf("second read: %q, want from %s", r, last)
	}
}

// An index the index cannot use (written before it had a version) is
// started again from loginGateWindow back; one starting after the window
// leaves the check to the whole read.
func TestLoginIndexOldFormat(t *testing.T) {
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	j := &fakeJournal{}
	j.failed(now.Add(-time.Hour), "203.0.113.10")
	dir, whole := withIndex(t, j, &now)
	old := `{"cursor":"` + j.cursorN(1) + `","from":"` + now.Add(-time.Hour).Format(time.RFC3339) + `","addrs":{}}`
	os.WriteFile(filepath.Join(dir, LoginIndexFile), []byte(old), 0o600)
	if v, _, err := check("203.0.113.10"); !v || *whole != 0 {
		t.Fatalf("old index: verified %v (%v), whole reads %d", v, err, *whole)
	}
	if r := j.reads[0]; r != "since "+now.Add(-loginGateWindow).Format(time.RFC3339) {
		t.Errorf("old index not started again: %q", j.reads)
	}

	short := fmt.Sprintf(`{"version":1,"cursor":%q,"from":%q,"read_at":%q,"addrs":{}}`, j.cursorN(j.seq), now.Add(-10*time.Hour).Format(time.RFC3339), now.Format(time.RFC3339))
	os.WriteFile(filepath.Join(dir, LoginIndexFile), []byte(short), 0o600)
	if _, _, err := check("203.0.113.30"); *whole == 0 {
		t.Errorf("an index of 10 hours answered for 720h (%v)", err)
	}
}

// Past maxIndexAddrs an address's events go to the overflow: such an
// address, or one with none kept, is not answered for while the overflow
// has events in the window; one kept from before the overflow is.
func TestLoginIndexOverflow(t *testing.T) {
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	old := maxIndexAddrs
	maxIndexAddrs = 2
	t.Cleanup(func() { maxIndexAddrs = old })
	j := &fakeJournal{}
	j.failed(now.Add(-5*time.Hour), "203.0.113.1")
	j.failed(now.Add(-4*time.Hour), "203.0.113.2")
	j.failed(now.Add(-3*time.Hour), "203.0.113.3")
	j.failed(now.Add(-2*time.Hour), "203.0.113.1")
	withIndex(t, j, &now)
	for _, c := range []struct {
		ip   string
		v    bool
		code BlockCode
	}{
		{"203.0.113.3", false, BlockStateError},
		{"203.0.113.9", false, BlockStateError},
		{"203.0.113.1", true, BlockOK},
	} {
		if v, code, err := check(c.ip); v != c.v || code != c.code {
			t.Errorf("%s: verified %v, %q (%v); want %v %q", c.ip, v, code, err, c.v, c.code)
		}
	}
}

// A read cut short by the check's time is refused as not checked in time,
// and what it read is kept: the next check goes on from there, so a
// flooded journal is read through over the checks.
func TestLoginIndexCutShort(t *testing.T) {
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	j := &fakeJournal{hangAfter: 2}
	for i := 0; i < 4; i++ {
		j.failed(now.Add(-time.Duration(4-i)*time.Minute), "203.0.113.10")
	}
	withIndex(t, j, &now)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err := loginCheck(ctx, &Env{}, net.ParseIP("203.0.113.10"))
	if codeOf(err) != BlockTimeout {
		t.Fatalf("cut short: %q (%v)", codeOf(err), err)
	}
	j.mu.Lock()
	j.hangAfter = 0
	j.mu.Unlock()
	if v, _, err := check("203.0.113.10"); !v {
		t.Errorf("next check: %v", err)
	}
	if r := j.reads[len(j.reads)-1]; r != "cursor "+j.cursorN(2) {
		t.Errorf("next read: %q, want from the second entry", r)
	}
}
