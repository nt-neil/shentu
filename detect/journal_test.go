package detect

import (
	"context"
	"io/fs"
	"strings"
	"testing"
	"time"

	"github.com/nt-neil/shentu/hostenv"
)

const (
	jc1 = "s=0123456789abcdef0123456789abcdef;i=1;b=0123456789abcdef0123456789abcdef;m=1;t=1;x=1"
	jc2 = "s=0123456789abcdef0123456789abcdef;i=2;b=0123456789abcdef0123456789abcdef;m=2;t=2;x=2"
)

// journalSrc answers journalctl reads of one unit: since a time, the whole
// journal; after a cursor, what follows it; a cursor it does not know, the
// error journalctl gives.
type journalSrc struct {
	entries []string // JSON lines, cursors jc1, jc2...
	cursors []string
	asked   []string
}

func (j *journalSrc) Info() hostenv.SourceInfo           { return hostenv.SourceInfo{GOOS: "linux"} }
func (j *journalSrc) ReadFile(p string) ([]byte, error)  { return nil, fs.ErrNotExist }
func (j *journalSrc) ReadDir(p string) ([]string, error) { return nil, fs.ErrNotExist }
func (j *journalSrc) Readlink(p string) (string, error)  { return "", fs.ErrNotExist }
func (j *journalSrc) Run(_ context.Context, argv []string) (hostenv.CmdResult, error) {
	if argv[0] != "/usr/bin/journalctl" {
		return hostenv.CmdResult{}, &fs.PathError{Op: "exec", Path: argv[0], Err: fs.ErrNotExist}
	}
	j.asked = append(j.asked, argv[3]+" "+argv[4])
	from := 0
	if argv[3] == "--after-cursor" {
		from = -1
		for i, c := range j.cursors {
			if c == argv[4] {
				from = i + 1
			}
		}
		if from < 0 {
			return hostenv.CmdResult{ExitCode: 1, Stderr: "Failed to seek to cursor: Invalid argument"}, nil
		}
	}
	return hostenv.CmdResult{Stdout: []byte(strings.Join(j.entries[from:], "\n") + "\n")}, nil
}

func entry(cursor, unit, uid, msg string) string {
	return `{"__CURSOR":"` + cursor + `","__REALTIME_TIMESTAMP":"1794700000000000","_SYSTEMD_UNIT":"` + unit + `","_UID":"` + uid + `","_TRANSPORT":"journal","MESSAGE":"` + msg + `"}`
}

func TestEntryTrust(t *testing.T) {
	web := hostenv.WebAccounts{UIDs: map[int]string{33: "www-data"}}
	u := hostenv.AppUnit{Name: "php8.2-fpm.service", FPM: true}
	asRoot := hostenv.AppUnit{Name: "app.service"} // no User=: the application may run as root
	for _, c := range []struct {
		e    hostenv.JournalEntry
		want JournalTrust
	}{
		{hostenv.JournalEntry{Unit: u.Name, UID: 0, Transport: "journal"}, JournalTrust{Verified: true}},
		{hostenv.JournalEntry{Unit: u.Name, UID: 0, Transport: "syslog"}, JournalTrust{Verified: true}},
		{hostenv.JournalEntry{Unit: u.Name, UID: 33, Transport: "journal"}, JournalTrust{Reason: hostenv.ReasonWebUserWritable}},
		{hostenv.JournalEntry{Unit: u.Name, UID: 1000, Transport: "syslog"}, JournalTrust{Reason: hostenv.ReasonUntrusted}},
		// A worker writing to the stderr the root master opened is logged as uid 0.
		{hostenv.JournalEntry{Unit: u.Name, UID: 0, Transport: "stdout"}, JournalTrust{Reason: hostenv.ReasonWebUserWritable}},
		{hostenv.JournalEntry{Unit: u.Name, UID: 33, Transport: "stdout"}, JournalTrust{Reason: hostenv.ReasonWebUserWritable}},
		{hostenv.JournalEntry{Unit: u.Name, UID: 0, Transport: "kernel"}, JournalTrust{Reason: hostenv.ReasonUnverified}},
		{hostenv.JournalEntry{Unit: "init.scope", UID: 0, Transport: "journal"}, JournalTrust{Reason: hostenv.ReasonUnverified}}, // systemd's message about the unit
		{hostenv.JournalEntry{Unit: u.Name, UID: -1, Transport: "journal"}, JournalTrust{Reason: hostenv.ReasonUnverified}},
	} {
		if got := EntryTrust(c.e, u, web); got != c.want {
			t.Errorf("%+v: %+v, want %+v", c.e, got, c.want)
		}
	}
	// The application itself may be root: its root message is not verified.
	if got := EntryTrust(hostenv.JournalEntry{Unit: "app.service", UID: 0, Transport: "journal"}, asRoot, web); got.Verified || got.Reason != hostenv.ReasonWebUserWritable {
		t.Errorf("root message of a unit without User=: %+v, want web_user_writable", got)
	}
}

func TestReadJournalUnit(t *testing.T) {
	u := hostenv.AppUnit{Name: "php8.2-fpm.service", FPM: true}
	src := &journalSrc{
		entries: []string{entry(jc1, u.Name, "33", "PHP Warning: one"), entry(jc2, u.Name, "0", "two")},
		cursors: []string{jc1, jc2},
	}
	web := hostenv.WebAccounts{UIDs: map[int]string{33: "www-data"}}
	var got []string
	fn := func(e hostenv.JournalEntry, tr JournalTrust) { got = append(got, e.Message+"/"+string(tr.Reason)) }

	// First run, a budget for one entry: stops after it, says so.
	c, r, err := ReadJournalUnit(context.Background(), src, u, nil, NewBudget(10, time.Minute), web, fn)
	if err != nil || c.Journal != jc1 || strings.Join(r.Partial, ",") != ReadFirstRun+","+ReadTruncated {
		t.Fatalf("first run: %v, cursor %q, partial %v", err, c.Journal, r.Partial)
	}
	if strings.Join(got, "|") != "PHP Warning: one/web_user_writable" {
		t.Errorf("first run entries %q", got)
	}
	// The next run goes on after it.
	got = nil
	c, r, err = ReadJournalUnit(context.Background(), src, u, &c, NewBudget(DefaultBudgetBytes, time.Minute), web, fn)
	if err != nil || c.Journal != jc2 || len(r.Partial) != 0 || strings.Join(got, "|") != "two/" {
		t.Errorf("next run: %v, cursor %q, partial %v, entries %q", err, c.Journal, r.Partial, got)
	}
	if !strings.HasPrefix(src.asked[1], "--after-cursor "+jc1) {
		t.Errorf("asked %q", src.asked)
	}
	// Nothing new: the cursor stays.
	c2, _, err := ReadJournalUnit(context.Background(), src, u, &c, NewBudget(DefaultBudgetBytes, time.Minute), web, fn)
	if err != nil || c2.Journal != jc2 {
		t.Errorf("nothing new: %v, cursor %q", err, c2.Journal)
	}
}

// A cursor the journal no longer has (rotated past it): read the window
// again, and say what may be lost.
func TestReadJournalUnitStaleCursor(t *testing.T) {
	u := hostenv.AppUnit{Name: "gunicorn.service", User: "www-data"}
	src := &journalSrc{entries: []string{entry(jc2, u.Name, "0", "after rotation")}, cursors: []string{jc2}}
	stale := Cursor{Journal: jc1}
	var got []string
	c, r, err := ReadJournalUnit(context.Background(), src, u, &stale, NewBudget(DefaultBudgetBytes, time.Minute), hostenv.WebAccounts{},
		func(e hostenv.JournalEntry, _ JournalTrust) { got = append(got, e.Message) })
	if err != nil || c.Journal != jc2 || strings.Join(got, "|") != "after rotation" {
		t.Fatalf("%v, cursor %q, entries %q", err, c.Journal, got)
	}
	p := strings.Join(r.Partial, ",")
	if !strings.Contains(p, ReadCursorRejected) || !strings.Contains(p, ReadFirstRun) {
		t.Errorf("partial %v, want cursor_rejected and first_run", r.Partial)
	}
}

// N-12: with the unit able to make root log the workers' words, a root
// message is not verified.
func TestEntryTrustElevatedFPM(t *testing.T) {
	u := hostenv.AppUnit{Name: "php8.2-fpm.service", FPM: true, Elevated: true}
	got := EntryTrust(hostenv.JournalEntry{Unit: u.Name, UID: 0, Transport: "syslog"}, u, hostenv.WebAccounts{})
	if got.Verified || got.Reason != hostenv.ReasonWebUserWritable {
		t.Errorf("%+v, want web_user_writable", got)
	}
}

// N-13: an entry journald gave no message for is said, not taken as empty.
func TestReadJournalUnitMissingMessage(t *testing.T) {
	u := hostenv.AppUnit{Name: "app.service", User: "www-data"}
	src := &journalSrc{entries: []string{`{"__CURSOR":"` + jc1 + `","MESSAGE":null,"_SYSTEMD_UNIT":"app.service","_UID":"33","_TRANSPORT":"journal"}`}, cursors: []string{jc1}}
	_, r, err := ReadJournalUnit(context.Background(), src, u, nil, NewBudget(DefaultBudgetBytes, time.Minute), hostenv.WebAccounts{}, func(hostenv.JournalEntry, JournalTrust) {})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(r.Partial, ","), ReadMessageMissing) {
		t.Errorf("partial %v, want message_missing", r.Partial)
	}
}

// A failure other than a refused cursor keeps the cursor and says
// io_error: it does not read the window again.
func TestReadJournalUnitIOErrorKeepsCursor(t *testing.T) {
	u := hostenv.AppUnit{Name: "app.service", User: "www-data"}
	src := &failingJournal{}
	c, r, err := ReadJournalUnit(context.Background(), src, u, &Cursor{Journal: jc1}, NewBudget(DefaultBudgetBytes, time.Minute), hostenv.WebAccounts{}, func(hostenv.JournalEntry, JournalTrust) {})
	if err == nil || c.Journal != jc1 || strings.Join(r.Partial, ",") != ReadIOError || src.windowReads != 0 {
		t.Errorf("err %v, cursor %q, partial %v, window reads %d", err, c.Journal, r.Partial, src.windowReads)
	}
}

type failingJournal struct {
	journalSrc
	windowReads int
}

func (f *failingJournal) Run(_ context.Context, argv []string) (hostenv.CmdResult, error) {
	if argv[0] != "/usr/bin/journalctl" {
		return hostenv.CmdResult{}, &fs.PathError{Op: "exec", Path: argv[0], Err: fs.ErrNotExist}
	}
	if argv[3] == "--since" {
		f.windowReads++
	}
	return hostenv.CmdResult{ExitCode: 1, Stderr: "Failed to open journal: Input/output error"}, nil
}

// N-R1: a unit failing run after run without moving on is cursor_stuck;
// a cut entry is entries_cut.
func TestReadJournalUnitStuckAndCut(t *testing.T) {
	u := hostenv.AppUnit{Name: "app.service", User: "www-data"}
	src := &failingJournal{}
	cur := Cursor{Journal: jc1}
	var r ReadResult
	for i := 0; i < StuckAfter; i++ {
		cur, r, _ = ReadJournalUnit(context.Background(), src, u, &cur, NewBudget(DefaultBudgetBytes, time.Minute), hostenv.WebAccounts{}, func(hostenv.JournalEntry, JournalTrust) {})
	}
	if cur.Failures != StuckAfter || !strings.Contains(strings.Join(r.Partial, ","), ReadCursorStuck) {
		t.Errorf("failures %d, partial %v", cur.Failures, r.Partial)
	}
	huge := `{"__CURSOR":"` + jc2 + `","MESSAGE":"` + strings.Repeat("x", hostenv.MaxJournalLine+10) + `"}`
	ok := &journalSrc{entries: []string{huge}, cursors: []string{jc2}}
	c, r, err := ReadJournalUnit(context.Background(), ok, u, nil, NewBudget(DefaultBudgetBytes, time.Minute), hostenv.WebAccounts{}, func(hostenv.JournalEntry, JournalTrust) {})
	if err != nil || c.Journal != jc2 || c.Failures != 0 || !strings.Contains(strings.Join(r.Partial, ","), ReadEntriesCut) {
		t.Errorf("cut entry: %v, cursor %+v, partial %v", err, c, r.Partial)
	}
}
