package tools

// The login index (v0.5.6, plan f98c3c n13): block_ip's login check from
// the SSH login events of sshd's journal units, kept per address and read
// on from the cursor where the last read stopped, so the check does not
// read a month of journal each time. The rules are loginCheckRead's:
// an address's events count only when sshd itself wrote all of them in
// the window; whatever the index cannot answer for (no index yet, a window
// it does not cover, no journald) goes to loginCheckRead's whole read.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/nt-neil/shentu/detect"
	"github.com/nt-neil/shentu/hostenv"
)

// LoginIndexFile is the index, in the state directory.
const LoginIndexFile = "loginindex.json"

// loginIndexVersion is the file's format; a file of another version, or of
// none (one written before it), is not read: the index starts again.
const loginIndexVersion = 1

// maxIndexAddrs bounds the addresses the index keeps. Past it, a new
// address's events go to the overflow, which only says when it last had
// one: an address that may have events there cannot be answered for.
var maxIndexAddrs = 1 << 16

// maxLoginIndexBytes bounds the file read back.
const maxLoginIndexBytes = 32 << 20

// loginIndex is the index as saved.
type loginIndex struct {
	Version int `json:"version"`
	// Cursor is the journal cursor of the last entry read.
	Cursor string `json:"cursor,omitempty"`
	// CursorTime is the time of the cursor's entry: where a read by time
	// goes on when the journal no longer has the cursor.
	CursorTime time.Time `json:"cursor_time,omitzero"`
	// From: the index has every event of sshd's units since From (the
	// first read's start).
	From time.Time `json:"from"`
	// GapUntil: events before it may be missing, because the journal had
	// dropped the cursor's entry (rotated, vacuumed, flooded) when it was
	// read on. A window starting before it cannot be answered in full.
	GapUntil time.Time `json:"gap_until,omitzero"`
	// ReadAt is when the last read ended.
	ReadAt time.Time                  `json:"read_at"`
	Addrs  map[string]*loginIndexAddr `json:"addrs"`
	// OverflowFirst and OverflowLast are the first and the last event of
	// an address the index had no room for.
	OverflowFirst time.Time `json:"overflow_first,omitzero"`
	OverflowLast  time.Time `json:"overflow_last,omitzero"`
}

// loginIndexAddr is one address's events.
type loginIndexAddr struct {
	Since      time.Time `json:"since"`                // when the index began to keep it
	Last       time.Time `json:"last"`                 // its last event
	ForgedLast time.Time `json:"forged_last,omitzero"` // its last event sshd did not write itself
	Events     int       `json:"events"`
	Forged     int       `json:"forged,omitempty"`
}

// readSSHJournal is hostenv.ReadSSHJournal (tests replace it).
var readSSHJournal = func(ctx context.Context, after string, since time.Time, fn func(hostenv.JournalEntry) error) (string, error) {
	return hostenv.ReadSSHJournal(ctx, hostSource(), after, since, fn)
}

// indexNow is the index's clock (tests replace it).
var indexNow = time.Now

// KeepLoginIndex: the index is kept. Tests of other things turn it off, so
// they never read the journal of the host they run on.
var KeepLoginIndex = true

// loginIndexMu keeps one read of the index at a time in this process.
// Another process (the patrol, the bot) may read on at the same time: each
// saves a whole index (its counts with its cursor), the last one renamed in
// place wins, and the next read goes on from its cursor, so no event is
// counted twice or lost.
var loginIndexMu sync.Mutex

// add counts one event.
func (x *loginIndex) add(ip string, at time.Time, own bool) {
	a := x.Addrs[ip]
	if a == nil {
		if len(x.Addrs) >= maxIndexAddrs {
			x.prune(at)
		}
		if len(x.Addrs) >= maxIndexAddrs {
			if x.OverflowFirst.IsZero() || at.Before(x.OverflowFirst) {
				x.OverflowFirst = at
			}
			if at.After(x.OverflowLast) {
				x.OverflowLast = at
			}
			return
		}
		a = &loginIndexAddr{Since: at}
		x.Addrs[ip] = a
	}
	a.Events++
	if at.After(a.Last) {
		a.Last = at
	}
	if !own {
		a.Forged++
		if at.After(a.ForgedLast) {
			a.ForgedLast = at
		}
	}
}

// prune drops the addresses with no event in loginGateWindow before now:
// no window the check reads reaches them.
func (x *loginIndex) prune(now time.Time) {
	for ip, a := range x.Addrs {
		if a.Last.Before(now.Add(-loginGateWindow)) {
			delete(x.Addrs, ip)
		}
	}
}

// loadLoginIndex reads the index; nil when there is none, it is of another
// version, or it cannot be read (the index starts again).
func loadLoginIndex(dir string) *loginIndex {
	b, err := detect.ReadStateFile(dir, LoginIndexFile, maxLoginIndexBytes)
	if err != nil {
		return nil
	}
	var x loginIndex
	if json.Unmarshal(b, &x) != nil || x.Version != loginIndexVersion || x.From.IsZero() || x.Addrs == nil {
		return nil
	}
	return &x
}

// save writes the index: a new file (0600, created exclusively), synced,
// renamed over the old one.
func (x *loginIndex) save(dir string) error {
	b, err := json.Marshal(x)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, LoginIndexFile+".*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, filepath.Join(dir, LoginIndexFile))
	}
	if err != nil {
		os.Remove(tmp)
	}
	return err
}

// errNoLoginIndex: the index cannot be kept here (no state directory, or
// journald does not show this process every unit's entries).
var errNoLoginIndex = errors.New("no login index here")

// updateLoginIndex reads the journal on from the index's cursor (from
// loginGateWindow back when there is no index) and saves what it read,
// even when the read is cut short: the next read goes on from there, so a
// flooded journal is read through over the checks, each within its time.
//
// A cursor the journal no longer has (rotated, vacuumed, flooded) is read
// on by time from the cursor's entry instead. What the index keeps of an
// address is its times (Last, ForgedLast are maxima, Since a minimum), so
// entries read twice change nothing that is judged; the events between the
// lost cursor and the first entry still there may be gone, which GapUntil
// marks.
func updateLoginIndex(ctx context.Context) (*loginIndex, error) {
	dir := attackStateDir
	if !KeepLoginIndex || dir == "" || !journalAll() {
		return nil, errNoLoginIndex
	}
	loginIndexMu.Lock()
	defer loginIndexMu.Unlock()
	now := indexNow()
	x := loadLoginIndex(dir)
	if x == nil {
		x = &loginIndex{Version: loginIndexVersion, From: now.Add(-loginGateWindow), Addrs: map[string]*loginIndexAddr{}}
	}
	var first time.Time // the first entry this update read
	read := func(after string, since time.Time) error {
		_, err := readSSHJournal(ctx, after, since, func(e hostenv.JournalEntry) error {
			if first.IsZero() {
				first = e.Time
			}
			if ip, own, ok := hostenv.SSHDLoginEvent(e); ok {
				x.add(ip, e.Time, own)
			}
			x.Cursor, x.CursorTime = e.Cursor, e.Time // also past entries that are not events
			return nil
		})
		return err
	}
	err := read(x.Cursor, x.From)
	if errors.Is(err, hostenv.ErrCursorRejected) {
		since := x.CursorTime
		if since.Before(x.From) {
			since = x.From
		}
		x.Cursor, first = "", time.Time{}
		err = read("", since)
		// Events between the cursor's entry and the first entry read may be
		// gone (none read: anything up to now). The journal still holding
		// the cursor's time loses nothing.
		gap := first
		if gap.IsZero() {
			gap = now
		}
		if gap.After(since) && gap.After(x.GapUntil) {
			x.GapUntil = gap
		}
	}
	if x.Cursor != "" || err == nil {
		x.ReadAt = indexNow()
		x.prune(x.ReadAt)
		if serr := x.save(dir); err == nil && serr != nil {
			err = fmt.Errorf("saving %s: %w", LoginIndexFile, serr)
		}
	}
	if err != nil {
		return nil, err
	}
	return x, nil
}

// errIndexDoesNotCover: the index does not reach back to the window.
var errIndexDoesNotCover = errors.New("the login index does not cover the window")

// indexedLogins answers loginCheckRead's question from the index:
// whether ip has events in the window (the last day if it has any there,
// else loginGateWindow), and if so whether sshd itself wrote all of them.
// errIndexDoesNotCover when the index starts after the window.
func (x *loginIndex) indexedLogins(ip net.IP, now time.Time) (seen bool, err error) {
	want := hostenv.CanonicalIP(ip.String())
	a := x.Addrs[want]
	w := now.Add(-loginGateFirst)
	if a == nil || a.Last.Before(w) {
		w = now.Add(-loginGateWindow)
	}
	switch {
	case x.From.After(w):
		return false, errIndexDoesNotCover
	case x.GapUntil.After(w):
		return false, coded(BlockStateError, fmt.Errorf("refusing to block %s: the journal dropped entries the login index had not read yet (rotated, vacuumed, or flooded) since %s, so forged SSH logins in that time cannot be ruled out; check the logs as root and, if they are real, ask again with override_unverified", ip, x.GapUntil.Format(time.RFC3339)))
	// An address's events can be in the overflow only from before the index
	// kept it (an address kept never overflows): in the window, before Since.
	case !x.OverflowLast.Before(w) && (a == nil || a.Since.After(w) && x.OverflowFirst.Before(a.Since)):
		return false, coded(BlockStateError, fmt.Errorf("refusing to block %s: more addresses tried SSH than the login index keeps (%d), and some of its events may be among those not kept; check the logs as root and, if they are real, ask again with override_unverified", ip, maxIndexAddrs))
	}
	if a == nil || a.Last.Before(w) {
		return false, nil
	}
	if !a.ForgedLast.Before(w) {
		return true, coded(BlockUnverified, fmt.Errorf("refusing to block %s: some of its SSH login events in journald since %s were not written by sshd itself (they came from another program in sshd's unit, e.g. logger), so they may be forged; check them as root and, if they are real, ask again with override_unverified", ip, w.Format(time.RFC3339)))
	}
	return true, nil
}

// RefreshLoginIndex reads the login index on, for the patrol: run every
// hour, it leaves a check only the entries since to read. Where block_ip
// does not run there is no index; a failure is the next read's to meet.
func RefreshLoginIndex(ctx context.Context) {
	if blockUnsupported() == nil {
		updateLoginIndex(ctx)
	}
}
