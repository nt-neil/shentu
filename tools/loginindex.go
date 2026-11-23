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
	// UnreadableLast is the last entry in sshd's units too long to read
	// whole (past MaxSSHJournalMessage, which the whole read cannot read
	// either and fails on): it may be an event for any address, so a
	// window holding it is not verified.
	UnreadableLast time.Time `json:"unreadable_last,omitzero"`
	// JournalFrom: the journal has sshd's units' entries only from here on,
	// the rest vacuumed after the index read them (sshd's units' first
	// entry, read at each read). The whole read sees nothing before it, so
	// nothing the index kept from before it counts, for an address or
	// against it: not its events, its forged ones, an unreadable entry, nor
	// the overflow. The index answers as strictly as the whole read, and no
	// more so for what that read cannot see.
	JournalFrom time.Time `json:"journal_from,omitzero"`
	// Notes say what the index met, the last maxLoginIndexNotes of them:
	// the journal moving on past its cursor.
	Notes []loginIndexNote `json:"notes,omitempty"`
	// ReadAt is when the last read ended.
	ReadAt time.Time                  `json:"read_at"`
	Addrs  map[string]*loginIndexAddr `json:"addrs"`
	// OverflowFirst and OverflowLast are the first and the last event of
	// an address the index had no room for.
	OverflowFirst time.Time `json:"overflow_first,omitzero"`
	OverflowLast  time.Time `json:"overflow_last,omitzero"`
}

// loginIndexNote is one note, with when it was made.
type loginIndexNote struct {
	At   time.Time `json:"at"`
	Text string    `json:"text"`
}

const maxLoginIndexNotes = 20

func (x *loginIndex) note(at time.Time, text string) {
	x.Notes = append(x.Notes, loginIndexNote{at, text})
	if len(x.Notes) > maxLoginIndexNotes {
		x.Notes = x.Notes[len(x.Notes)-maxLoginIndexNotes:]
	}
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
var readSSHJournal = func(ctx context.Context, from string, since time.Time, fn func(hostenv.JournalEntry) error) (string, error) {
	return hostenv.ReadSSHJournal(ctx, hostSource(), from, since, fn)
}

// sshJournalFirst is hostenv.SSHJournalFirst (tests read their fake through it).
var sshJournalFirst = func(ctx context.Context) (hostenv.JournalEntry, bool, error) {
	return hostenv.SSHJournalFirst(ctx, hostSource())
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
// version, or it cannot be read (the index starts again). An address with
// no entry (null) is dropped, and a cursor not shaped as one (cut short,
// edited) is dropped too: the read goes on by time from the cursor's entry
// instead (N-213-3, S-213-2).
func loadLoginIndex(dir string, now time.Time) *loginIndex {
	b, err := detect.ReadStateFile(dir, LoginIndexFile, maxLoginIndexBytes)
	if err != nil {
		return nil
	}
	var x loginIndex
	if json.Unmarshal(b, &x) != nil || x.Version != loginIndexVersion || x.From.IsZero() || x.Addrs == nil {
		return nil
	}
	for ip, a := range x.Addrs {
		if a == nil {
			delete(x.Addrs, ip)
		}
	}
	if x.Cursor != "" && !hostenv.ValidCursor(x.Cursor) {
		x.Cursor = ""
		x.note(now, "the saved journal cursor was not a cursor: read on by time from its entry")
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
// The read starts at the cursor's own entry (already counted, so skipped).
// When the first entry is another one, or none comes, the journal no longer
// has the cursor's entry (rotated, vacuumed, flooded) and journalctl went to
// the nearest one still there: everything still there is read, so the index
// sees what the whole read sees, keeps what it had (it only ever makes an
// answer stricter), and notes it. A cursor journalctl refuses is read on by
// time from its entry: an address keeps times (maxima, a minimum), so an
// entry read twice changes nothing judged.
func updateLoginIndex(ctx context.Context) (*loginIndex, error) {
	dir := attackStateDir
	if !KeepLoginIndex || dir == "" || !journalAll() {
		return nil, errNoLoginIndex
	}
	loginIndexMu.Lock()
	defer loginIndexMu.Unlock()
	now := indexNow()
	x := loadLoginIndex(dir, now)
	if x == nil {
		x = &loginIndex{Version: loginIndexVersion, From: now.Add(-loginGateWindow), Addrs: map[string]*loginIndexAddr{}}
	}
	moved := false        // the journal no longer had the cursor's entry
	var movedTo time.Time // the first entry read after it moved
	read := func(from string, since time.Time) error {
		first := true
		_, err := readSSHJournal(ctx, from, since, func(e hostenv.JournalEntry) error {
			if first {
				first = false
				if from != "" && e.Cursor == from {
					return nil // the cursor's own entry, counted by the last read
				}
				moved = moved || from != ""
			}
			at := e.Time
			if at.IsZero() {
				at = now // an entry cut before its time: taken as now, the strict side
			}
			if moved && movedTo.IsZero() {
				movedTo = at
			}
			if ip, own, ok := hostenv.SSHDLoginEvent(e); ok {
				x.add(ip, at, own)
			} else if e.Cut && at.After(x.UnreadableLast) {
				// Past the line the whole read takes (MaxSSHJournalMessage):
				// that read fails on it, whoever wrote it, so a window
				// holding it is not verified here either (S-213-4). Shorter
				// entries are read whole and counted for their address.
				x.UnreadableLast = at
			}
			x.Cursor, x.CursorTime = e.Cursor, at // also past entries that are not events
			return nil
		})
		if err == nil && first && from != "" {
			moved = true // not even the cursor's entry: it is gone
		}
		return err
	}
	since := x.From
	if x.CursorTime.After(since) {
		since = x.CursorTime
	}
	err := read(x.Cursor, since)
	if x.Cursor != "" && (errors.Is(err, hostenv.ErrCursorRejected) || errors.Is(err, hostenv.ErrNotAllowed)) {
		x.Cursor = ""
		x.note(now, "journalctl refused the saved cursor: read on by time from its entry")
		err = read("", since)
	}
	if moved {
		if movedTo.IsZero() {
			movedTo = now // nothing of sshd's units is left from before now
		}
		if movedTo.After(x.JournalFrom) {
			x.JournalFrom = movedTo
		}
		x.note(now, "the journal had moved on past the index's position (its entry of "+since.UTC().Format(time.RFC3339)+" is gone): read on from the first entry still there")
	}
	if err == nil {
		// Where the journal starts now, each read (S-213-3): entries older
		// than sshd's units' first one were vacuumed, even with the
		// cursor's entry still there, and the whole read no longer sees
		// them.
		first, ok, ferr := sshJournalFirst(ctx)
		start := now // none left
		if ok {
			start = first.Time
		}
		if ferr != nil {
			err = fmt.Errorf("where the journal starts: %w", ferr)
		} else if start.After(x.JournalFrom) {
			x.JournalFrom = start
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
	// An address's events can be in the overflow only from before the index
	// kept it (an address kept never overflows): in the window, before Since.
	case !x.OverflowLast.Before(w) && !x.OverflowLast.Before(x.JournalFrom) && (a == nil || a.Since.After(w) && x.OverflowFirst.Before(a.Since)):
		return false, coded(BlockStateError, fmt.Errorf("refusing to block %s: more addresses tried SSH than the login index keeps (%d), and some of its events may be among those not kept; check the logs as root and, if they are real, ask again with override_unverified", ip, maxIndexAddrs))
	case !x.UnreadableLast.Before(w) && !x.UnreadableLast.Before(x.JournalFrom):
		return a != nil && !a.Last.Before(w), coded(BlockUnverified, fmt.Errorf("refusing to block %s: since %s an entry in sshd's unit was too long to read whole (over 1 MiB), so an SSH login event in it, forged or not, cannot be ruled out; check them as root (journalctl -u ssh) and, if the block is right, ask again with override_unverified", ip, w.Format(time.RFC3339)))
	}
	if a == nil || a.Last.Before(w) {
		return false, nil
	}
	if !a.ForgedLast.Before(w) && !a.ForgedLast.Before(x.JournalFrom) {
		return true, coded(BlockUnverified, fmt.Errorf("refusing to block %s: some of its SSH login events in journald since %s were not written by sshd itself (they came from another program in sshd's unit, e.g. logger), so they may be forged; check them as root and, if they are real, ask again with override_unverified", ip, w.Format(time.RFC3339)))
	}
	if a.Last.Before(x.JournalFrom) {
		return false, nil // its events are no longer in the journal: as the whole read, not seen
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
