package detect

import (
	"context"
	"time"

	"github.com/nt-neil/shentu/hostenv"
)

// JournalKey is a journal source's key in the cursor file.
func JournalKey(unit string) string { return "journald:" + unit }

// FirstJournalWindow is how far back a unit is read the first time.
const FirstJournalWindow = 24 * time.Hour

// JournalTrust is how far one entry can be believed.
type JournalTrust struct {
	Verified bool           `json:"verified"`
	Reason   hostenv.Reason `json:"reason,omitempty"`
}

// EntryTrust judges an entry of unit: written by a process of that unit
// (_SYSTEMD_UNIT, which journald sets from the sender's cgroup) running as
// root, verified; as a web server's or PHP's account (PHP-FPM's workers,
// the application itself), web_user_writable: still unverified, a
// compromised application can write what it likes there; anything else
// (another unit's message about this one, another user) unverified.
func EntryTrust(e hostenv.JournalEntry, unit string, web hostenv.WebAccounts) JournalTrust {
	switch {
	case e.Unit != unit || e.UID < 0:
		return JournalTrust{Reason: hostenv.ReasonUnverified}
	case e.UID == 0:
		return JournalTrust{Verified: true}
	}
	if _, ok := web.UIDs[e.UID]; ok {
		return JournalTrust{Reason: hostenv.ReasonWebUserWritable}
	}
	return JournalTrust{Reason: hostenv.ReasonUntrusted}
}

// ReadJournalUnit reads unit's entries after cur (nil: those of the last
// FirstJournalWindow, a first run), within the budget, giving each with
// its trust to fn, and returns the cursor to keep. Out of budget, it stops
// after a whole entry and says truncated; the next run goes on from there.
// A stale cursor (the journal rotated past it) reads nothing from journald
// and is said as rotated_gap.
func ReadJournalUnit(ctx context.Context, src hostenv.Source, unit string, cur *Cursor, b *Budget, web hostenv.WebAccounts, fn func(hostenv.JournalEntry, JournalTrust)) (Cursor, ReadResult, error) {
	var res ReadResult
	after := ""
	since := b.now().Add(-FirstJournalWindow)
	if cur != nil && cur.Journal != "" {
		after = cur.Journal
	} else {
		res.partial(ReadFirstRun)
	}
	deadline, cancel := context.WithDeadline(ctx, b.deadline)
	defer cancel()
	last, err := hostenv.ReadJournal(deadline, src, unit, after, since, func(e hostenv.JournalEntry) error {
		if b.spent() {
			res.partial(ReadTruncated)
			return hostenv.ErrStopJournal
		}
		n := int64(len(e.Message))
		res.Lines++
		res.Bytes += n
		b.left -= n
		fn(e, EntryTrust(e, unit, web))
		return nil
	})
	next := keep(cur)
	if last != "" {
		next.Journal = last
	}
	next.ReadAt = time.Now().UTC()
	if err != nil {
		if deadline.Err() != nil && ctx.Err() == nil { // the run's time ran out, not the caller's
			res.partial(ReadTruncated)
			return next, res, nil
		}
		if after != "" && last == "" && res.Lines == 0 {
			// journalctl refuses a cursor it no longer has: read again from
			// the window, and say what may be lost.
			res.partial(ReadRotatedGap)
			c, r2, err2 := ReadJournalUnit(ctx, src, unit, nil, b, web, fn)
			r2.Partial = append(r2.Partial, res.Partial...)
			return c, r2, err2
		}
		return next, res, err
	}
	return next, res, nil
}
