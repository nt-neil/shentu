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

// EntryTrust judges an entry of unit. _SYSTEMD_UNIT and _UID are set by
// journald, but what they say depends on the transport:
//   - journal (sd_journal_send) and syslog: each message carries its
//     sender's credentials. A root process of the unit is verified only
//     when the application itself cannot be running as root (a User= that
//     is not root, or PHP-FPM's master); otherwise a root message may be
//     the application's, web_user_writable. The unit's web account is
//     web_user_writable; anything else untrusted.
//   - stdout (a unit's stdout and stderr): the credentials are those of the
//     process that opened the stream when the unit started, and every child
//     writing to the inherited descriptor (PHP-FPM's workers with
//     catch_workers_output, gunicorn's) is logged as that process, uid 0
//     included. These units run the web application, so its output is
//     web_user_writable, whatever _UID says.
//   - kernel, audit, driver, or another unit's message about this one (the
//     cgroup is not the unit's): unverified.
func EntryTrust(e hostenv.JournalEntry, unit hostenv.AppUnit, web hostenv.WebAccounts) JournalTrust {
	if e.Unit != unit.Name || e.UID < 0 {
		return JournalTrust{Reason: hostenv.ReasonUnverified}
	}
	_, webUID := web.UIDs[e.UID]
	switch e.Transport {
	case "stdout":
		if e.UID == 0 || webUID {
			return JournalTrust{Reason: hostenv.ReasonWebUserWritable}
		}
		return JournalTrust{Reason: hostenv.ReasonUntrusted}
	case "journal", "syslog":
		switch {
		case e.UID == 0 && !unit.RunsAppAsRoot():
			return JournalTrust{Verified: true}
		case e.UID == 0, webUID:
			return JournalTrust{Reason: hostenv.ReasonWebUserWritable}
		}
		return JournalTrust{Reason: hostenv.ReasonUntrusted}
	}
	return JournalTrust{Reason: hostenv.ReasonUnverified}
}

// ReadJournalUnit reads unit's entries after cur (nil: those of the last
// FirstJournalWindow, a first run), within the budget, giving each with
// its trust to fn, and returns the cursor to keep. Out of budget, it stops
// after a whole entry and says truncated; the next run goes on from there.
// A stale cursor (the journal rotated past it) reads nothing from journald
// and is said as rotated_gap.
func ReadJournalUnit(ctx context.Context, src hostenv.Source, unit hostenv.AppUnit, cur *Cursor, b *Budget, web hostenv.WebAccounts, fn func(hostenv.JournalEntry, JournalTrust)) (Cursor, ReadResult, error) {
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
	last, err := hostenv.ReadJournal(deadline, src, unit.Name, after, since, func(e hostenv.JournalEntry) error {
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
