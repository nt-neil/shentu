package detect

import (
	"context"

	"github.com/nt-neil/shentu/hostenv"
)

// MaxSamples is how many lines each signal points at.
const MaxSamples = 5

// LinePos points at one line: the file, and where in it the line starts.
type LinePos struct {
	File   string `json:"file"`
	Offset int64  `json:"offset"`
}

// SignalCount is how many lines showed a signal, and where the first were.
type SignalCount struct {
	Count   int       `json:"count"`
	Samples []LinePos `json:"samples,omitempty"`
}

func (s *SignalCount) add(l Line) {
	s.Count++
	if len(s.Samples) < MaxSamples {
		s.Samples = append(s.Samples, LinePos{l.From, l.Offset})
	}
}

// Signals is what reading one access log saw besides its requests, for
// the alerts (P3, P4): an attacker making his own lines unparseable,
// splitting them two ways, or padding them past the cut, shows here.
type Signals struct {
	Lines      int         `json:"lines"`
	Unparsed   SignalCount `json:"unparsed"`                 // not in the log's format
	Suspicious SignalCount `json:"suspicious"`               // split only from the middle (AccessRecord.Suspicious)
	Ambiguous  SignalCount `json:"ambiguous"`                // split into more than one request (AccessRecord.Ambiguous)
	Cut        SignalCount `json:"cut"`                      // longer than MaxLine: parsed from its start
	Dropped    string      `json:"cursor_dropped,omitempty"` // why the cursor kept for this log was not valid (Cursors.Dropped): read as a first run
}

// ScanAccess reads the access log ls's lines added since cur (ReadLog),
// parses each in ls's format, and gives fn every record with the line it
// came from (a record's Alts are to be matched too). dropped is why the
// cursor kept for ls was dropped, if it was. A format detect cannot parse
// is an error (ErrFormatUnrecognized), nothing read.
func ScanAccess(src hostenv.Source, ls hostenv.LogSource, cur *Cursor, dropped string, b *Budget, trust TrustFunc, fn func(AccessRecord, Line)) (Cursor, ReadResult, Signals, error) {
	sig := Signals{Dropped: dropped}
	p, err := ParserFor(ls)
	if err != nil {
		return keep(cur), ReadResult{}, sig, err
	}
	c, res, err := ReadLog(src, ls.Path, cur, b, ReadOpts{Want: &ls, Trust: trust}, scanLine(p, &sig, fn))
	return c, res, sig, err
}

// scanLine parses each line in p's format, counting what it saw in sig,
// and gives fn the records.
func scanLine(p *Parser, sig *Signals, fn func(AccessRecord, Line)) func(Line) {
	return func(l Line) {
		sig.Lines++
		var r AccessRecord
		var ok bool
		if l.Cut {
			sig.Cut.add(l)
			r, ok = p.ParseCut(l.Text)
		} else {
			r, ok = p.Parse(l.Text)
		}
		if !ok {
			sig.Unparsed.add(l)
			return
		}
		if r.Suspicious {
			sig.Suspicious.add(l)
		}
		if r.Ambiguous {
			sig.Ambiguous.add(l)
		}
		fn(r, l)
	}
}

// ScanJournalAccess is ScanAccess for an access log nginx sends to
// journald (ls.Journal): the unit's entries tagged ls.JournalTag, in
// order, each verified only when ls is and journald says it came over
// syslog from ls.JournalExe running as ls.JournalUID in the unit. The tag
// is the sender's to write: it only picks the access log's entries from
// the unit's others. A line's Offset is its place in this read.
func ScanJournalAccess(ctx context.Context, src hostenv.Source, ls hostenv.LogSource, cur *Cursor, dropped string, b *Budget, fn func(AccessRecord, Line)) (Cursor, ReadResult, Signals, error) {
	sig := Signals{Dropped: dropped}
	p, err := ParserFor(ls)
	if err != nil {
		return keep(cur), ReadResult{}, sig, err
	}
	scan := scanLine(p, &sig, fn)
	var n int64
	c, res, err := readJournal(ctx, src, ls.Journal, cur, b, func(e hostenv.JournalEntry) {
		if e.Unit != ls.Journal || e.Ident != ls.JournalTag || e.MessageMissing {
			return
		}
		n++
		verified := ls.Verified && ls.JournalUID != 0 && e.Transport == "syslog" && e.Exe == ls.JournalExe && e.UID == ls.JournalUID
		scan(Line{From: JournalKey(ls.Journal), Offset: n, Text: []byte(e.Message), Cut: e.Cut, Verified: verified})
	})
	return c, res, sig, err
}
