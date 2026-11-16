package detect

import "github.com/nt-neil/shentu/hostenv"

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
	c, res, err := ReadLog(src, ls.Path, cur, b, ReadOpts{Want: &ls, Trust: trust}, func(l Line) {
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
	})
	return c, res, sig, err
}
