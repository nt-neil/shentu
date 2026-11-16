package detect

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/nt-neil/shentu/hostenv"
)

// Bounds on reading logs, for a 512MB host with a large site's logs.
const (
	MaxLine            = 16 << 10 // a longer line is cut here and counted, not a reason to stop
	DefaultBudgetBytes = 256 << 20
	DefaultBudgetTime  = 90 * time.Second
	headLen            = 256
	maxRotated         = 32 // rotated files looked at for the one the cursor was in
)

// Why a read is partial. The lines read are still good; what was not read
// is said, never taken for a quiet log.
const (
	ReadFirstRun   = "first_run"   // no cursor: only the last budget's worth was read
	ReadRotatedGap = "rotated_gap" // the file read last time is gone: what it got after the cursor is lost
	ReadRewritten  = "rewritten"   // the same file with other content at its start: read again from the start (tampering?)
	ReadTruncated  = "truncated"   // the run's budget ran out: the next run goes on from here
)

// Budget is what one run may read, across all its logs.
type Budget struct {
	left     int64
	deadline time.Time
	now      func() time.Time
}

// NewBudget allows bytes and d from now.
func NewBudget(bytes int64, d time.Duration) *Budget {
	return &Budget{left: bytes, deadline: time.Now().Add(d), now: time.Now}
}

func (b *Budget) spent() bool { return b.left <= 0 || b.now().After(b.deadline) }

// ReadResult is what reading one log came to.
type ReadResult struct {
	Lines     int           `json:"lines"`
	Bytes     int64         `json:"bytes"`
	LongLines int           `json:"long_lines,omitempty"` // cut at MaxLine
	Rotated   []RotatedFile `json:"rotated,omitempty"`    // rotated files the rest of the last read was found in
	Partial   []string      `json:"partial,omitempty"`    // ReadFirstRun, ReadRotatedGap, ReadRewritten, ReadTruncated
}

// RotatedFile is a rotated log lines were read from. It was found by a
// pattern beside the log, not named by the configuration, so its own trust
// is judged: it does not carry the log's.
type RotatedFile struct {
	Path     string         `json:"path"`
	Verified bool           `json:"verified"`
	Reason   hostenv.Reason `json:"reason,omitempty"`
}

func (r *ReadResult) partial(why string) {
	for _, p := range r.Partial {
		if p == why {
			return
		}
	}
	r.Partial = append(r.Partial, why)
}

// LineFunc gets each line without its newline, valid only during the call,
// and the file it came from: the log, or a rotated file (ReadResult.Rotated
// says how far that one is to be trusted).
type LineFunc func(from string, line []byte)

// TrustFunc judges a rotated file found beside a log (hostenv.LogTrust with
// the host's web accounts). Nil: every rotated file is unverified.
type TrustFunc func(path string) (bool, hostenv.Reason)

// ReadLog reads p's lines added since cur (nil: none, a first run), giving
// each to fn, and returns the cursor to keep. When p is no longer the file
// cur was in (renamed by logrotate, copied and truncated, compressed), the
// rest of that file is read first from the rotated file holding it: .1,
// -YYYYMMDD, .gz, opened without following a link and judged by trust. A
// last line without its newline is left for the next run. On an error
// opening p the old cursor is returned unchanged.
func ReadLog(src hostenv.Source, p string, cur *Cursor, b *Budget, trust TrustFunc, fn LineFunc) (Cursor, ReadResult, error) {
	var res ReadResult
	f, err := hostenv.OpenLog(src, p)
	if err != nil {
		return keep(cur), res, err
	}
	defer f.Close()
	st := f.Stat()
	head, err := readHead(f)
	if err != nil {
		return keep(cur), res, err
	}
	var start int64
	skip := false // start is inside a line: skip to its end
	switch {
	case cur == nil:
		res.partial(ReadFirstRun)
		start = max(0, st.Size-b.left)
		skip = start > 0
	case sameFile(cur, st, head):
		start, skip = cur.Offset, cur.MidLine
	default: // rotated, copied and truncated, or rewritten
		if rf, ok := readRotated(src, p, cur, b, trust, &res, fn); ok {
			res.Rotated = append(res.Rotated, rf)
		} else if cur.ID != "" && cur.ID == st.ID && st.Size >= cur.Offset {
			res.partial(ReadRewritten)
		} else {
			res.partial(ReadRotatedGap)
		}
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return keep(cur), res, err
	}
	br := bufio.NewReaderSize(f, MaxLine)
	mid := false
	end := start
	if skip {
		n, ok := skipLine(br, b)
		end += n
		mid = !ok
	}
	if !mid {
		end, mid = readLines(br, p, end, b, false, &res, fn)
	} else if b.spent() {
		res.partial(ReadTruncated)
	}
	return Cursor{ID: st.ID, Offset: end, MidLine: mid, Size: st.Size, ModTime: st.ModTime, Head: hashHead(head), HeadLen: len(head), ReadAt: time.Now().UTC()}, res, nil
}

func keep(cur *Cursor) Cursor {
	if cur != nil {
		return *cur
	}
	return Cursor{}
}

// sameFile: p is still the file cur was in, grown or not: the same ID
// where both are known, no shorter than what was read, and the same first
// cur.HeadLen bytes.
func sameFile(cur *Cursor, st hostenv.FileStat, head []byte) bool {
	switch {
	case cur.ID != "" && st.ID != "" && cur.ID != st.ID:
		return false
	case st.Size < cur.Offset:
		return false // truncated (copytruncate) or replaced
	case cur.HeadLen > len(head):
		return false
	}
	return cur.HeadLen == 0 || hashHead(head[:cur.HeadLen]) == cur.Head
}

// readHead is f's first headLen bytes, f left at its start.
func readHead(f io.ReadSeeker) ([]byte, error) {
	buf := make([]byte, headLen)
	n, err := io.ReadFull(f, buf)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// skipLine discards through the next newline, charging the budget: n bytes,
// ok if the newline was reached (not: the file or the budget ended first).
func skipLine(br *bufio.Reader, b *Budget) (n int64, ok bool) {
	for !b.spent() {
		s, err := br.ReadSlice('\n')
		n += int64(len(s))
		b.left -= int64(len(s))
		if err == nil {
			return n, true
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			return n, false
		}
	}
	return n, false
}

func hashHead(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// globEscape quotes a path's pattern characters, so that a rotation suffix
// is the only pattern in what is globbed.
func globEscape(p string) string {
	var sb strings.Builder
	for _, r := range p {
		if strings.ContainsRune(`*?[\`, r) {
			sb.WriteByte('\\')
		}
		sb.WriteRune(r)
	}
	return sb.String()
}

// readRotated finds the rotated file holding the rest of what cur was
// reading, by its ID (renamed) or by its head (copied, compressed; never by
// an empty head, which any file has), reads it from cur.Offset to its end,
// and says which it was and how far it is trusted.
func readRotated(src hostenv.Source, p string, cur *Cursor, b *Budget, trust TrustFunc, res *ReadResult, fn LineFunc) (RotatedFile, bool) {
	var cands []string
	for _, g := range []string{globEscape(p) + ".*", globEscape(p) + "-*"} {
		for _, c := range hostenv.Glob(src, g) {
			if c != p && len(cands) < maxRotated {
				cands = append(cands, c)
			}
		}
	}
	try := func(c string, byID bool) (RotatedFile, bool) {
		rf := RotatedFile{Path: c, Reason: hostenv.ReasonUnverified}
		if trust != nil {
			rf.Verified, rf.Reason = trust(c)
		}
		return rf, readRest(src, c, strings.HasSuffix(c, ".gz"), byID, cur, b, res, fn)
	}
	if cur.ID != "" { // by ID first: a stat, no read
		for _, c := range cands {
			if strings.HasSuffix(c, ".gz") {
				continue
			}
			if st, err := hostenv.Stat(src, c); err == nil && st.ID == cur.ID {
				if rf, ok := try(c, true); ok {
					return rf, true
				}
			}
		}
	}
	if cur.HeadLen == 0 {
		return RotatedFile{}, false
	}
	for _, c := range cands {
		if rf, ok := try(c, false); ok {
			return rf, true
		}
	}
	return RotatedFile{}, false
}

// readRest reads c from cur.Offset to its end if it is the file cur was in:
// its head is cur's (and, byID, its ID was already found to be).
func readRest(src hostenv.Source, c string, gz, byID bool, cur *Cursor, b *Budget, res *ReadResult, fn LineFunc) bool {
	f, err := hostenv.OpenLogNoFollow(src, c)
	if err != nil {
		return false
	}
	defer f.Close()
	if byID && f.Stat().ID != cur.ID { // swapped since the stat
		return false
	}
	var r io.Reader = f
	if gz {
		z, err := gzip.NewReader(f)
		if err != nil {
			return false
		}
		defer z.Close()
		r = z
	}
	br := bufio.NewReaderSize(r, MaxLine)
	h, _ := br.Peek(cur.HeadLen)
	if len(h) < cur.HeadLen || hashHead(h) != cur.Head {
		return false
	}
	if gz { // no seeking in a stream: what is skipped is read, and charged
		if cur.Offset > b.left {
			res.partial(ReadTruncated)
			res.partial(ReadRotatedGap)
			return true
		}
		b.left -= cur.Offset
		if _, err := io.CopyN(io.Discard, br, cur.Offset); err != nil {
			return false
		}
	} else {
		if _, err := f.Seek(cur.Offset, io.SeekStart); err != nil {
			return false
		}
		br.Reset(f)
	}
	if cur.MidLine {
		if _, ok := skipLine(br, b); !ok {
			return true
		}
	}
	readLines(br, c, cur.Offset, b, true, res, fn)
	return true
}

// readLines gives fn each line of br from offset off, within the budget,
// and returns the offset after what was read, and mid: it stops inside a
// line longer than MaxLine (its start given, cut), which the next read
// skips to its end. final: the file is rotated and complete, so a last line
// without a newline is given too; otherwise one shorter than MaxLine is
// left for the next run.
func readLines(br *bufio.Reader, from string, off int64, b *Budget, final bool, res *ReadResult, fn LineFunc) (int64, bool) {
	var long []byte
	for {
		if b.spent() {
			if _, err := br.Peek(1); err == nil { // more there: not read for the budget
				res.partial(ReadTruncated)
			}
			return off, false
		}
		line, err := br.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) { // longer than MaxLine: give its start, skip the rest
			long = append(long[:0], line...)
			n := int64(len(line))
			b.left -= n
			res.LongLines++
			res.Lines++
			fn(from, long)
			rest, ended := skipLine(br, b)
			n += rest
			res.Bytes += n
			off += n
			if !ended {
				if b.spent() {
					res.partial(ReadTruncated)
				}
				return off, !final
			}
			continue
		}
		if err != nil {
			if final && len(line) > 0 {
				res.Lines++
				res.Bytes += int64(len(line))
				b.left -= int64(len(line))
				off += int64(len(line))
				fn(from, line)
			}
			return off, false
		}
		n := int64(len(line))
		res.Lines++
		res.Bytes += n
		b.left -= n
		off += n
		fn(from, bytes.TrimSuffix(line[:len(line)-1], []byte("\r")))
	}
}
