package detect

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"sort"
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
	maxRotated         = 32   // rotated files looked at for the one the cursor was in, the newest first
	maxRotatedNames    = 4096 // names gathered before choosing them
)

// Why a read is partial. The lines read are still good; what was not read
// is said, never taken for a quiet log.
const (
	ReadFirstRun   = "first_run"   // no cursor: only the last budget's worth was read
	ReadRotatedGap = "rotated_gap" // what the file read last time got after the cursor is lost: gone, unreadable, or not read to its end
	ReadTruncated  = "truncated"   // the run's budget ran out: the next run goes on from here
	ReadIOError    = "io_error"    // a read failed before the end (a corrupt .gz, a disk error): what follows is not read
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
	Partial   []string      `json:"partial,omitempty"`    // ReadFirstRun, ReadRotatedGap, ReadTruncated, ReadIOError
	// Verified: the log's own lines are trusted: ReadOpts.Want was verified
	// and the file opened is still it, root's, writable by root alone.
	Verified bool           `json:"verified"`
	Reason   hostenv.Reason `json:"reason,omitempty"`
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

// Line is one line read.
type Line struct {
	From     string // the log, or the rotated file it came from
	Text     []byte // without its newline, valid only during the call
	Cut      bool   // longer than MaxLine: Text is its start (parse it with ParseCut)
	Verified bool   // the file it came from is trusted (ReadResult.Verified, RotatedFile.Verified)
}

// LineFunc gets each line.
type LineFunc func(Line)

// TrustFunc judges a rotated file found beside a log: hostenv.JudgeLog with
// the host's web accounts. Nil: every rotated file is unverified.
type TrustFunc func(path string) hostenv.TrustResult

// ReadOpts is what ReadLog is to check the files it opens against.
type ReadOpts struct {
	// Want is the log as WebLogs judged it; nil, or not verified: the log's
	// lines are unverified.
	Want  *hostenv.LogSource
	Trust TrustFunc
}

// rootUID is who alone may write a verified log: root. (Tests, run as a
// user, set their own.)
var rootUID = 0

// opened says whether the file opened is the one judged, and still only
// root's to change: the judgment was on the path, and the path may have
// been swapped since.
func opened(st hostenv.FileStat, judgedID string) (bool, hostenv.Reason) {
	switch {
	case judgedID == "" || st.ID == "" || st.ID != judgedID:
		return false, hostenv.ReasonUnverified // not the file judged, or not known to be
	case !st.Mode.IsRegular():
		return false, hostenv.ReasonNotRegular
	case st.UID != rootUID || st.Mode.Perm()&0o022 != 0:
		return false, hostenv.ReasonUntrusted
	}
	return true, ""
}

// ReadLog reads p's lines added since cur (nil: none, a first run), giving
// each to fn, and returns the cursor to keep. When p is no longer the file
// cur was in (renamed by logrotate, copied and truncated, compressed), the
// rest of that file is read first from the rotated file holding it: .1,
// -YYYYMMDD, .gz, the newest 32, opened without following a link and judged
// on their own. A last line without its newline is left for the next run.
// On an error opening p the old cursor is returned unchanged.
func ReadLog(src hostenv.Source, p string, cur *Cursor, b *Budget, opts ReadOpts, fn LineFunc) (Cursor, ReadResult, error) {
	var res ReadResult
	f, err := hostenv.OpenLog(src, p)
	if err != nil {
		return keep(cur), res, err
	}
	defer f.Close()
	st := f.Stat()
	res.Reason = hostenv.ReasonUnverified
	if opts.Want != nil && opts.Want.Verified {
		res.Verified, res.Reason = opened(st, opts.Want.FileID)
	} else if opts.Want != nil && opts.Want.Reason != "" {
		res.Reason = opts.Want.Reason
	}
	head, err := readHead(f)
	if err != nil {
		return keep(cur), res, err
	}
	var start int64
	switch {
	case cur == nil:
		res.partial(ReadFirstRun)
		start = max(0, st.Size-max(b.left, 0))
	case sameFile(cur, st, head):
		start = cur.Offset
		if cur.HeadLen == 0 && rotatedSince(src, p, cur.ReadAt) {
			// Empty when last read, and a rotated file written since: what
			// it got before the rotation (copytruncate) cannot be told apart.
			res.partial(ReadRotatedGap)
		}
	default: // rotated, copied and truncated, rewritten, or a new file that got the old one's inode
		if rf, ok := readRotated(src, p, cur, b, opts.Trust, &res, fn); ok {
			res.Rotated = append(res.Rotated, rf)
		} else {
			res.partial(ReadRotatedGap)
		}
	}
	// Inside a line? Only when the byte before start is not a newline: a
	// cursor at a line's end, or a first run with nothing left to read,
	// skips nothing.
	skip := false
	if cur != nil && sameFile(cur, st, head) {
		skip = cur.MidLine
	} else if cur == nil && start > 0 {
		skip = !newlineBefore(f, start)
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return keep(cur), res, err
	}
	br := bufio.NewReaderSize(f, MaxLine)
	mid := false
	end := start
	if skip {
		n, ok, serr := skipLine(br, b)
		end += n
		mid = !ok
		if serr != nil {
			res.partial(ReadIOError)
		} else if mid && b.spent() {
			res.partial(ReadTruncated)
		}
	}
	if !mid {
		var stop error
		end, mid, stop = readLines(br, Line{From: p, Verified: res.Verified}, end, b, false, &res, fn)
		if stop != nil {
			res.partial(ReadIOError)
		}
	}
	return Cursor{ID: st.ID, Offset: end, MidLine: mid, Size: st.Size, ModTime: st.ModTime, Head: hashHead(head), HeadLen: len(head), ReadAt: time.Now().UTC()}, res, nil
}

func keep(cur *Cursor) Cursor {
	if cur != nil {
		return *cur
	}
	return Cursor{}
}

// newlineBefore: the byte before off is a newline.
func newlineBefore(f io.ReadSeeker, off int64) bool {
	if _, err := f.Seek(off-1, io.SeekStart); err != nil {
		return false
	}
	var b [1]byte
	n, _ := f.Read(b[:])
	return n == 1 && b[0] == '\n'
}

// sameFile: p is still the file cur was in, grown or not: the same ID
// where both are known, no shorter than what was read, and the same first
// cur.HeadLen bytes. The ID alone proves nothing: ext4 and tmpfs give a
// file created after another's removal the same inode, so the same ID
// with another head is a new file (read from its start, the old one's
// rest a gap), whether it was rewritten in place or replaced.
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
// ok if the newline was reached (not: the file or the budget ended first),
// err a read that failed other than at the end.
func skipLine(br *bufio.Reader, b *Budget) (n int64, ok bool, err error) {
	for !b.spent() {
		s, e := br.ReadSlice('\n')
		n += int64(len(s))
		b.left -= int64(len(s))
		switch {
		case e == nil:
			return n, true, nil
		case errors.Is(e, bufio.ErrBufferFull):
			continue
		case errors.Is(e, io.EOF):
			return n, false, nil
		default:
			return n, false, e
		}
	}
	return n, false, nil
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

// rotatedFiles are the files beside p its rotation may have made, the most
// recently changed first, at most maxRotated: with dateext a log may have
// dozens, and the one wanted is the newest.
func rotatedFiles(src hostenv.Source, p string) []string {
	type cand struct {
		path string
		mod  time.Time
	}
	var cs []cand
	for _, g := range []string{globEscape(p) + ".*", globEscape(p) + "-*"} {
		for _, c := range hostenv.Glob(src, g) {
			if c == p || len(cs) >= maxRotatedNames {
				continue
			}
			st, _ := hostenv.Stat(src, c)
			cs = append(cs, cand{c, st.ModTime})
		}
	}
	sort.SliceStable(cs, func(i, j int) bool {
		if !cs[i].mod.Equal(cs[j].mod) {
			return cs[i].mod.After(cs[j].mod)
		}
		return cs[i].path < cs[j].path
	})
	var out []string
	for _, c := range cs {
		if len(out) == maxRotated {
			break
		}
		out = append(out, c.path)
	}
	return out
}

// rotatedSince: a rotated file of p changed after t.
func rotatedSince(src hostenv.Source, p string, t time.Time) bool {
	for _, c := range rotatedFiles(src, p) {
		if st, err := hostenv.Stat(src, c); err == nil && st.ModTime.After(t) && st.Size > 0 {
			return true
		}
	}
	return false
}

// readRotated finds the rotated file holding the rest of what cur was
// reading, by its ID (renamed) or by its head (copied, compressed), reads
// it from cur.Offset to its end, and says which it was and how far it is
// trusted. Its head must be cur's either way: an ID may be a reused inode.
// With an empty head (the log was empty when last read) nothing tells the
// file read from another, so none is taken.
func readRotated(src hostenv.Source, p string, cur *Cursor, b *Budget, trust TrustFunc, res *ReadResult, fn LineFunc) (RotatedFile, bool) {
	if cur.HeadLen == 0 {
		return RotatedFile{}, false
	}
	cands := rotatedFiles(src, p)
	if cur.ID != "" { // by ID first: a stat, no read
		for _, c := range cands {
			if strings.HasSuffix(c, ".gz") {
				continue
			}
			if st, err := hostenv.Stat(src, c); err == nil && st.ID == cur.ID {
				if rf, ok := readRest(src, c, false, true, cur, b, trust, res, fn); ok {
					return rf, true
				}
			}
		}
	}
	for _, c := range cands {
		if rf, ok := readRest(src, c, strings.HasSuffix(c, ".gz"), false, cur, b, trust, res, fn); ok {
			return rf, true
		}
	}
	return RotatedFile{}, false
}

// readRest reads c from cur.Offset to its end if it is the file cur was in:
// its head is cur's (and, byID, its ID was already found to be). A rotated
// file shorter than the cursor (non-gzip) is not it.
func readRest(src hostenv.Source, c string, gz, byID bool, cur *Cursor, b *Budget, trust TrustFunc, res *ReadResult, fn LineFunc) (RotatedFile, bool) {
	rf := RotatedFile{Path: c, Reason: hostenv.ReasonUnverified}
	var judged hostenv.TrustResult
	if trust != nil {
		judged = trust(c)
	}
	f, err := hostenv.OpenLogNoFollow(src, c)
	if err != nil {
		return rf, false
	}
	defer f.Close()
	st := f.Stat()
	if byID && st.ID != cur.ID { // swapped since the stat
		return rf, false
	}
	if !gz && st.Size < cur.Offset {
		return rf, false
	}
	if judged.Verified {
		rf.Verified, rf.Reason = opened(st, judged.File.ID)
	} else if judged.Reason != "" {
		rf.Reason = judged.Reason
	}
	var r io.Reader = f
	if gz {
		z, err := gzip.NewReader(f)
		if err != nil {
			return rf, false
		}
		defer z.Close()
		r = z
	}
	br := bufio.NewReaderSize(r, MaxLine)
	h, _ := br.Peek(cur.HeadLen)
	if len(h) < cur.HeadLen || hashHead(h) != cur.Head {
		return rf, false
	}
	if gz { // no seeking in a stream: what is skipped is read, and charged
		if cur.Offset > b.left {
			res.partial(ReadTruncated)
			res.partial(ReadRotatedGap)
			return rf, true
		}
		b.left -= cur.Offset
		if _, err := io.CopyN(io.Discard, br, cur.Offset); err != nil {
			res.partial(ReadIOError)
			res.partial(ReadRotatedGap)
			return rf, true
		}
	} else {
		if _, err := f.Seek(cur.Offset, io.SeekStart); err != nil {
			return rf, false
		}
		br.Reset(f)
	}
	// What is not read of a rotated file now is never read: the cursor
	// moves to the new file. Say so.
	lost := func() { res.partial(ReadRotatedGap) }
	if cur.MidLine {
		_, ok, err := skipLine(br, b)
		if err != nil {
			res.partial(ReadIOError)
			lost()
			return rf, true
		}
		if !ok {
			if b.spent() {
				res.partial(ReadTruncated)
				lost()
			}
			return rf, true
		}
	}
	_, _, stop := readLines(br, Line{From: c, Verified: rf.Verified}, cur.Offset, b, true, res, fn)
	if stop != nil {
		res.partial(ReadIOError)
		lost()
	} else if b.spent() {
		if _, err := br.Peek(1); err == nil {
			lost()
		}
	}
	return rf, true
}

// readLines gives fn each line of br from offset off, within the budget,
// and returns the offset after what was read; mid: it stops inside a line
// longer than MaxLine (its start given, cut), which the next read skips to
// its end; err: a read failed other than at the end. final: the file is
// rotated and complete, so a last line without a newline is given too;
// otherwise one shorter than MaxLine is left for the next run.
func readLines(br *bufio.Reader, l Line, off int64, b *Budget, final bool, res *ReadResult, fn LineFunc) (int64, bool, error) {
	var long []byte
	for {
		if b.spent() {
			if _, err := br.Peek(1); err == nil { // more there: not read for the budget
				res.partial(ReadTruncated)
			}
			return off, false, nil
		}
		line, err := br.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) { // longer than MaxLine: give its start, skip the rest
			long = append(long[:0], line...)
			n := int64(len(line))
			b.left -= n
			res.LongLines++
			res.Lines++
			l.Text, l.Cut = long, true
			fn(l)
			rest, ended, serr := skipLine(br, b)
			n += rest
			res.Bytes += n
			off += n
			if serr != nil {
				return off, false, serr
			}
			if !ended {
				if b.spent() {
					res.partial(ReadTruncated)
				}
				return off, !final, nil
			}
			continue
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				return off, false, err
			}
			if final && len(line) > 0 {
				res.Lines++
				res.Bytes += int64(len(line))
				b.left -= int64(len(line))
				off += int64(len(line))
				l.Text, l.Cut = line, false
				fn(l)
			}
			return off, false, nil
		}
		n := int64(len(line))
		res.Lines++
		res.Bytes += n
		b.left -= n
		off += n
		l.Text, l.Cut = bytes.TrimSuffix(line[:len(line)-1], []byte("\r")), false
		fn(l)
	}
}
