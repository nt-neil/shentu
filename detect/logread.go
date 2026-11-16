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
	Lines     int      `json:"lines"`
	Bytes     int64    `json:"bytes"`
	LongLines int      `json:"long_lines,omitempty"` // cut at MaxLine
	Rotated   []string `json:"rotated,omitempty"`    // rotated files the rest of the last read was found in
	Partial   []string `json:"partial,omitempty"`    // ReadFirstRun, ReadRotatedGap, ReadRewritten, ReadTruncated
}

func (r *ReadResult) partial(why string) {
	for _, p := range r.Partial {
		if p == why {
			return
		}
	}
	r.Partial = append(r.Partial, why)
}

// ReadLog reads p's lines added since cur (nil: none, a first run), giving
// each to fn without its newline (only valid during the call), and returns
// the cursor to keep. When p is no longer the file cur was in (renamed by
// logrotate, copied and truncated, compressed), the rest of that file is
// read first from the rotated file holding it: .1, -YYYYMMDD, .gz. A last
// line without its newline is left for the next run. On an error opening p
// the old cursor is returned unchanged.
func ReadLog(src hostenv.Source, p string, cur *Cursor, b *Budget, fn func(line []byte)) (Cursor, ReadResult, error) {
	var res ReadResult
	f, err := hostenv.OpenLog(src, p)
	if err != nil {
		if cur != nil {
			return *cur, res, err
		}
		return Cursor{}, res, err
	}
	defer f.Close()
	st := f.Stat()
	head, err := readHead(f)
	if err != nil {
		return keep(cur), res, err
	}
	var start int64
	switch {
	case cur == nil:
		res.partial(ReadFirstRun)
		start = max(0, st.Size-b.left)
	case sameFile(cur, st, head):
		start = cur.Offset
	default: // rotated, copied and truncated, or rewritten
		if name, ok := readRotated(src, p, cur, b, &res, fn); ok {
			res.Rotated = append(res.Rotated, name)
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
	if start > 0 && cur == nil { // started mid-file: skip to the next whole line
		n, _ := skipLine(br)
		start += n
	}
	end := readLines(br, start, b, false, &res, fn)
	return Cursor{ID: st.ID, Offset: end, Size: st.Size, ModTime: st.ModTime, Head: hashHead(head), HeadLen: len(head), ReadAt: time.Now().UTC()}, res, nil
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

// skipLine discards through the next newline: n bytes, ok if one was found.
func skipLine(br *bufio.Reader) (n int64, ok bool) {
	for {
		s, err := br.ReadSlice('\n')
		n += int64(len(s))
		if err == nil {
			return n, true
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			return n, false
		}
	}
}

func hashHead(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// readRotated finds the rotated file holding the rest of what cur was
// reading, by its ID (renamed) or by its head (copied, compressed), reads it
// from cur.Offset to its end, and says which it was.
func readRotated(src hostenv.Source, p string, cur *Cursor, b *Budget, res *ReadResult, fn func([]byte)) (string, bool) {
	var cands []string
	for _, g := range []string{p + ".*", p + "-*"} {
		for _, c := range hostenv.Glob(src, g) {
			if c != p && len(cands) < maxRotated {
				cands = append(cands, c)
			}
		}
	}
	// By ID first: a stat, no read. Then by head.
	for _, c := range cands {
		if strings.HasSuffix(c, ".gz") || cur.ID == "" {
			continue
		}
		if st, err := hostenv.Stat(src, c); err == nil && st.ID == cur.ID {
			if readRest(src, c, false, cur, b, res, fn) {
				return c, true
			}
		}
	}
	for _, c := range cands {
		if readRest(src, c, strings.HasSuffix(c, ".gz"), cur, b, res, fn) {
			return c, true
		}
	}
	return "", false
}

// readRest reads c from cur.Offset to its end if its head is cur's.
func readRest(src hostenv.Source, c string, gz bool, cur *Cursor, b *Budget, res *ReadResult, fn func([]byte)) bool {
	f, err := hostenv.OpenLog(src, c)
	if err != nil {
		return false
	}
	defer f.Close()
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
	if gz {
		if _, err := io.CopyN(io.Discard, br, cur.Offset); err != nil {
			return false
		}
	} else {
		if _, err := f.Seek(cur.Offset, io.SeekStart); err != nil {
			return false
		}
		br.Reset(f)
	}
	readLines(br, cur.Offset, b, true, res, fn)
	return true
}

// readLines gives fn each line of br from offset off, within the budget,
// and returns the offset after the last line given. final: the file is
// rotated and complete, so a last line without a newline is given too.
func readLines(br *bufio.Reader, off int64, b *Budget, final bool, res *ReadResult, fn func([]byte)) int64 {
	var long []byte
	for {
		if b.spent() {
			res.partial(ReadTruncated)
			return off
		}
		line, err := br.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) { // longer than MaxLine: keep its start, skip to its end
			long = append(long[:0], line...)
			n := int64(len(line))
			for errors.Is(err, bufio.ErrBufferFull) {
				line, err = br.ReadSlice('\n')
				n += int64(len(line))
			}
			if err != nil && !(final && errors.Is(err, io.EOF)) {
				return off // not ended yet: the next run reads it whole
			}
			res.LongLines++
			res.Lines++
			res.Bytes += n
			b.left -= n
			off += n
			fn(long)
			if err != nil {
				return off
			}
			continue
		}
		if err != nil {
			if final && len(line) > 0 {
				res.Lines++
				res.Bytes += int64(len(line))
				b.left -= int64(len(line))
				off += int64(len(line))
				fn(line)
			}
			return off
		}
		n := int64(len(line))
		res.Lines++
		res.Bytes += n
		b.left -= n
		off += n
		fn(bytes.TrimSuffix(line[:len(line)-1], []byte("\r")))
	}
}
