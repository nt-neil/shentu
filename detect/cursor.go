package detect

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// CursorFileName is where, under the state directory, detect keeps how far
// it has read each log: apart from patrol's state.json, written the same
// way (a temporary file renamed over it).
const CursorFileName = "logcursor.json"

// MaxCursors bounds the file: sources beyond it (the least recently read)
// are dropped, and are read again as a first run.
const MaxCursors = 1024

// Cursor is how far one log was read.
type Cursor struct {
	ID     string `json:"id,omitempty"` // device:inode of the file read; "" where the source cannot tell
	Offset int64  `json:"offset"`       // bytes read, up to the end of the last whole line
	// MidLine: Offset is inside a line longer than MaxLine, whose start was
	// given: the next read skips to its end rather than read the rest again.
	MidLine bool `json:"mid_line,omitempty"`
	// Born is the file's birth time when the source knows it: an inode
	// reused for a new file (ext4, tmpfs) has the same ID and another Born.
	Born time.Time `json:"born,omitempty"`
	// Failures counts the runs in a row that failed on this source without
	// moving it on: three or more is cursor_stuck, an alert of its own.
	Failures int       `json:"failures,omitempty"`
	Size     int64     `json:"size"`
	ModTime  time.Time `json:"mtime"`
	// Head is the SHA-256 of the file's first HeadLen bytes (at most 256):
	// the same name with other content at its start is not the file read,
	// and a rotated copy (copytruncate, gzip) is found by it.
	Head    string `json:"head,omitempty"`
	HeadLen int    `json:"head_len,omitempty"`
	// Journal is journald's __CURSOR, for a journal source.
	Journal string    `json:"journal_cursor,omitempty"`
	ReadAt  time.Time `json:"read_at"`
}

// Cursors is the file's content, keyed by source (a log's path, or
// journald:<unit>).
type Cursors struct {
	Version int               `json:"version"`
	Sources map[string]Cursor `json:"sources"`
	// Dropped: the entries the file held that were not valid cursors (a
	// negative offset, a head that is no hash), each "key (why)": read as
	// a first run, and to be reported.
	Dropped []string `json:"-"`
}

// valid says why a cursor read from the file cannot be used, "" if it can.
func (c Cursor) valid() string {
	switch {
	case c.Offset < 0 || c.Size < 0 || c.Failures < 0:
		return "negative offset or size"
	case c.HeadLen < 0 || c.HeadLen > headLen:
		return "head_len out of 0..256"
	case c.HeadLen > 0 && !isSHA256Hex(c.Head):
		return "head is not a SHA-256"
	}
	return ""
}

func isSHA256Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// LoadCursors reads dir's cursor file. None yet: empty, no error. One that
// cannot be read or parsed, is a link, or that someone other than this
// process's user owns or may write: empty, and the error, so that the
// caller says every log is read as on a first run rather than as if
// nothing changed. Entries that are not valid are dropped (Dropped).
func LoadCursors(dir string) (*Cursors, error) {
	c := &Cursors{Version: 1, Sources: map[string]Cursor{}}
	p := filepath.Join(dir, CursorFileName)
	f, err := openNoFollow(p) // a link is refused by the open itself, not by a check before it
	if errors.Is(err, fs.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return c, fmt.Errorf("%s: %w", CursorFileName, err)
	}
	defer f.Close()
	st, err := f.Stat() // of the file opened
	if err != nil {
		return c, err
	}
	if why := ownedByUs(st); why != "" {
		return c, fmt.Errorf("%s: %s", CursorFileName, why)
	}
	b, err := io.ReadAll(io.LimitReader(f, 64<<20))
	if err != nil {
		return c, err
	}
	var in Cursors
	if err := json.Unmarshal(b, &in); err != nil {
		return c, fmt.Errorf("%s: %w", CursorFileName, err)
	}
	if in.Version != 1 {
		return c, fmt.Errorf("%s: version %d, want 1", CursorFileName, in.Version)
	}
	for k, v := range in.Sources {
		if why := v.valid(); why != "" {
			c.Dropped = append(c.Dropped, k+" ("+why+")")
			continue
		}
		c.Sources[k] = v
	}
	sort.Strings(c.Dropped)
	return c, nil
}

// Save writes the cursors to dir, keeping the MaxCursors most recently
// read: to a new temporary file (created exclusively, never through a link
// someone left there), synced, then renamed over the old one.
func (c *Cursors) Save(dir string) error {
	if len(c.Sources) > MaxCursors {
		keys := make([]string, 0, len(c.Sources))
		for k := range c.Sources {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			a, b := c.Sources[keys[i]].ReadAt, c.Sources[keys[j]].ReadAt
			if !a.Equal(b) {
				return a.After(b)
			}
			return keys[i] < keys[j]
		})
		for _, k := range keys[MaxCursors:] {
			delete(c.Sources, k)
		}
	}
	c.Version = 1
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, CursorFileName+".*.tmp") // O_EXCL, 0600
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, werr := f.Write(b)
	serr := f.Sync()
	cerr := f.Close()
	if err := errors.Join(werr, serr, cerr); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, filepath.Join(dir, CursorFileName)); err != nil {
		os.Remove(tmp)
		return err
	}
	return syncDir(dir) // the rename itself, past a crash
}
