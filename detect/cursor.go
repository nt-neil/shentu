package detect

import (
	"encoding/json"
	"errors"
	"fmt"
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
	ID      string    `json:"id,omitempty"` // device:inode of the file read; "" where the source cannot tell
	Offset  int64     `json:"offset"`       // bytes read, up to the end of the last whole line
	Size    int64     `json:"size"`
	ModTime time.Time `json:"mtime"`
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
}

// LoadCursors reads dir's cursor file. None yet: empty, no error. One that
// cannot be read or parsed: empty, and the error, so that the caller says
// every log is read as on a first run rather than as if nothing changed.
func LoadCursors(dir string) (*Cursors, error) {
	c := &Cursors{Version: 1, Sources: map[string]Cursor{}}
	b, err := os.ReadFile(filepath.Join(dir, CursorFileName))
	if errors.Is(err, fs.ErrNotExist) {
		return c, nil
	}
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
		c.Sources[k] = v
	}
	return c, nil
}

// Save writes the cursors to dir, keeping the MaxCursors most recently read.
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
	tmp := filepath.Join(dir, CursorFileName+".tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, CursorFileName))
}
