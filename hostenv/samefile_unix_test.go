//go:build unix

package hostenv

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// A file swapped between the checks and the read is refused (TOCTOU).
func TestReadFileIfSame(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "site.conf")
	os.WriteFile(p, []byte("root /var/www/a;\n"), 0o644)
	live := &Live{}
	st, err := live.Stat(p)
	if err != nil || st.ID == "" {
		t.Fatalf("stat %+v %v", st, err)
	}
	if b, err := ReadFileIfSame(live, p, st); err != nil || string(b) != "root /var/www/a;\n" {
		t.Errorf("same file: %q %v", b, err)
	}
	os.Rename(p, p+".old")
	os.WriteFile(p, []byte("root /;\n"), 0o644) // another file under the same name
	if _, err := ReadFileIfSame(live, p, st); !errors.Is(err, ErrChanged) {
		t.Errorf("swapped file read: %v", err)
	}
}
