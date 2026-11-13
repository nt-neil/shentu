//go:build windows

package hostenv

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// Final review: a link whose target is missing is reported as dangling,
// with the link's own owner, not as a path that does not exist.
func TestFileSecurityDanglingLink(t *testing.T) {
	dir := t.TempDir()
	link := filepath.Join(dir, "x.conf")
	if err := os.Symlink(filepath.Join(dir, "missing.conf"), link); err != nil {
		t.Fatal(err)
	}
	sec, err := (&Live{}).FileSecurity(link)
	if err != nil || !sec.Dangling || sec.Link == nil || sec.Link.Owner == "" || len(sec.Untrusted()) == 0 {
		t.Errorf("dangling link: %+v %v", sec, err)
	}
	if _, err := (&Live{}).FileSecurity(filepath.Join(dir, "nothing")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a missing path is still not-exist: %v", err)
	}
}
