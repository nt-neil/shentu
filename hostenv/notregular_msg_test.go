package hostenv

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/nt-neil/shentu/internal/osutil"
)

// The nit of #257's review: a reparse point refused says "not a regular
// file" once, and is still ErrNotRegular (open_windows.go's error).
func TestNotRegularReparseMessage(t *testing.T) {
	err := &os.PathError{Op: "open", Path: `C:\site\a.php`, Err: notRegular(osutil.ReparseKind(osutil.FileAttributeReparsePoint, 0x9000001A))}
	if n := strings.Count(err.Error(), "not a regular file"); n != 1 || !errors.Is(err, ErrNotRegular) {
		t.Errorf("%q: %d times, ErrNotRegular %v", err, n, errors.Is(err, ErrNotRegular))
	}
}
