package hostenv

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// An apk database over MaxFileBytes is still read whole.
func TestApkDatabaseLarge(t *testing.T) {
	root := t.TempDir()
	var b strings.Builder
	for i := 0; b.Len() < MaxFileBytes+2<<20; i++ {
		fmt.Fprintf(&b, "P:pkg%d\nV:1.%d-r0\nA:aarch64\nF:usr/share/pkg%d\n%s\n", i, i, i, strings.Repeat("R:file-with-a-long-name\n", 20))
	}
	b.WriteString("P:last\nV:9-r0\nA:aarch64\n\n")
	os.MkdirAll(filepath.Join(root, "lib/apk/db"), 0o755)
	os.WriteFile(filepath.Join(root, "lib/apk/db/installed"), []byte(b.String()), 0o644)
	live := &Live{Remap: map[string]string{"/lib": filepath.Join(root, "lib")}}
	set := LinuxCollector{}.Packages(context.Background(), live, map[string]string{"ID": "alpine", "VERSION_ID": "3.22.4"})
	last := false
	for _, p := range set.Value.Items {
		last = last || p.Name == "last"
	}
	if !last || set.Status != StatusOK {
		t.Errorf("%s %q, %d packages, last read: %v", set.Status, set.Detail, len(set.Value.Items), last)
	}
}
