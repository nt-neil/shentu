package tools

import (
	"path/filepath"
	"testing"
)

// As v0.2.5's insideAny: a filesystem root contains only itself.
func TestInsideFilesystemRoot(t *testing.T) {
	root := string(filepath.Separator)
	if v := filepath.VolumeName(t.TempDir()); v != "" {
		root = v + root
	}
	if !inside(root, root) || inside(filepath.Join(root, "etc", "passwd"), root) || insideAny(filepath.Join(root, "x"), []string{root}) {
		t.Error("a root of / must contain only /")
	}
	if !inside(filepath.Join(root, "srv", "a", "b"), filepath.Join(root, "srv")) {
		t.Error("a folder still contains what is below it")
	}
}
