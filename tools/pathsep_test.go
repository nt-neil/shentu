package tools

import (
	"path/filepath"
	"testing"
)

func TestInsideAnyBoundaries(t *testing.T) {
	roots := []string{filepath.FromSlash("/var/www"), filepath.FromSlash("/srv/app/")}
	for p, want := range map[string]bool{
		"/var/www": true, "/var/www/a/b.php": true, "/var/www-old/x": false, "/var/ww": false,
		"/srv/app": true, "/srv/app/../app2/x": false, "/srv/app/./x": true, "/etc/passwd": false,
	} {
		if got := insideAny(filepath.FromSlash(p), roots); got != want {
			t.Errorf("insideAny(%q) = %v, want %v", p, got, want)
		}
	}
}

func TestDepthUsesOSSeparator(t *testing.T) {
	if d := depth(filepath.Join("a", "b", "c")); d != 2 {
		t.Errorf("depth = %d, want 2", d)
	}
}
