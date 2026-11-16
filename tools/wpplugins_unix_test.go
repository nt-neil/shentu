//go:build unix

package tools

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// Security review of part 4: a FIFO left in a plugin's directory (the web
// account's to write) does not hold the patrol, and a link is not followed.
func TestWordPressPluginsFIFO(t *testing.T) {
	web := t.TempDir()
	dir := filepath.Join(web, "wp-content", "plugins", "marker-fifo")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(dir, "a.php"), 0o644); err != nil {
		t.Skip(err)
	}
	os.WriteFile(filepath.Join(dir, "b.php"), []byte("<?php\n/* Plugin Name: Marker FIFO\nVersion: 1.0 */\n"), 0o644)
	target := filepath.Join(web, "elsewhere.php")
	os.WriteFile(target, []byte("<?php\n/* Plugin Name: Linked\nVersion: 9.9 */\n"), 0o644)
	ld := filepath.Join(web, "wp-content", "plugins", "marker-link")
	os.MkdirAll(ld, 0o755)
	os.Symlink(target, filepath.Join(ld, "marker-link.php"))
	done := make(chan []WPPlugin, 1)
	go func() { ps, _ := WordPressPlugins([]string{web}); done <- ps }()
	select {
	case ps := <-done:
		if len(ps) != 1 || ps[0].Slug != "marker-fifo" || ps[0].Version != "1.0" {
			t.Errorf("plugins %+v", ps)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("held by a FIFO")
	}
}
