package tools

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// P5 part 4: WordPress plugins' versions from their main files' headers.
func TestWordPressPlugins(t *testing.T) {
	web := t.TempDir()
	mk := func(p, s string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	plug := filepath.Join(web, "wp-content", "plugins")
	mk(filepath.Join(plug, "marker-plugin", "readme.php"), "<?php // no header here\n")
	mk(filepath.Join(plug, "marker-plugin", "marker-plugin.php"), "<?php\n/**\n * Plugin Name: Marker Plugin\n * Version: 1.2.3\n */\n")
	mk(filepath.Join(plug, "hello-marker.php"), "<?php\n/*\nPlugin Name: Hello Marker\r\nVersion:2.0-beta */\n")
	mk(filepath.Join(plug, "no-header", "x.php"), "<?php echo 1;\n")
	mk(filepath.Join(plug, "odd", "odd.php"), "<?php\n/* Plugin Name: Odd\n Version: 1.0\nfake line */\n")
	mk(filepath.Join(web, "blog", "wp-content", "plugins", "sub-marker", "sub-marker.php"), "<?php\n/* Plugin Name: Sub Marker\nVersion: 0.9 */\n")
	if err := os.Symlink(filepath.Join(plug, "marker-plugin"), filepath.Join(plug, "linked")); err != nil {
		t.Skip(err)
	}
	ps, unread := WordPressPlugins([]string{web})
	var got []string
	for _, p := range ps {
		got = append(got, p.Slug+"@"+p.Version)
	}
	// Review 1 of #91 (N-2): the linked plugin is said, not left out quietly.
	// Review 2 of #91 (S-b): .php files without a header are said too.
	if strings.Join(got, ",") != "hello-marker@2.0-beta,marker-plugin@1.2.3,odd@1.0,sub-marker@0.9" || len(unread) != 2 ||
		!strings.Contains(strings.Join(unread, "|"), "linked (a link, not followed)") || !strings.Contains(strings.Join(unread, "|"), "no-header (.php files but no plugin header found)") {
		t.Errorf("plugins %v, unread %v", got, unread)
	}
	if ps[1].Name != "Marker Plugin" || ps[1].Root != web {
		t.Errorf("%+v", ps[1])
	}
	s := SurfacePlugins(ps)
	if len(s) != 4 || s[1].Ecosystem != "WordPress" || s[1].Package != "marker-plugin" || s[1].Version != "1.2.3" {
		t.Errorf("surface %+v", s)
	}
}

// Review 2 of #91 (S-b, S-G): a main file that is a link is said; the
// main file is chosen in name order; a directory with more entries than
// read is said, one with exactly as many is not.
func TestWordPressPluginsReview2(t *testing.T) {
	web := t.TempDir()
	plug := filepath.Join(web, "wp-content", "plugins")
	os.MkdirAll(filepath.Join(plug, "marker-link"), 0o755)
	target := filepath.Join(web, "elsewhere.php")
	os.WriteFile(target, []byte("<?php\n/* Plugin Name: Linked\nVersion: 9.9 */\n"), 0o644)
	if err := os.Symlink(target, filepath.Join(plug, "marker-link", "marker-link.php")); err != nil {
		t.Skip(err)
	}
	os.MkdirAll(filepath.Join(plug, "marker-two"), 0o755)
	os.WriteFile(filepath.Join(plug, "marker-two", "b.php"), []byte("<?php\n/* Plugin Name: B\nVersion: 2.0 */\n"), 0o644)
	os.WriteFile(filepath.Join(plug, "marker-two", "a.php"), []byte("<?php\n/* Plugin Name: A\nVersion: 1.0 */\n"), 0o644)
	ps, unread := WordPressPlugins([]string{web})
	if len(ps) != 1 || ps[0].Slug != "marker-two" || ps[0].Version != "1.0" {
		t.Errorf("plugins %+v (want a.php's header, the first by name)", ps)
	}
	if !strings.Contains(strings.Join(unread, "|"), "marker-link (no header read; marker-link.php: a link, not followed)") {
		t.Errorf("unread %v", unread)
	}
	d := t.TempDir()
	for i := 0; i < wpMaxDirEntries; i++ {
		os.WriteFile(filepath.Join(d, fmt.Sprintf("f%05d", i)), nil, 0o644)
	}
	if _, err := readDirMax(hostSource(), d, wpMaxDirEntries); err != nil {
		t.Errorf("exactly %d entries: %v", wpMaxDirEntries, err)
	}
	os.WriteFile(filepath.Join(d, "extra"), nil, 0o644)
	if _, err := readDirMax(hostSource(), d, wpMaxDirEntries); !errors.Is(err, errTooMany) {
		t.Errorf("one more: %v", err)
	}
}
