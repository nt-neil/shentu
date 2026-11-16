package tools

import (
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
	if strings.Join(got, ",") != "hello-marker@2.0-beta,marker-plugin@1.2.3,odd@1.0,sub-marker@0.9" || len(unread) != 0 {
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
