package detect

import (
	"strings"
	"testing"

	"github.com/nt-neil/shentu/detect/sig"
)

// v0.5.9 item 1 e: the embedded signature for Drupal core's installer
// matches a request to /core/install.php or /install.php on a host whose
// installed core (tools.SurfaceDrupal) is in SA-CORE-2026-017/019's ranges;
// a fixed core, and another path (WordPress's /wp-admin/install.php), are not;
// PATH_INFO after it (/core/install.php/foo) still reaches the installer.
func TestDrupalInstallerSignature(t *testing.T) {
	ss, err := sig.Load()
	if err != nil {
		t.Fatal(err)
	}
	const id = "sa-core-2026-017-019-drupal-installer"
	hit := func(version, path string) bool {
		s := Build(nil, nil, InstalledPackage{Source: "/var/www/site", Ecosystem: "Packagist", Package: "drupal/core", Version: version})
		g := NewJudge(s, ss).Judge(NewMatcher(ss).Match(Normalize(AccessRecord{Method: "GET", Path: path, Status: 200})))
		for _, c := range g.Candidates {
			for _, h := range c.Hits {
				if h.Signature == id {
					return true
				}
			}
			if strings.Contains(c.Entry, "drupal/core") && strings.Contains(c.Entry, id) {
				return true
			}
		}
		return false
	}
	for _, c := range []struct {
		v, path string
		want    bool
	}{
		{"10.6.21", "/core/install.php", true},
		{"10.6.22", "/install.php", true}, // 019's range
		{"11.4.13", "/core/install.php", true},
		{"11.4.14", "/core/install.php", false},
		{"11.3.23", "/install.php", false},
		{"10.6.21", "/wp-admin/install.php", false},
		{"10.6.21", "/core/install.php/foo", true}, // PATH_INFO: the installer still runs (what an exact location block leaves)
	} {
		if got := hit(c.v, c.path); got != c.want {
			t.Errorf("%s %s: %v, want %v", c.v, c.path, got, c.want)
		}
	}
}
