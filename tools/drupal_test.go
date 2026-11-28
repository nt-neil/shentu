package tools

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/nt-neil/shentu/hostenv"
)

func drupalPHP(v string) string {
	return "<?php\nnamespace Drupal;\nclass Drupal {\n  const VERSION = '" + v + "';\n}\n"
}

// v0.5.9 item 1 (a, b): Drupal found under a web root by its core's
// Drupal.php (a Composer layout's web/ too), its version read from the
// file, and the installer advisories' ranges: an affected version is
// critical, a fixed one says nothing, one that is not a release version
// is said as not compared; a link is not followed. Through the host source.
func TestDrupalSites(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privilege on Windows")
	}
	withHost(t, &hostenv.Live{})
	root := t.TempDir()
	put := func(rel, v string) {
		p := filepath.Join(root, rel, "core", "lib", "Drupal.php")
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		os.WriteFile(p, []byte(drupalPHP(v)), 0o644)
	}
	put("site1/web", "10.6.21")
	put("site2", "11.4.14")
	put("site3", "11.x-dev")
	if err := os.Symlink(filepath.Join(root, "site1", "web"), filepath.Join(root, "lnk")); err != nil {
		t.Fatal(err)
	}
	sites, unread := DrupalSites([]string{root})
	got := map[string]string{}
	for _, s := range sites {
		got[strings.TrimPrefix(s.Root, root)] = s.Version
	}
	if len(sites) != 3 || got["/site1/web"] != "10.6.21" || got["/site2"] != "11.4.14" || got["/site3"] != "11.x-dev" {
		t.Errorf("sites %+v", sites)
	}
	if len(unread) != 1 || !strings.Contains(unread[0], "lnk (a link to a Drupal, not followed)") {
		t.Errorf("unread %q", unread)
	}
	risks := drupalRisks(sites, unread)
	var crit, unk, unr []Risk
	for _, r := range risks {
		switch {
		case r.Severity == "critical":
			crit = append(crit, r)
		case strings.HasPrefix(r.Key, uncheckedPrefix+"drupal:"):
			unk = append(unk, r)
		case r.Key == uncheckedPrefix+"drupal":
			unr = append(unr, r)
		}
	}
	if len(crit) != 1 || !strings.Contains(crit[0].Summary, "10.6.21") || !strings.Contains(crit[0].Summary, "SA-CORE-2026-017") || !strings.Contains(crit[0].Summary, "SA-CORE-2026-019") {
		t.Errorf("critical %+v", crit)
	}
	if len(unk) != 1 || !strings.Contains(unk[0].Summary, "11.x-dev") || len(unr) != 1 {
		t.Errorf("not compared %+v, unread %+v", unk, unr)
	}
	if len(risks) != 3 {
		t.Errorf("risks %+v (the fixed 11.4.14 says nothing)", risks)
	}
}

func TestDrupalAffected(t *testing.T) {
	for _, c := range []struct {
		v        string
		a17, a19 bool
	}{
		{"9.5.11", true, true}, {"10.6.21", true, true}, {"10.6.22", false, true}, {"10.6.23", false, false},
		{"11.0.0", true, true}, {"11.3.21", true, true}, {"11.3.22", false, true}, {"11.3.23", false, false},
		{"11.4.0", true, true}, {"11.4.12", true, true}, {"11.4.13", false, true}, {"11.4.14", false, false},
		{"11.5.0", false, false},
	} {
		a17, k17 := drupalAffected(drupalSAs[0], c.v)
		a19, k19 := drupalAffected(drupalSAs[1], c.v)
		if !k17 || !k19 || a17 != c.a17 || a19 != c.a19 {
			t.Errorf("%s: 017 %v 019 %v, want %v %v", c.v, a17, a19, c.a17, c.a19)
		}
	}
	if _, k := drupalAffected(drupalSAs[0], "10.6.21-rc1"); k {
		t.Error("a pre-release compared")
	}
}
