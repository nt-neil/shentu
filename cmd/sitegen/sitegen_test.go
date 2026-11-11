package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/nt-neil/shentu/rules"
)

// The catalog lists every rule once, in both languages, and the site builds
// from the repository alone.
func TestSiteListsEveryRule(t *testing.T) {
	out := t.TempDir()
	if err := build("../..", "../../docs/site-src", out, "https://example.test/"); err != nil {
		t.Fatal(err)
	}
	rs, err := rules.Load()
	if err != nil {
		t.Fatal(err)
	}
	id := regexp.MustCompile(`data-rule-id="([^"]+)"`)
	for _, page := range []string{"rules.html", "zh-TW/rules.html"} {
		b, err := os.ReadFile(filepath.Join(out, page))
		if err != nil {
			t.Fatal(err)
		}
		seen := map[string]int{}
		for _, m := range id.FindAllStringSubmatch(string(b), -1) {
			seen[m[1]]++
		}
		if len(seen) != len(rs) {
			t.Errorf("%s lists %d rules, rules/ has %d", page, len(seen), len(rs))
		}
		for _, r := range rs {
			if seen[r.ID] != 1 {
				t.Errorf("%s: %s listed %d times", page, r.ID, seen[r.ID])
			}
		}
	}
	for _, f := range []string{"index.html", "bench.html", "install.html", "releases.html", "zh-TW/index.html", "zh-TW/bench.html", "zh-TW/install.html", "zh-TW/releases.html", "feed.xml", "site.css"} {
		b, err := os.ReadFile(filepath.Join(out, f))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), "__SECRET__") {
			t.Errorf("%s holds a secret placeholder", f)
		}
		if strings.HasSuffix(f, ".html") && strings.Contains(string(b), "http://") || regexp.MustCompile(`<(script|link|img)[^>]+src="https?:`).Match(b) {
			t.Errorf("%s loads an outside resource", f)
		}
	}
}

func TestChangelogAndRuleDiff(t *testing.T) {
	rels, err := parseChangelog("../../CHANGELOG.md")
	if err != nil {
		t.Fatal(err)
	}
	cur := Snapshot{Rules: []string{"a", "b", "c"}, Frameworks: []string{"django"}}
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "rules-history"), 0o755)
	os.WriteFile(filepath.Join(dir, "rules-history", "0.0.1.txt"), []byte("rule a\nrule z\n"), 0o644)
	rs := []Release{{Version: "0.0.2", Rules: -1}, {Version: "0.0.1", Date: "2026-01-01", Rules: -1}}
	if err := fillReleases(rs, dir, cur); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(rs[0].Added, ","); got != "b,c" {
		t.Errorf("added %q, want b,c", got)
	}
	if got := strings.Join(rs[0].Removed, ","); got != "z" {
		t.Errorf("removed %q, want z", got)
	}
	if got := strings.Join(rs[0].Frameworks, ","); got != "django" {
		t.Errorf("frameworks %q, want django", got)
	}
	if len(rels) == 0 || rels[0].Version == "" {
		t.Fatal("no releases in CHANGELOG.md")
	}
}

// Every release has items in both changelogs, under the same version and date.
func TestChangelogTranslated(t *testing.T) {
	en, err := parseChangelog("../../CHANGELOG.md")
	if err != nil {
		t.Fatal(err)
	}
	zh, err := parseChangelog("../../CHANGELOG.zh-TW.md")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := translate(en, zh, "CHANGELOG.zh-TW.md"); err != nil {
		t.Fatal(err)
	}
	for i := range en {
		if strings.Join(en[i].Items, "") == strings.Join(zh[i].Items, "") {
			t.Errorf("v%s: CHANGELOG.zh-TW.md has the English items", en[i].Version)
		}
	}
	if _, err := translate(en, zh[1:], "x"); err == nil {
		t.Error("a missing release was not reported")
	}
	short := append([]Release(nil), zh...)
	short[0].Items = nil
	if _, err := translate(en, short, "x"); err == nil {
		t.Error("a release with no items was not reported")
	}
}

func TestByLang(t *testing.T) {
	got := byLang([]string{"js-a", "php-b", "python-c", "php-d"})
	var parts []string
	for _, g := range got {
		parts = append(parts, g.Lang+":"+strings.Join(g.IDs, ","))
	}
	if s := strings.Join(parts, " "); s != "php:php-b,php-d python:python-c js:js-a" {
		t.Errorf("byLang = %q", s)
	}
}

func TestMask(t *testing.T) {
	for in, want := range map[string]string{
		"$k = '__SECRET__';":                          "$k = 'EXAMPLE-NOT-A-SECRET';",
		`key = "AKIA` + "ABCDEFGH12345678XY" + `"`:    `key = "EXAMPLE-NOT-A-SECRET"`,
		`path = "/var/www/uploads/2024/files/x"`:      `path = "/var/www/uploads/2024/files/x"`,
		`$s = 'SELECT name FROM users WHERE id = 1';`: `$s = 'SELECT name FROM users WHERE id = 1';`,
	} {
		if got := mask(in); got != want {
			t.Errorf("mask(%q) = %q, want %q", in, got, want)
		}
	}
}

// Every word a template asks for is there in both languages.
func TestTemplateKeys(t *testing.T) {
	key := regexp.MustCompile(`\{\{t "([^"]+)"\}\}`)
	files, err := tmplFS.ReadDir("templates")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if f.IsDir() {
			continue
		}
		b, err := tmplFS.ReadFile("templates/" + f.Name())
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range key.FindAllStringSubmatch(string(b), -1) {
			for _, l := range languages() {
				if _, ok := l.T[m[1]]; !ok {
					t.Errorf("%s: key %q missing in %s", f.Name(), m[1], l.Code)
				}
			}
		}
	}
}

// The display font is a subset: every character of the site must be in it, or
// a heading falls back to another face glyph by glyph. Rebuild the subset with
// fontsubset.py when this fails.
func TestFontCoversSite(t *testing.T) {
	out := t.TempDir()
	if err := build("../..", "../../docs/site-src", out, "https://example.test/"); err != nil {
		t.Fatal(err)
	}
	chars, err := os.ReadFile("templates/fonts/chars.txt")
	if err != nil {
		t.Fatal(err)
	}
	have := map[rune]bool{}
	for _, r := range string(chars) {
		have[r] = true
	}
	tag := regexp.MustCompile(`(?s)<script.*?</script>|<[^>]+>`)
	missing := map[rune]bool{}
	for _, f := range []string{"index.html", "rules.html", "bench.html", "install.html", "releases.html"} {
		for _, dir := range []string{"", "zh-TW"} {
			b, err := os.ReadFile(filepath.Join(out, dir, f))
			if err != nil {
				t.Fatal(err)
			}
			for _, r := range tag.ReplaceAllString(string(b), " ") {
				if r >= 0x2E80 && !have[r] {
					missing[r] = true
				}
			}
		}
	}
	if len(missing) > 0 {
		var s []string
		for r := range missing {
			s = append(s, string(r))
		}
		t.Errorf("the display font lacks %d characters the site uses: %s", len(s), strings.Join(s, ""))
	}
}
