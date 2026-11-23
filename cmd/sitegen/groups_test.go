package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// fromVersion writes a repository root whose changelogs start at version v,
// so that v is the newest release the site shows.
func fromVersion(t *testing.T, v string) string {
	t.Helper()
	root := t.TempDir()
	for _, f := range []string{"CHANGELOG.md", "CHANGELOG.zh-TW.md"} {
		b, err := os.ReadFile(filepath.Join("../..", f))
		if err != nil {
			t.Fatal(err)
		}
		s := string(b)
		head := "\n## v" + v + " "
		i := strings.Index(s, head)
		if i < 0 {
			t.Fatalf("%s has no v%s", f, v)
		}
		j := strings.Index(s, "\n## v")
		if err := os.WriteFile(filepath.Join(root, f), []byte(s[:j]+s[i:]), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// The bench page's attack detection section reads these.
	for _, f := range []string{"tools/detecteval/baseline.json", "docs/attack-detection-limits.md"} {
		b, err := os.ReadFile(filepath.Join("../..", f))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(filepath.Join(root, f)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, f), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

var grpRe = regexp.MustCompile(`<div class="grp (grp-[a-z]+)"><h4><i aria-hidden="true"></i>[^<]*</h4><ul>(.*?)</ul></div>`)

// newestGroups is the newest release's card on a home page: each heading's
// class and the number of lines under it, in order.
func newestGroups(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	i := strings.Index(s, `<div class="newest"`)
	if i < 0 {
		t.Fatalf("%s has no newest release", path)
	}
	var out []string
	for _, m := range grpRe.FindAllStringSubmatch(s[i:], -1) {
		out = append(out, m[1]+" "+itoa(strings.Count(m[2], "<li>")))
	}
	return out
}

func itoa(n int) string {
	return strings.TrimSpace(strings.Repeat(" ", 0) + string(rune('0'+n/10%10)) + string(rune('0'+n%10)))
}

// The newest release's card groups both languages alike, and the changelog's
// "###" sections (fixes, upgrade notes, known issues) are groups of their own.
func TestNewestGroups(t *testing.T) {
	for _, c := range []struct {
		version string
		want    []string // the sections' groups, in this order, at the card's end
	}{
		{"0.3.1", []string{"grp-known 05"}},
		{"0.4.0", []string{"grp-fixed 04", "grp-upgrade 01", "grp-known 07"}},
	} {
		t.Run(c.version, func(t *testing.T) {
			out := t.TempDir()
			if err := build(fromVersion(t, c.version), "../../docs/site-src", out, "https://example.test/"); err != nil {
				t.Fatal(err)
			}
			en := newestGroups(t, filepath.Join(out, "index.html"))
			zh := newestGroups(t, filepath.Join(out, "zh-TW", "index.html"))
			if strings.Join(en, ",") != strings.Join(zh, ",") {
				t.Errorf("v%s is grouped differently: English %v, zh-TW %v", c.version, en, zh)
			}
			if len(en) < len(c.want) || strings.Join(en[len(en)-len(c.want):], ",") != strings.Join(c.want, ",") {
				t.Errorf("v%s: groups %v, want them to end with %v", c.version, en, c.want)
			}
		})
	}
}

var dataGroupsRe = regexp.MustCompile(`<div class="newest" id="rv-[^"]+" data-groups="(\d+)">`)

// The newest release's card says how many groups it has (data-groups), and
// site.css lays the card out by that number, so it must be the number of
// groups the card holds: one to four in the releases checked here.
func TestNewestDataGroups(t *testing.T) {
	for _, c := range []struct {
		version string
		want    string
	}{
		{"0.5.0", "1"}, {"0.5.1", "2"}, {"0.4.3", "3"}, {"0.4.2", "4"},
	} {
		t.Run(c.version, func(t *testing.T) {
			out := t.TempDir()
			if err := build(fromVersion(t, c.version), "../../docs/site-src", out, "https://example.test/"); err != nil {
				t.Fatal(err)
			}
			for _, page := range []string{"index.html", filepath.Join("zh-TW", "index.html"), "releases.html", filepath.Join("zh-TW", "releases.html")} {
				b, err := os.ReadFile(filepath.Join(out, page))
				if err != nil {
					t.Fatal(err)
				}
				m := dataGroupsRe.FindStringSubmatch(string(b))
				if m == nil {
					t.Fatalf("v%s %s: no data-groups on the newest release's card", c.version, page)
				}
				// the card's own groups: from its start to its closing tag
				card := string(b)[strings.Index(string(b), m[0]):]
				card = card[:strings.Index(card, "\n</div>")]
				if n := len(grpRe.FindAllString(card, -1)); m[1] != c.want || m[1] != strconv.Itoa(n) {
					t.Errorf("v%s %s: data-groups=%s, %d groups on the card, want %s", c.version, page, m[1], n, c.want)
				}
			}
		})
	}
}

// A line naming a CVE is what Shentu sees, though it speaks of memory or
// workers (v0.4.1's nginx HTTP/2 warning was put under "Runs lightly").
func TestCVELineIsReach(t *testing.T) {
	cve := "The host survey warns about nginx serving HTTP/2: CVE-2026-123007, HTTP/2 memory corruption that lets a client crash the workers."
	light := "The patrol keeps its heap under 64 MB."
	g := groups(Release{Items: []string{cve, light}})
	if len(g) != 2 || g[0].Key != "grp.reach" || g[0].Items[0] != cve || g[1].Key != "grp.light" || g[1].Items[0] != light {
		t.Errorf("groups %+v, want the CVE line under grp.reach and the heap line under grp.light", g)
	}
}

// A "###" heading the card does not know is an error, not a silent group.
func TestUnknownSection(t *testing.T) {
	p := filepath.Join(t.TempDir(), "CHANGELOG.md")
	if err := os.WriteFile(p, []byte("## v1.0.0 — 2026-01-01\n\n- a\n\n### Security\n\n- b\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := parseChangelog(p); err == nil || !strings.Contains(err.Error(), "Security") {
		t.Errorf("an unknown section was not reported: %v", err)
	}
}

// The attack detection numbers are read from the baseline and the limits
// document, never typed: the ones the docs quote today.
func TestAttackEval(t *testing.T) {
	e, err := loadAttackEval("../..")
	if err != nil {
		t.Fatal(err)
	}
	got := []any{e.Version, e.Nuclei, e.Commit, e.Signatures, e.Caught, e.Templates, e.Rate, e.Distinct, e.Requests, e.Routes, e.Apps, e.Upper, e.HostCVEs, e.HostAlerted, e.HostL1}
	want := []any{"0.5.6", "10.5.2", "5442582a", 28, 1549, 3822, "40.5%", 363, 1216, 152, 8, "0.8%", 10, 3, 2}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("field %d: got %v, want %v", i, got[i], want[i])
		}
	}
}

// TestAttackEvalAgrees: the limits document's signature count and detected
// templates must be the build's and the baseline's, or the page is not made.
func TestAttackEvalAgrees(t *testing.T) {
	base, err := os.ReadFile("../../tools/detecteval/baseline.json")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := os.ReadFile("../../docs/attack-detection-limits.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ from, to, want string }{
		{"Shentu ships 28 attack signatures", "Shentu ships 27 attack signatures", "attack signatures, the build has 28"},
		{"detected (1549 of 3822)", "detected (1548 of 3822)", "templates detected"},
	} {
		root := t.TempDir()
		for p, b := range map[string][]byte{"tools/detecteval/baseline.json": base, "docs/attack-detection-limits.md": []byte(strings.Replace(string(doc), c.from, c.to, 1))} {
			if err := os.MkdirAll(filepath.Join(root, filepath.Dir(p)), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, p), b, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		if !strings.Contains(string(doc), c.from) {
			t.Fatalf("the document no longer says %q", c.from)
		}
		if _, err := loadAttackEval(root); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%q: %v, want an error saying %q", c.to, err, c.want)
		}
	}
}
