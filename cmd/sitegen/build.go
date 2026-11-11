package main

import (
	"bytes"
	"embed"
	"encoding/xml"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/nt-neil/shentu/rules"
)

//go:embed templates/*.html templates/site.css templates/fonts
var tmplFS embed.FS

// Lang is one language of the site: where its pages go and its words.
type Lang struct {
	Code   string // "en", "zh-TW"
	Dir    string // "" or "zh-TW/"
	Root   string // the way back to the site root from its pages
	Other  string // the other language's path from here
	OtherN string // the other language's name
	T      map[string]string
}

// RuleView is a rule as the catalog shows it.
type RuleView struct {
	ID, CWE, Severity, Title, Fix, Class, Lang string
	Vulnerable, Safe                           string // one sample of each kind, secrets masked
	VulnNote, SafeNote                         string
	Frameworks                                 []string
}

// Group is the rules of one language and class.
type Group struct {
	Lang, Class string
	Rules       []RuleView
}

type page struct {
	L        Lang
	Page     string // the page's file name, for the navigation
	Base     string
	Rules    []RuleView
	Groups   []Group
	Langs    []string
	Classes  []string
	Routes   map[string][]string // language → frameworks with route models
	Releases []Release
	Latest   []Release
	Main     *Bench
	Holdout  *Bench
	TS       *Bench
	Count    int
}

var langNames = map[string]string{"php": "PHP", "python": "Python", "js": "JavaScript / TypeScript"}

func build(root, src, out, base string) error {
	rs, err := rules.Load()
	if err != nil {
		return err
	}
	routes, err := rules.LoadRoutes()
	if err != nil {
		return err
	}
	rels, err := parseChangelog(filepath.Join(root, "CHANGELOG.md"))
	if err != nil {
		return err
	}
	if err := fillReleases(rels, src, currentSnapshot(rs, routes)); err != nil {
		return err
	}
	zhPath := filepath.Join(root, "CHANGELOG.zh-TW.md")
	zhRels, err := parseChangelog(zhPath)
	if err != nil {
		return err
	}
	if zhRels, err = translate(rels, zhRels, zhPath); err != nil {
		return err
	}
	p := page{Base: base, Routes: map[string][]string{}, Count: len(rs)}
	for _, r := range rs {
		p.Rules = append(p.Rules, view(r))
	}
	sort.Slice(p.Rules, func(i, j int) bool {
		a, b := p.Rules[i], p.Rules[j]
		if a.Lang != b.Lang {
			return langOrder(a.Lang) < langOrder(b.Lang)
		}
		if a.Class != b.Class {
			return a.Class < b.Class
		}
		return a.ID < b.ID
	})
	seenL, seenC := map[string]bool{}, map[string]bool{}
	for _, r := range p.Rules {
		if n := len(p.Groups); n == 0 || p.Groups[n-1].Lang != r.Lang || p.Groups[n-1].Class != r.Class {
			p.Groups = append(p.Groups, Group{Lang: r.Lang, Class: r.Class})
		}
		g := &p.Groups[len(p.Groups)-1]
		g.Rules = append(g.Rules, r)
		if !seenL[r.Lang] {
			seenL[r.Lang] = true
			p.Langs = append(p.Langs, r.Lang)
		}
		if !seenC[r.Class] {
			seenC[r.Class] = true
			p.Classes = append(p.Classes, r.Class)
		}
	}
	sort.Strings(p.Classes)
	for _, r := range routes {
		if !contains(p.Routes[r.Lang], r.Framework) {
			p.Routes[r.Lang] = append(p.Routes[r.Lang], r.Framework)
		}
	}
	// The bench results shown are those of the newest release that has them.
	for _, r := range rels {
		dir := filepath.Join(src, "bench", r.Version)
		if p.Main, err = loadBench(filepath.Join(dir, "cves.md")); err != nil {
			return err
		}
		if p.Main == nil {
			continue
		}
		if p.Holdout, err = loadBench(filepath.Join(dir, "holdout.md")); err != nil {
			return err
		}
		if p.TS, err = loadBench(filepath.Join(dir, "cves-ts.md")); err != nil {
			return err
		}
		break
	}
	if p.Main == nil {
		return fmt.Errorf("no bench results in %s/bench", src)
	}
	css, err := tmplFS.ReadFile("templates/site.css")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(out, "zh-TW"), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(out, "site.css"), css, 0o644); err != nil {
		return err
	}
	// The display face, a subset of Noto Serif TC (OFL), with its license.
	if err := os.MkdirAll(filepath.Join(out, "fonts"), 0o755); err != nil {
		return err
	}
	for _, f := range []string{"shentu-serif.woff2", "OFL.txt"} {
		b, err := tmplFS.ReadFile("templates/fonts/" + f)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(out, "fonts", f), b, 0o644); err != nil {
			return err
		}
	}
	// Pages served as files: no Jekyll processing on GitHub Pages.
	if err := os.WriteFile(filepath.Join(out, ".nojekyll"), nil, 0o644); err != nil {
		return err
	}
	for _, l := range languages() {
		for _, name := range []string{"index", "rules", "bench", "install", "releases"} {
			t, err := template.New("layout.html").Funcs(funcs(l)).ParseFS(tmplFS, "templates/layout.html", "templates/"+name+".html")
			if err != nil {
				return err
			}
			p.L, p.Page, p.Releases = l, name+".html", rels
			if l.Code == "zh-TW" {
				p.Releases = zhRels
			}
			p.Latest = p.Releases[:min(3, len(p.Releases))]
			var b bytes.Buffer
			if err := t.Execute(&b, p); err != nil {
				return fmt.Errorf("%s%s: %w", l.Dir, name, err)
			}
			if err := os.WriteFile(filepath.Join(out, l.Dir, name+".html"), b.Bytes(), 0o644); err != nil {
				return err
			}
		}
	}
	feed, err := atom(rels, base)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(out, "feed.xml"), feed, 0o644)
}

func writeSnapshot(src, version string) error {
	if !verRe.MatchString(version) {
		return fmt.Errorf("version %q is not X.Y.Z", version)
	}
	rs, err := rules.Load()
	if err != nil {
		return err
	}
	routes, err := rules.LoadRoutes()
	if err != nil {
		return err
	}
	dir := filepath.Join(src, "rules-history")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, version+".txt"), []byte(currentSnapshot(rs, routes).text()), 0o644)
}

func langOrder(l string) int {
	return map[string]int{"php": 0, "python": 1, "js": 2}[l]
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

func view(r rules.Rule) RuleView {
	v := RuleView{ID: r.ID, CWE: r.CWE, Severity: r.Severity, Title: r.Title, Fix: r.Fix, Class: r.Class, Lang: r.Lang, Frameworks: r.Frameworks}
	for _, s := range r.Samples {
		code := mask(strings.Trim(s.Code, "\n"))
		switch {
		case s.Kind == "vulnerable" && v.Vulnerable == "":
			v.Vulnerable, v.VulnNote = code, s.Note
		case s.Kind == "safe" && v.Safe == "":
			v.Safe, v.SafeNote = code, s.Note
		}
	}
	return v
}

var (
	// a rule's test placeholder for a secret, filled in at test time
	secretMark = regexp.MustCompile(`__SECRET__|__[A-Z]+_SECRET__`)
	// a long run of key-like characters in quotes: shown as an obvious fake
	keyLike  = regexp.MustCompile(`(["'])[A-Za-z0-9_\-+/=.]{20,}(["'])`)
	hasDigit = regexp.MustCompile(`[0-9]`)
	hasAlpha = regexp.MustCompile(`[A-Za-z]`)
)

// mask replaces anything in a sample that looks like a credential with a value
// that is obviously not one, so the published site holds no key, real or not.
func mask(code string) string {
	code = secretMark.ReplaceAllString(code, "EXAMPLE-NOT-A-SECRET")
	return keyLike.ReplaceAllStringFunc(code, func(m string) string {
		inner := m[1 : len(m)-1]
		if !hasDigit.MatchString(inner) || !hasAlpha.MatchString(inner) || strings.Contains(inner, "/") && !strings.ContainsAny(inner, "+=") {
			return m // a path, a word or a number, not a key
		}
		return m[:1] + "EXAMPLE-NOT-A-SECRET" + m[len(m)-1:]
	})
}

func funcs(l Lang) template.FuncMap {
	return template.FuncMap{
		"t": func(k string) string {
			if s, ok := l.T[k]; ok {
				return s
			}
			return k
		},
		"langName":  func(s string) string { return langNames[s] },
		"className": func(c string) string { return className(l, c) },
		"item":      item,
		"join":      strings.Join,
		"sub":       func(a, b int) int { return a - b },
		"seq":       func(n int) []int { return make([]int, n) },
		// the character on a severity's seal
		"seal": func(sev string) string {
			return map[string]string{"critical": "極", "high": "高", "medium": "中", "low": "低"}[sev]
		},
		"signed": func(n int) string {
			if n > 0 {
				return fmt.Sprintf("+%d", n)
			}
			return fmt.Sprint(n)
		},
	}
}

var codeRe = regexp.MustCompile("`([^`]+)`")

// item renders a changelog line: text, with `code` in code tags.
func item(s string) template.HTML {
	var b strings.Builder
	last := 0
	for _, m := range codeRe.FindAllStringSubmatchIndex(s, -1) {
		b.WriteString(template.HTMLEscapeString(s[last:m[0]]))
		b.WriteString("<code>" + template.HTMLEscapeString(s[m[2]:m[3]]) + "</code>")
		last = m[1]
	}
	b.WriteString(template.HTMLEscapeString(s[last:]))
	return template.HTML(b.String())
}

// atom is the releases as an Atom feed, the released ones only.
func atom(rels []Release, base string) ([]byte, error) {
	type link struct {
		Href string `xml:"href,attr"`
		Rel  string `xml:"rel,attr,omitempty"`
	}
	type content struct {
		Type string `xml:"type,attr"`
		Body string `xml:",chardata"`
	}
	type entry struct {
		Title   string  `xml:"title"`
		ID      string  `xml:"id"`
		Updated string  `xml:"updated"`
		Link    link    `xml:"link"`
		Content content `xml:"content"`
	}
	type feed struct {
		XMLName xml.Name `xml:"http://www.w3.org/2005/Atom feed"`
		Title   string   `xml:"title"`
		ID      string   `xml:"id"`
		Updated string   `xml:"updated"`
		Links   []link   `xml:"link"`
		Author  struct {
			Name string `xml:"name"`
		} `xml:"author"`
		Entries []entry `xml:"entry"`
	}
	f := feed{Title: "Shentu releases", ID: base + "feed.xml", Links: []link{{Href: base + "feed.xml", Rel: "self"}, {Href: base + "releases.html"}}}
	f.Author.Name = "Shentu"
	for _, r := range rels {
		if r.Date == "" {
			continue
		}
		if f.Updated == "" {
			f.Updated = r.Date + "T00:00:00Z"
		}
		var b strings.Builder
		b.WriteString("<ul>")
		for _, it := range r.Items {
			b.WriteString("<li>" + string(item(it)) + "</li>")
		}
		b.WriteString("</ul>")
		if len(r.Added) > 0 || len(r.Removed) > 0 {
			fmt.Fprintf(&b, "<p>Rules: %d added, %d removed.</p>", len(r.Added), len(r.Removed))
		}
		f.Entries = append(f.Entries, entry{Title: "Shentu v" + r.Version, ID: base + "releases.html#v" + r.Version,
			Updated: r.Date + "T00:00:00Z", Link: link{Href: base + "releases.html#v" + r.Version}, Content: content{Type: "html", Body: b.String()}})
	}
	if f.Updated == "" {
		return nil, fmt.Errorf("CHANGELOG.md has no dated release for the feed")
	}
	out, err := xml.MarshalIndent(f, "", "  ")
	if err != nil {
		return nil, err
	}
	return append([]byte(xml.Header), append(out, '\n')...), nil
}
