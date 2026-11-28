package main

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/nt-neil/shentu/rules/engine"
)

// Case is one published vulnerability: a package, the last vulnerable release,
// the first fixed release, and where the fix changed the code. A case file holds
// no code, only these facts.
type Case struct {
	ID         string    `toml:"id"`         // CVE or GHSA id
	Ecosystem  string    `toml:"ecosystem"`  // wordpress-plugin, composer, pypi, npm or github
	Package    string    `toml:"package"`    // plugin slug, owner/repo on GitHub, or registry name
	Vulnerable string    `toml:"vulnerable"` // release (for composer: git tag) that has the flaw
	Fixed      string    `toml:"fixed"`      // first release with the fix
	Class      string    `toml:"class"`      // a rule class, a key of classes
	Lang       string    `toml:"lang"`       // php, python, js or ts
	FixFiles   []FixFile `toml:"fix_files"`
	SourceURL  string    `toml:"source_url"` // CVE.org, NVD, GitHub Advisory or OSV
	Note       string    `toml:"note"`       // one sentence in our own words
	// KnownGap: why the rules cannot catch this case yet (its input is not a
	// source they read, say). Such a case is run and reported on its own, out
	// of the catch and fixed FP rates, so it does not dilute them.
	KnownGap string `toml:"known_gap"`
	// Sinks: the call the fix protects, where it is not in the fix files' changed
	// lines (the engine reports a cross-file flow at the callee's sink, in another
	// file or far from the change). A finding of the class on that very line counts
	// as caught in the "with sink lines" columns only, never in the main verdict.
	// Each [[sinks]] is preceded by a "# basis:" comment saying which upstream fix
	// protects that call and why it is the one; a shared one starts it with
	// "shared helper: ", and only a shared one does.
	Sinks []SinkLine `toml:"sinks"`

	file string
}

// SinkLine is one call the fix protects, by its line in each release.
type SinkLine struct {
	Path       string `toml:"path"`
	Vulnerable int    `toml:"vulnerable"` // its line in the vulnerable release
	Fixed      int    `toml:"fixed"`      // the same call in the fixed release; 0 when the fix removed it
	// Shared: a helper or wrapper other flows reach too, so a finding there may
	// come from another flow; marked in the report and in the basis.
	Shared bool `toml:"shared"`
}

// FixFile is a file the fix commit or changeset changed, with the line ranges
// it changed in each release. Paths are relative to the package root (the
// archive's top-level directory removed).
type FixFile struct {
	Path       string  `toml:"path"`
	Vulnerable [][]int `toml:"vulnerable"` // [first, last] lines changed or removed in the vulnerable release
	Fixed      [][]int `toml:"fixed"`      // [first, last] lines changed or added in the fixed release
}

var (
	ecosystems = map[string]string{"wordpress-plugin": "php", "composer": "php", "pypi": "python", "npm": "js", "github": "ts"}
	classes    = map[string]bool{"sqli": true, "cmdi": true, "code-eval": true, "deserialization": true, "path-traversal": true, "xss": true, "ssrf": true, "open-redirect": true, "xxe": true, "ldapi": true, "nosqli": true, "file-upload": true, "weak-crypto": true, "hardcoded-secret": true, "crlf": true} // ldapi: LDAP injection, nosqli: NoSQL operator injection, file-upload: dangerous file type accepted, weak-crypto: broken algorithm or hash, hardcoded-secret: credential in source, crlf: a line break written into a line-based format
	idRe       = regexp.MustCompile(`^(CVE-\d{4}-\d{4,}|GHSA(-[23456789cfghjmpqrvwx]{4}){3})$`)
	versionRe  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]*$`)
	tagRe      = regexp.MustCompile(`^(@[a-z0-9][a-z0-9._-]*/)?[A-Za-z0-9][A-Za-z0-9._+-]*@[0-9][A-Za-z0-9._+-]*$`) // monorepo tags: name@1.2.3
	packageRe  = map[string]*regexp.Regexp{
		"wordpress-plugin": regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`),
		"composer":         regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*$`),
		"pypi":             regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`),
		"npm":              regexp.MustCompile(`^(@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*$`),
		"github":           regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*$`),
	}
	// sourceHosts are the only places a case may cite.
	sourceHosts = map[string]string{"www.cve.org": "", "cve.org": "", "nvd.nist.gov": "/vuln/detail/", "github.com": "/advisories/", "osv.dev": "/vulnerability/"}
)

// loadCases reads and checks every case file in dir, sorted by id.
func loadCases(dir string) ([]Case, error) {
	names, err := filepath.Glob(filepath.Join(dir, "*.toml"))
	if err != nil {
		return nil, err
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("no case files in %s", dir)
	}
	var out []Case
	for _, name := range names {
		var c Case
		md, err := toml.DecodeFile(name, &c)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		if extra := md.Undecoded(); len(extra) > 0 {
			return nil, fmt.Errorf("%s: unknown keys %v", name, extra)
		}
		c.file = name
		if err := c.check(); err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (c Case) check() error {
	switch {
	case !idRe.MatchString(c.ID):
		return fmt.Errorf("id %q is not a CVE or GHSA id", c.ID)
	case filepath.Base(c.file) != c.ID+".toml":
		return fmt.Errorf("file must be named %s.toml", c.ID)
	case ecosystems[c.Ecosystem] == "":
		return fmt.Errorf("ecosystem %q is not one of wordpress-plugin, composer, pypi, npm, github", c.Ecosystem)
	case ecosystems[c.Ecosystem] != c.Lang:
		return fmt.Errorf("lang %q does not fit ecosystem %s", c.Lang, c.Ecosystem)
	case !packageRe[c.Ecosystem].MatchString(c.Package):
		return fmt.Errorf("package %q is not a valid %s name", c.Package, c.Ecosystem)
	case !versionRe.MatchString(c.Vulnerable) && !(c.Ecosystem == "github" && tagRe.MatchString(c.Vulnerable)) ||
		!versionRe.MatchString(c.Fixed) && !(c.Ecosystem == "github" && tagRe.MatchString(c.Fixed)):
		return fmt.Errorf("vulnerable and fixed must be release versions")
	case c.Vulnerable == c.Fixed:
		return fmt.Errorf("vulnerable and fixed are the same release")
	case !classes[c.Class]:
		return fmt.Errorf("class %q is not a rule class", c.Class)
	case len(c.FixFiles) == 0:
		return fmt.Errorf("fix_files is empty")
	}
	if err := checkSource(c.SourceURL); err != nil {
		return err
	}
	if err := checkNote(c.Note); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, ff := range c.FixFiles {
		p := ff.Path
		if p == "" || path.Clean(p) != p || path.IsAbs(p) || p == ".." || strings.HasPrefix(p, "../") || strings.Contains(p, "\\") {
			return fmt.Errorf("fix file %q must be a clean relative path", p)
		}
		if seen[p] {
			return fmt.Errorf("fix file %s is listed twice", p)
		}
		seen[p] = true
		if l := engine.LangOf(p); l != c.Lang && !(c.Lang == "ts" && l == "tsx") {
			return fmt.Errorf("fix file %s is not a %s file", p, c.Lang)
		}
		if skipped(p) {
			return fmt.Errorf("fix file %s is in a directory the scan skips", p)
		}
		if len(ff.Vulnerable) == 0 || len(ff.Fixed) == 0 {
			return fmt.Errorf("fix file %s needs line ranges for both releases", p)
		}
		for _, r := range append(append([][]int{}, ff.Vulnerable...), ff.Fixed...) {
			if len(r) != 2 || r[0] < 1 || r[1] < r[0] {
				return fmt.Errorf("fix file %s: range %v is not [first, last]", p, r)
			}
		}
	}
	return c.checkSinks()
}

// checkSinks: each sink line is a clean relative path of the case's language
// with a line in the vulnerable release, listed once, and has its basis written
// in a "# basis:" comment right above its [[sinks]] header.
func (c Case) checkSinks() error {
	if len(c.Sinks) == 0 {
		return nil
	}
	seen := map[string]bool{}
	for _, sl := range c.Sinks {
		p := sl.Path
		if p == "" || path.Clean(p) != p || path.IsAbs(p) || p == ".." || strings.HasPrefix(p, "../") || strings.Contains(p, "\\") {
			return fmt.Errorf("sink %q must be a clean relative path", p)
		}
		if l := engine.LangOf(p); l != c.Lang && !(c.Lang == "ts" && l == "tsx") {
			return fmt.Errorf("sink %s is not a %s file", p, c.Lang)
		}
		if sl.Vulnerable < 1 || sl.Fixed < 0 {
			return fmt.Errorf("sink %s: needs its line in the vulnerable release (and 0 or a line in the fixed one)", p)
		}
		k := fmt.Sprintf("%s:%d", p, sl.Vulnerable)
		if seen[k] {
			return fmt.Errorf("sink %s is listed twice", k)
		}
		seen[k] = true
	}
	if len(c.Sinks) > 1 {
		return fmt.Errorf("one sink per case: the call the fix protects")
	}
	if c.file == "" {
		return nil
	}
	b, err := os.ReadFile(c.file)
	if err != nil {
		return err
	}
	lines := strings.Split(string(b), "\n")
	n := 0
	for i, l := range lines {
		if strings.TrimSpace(l) != "[[sinks]]" {
			continue
		}
		n++
		if i == 0 || !strings.HasPrefix(strings.TrimSpace(lines[i-1]), "# basis: ") || len(strings.TrimSpace(lines[i-1])) < len("# basis: ")+20 {
			return fmt.Errorf("[[sinks]] at line %d needs a \"# basis: ...\" comment right above it (the upstream fix and why it protects this call)", i+1)
		}
		if shared := strings.HasPrefix(strings.TrimSpace(lines[i-1]), "# basis: shared helper: "); shared != c.Sinks[n-1].Shared {
			return fmt.Errorf("[[sinks]] at line %d: shared = true and a basis starting \"shared helper: \" go together", i+1)
		}
	}
	if n != len(c.Sinks) {
		return fmt.Errorf("sinks must be written as [[sinks]] tables, one per call")
	}
	return nil
}

func checkSource(s string) error {
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.User != nil {
		return fmt.Errorf("source_url %q must be an https URL", s)
	}
	prefix, ok := sourceHosts[u.Host]
	if !ok || !strings.HasPrefix(u.Path, prefix) {
		return fmt.Errorf("source_url %q must be on CVE.org, NVD, GitHub Advisory or OSV", s)
	}
	return nil
}

// checkNote keeps notes to one plain sentence: no line breaks and none of the
// characters that would let code in.
func checkNote(s string) error {
	switch {
	case strings.TrimSpace(s) == "":
		return fmt.Errorf("note is empty")
	case len([]rune(s)) > 200:
		return fmt.Errorf("note is longer than 200 characters")
	case strings.ContainsAny(s, "\n\r$;{}<>`=") || strings.Contains(s, "->") || strings.Contains(s, "::") || strings.Contains(s, "()"):
		return fmt.Errorf("note must be a plain sentence, not code")
	}
	return nil
}

// checkFixFiles makes sure every fix file exists in both releases and every
// range lies inside it, so a wrong path or a range from another release shows
// up as an error instead of a silent miss.
func checkFixFiles(c Case, vulnDir, fixedDir string) error {
	for _, sl := range c.Sinks {
		for _, side := range []struct {
			name, dir string
			line      int
		}{{"vulnerable", vulnDir, sl.Vulnerable}, {"fixed", fixedDir, sl.Fixed}} {
			if side.line == 0 {
				continue
			}
			n, err := countLines(filepath.Join(side.dir, filepath.FromSlash(sl.Path)))
			if err != nil {
				return fmt.Errorf("sink %s in the %s release: %v", sl.Path, side.name, err)
			}
			if side.line > n {
				return fmt.Errorf("sink %s: %s line %d is past its %d lines", sl.Path, side.name, side.line, n)
			}
		}
	}
	for _, ff := range c.FixFiles {
		for _, side := range []struct {
			name, dir string
			ranges    [][]int
		}{{"vulnerable", vulnDir, ff.Vulnerable}, {"fixed", fixedDir, ff.Fixed}} {
			n, err := countLines(filepath.Join(side.dir, filepath.FromSlash(ff.Path)))
			if err != nil {
				return fmt.Errorf("fix file %s in the %s release: %v", ff.Path, side.name, err)
			}
			for _, r := range side.ranges {
				if r[1] > n {
					return fmt.Errorf("fix file %s: %s range %v is past its %d lines", ff.Path, side.name, r, n)
				}
			}
		}
	}
	return nil
}

func countLines(name string) (int, error) {
	f, err := os.Open(name)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 64*1024), maxScanFile)
	n := 0
	for s.Scan() {
		n++
	}
	return n, s.Err()
}
