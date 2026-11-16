package sig

import (
	"regexp"
	"strings"
	"testing"
	"testing/fstest"
)

// Review 1 of #87, N-12: Composer's patch releases come after the release,
// build metadata is left out, a branch is not a version.
func TestInRangeComposer(t *testing.T) {
	cases := []struct {
		eco, versions, v string
		in, ok           bool
	}{
		{"Packagist", ">=2.4.3, <2.4.3-p2", "2.4.3-p1", true, true},
		{"Packagist", "<2.4.3", "2.4.3-p1", false, true},
		{"Packagist", "<2.4.4", "2.4.3-p1", true, true},
		{"Packagist", "<=2.4.3-p1", "2.4.3-p2", false, true},
		{"Packagist", "<1.0.1", "1.0-patch2", true, true},
		{"Packagist", ">1.0", "1.0-patch2", true, true},
		{"Packagist", "<2.4.3", "2.4.3-beta1", true, true},
		{"Packagist", "<1.3", "1.2.x-dev", false, false},
		{"Packagist", "<1.3", "dev-main", false, false},
		{"npm", "=1.2.0", "1.2.0+build.5", true, true},
		{"npm", "<1.2.0", "1.2.0+build.5", false, true},
		{"npm", "<1.2.0", "1.2.0-p1", true, true}, // npm's -p1 is a pre-release
	}
	for _, c := range cases {
		in, ok := InRange(Range{Ecosystem: c.eco, Package: "x", Versions: c.versions}, c.v)
		if in != c.in || ok != c.ok {
			t.Errorf("%s %s in %q: in %v ok %v, want %v %v", c.eco, c.v, c.versions, in, ok, c.in, c.ok)
		}
	}
}

// Load refuses what would never compare or never match as written, or
// match everything; path_regex is lowered as the path is.
func TestLoadReview1(t *testing.T) {
	load := func(extra string) ([]Signature, error) {
		return LoadFS(fstest.MapFS{"s/a.toml": {Data: []byte(good + extra + "\n")}}, "s")
	}
	for name, extra := range map[string]string{
		"Debian ecosystem":        "[[signature.applies_to]]\necosystem = \"Debian\"\npackage = \"x\"\nversions = \"<1.0\"",
		"Debian release":          "[[signature.applies_to]]\necosystem = \"Debian:12\"\npackage = \"x\"\nversions = \"<1.0\"",
		"bound not a version":     "[[signature.applies_to]]\necosystem = \"npm\"\npackage = \"x\"\nversions = \">=1.0.0_beta\"",
		"upper case literal":      "[[signature.match]]\npart = \"query\"\nregex = \"marker-X\"",
		"upper case class":        "[[signature.match]]\npart = \"query\"\nregex = \"marker[A-Z]\"",
		"empty match":             "[[signature.match]]\npart = \"query\"\nregex = \"(?:marker)?\"",
		"empty match, assertion":  "[[signature.match]]\npart = \"query\"\nregex = \"\\\\b\"",
		"empty match, path_regex": "[[signature.route]]\npath_regex = \"x*\"",
	} {
		if _, err := load(extra); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for name, extra := range map[string]string{
		"(?i) literal":    "[[signature.match]]\npart = \"query\"\nregex = \"(?i)marker-X\"",
		"both cases":      "[[signature.match]]\npart = \"query\"\nregex = \"marker[A-Za-z]\\\\S+\\\\W\"",
		"a range of npm":  "[[signature.applies_to]]\necosystem = \"npm\"\npackage = \"x\"\nversions = \">=1.0.0-beta.1, <2\"",
		"a patch release": "[[signature.applies_to]]\necosystem = \"Packagist\"\npackage = \"x/y\"\nversions = \"<2.4.3-p2\"",
	} {
		if _, err := load(extra); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	ss, err := load("[[signature.route]]\npath_regex = \"^/Marker/[A-F0-9]+$\"")
	if err != nil {
		t.Fatal(err)
	}
	if re := regexp.MustCompile(ss[0].Routes[0].PathRegex); !re.MatchString("/marker/ab12") {
		t.Errorf("path_regex %s does not match the lower-cased path", re)
	}
}

// Load's error says the build is at fault (review S: P5 must report it).
func TestLoadErrorSaid(t *testing.T) {
	if _, err := Load(); err != nil {
		t.Fatal(err)
	}
	_, err := LoadFS(fstest.MapFS{"s/a.toml": {Data: []byte(good + "[[signature.match]]\npart = \"query\"\nregex = \"x*\"\n")}}, "s")
	if err == nil || !strings.Contains(err.Error(), "s/a.toml") || !strings.Contains(err.Error(), "x-one") {
		t.Errorf("error %v: should name the file and the signature", err)
	}
}

// Review 2 of #87: only ecosystems whose order is compared are taken
// (N-1, N-2); versions is required (S); a negated class is not an upper
// case letter (N-3).
func TestLoadReview2(t *testing.T) {
	load := func(extra string) error {
		_, err := LoadFS(fstest.MapFS{"s/a.toml": {Data: []byte(good + extra + "\n")}}, "s")
		return err
	}
	rng := func(eco, versions string) string {
		return "[[signature.applies_to]]\necosystem = \"" + eco + "\"\npackage = \"x\"\nversions = \"" + versions + "\""
	}
	for _, eco := range []string{"PyPI", "Maven", "RubyGems", "rpm", "Red Hat", "Alpine", "apk", "Debian", "Ubuntu", "Go"} {
		err := load(rng(eco, "<1.0"))
		if err == nil || !strings.Contains(err.Error(), "not supported yet") {
			t.Errorf("%s: %v, want refused as not supported yet", eco, err)
		}
	}
	for _, eco := range []string{"npm", "Packagist", "packagist"} {
		if err := load(rng(eco, "<1.0")); err != nil {
			t.Errorf("%s: %v", eco, err)
		}
	}
	if err := load(rng("npm", "")); err == nil || !strings.Contains(err.Error(), "versions is required") {
		t.Errorf("empty versions: %v", err)
	}
	for _, re := range []string{`marker[^a-z]`, `(?:^|[^a-z0-9_])marker`, `marker\W`, `marker[^A-Z]x`} {
		if err := load("[[signature.match]]\npart = \"query\"\nregex = '" + re + "'"); err != nil {
			t.Errorf("negated class %s: %v", re, err)
		}
	}
}

// Review 3 of #87: a class holding U+10FFFF but not starting at 0 is not a
// negated one (N-3); an ecosystem's case does not matter (S).
func TestLoadReview3(t *testing.T) {
	load := func(extra string) error {
		_, err := LoadFS(fstest.MapFS{"s/a.toml": {Data: []byte(good + extra + "\n")}}, "s")
		return err
	}
	if err := load("[[signature.match]]\npart = \"query\"\nregex = 'marker[\\x{10FFFF}A]'"); err == nil {
		t.Error(`[\x{10FFFF}A] taken for a negated class`)
	}
	for _, eco := range []string{"NPM", "PACKAGIST", "Npm"} {
		if err := load("[[signature.applies_to]]\necosystem = \"" + eco + "\"\npackage = \"x\"\nversions = \"<1.0\""); err != nil {
			t.Errorf("%s: %v", eco, err)
		}
	}
	if in, ok := InRange(Range{Ecosystem: "PACKAGIST", Package: "x", Versions: "<2.4.3"}, "2.4.3-p1"); in || !ok {
		t.Errorf("PACKAGIST 2.4.3-p1 < 2.4.3: in %v ok %v", in, ok)
	}
}
