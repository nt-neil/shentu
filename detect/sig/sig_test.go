package sig

import (
	"os"
	"strings"
	"testing"
	"testing/fstest"
)

func TestLoadEmbedded(t *testing.T) {
	ss, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(ss) == 0 {
		t.Fatal("no signatures")
	}
	for _, s := range ss { // a Nuclei signature ships with the templates' license
		if s.Source == "nuclei" {
			if b, err := os.ReadFile("NOTICE"); err != nil || !strings.Contains(string(b), "ProjectDiscovery") {
				t.Fatalf("%s is from Nuclei and NOTICE does not carry its license: %v", s.ID, err)
			}
		}
	}
	for _, s := range ss {
		for _, m := range s.Matches {
			if m.Regex != "" && m.Re() == nil {
				t.Errorf("%s: regex not compiled", s.ID)
			}
		}
	}
}

const good = `
[[signature]]
id = "x-one"
title = "t"
class = "sqli"
source = "shentu"
license = "Apache-2.0"
[[signature.match]]
part = "param"
param = "id"
contains = ["UNION"]
`

// Every rule of a valid signature, and a set with one bad signature is
// refused whole.
func TestLoadValidation(t *testing.T) {
	ss, err := LoadFS(fstest.MapFS{"s/a.toml": {Data: []byte(good)}}, "s")
	if err != nil || len(ss) != 1 || ss[0].Matches[0].Contains[0] != "union" {
		t.Fatalf("%v %+v", err, ss)
	}
	bad := map[string]string{
		"id not kebab":             `id = "X_one"`,
		"unknown class":            `class = "magic"`,
		"source not allowed":       `source = "crs"`,
		"sigma not allowed":        `source = "sigma"`,
		"license of shentu":        `license = "MIT"`,
		"nuclei without its id":    "source = \"nuclei\"\nlicense = \"MIT\"",
		"bad regex":                "[[signature.match]]\npart = \"query\"\nregex = \"(\"",
		"bad part":                 "[[signature.match]]\npart = \"cookie\"\ncontains = [\"x\"]",
		"param without part param": "[[signature.match]]\npart = \"query\"\nparam = \"id\"\ncontains = [\"x\"]",
		"empty match":              "[[signature.match]]\npart = \"query\"",
		"bad cve":                  `cves = ["CVE-2024"]`,
		"bad version":              "[[signature.applies_to]]\necosystem = \"npm\"\npackage = \"x\"\nversions = \"~>1\"",
		"route without /":          "[[signature.route]]\npath = \"admin\"",
		"unknown key":              `severity = "high"`,
		"route and any_param":      "[[signature.route]]\npath = \"/x\"\n[[signature.match]]\npart = \"any_param\"\ncontains = [\"x\"]",
	}
	for name, extra := range bad {
		src := good
		key := strings.SplitN(extra, " ", 2)[0]
		if strings.HasPrefix(extra, "[[") {
			src += extra + "\n"
		} else if strings.Contains(good, "\n"+key+" ") {
			lines := strings.Split(src, "\n")
			for i, l := range lines {
				if strings.HasPrefix(l, key+" ") {
					lines[i] = ""
				}
			}
			src = strings.Replace(strings.Join(lines, "\n"), "[[signature]]\n", "[[signature]]\n"+extra+"\n", 1)
		} else {
			src = strings.Replace(src, "[[signature]]\n", "[[signature]]\n"+extra+"\n", 1)
		}
		if _, err := LoadFS(fstest.MapFS{"s/a.toml": {Data: []byte(src)}}, "s"); err == nil {
			t.Errorf("%s: accepted\n%s", name, src)
		}
	}
	dup := good + strings.Replace(good, "[[signature]]", "[[signature]]", 1)
	if _, err := LoadFS(fstest.MapFS{"s/a.toml": {Data: []byte(dup)}}, "s"); err == nil {
		t.Error("a duplicate id was accepted")
	}
	nuclei := strings.Replace(strings.Replace(good, `source = "shentu"`, "source = \"nuclei\"\nnuclei_template = \"CVE-2024-1234\"\nnuclei_version = \"v10.1.0\"", 1), `"Apache-2.0"`, `"MIT"`, 1)
	if _, err := LoadFS(fstest.MapFS{"s/a.toml": {Data: []byte(nuclei)}}, "s"); err != nil {
		t.Errorf("a Nuclei signature with its template: %v", err)
	}
}

// v0.4.1 (n35-b): a signature for a vulnerability has no placeholder to
// anchor a path segment hit, so any_param is refused (with a route it
// already was).
func TestVulnAnyParamRefused(t *testing.T) {
	anyParam := strings.Replace(good, "part = \"param\"\nparam = \"id\"", "part = \"any_param\"", 1)
	if _, err := LoadFS(fstest.MapFS{"s/a.toml": {Data: []byte(anyParam)}}, "s"); err != nil {
		t.Fatalf("a class signature with any_param: %v", err)
	}
	for name, extra := range map[string]string{
		"cves":       `cves = ["CVE-2099-0001"]`,
		"advisories": `advisories = ["GHSA-xxxx-xxxx-xxxx"]`,
		"applies_to": "",
	} {
		src := strings.Replace(anyParam, "[[signature]]\n", "[[signature]]\n"+extra+"\n", 1)
		if name == "applies_to" {
			src += "[[signature.applies_to]]\necosystem = \"npm\"\npackage = \"marker\"\nversions = \"<2.0\"\n"
		}
		if _, err := LoadFS(fstest.MapFS{"s/a.toml": {Data: []byte(src)}}, "s"); err == nil {
			t.Errorf("%s with any_param: accepted\n%s", name, src)
		}
	}
}

func TestInRange(t *testing.T) {
	r := Range{Ecosystem: "npm", Package: "x", Versions: ">=1.2, <1.4.3"}
	for v, want := range map[string]bool{"1.2": true, "1.2.0": true, "1.4.2": true, "1.4.3": false, "1.1.9": false, "v1.3.0": true} {
		if in, ok := InRange(r, v); !ok || in != want {
			t.Errorf("%s: in %v ok %v, want %v", v, in, ok, want)
		}
	}
	if _, ok := InRange(r, "1.4.3-beta"); ok {
		t.Error("a pre-release compared (review 4 of #87: not ordered)")
	}
	if _, ok := InRange(r, "1:2.3-4ubuntu1"); ok {
		t.Error("a Debian epoch compared")
	}
	if in, ok := InRange(Range{Ecosystem: "npm", Package: "x"}, "anything"); !in || !ok {
		t.Error("no versions: every version")
	}
}

func TestKEVIndex(t *testing.T) {
	ss := []Signature{{ID: "b", CVEs: []string{"CVE-2024-1"}}, {ID: "a", CVEs: []string{"CVE-2024-1", "CVE-2024-2"}}, {ID: "c"}}
	idx := KEVIndex(ss)
	if len(idx) != 2 || strings.Join(idx["CVE-2024-1"], ",") != "a,b" || strings.Join(idx["CVE-2024-2"], ",") != "a" {
		t.Errorf("%v", idx)
	}
}
