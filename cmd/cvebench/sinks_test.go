package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nt-neil/shentu/rules"
	"github.com/nt-neil/shentu/rules/engine"
)

// A case's sink lines count only in the "with sink lines" verdict, only on the
// very line of the call, and only for a rule of the case's class; the main
// verdict does not change.
func TestSinkLines(t *testing.T) {
	rs := []rules.Rule{
		{ID: "php-sqli-a", Lang: "php", Class: "sqli"},
		{ID: "php-cmdi-a", Lang: "php", Class: "cmdi"},
	}
	c := Case{Lang: "php", Class: "sqli",
		FixFiles: []FixFile{{Path: "a.php", Vulnerable: [][]int{{100, 102}}, Fixed: [][]int{{100, 105}}}},
		Sinks:    []SinkLine{{Path: "lib/db.php", Vulnerable: 40, Fixed: 42}}}
	for _, x := range []struct {
		name               string
		vuln, fixed        []engine.Finding
		caught, fp, cs, fs bool
	}{
		{"on the sink line, in another file", []engine.Finding{{RuleID: "php-sqli-a", Path: "lib/db.php", Line: 40}}, nil, false, false, true, false},
		{"on the sink line in both releases", []engine.Finding{{RuleID: "php-sqli-a", Path: "lib/db.php", Line: 40}}, []engine.Finding{{RuleID: "php-sqli-a", Path: "lib/db.php", Line: 42}}, false, false, true, true},
		{"one line off the sink: no window", []engine.Finding{{RuleID: "php-sqli-a", Path: "lib/db.php", Line: 41}}, nil, false, false, false, false},
		{"another line of the sink's file", []engine.Finding{{RuleID: "php-sqli-a", Path: "lib/db.php", Line: 12}}, nil, false, false, false, false},
		{"another class on the sink line", []engine.Finding{{RuleID: "php-cmdi-a", Path: "lib/db.php", Line: 40}}, nil, false, false, false, false},
		{"at the fix: both verdicts", []engine.Finding{{RuleID: "php-sqli-a", Path: "a.php", Line: 101}}, nil, true, false, true, false},
	} {
		r := caseResult{Case: c}
		r.Vuln.Findings, r.FixedScan.Findings = x.vuln, x.fixed
		judge(&r, rs)
		if r.Caught != x.caught || r.FixedFP != x.fp || r.CaughtSink != x.cs || r.FixedFPSink != x.fs {
			t.Errorf("%s: caught %v fixed FP %v, with sink lines %v %v; want %v %v, %v %v", x.name, r.Caught, r.FixedFP, r.CaughtSink, r.FixedFPSink, x.caught, x.fp, x.cs, x.fs)
		}
	}
	md := markdown([]caseResult{{Case: c, CaughtSink: true}}, nil, time.Unix(0, 0), "")
	if !strings.Contains(md, "| all | 1 | 0 | 0.0% |") || !strings.Contains(md, "| 1 (100.0%) | 0 (0.0%) |") {
		t.Errorf("the two verdicts are not side by side:\n%s", md)
	}
}

// Every [[sinks]] needs its basis in a "# basis:" comment right above it.
func TestSinkBasis(t *testing.T) {
	head := "id = \"CVE-2099-0001\"\necosystem = \"wordpress-plugin\"\npackage = \"demo\"\nvulnerable = \"1.0\"\nfixed = \"1.1\"\nclass = \"sqli\"\nlang = \"php\"\n" +
		"source_url = \"https://nvd.nist.gov/vuln/detail/CVE-2099-0001\"\nnote = \"A list id from the request reaches a query in a helper of another file.\"\n\n" +
		"[[fix_files]]\npath = \"a.php\"\nvulnerable = [[10, 10]]\nfixed = [[10, 11]]\n\n"
	sink := "[[sinks]]\npath = \"lib/db.php\"\nvulnerable = 40\nfixed = 42\n"
	for _, x := range []struct {
		name, body string
		ok         bool
	}{
		{"with its basis", head + "# basis: the fix casts the id in a.php:10 before lib/db.php:40 runs it\n" + sink, true},
		{"no comment", head + sink, false},
		{"a comment that is no basis", head + "# the sink\n" + sink, false},
		{"a basis too short to say anything", head + "# basis: see fix\n" + sink, false},
		{"a shared helper says so", head + "# basis: shared helper: the fix casts the id in a.php:10 before lib/db.php:40 runs it\n" + sink + "shared = true\n", true},
		{"a shared helper that does not say so", head + "# basis: the fix casts the id in a.php:10 before lib/db.php:40 runs it\n" + sink + "shared = true\n", false},
		{"the words alone are no marker", head + "# basis: not a shared helper; the fix casts the id in a.php:10 before lib/db.php:40 runs it\n" + sink + "shared = true\n", false},
		{"the marker without shared = true", head + "# basis: shared helper: the fix casts the id in a.php:10 before lib/db.php:40 runs it\n" + sink, false},
		{"two sinks", head + "# basis: the fix casts the id in a.php:10 before lib/db.php:40 runs it\n" + sink + "\n# basis: the same cast also guards the count query at lib/db.php:50\n[[sinks]]\npath = \"lib/db.php\"\nvulnerable = 50\nfixed = 52\n", false},
	} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "CVE-2099-0001.toml"), []byte(x.body), 0o644); err != nil {
			t.Fatal(err)
		}
		_, err := loadCases(dir)
		if (err == nil) != x.ok {
			t.Errorf("%s: err %v, want ok %v", x.name, err, x.ok)
		}
	}
}
