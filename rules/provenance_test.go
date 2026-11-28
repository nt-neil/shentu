package rules

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// provenanceTools: no record (and no rule file) names another analysis tool or
// a model: the rules are designed from the vulnerability and its fix alone.
var provenanceTools = regexp.MustCompile(`(?i)\b(semgrep|opengrep|codeql|snyk|sonar\w*|bandit|psalm|phpstan|nuclei|brakeman|gosec|gpt[\w.-]*|chatgpt|claude|gemini|llms?|copilot|openai|anthropic)\b`)

var (
	provenanceKindLine = regexp.MustCompile(`(?mi)^[ \t]*kind[ \t]*:.*$`) // any spelling, to refuse the wrong ones
	provenanceKind     = regexp.MustCompile(`^Kind: (cve|precision)$`)
	provenanceCase     = regexp.MustCompile("`bench/cves/((?:CVE|GHSA)-[A-Za-z0-9-]+)\\.toml`")
	provenanceID       = regexp.MustCompile(`\b(?:CVE-\d{4}-\d+|GHSA(?:-[A-Za-z0-9]{4}){3})\b`)
	provenanceRule     = regexp.MustCompile(`(?m)^\|[ \t:]*-{3,}`)               // a table's separator row
	provenanceNumbers  = regexp.MustCompile(`(?m)^\|[^\n]*[0-9][^\n]*\|[ \t]*$`) // a table row holding a number
)

// provenanceLegacyMax: provenance-legacy.txt may only shrink.
const provenanceLegacyMax = 127

// section is the body of the "## name" section of a record, and whether it has one.
func section(text, name string) (string, bool) {
	_, after, ok := strings.Cut(text, "\n## "+name+"\n")
	body, _, _ := strings.Cut(after, "\n## ")
	return body, ok
}

// provenanceSet holds what the records are checked against.
type provenanceSet struct {
	refs   map[string][]string // each rule's and route model's refs, by id
	rules  map[string]bool     // the rule ids (route models are not rules)
	cveFor map[string]bool     // ids that have a cve record
	legacy map[string]bool     // rules older than the records: a precision record without a cve record is allowed
	bench  string              // the bench/ folder
}

func (ps provenanceSet) caseIn(c string, sets ...string) bool {
	for _, set := range sets {
		if _, err := os.Stat(filepath.Join(ps.bench, set, c+".toml")); err == nil {
			return true
		}
	}
	return false
}

// recordKind is the record's kind: the one Kind line between its title and its
// first section. No line means cve; a Kind line anywhere else, a second one or
// any other spelling or value is an error, never read as cve.
func recordKind(text string) (string, error) {
	head, _, _ := strings.Cut(text, "\n## ")
	var kind string
	for _, l := range provenanceKindLine.FindAllString(head, -1) {
		m := provenanceKind.FindStringSubmatch(l)
		switch {
		case m == nil:
			return "", fmt.Errorf("%q: the kind line is \"Kind: cve\" or \"Kind: precision\"", l)
		case kind != "":
			return "", fmt.Errorf("more than one Kind line")
		}
		kind = m[1]
	}
	if i := len(head); i < len(text) && provenanceKindLine.MatchString(text[i:]) {
		return "", fmt.Errorf("a Kind line after the first section: it goes between the title and the first section")
	}
	if kind == "" {
		kind = "cve"
	}
	return kind, nil
}

// checkProvenance checks one record (base, its file name; text, its content)
// and returns what is wrong with it.
//
//   - Kind: cve (or no Kind line): the change was designed from a CVE. The file
//     is <rule or route model id>--<short name>.md (an engine change made for a
//     CVE takes the id of the rule or route model that catches it), its Case
//     section names the bench/cves case, that id cites it in refs, and it is
//     not a hold-out case.
//   - Kind: precision: a change made to cut false positives, or to the engine
//     itself, that no CVE was designed from (a citation would be made up). The
//     file is engine--<short name>.md, or <rule or route model id>--<short
//     name>.md for a rule that cites a CVE in refs and already has a cve record
//     (or is in provenance-legacy.txt). A Measured on section names the cases
//     the change was designed and measured on, from bench/cves or
//     bench/cves-ts only, and holds the numbers in a table. A hold-out case may
//     appear only in a Holdout check section, which shows the change did not
//     make it worse: hold-out cases are never a reason for a change.
//
// Neither kind may name another analysis tool or a model.
func checkProvenance(base, text string, ps provenanceSet) []string {
	var bad []string
	if m := provenanceTools.FindString(text); m != "" {
		bad = append(bad, fmt.Sprintf("names another tool or a model (%q)", m))
	}
	kind, err := recordKind(text)
	if err != nil {
		return append(bad, err.Error())
	}
	id, _, ok := strings.Cut(strings.TrimSuffix(base, ".md"), "--")
	if !ok {
		return append(bad, "name is not <id>--<short name>.md")
	}
	cited, known := ps.refs[id]
	switch kind {
	case "cve":
		if !known {
			return append(bad, fmt.Sprintf("no rule or route model %q (engine-- is for precision records only)", id))
		}
		body, ok := section(text, "Case")
		m := provenanceCase.FindStringSubmatch(body)
		if !ok || m == nil {
			return append(bad, "the Case section names no bench/cves case")
		}
		c := m[1]
		if !slices.Contains(cited, c) {
			bad = append(bad, fmt.Sprintf("%s does not cite %s in refs", id, c))
		}
		if !ps.caseIn(c, "cves") {
			bad = append(bad, fmt.Sprintf("%s is not a bench/cves case", c))
		}
		if ps.caseIn(c, "holdout") {
			bad = append(bad, fmt.Sprintf("%s is a hold-out case", c))
		}
	case "precision":
		switch {
		case id == "engine":
		case !known:
			bad = append(bad, fmt.Sprintf("no rule or route model %q (an engine change is engine--<short name>.md)", id))
		case ps.rules[id] && len(cited) == 0:
			bad = append(bad, fmt.Sprintf("%s cites no CVE in refs: a new rule needs a cve record, not a precision one", id))
		case ps.rules[id] && !ps.cveFor[id] && !ps.legacy[id]:
			bad = append(bad, fmt.Sprintf("%s has no cve record: a precision record comes after the rule's cve record", id))
		}
		body, ok := section(text, "Measured on")
		if !ok {
			return append(bad, "a precision record has no Measured on section")
		}
		ids := provenanceID.FindAllString(body, -1)
		if len(ids) == 0 {
			bad = append(bad, "the Measured on section names no bench case")
		}
		for _, c := range ids {
			switch {
			case ps.caseIn(c, "holdout"):
				bad = append(bad, fmt.Sprintf("%s is a hold-out case: it goes in the Holdout check section only", c))
			case !ps.caseIn(c, "cves", "cves-ts"):
				bad = append(bad, fmt.Sprintf("%s is not a bench/cves or bench/cves-ts case", c))
			}
		}
		if !provenanceRule.MatchString(body) || !provenanceNumbers.MatchString(body) {
			bad = append(bad, "the Measured on section has no table of numbers (a |--- row and a row with a number)")
		}
		hold, _ := section(text, "Holdout check")
		for _, c := range provenanceID.FindAllString(hold, -1) {
			if !ps.caseIn(c, "holdout") {
				bad = append(bad, fmt.Sprintf("%s in the Holdout check section is not a hold-out case", c))
			}
		}
		rest := strings.Replace(text, hold, "", 1)
		for _, c := range provenanceID.FindAllString(rest, -1) {
			if ps.caseIn(c, "holdout") && !strings.Contains(body, c) {
				bad = append(bad, fmt.Sprintf("%s is a hold-out case named outside the Holdout check section", c))
			}
		}
	}
	return bad
}

// loadProvenanceSet reads the rules, route models, legacy list and records.
func loadProvenanceSet(t *testing.T, files []string) provenanceSet {
	t.Helper()
	rs, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	ps := provenanceSet{refs: map[string][]string{}, rules: map[string]bool{}, cveFor: map[string]bool{}, legacy: map[string]bool{}, bench: filepath.Join("..", "bench")}
	for _, r := range rs {
		ps.refs[r.ID] = r.Refs
		ps.rules[r.ID] = true
	}
	routes, err := LoadRoutes()
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range routes {
		ps.refs[r.ID] = r.Refs
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if k, err := recordKind(string(b)); err == nil && k == "cve" {
			id, _, _ := strings.Cut(filepath.Base(f), "--")
			ps.cveFor[id] = true
		}
	}
	b, err := os.ReadFile(filepath.Join("testdata", "provenance-legacy.txt"))
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range strings.Split(string(b), "\n") {
		if l = strings.TrimSpace(l); l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		if !ps.rules[l] {
			t.Errorf("provenance-legacy.txt: %s is no rule (take it out)", l)
		}
		if ps.cveFor[l] {
			t.Errorf("provenance-legacy.txt: %s has a cve record now (take it out)", l)
		}
		ps.legacy[l] = true
	}
	if len(ps.legacy) > provenanceLegacyMax {
		t.Errorf("provenance-legacy.txt has %d rules, more than %d: it may only shrink (a new rule needs a cve record)", len(ps.legacy), provenanceLegacyMax)
	}
	return ps
}

// TestProvenance checks the records in docs/rules-provenance/ (checkProvenance),
// and that no rule file names another tool or a model.
func TestProvenance(t *testing.T) {
	var files []string
	all, err := filepath.Glob(filepath.Join("..", "docs", "rules-provenance", "*.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range all {
		if filepath.Base(f) != "README.md" {
			files = append(files, f)
		}
	}
	if len(files) == 0 {
		t.Fatal("no provenance records read")
	}
	ps := loadProvenanceSet(t, files)
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range checkProvenance(filepath.Base(f), string(b), ps) {
			t.Errorf("%s: %s", filepath.Base(f), e)
		}
	}
	// The rule files themselves name no other tool or model either.
	tomls, err := filepath.Glob(filepath.Join("*", "*", "*.toml"))
	if err != nil || len(tomls) == 0 {
		t.Fatalf("no rule files read: %v", err)
	}
	for _, f := range tomls {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if m := provenanceTools.FindString(string(b)); m != "" {
			t.Errorf("%s: names another tool or a model (%q)", f, m)
		}
	}
}

// The two kinds are checked apart, and precision cannot stand in for cve.
func TestCheckProvenanceKinds(t *testing.T) {
	ps := provenanceSet{
		refs: map[string][]string{
			"php-sqli-string-concat": {"CVE-2026-56738"}, // has a cve record
			"php-ssrf-url-readers":   {"CVE-2026-38001"}, // legacy: no record yet
			"php-new-rule":           {},                 // a new rule, no refs
			"php-new-cited":          {"CVE-2026-56738"}, // a new rule citing a case, no cve record
			"elementor-route":        {"CVE-2025-13393"}, // a route model
		},
		rules:  map[string]bool{"php-sqli-string-concat": true, "php-ssrf-url-readers": true, "php-new-rule": true, "php-new-cited": true},
		cveFor: map[string]bool{"php-sqli-string-concat": true},
		legacy: map[string]bool{"php-ssrf-url-readers": true},
		bench:  filepath.Join("..", "bench"),
	}
	table := "\n| set | base | head |\n|---|---|---|\n| cves | 21 | 21 |\n"
	hold := "\n## Holdout check\n- CVE-2017-5954: the same lines on base and head\n"
	pre := "# x\nKind: precision\n\n## Measured on\n"
	for _, c := range []struct {
		name, base, text string
		ok               bool
	}{
		{"cve", "php-sqli-string-concat--x.md", "# x\n\n## Case\n- `bench/cves/CVE-2026-56738.toml`\n", true},
		{"cve, Kind line", "php-sqli-string-concat--x.md", "# x\nKind: cve\n\n## Case\n- `bench/cves/CVE-2026-56738.toml`\n", true},
		{"cve not cited", "php-sqli-string-concat--x.md", "# x\n\n## Case\n- `bench/cves/CVE-2025-67502.toml`\n", false},
		{"cve on a hold-out case", "php-sqli-string-concat--x.md", "# x\n\n## Case\n- `bench/cves/CVE-2017-5954.toml`\n", false},
		{"cve named engine", "engine--x.md", "# x\n\n## Case\n- `bench/cves/CVE-2026-56738.toml`\n", false},
		{"cve on a route model", "elementor-route--x.md", "# x\n\n## Case\n- `bench/cves/CVE-2025-13393.toml`\n", true},
		{"precision on the engine", "engine--not-array.md", pre + "- CVE-2026-56738, CVE-2023-6120\n" + table, true},
		{"precision on a rule with a cve record", "php-sqli-string-concat--fp.md", pre + "- CVE-2026-56738\n" + table, true},
		{"precision on a legacy rule", "php-ssrf-url-readers--fp.md", pre + "- CVE-2026-56738\n" + table, true},
		{"precision on a route model", "elementor-route--fp.md", pre + "- CVE-2026-56738\n" + table, true},
		{"precision with a cves-ts case", "engine--x.md", pre + "- CVE-2022-23340\n" + table, true},
		{"precision with a holdout check", "engine--x.md", pre + "- CVE-2026-56738\n" + table + hold, true},
		{"precision on a new rule without refs", "php-new-rule--x.md", pre + "- CVE-2026-56738\n" + table, false},
		{"precision on a new rule without a cve record", "php-new-cited--x.md", pre + "- CVE-2026-56738\n" + table, false},
		{"precision, no section", "engine--x.md", "# x\nKind: precision\n", false},
		{"precision, no case", "engine--x.md", pre + "- E7 only\n" + table, false},
		{"precision, unknown case", "engine--x.md", pre + "- CVE-1999-0001\n" + table, false},
		{"precision, hold-out case measured on", "engine--x.md", pre + "- CVE-2017-5954\n" + table, false},
		{"precision, hold-out case in the design", "engine--x.md", "# x\nKind: precision\n\n## Design\nfrom CVE-2017-5954's lines\n\n## Measured on\n- CVE-2026-56738\n" + table, false},
		{"precision, holdout check with a cves case", "engine--x.md", pre + "- CVE-2026-56738\n" + table + "\n## Holdout check\n- CVE-2025-67502\n", false},
		{"precision, no table", "engine--x.md", pre + "- CVE-2026-56738\n", false},
		{"precision, a table without numbers", "engine--x.md", pre + "- CVE-2026-56738\n| no numbers here |\n|---|\n| none |\n", false},
		{"precision, numbers without a separator", "engine--x.md", pre + "- CVE-2026-56738\n| cves | 21 |\n", false},
		{"precision names a model", "engine--x.md", "# x\nKind: precision\nWritten with GPT-5.\n\n## Measured on\n- CVE-2026-56738\n" + table, false},
		{"precision, unknown id", "nope--x.md", pre + "- CVE-2026-56738\n" + table, false},
		{"Kind in a later section", "php-new-rule--x.md", "# x\n\n## Probes\n```\nKind: precision\n```\n\n## Measured on\n- CVE-2026-56738\n" + table, false},
		{"two Kind lines", "engine--x.md", "# x\nKind: precision\nKind: cve\n\n## Measured on\n- CVE-2026-56738\n" + table, false},
		{"Kind in capitals", "engine--x.md", "# x\nKind: Precision\n\n## Measured on\n- CVE-2026-56738\n" + table, false},
		{"Kind with a trailing space", "engine--x.md", "# x\nKind: precision \n\n## Measured on\n- CVE-2026-56738\n" + table, false},
		{"unknown kind", "engine--x.md", "# x\nKind: speed\n", false},
	} {
		bad := checkProvenance(c.base, c.text, ps)
		if (len(bad) == 0) != c.ok {
			t.Errorf("%s: problems %v, want ok %v", c.name, bad, c.ok)
		}
	}
}
