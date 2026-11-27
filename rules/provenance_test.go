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
	provenanceKind = regexp.MustCompile(`(?m)^Kind: ([a-z]+)$`)
	provenanceCase = regexp.MustCompile("`bench/cves/((?:CVE|GHSA)-[A-Za-z0-9-]+)\\.toml`")
	provenanceID   = regexp.MustCompile(`\b(?:CVE-\d{4}-\d+|GHSA(?:-[a-z0-9]{4}){3})\b`)
)

// section is the body of the "## name" section of a record, and whether it has one.
func section(text, name string) (string, bool) {
	_, after, ok := strings.Cut(text, "\n## "+name+"\n")
	body, _, _ := strings.Cut(after, "\n## ")
	return body, ok
}

// checkProvenance checks one record (base, its file name; text, its content)
// and returns what is wrong with it. refs holds each rule's and route model's
// refs by id; bench is the bench/ folder.
//
//   - Kind: cve (or no Kind line): the change was designed from a CVE. The file
//     is <rule or route model id>--<short name>.md, its Case section names the
//     bench/cves case, that id cites it in refs, and it is not a hold-out case.
//   - Kind: precision: a change made to cut false positives, or to the engine
//     itself, that no CVE was designed from (a citation would be made up). The
//     file is <rule or route model id>--<short name>.md, or engine--<short
//     name>.md; no refs are asked for, but a Measured on section names the
//     bench cases it was measured on (each in bench/cves, bench/holdout or
//     bench/cves-ts) and holds the numbers, in a table.
//
// Neither kind may name another analysis tool or a model.
func checkProvenance(base, text string, refs map[string][]string, bench string) []string {
	var bad []string
	if m := provenanceTools.FindString(text); m != "" {
		bad = append(bad, fmt.Sprintf("names another tool or a model (%q)", m))
	}
	kind := "cve"
	if m := provenanceKind.FindStringSubmatch(text); m != nil {
		kind = m[1]
	}
	id, _, ok := strings.Cut(strings.TrimSuffix(base, ".md"), "--")
	if !ok {
		return append(bad, "name is not <id>--<short name>.md")
	}
	cited, known := refs[id]
	switch kind {
	case "cve":
		if !known {
			return append(bad, fmt.Sprintf("no rule or route model %q", id))
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
		if _, err := os.Stat(filepath.Join(bench, "cves", c+".toml")); err != nil {
			bad = append(bad, fmt.Sprintf("%s is not a bench/cves case", c))
		}
		if _, err := os.Stat(filepath.Join(bench, "holdout", c+".toml")); err == nil {
			bad = append(bad, fmt.Sprintf("%s is a hold-out case", c))
		}
	case "precision":
		if !known && id != "engine" {
			bad = append(bad, fmt.Sprintf("no rule or route model %q (an engine change is engine--<short name>.md)", id))
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
			found := false
			for _, set := range []string{"cves", "holdout", "cves-ts"} {
				if _, err := os.Stat(filepath.Join(bench, set, c+".toml")); err == nil {
					found = true
				}
			}
			if !found {
				bad = append(bad, fmt.Sprintf("%s is not a bench case", c))
			}
		}
		if !strings.Contains(body, "\n|") {
			bad = append(bad, "the Measured on section has no table of numbers")
		}
	default:
		bad = append(bad, fmt.Sprintf("Kind %q is not cve or precision", kind))
	}
	return bad
}

// TestProvenance checks the records in docs/rules-provenance/ (checkProvenance),
// and that no rule file names another tool or a model.
func TestProvenance(t *testing.T) {
	dir := filepath.Join("..", "docs", "rules-provenance")
	files, err := filepath.Glob(filepath.Join(dir, "*.md"))
	if err != nil {
		t.Fatal(err)
	}
	rs, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	refs := map[string][]string{}
	for _, r := range rs {
		refs[r.ID] = r.Refs
	}
	routes, err := LoadRoutes()
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range routes {
		refs[r.ID] = r.Refs
	}
	n := 0
	for _, f := range files {
		base := filepath.Base(f)
		if base == "README.md" {
			continue
		}
		n++
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range checkProvenance(base, string(b), refs, filepath.Join("..", "bench")) {
			t.Errorf("%s: %s", base, e)
		}
	}
	if n == 0 {
		t.Fatal("no provenance records read")
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

// The two kinds are checked apart: a precision record needs no refs but a
// Measured on section with bench cases and numbers; a cve record needs its case
// cited.
func TestCheckProvenanceKinds(t *testing.T) {
	bench := filepath.Join("..", "bench")
	refs := map[string][]string{"php-sqli-string-concat": {"CVE-2026-56738"}}
	table := "\n| set | base | head |\n|---|---|---|\n| cves | 21 | 21 |\n"
	for _, c := range []struct {
		name, base, text string
		ok               bool
	}{
		{"cve", "php-sqli-string-concat--x.md", "# x\n\n## Case\n- `bench/cves/CVE-2026-56738.toml`\n", true},
		{"cve not cited", "php-sqli-string-concat--x.md", "# x\n\n## Case\n- `bench/cves/CVE-2025-67502.toml`\n", false},
		{"precision", "engine--not-array.md", "# x\nKind: precision\n\n## Measured on\n- CVE-2026-56738, CVE-2023-6120\n" + table, true},
		{"precision on a rule", "php-sqli-string-concat--fp.md", "# x\nKind: precision\n\n## Measured on\n- CVE-2026-56738\n" + table, true},
		{"precision, no section", "engine--x.md", "# x\nKind: precision\n", false},
		{"precision, no case", "engine--x.md", "# x\nKind: precision\n\n## Measured on\n- E7 only\n" + table, false},
		{"precision, unknown case", "engine--x.md", "# x\nKind: precision\n\n## Measured on\n- CVE-1999-0001\n" + table, false},
		{"precision, no numbers", "engine--x.md", "# x\nKind: precision\n\n## Measured on\n- CVE-2026-56738\n", false},
		{"precision names a model", "engine--x.md", "# x\nKind: precision\nWritten with GPT-5.\n\n## Measured on\n- CVE-2026-56738\n" + table, false},
		{"precision, unknown id", "nope--x.md", "# x\nKind: precision\n\n## Measured on\n- CVE-2026-56738\n" + table, false},
		{"unknown kind", "engine--x.md", "# x\nKind: speed\n", false},
	} {
		bad := checkProvenance(c.base, c.text, refs, bench)
		if (len(bad) == 0) != c.ok {
			t.Errorf("%s: problems %v, want ok %v", c.name, bad, c.ok)
		}
	}
}
