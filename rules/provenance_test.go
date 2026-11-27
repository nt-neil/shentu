package rules

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// TestProvenance checks the records in docs/rules-provenance/: each names an
// existing rule (the file name up to "--") and, in its Case section, the
// bench/cves case the change was designed from. That rule cites the case in
// refs, the case is in bench/cves and not in bench/holdout, and no record names
// another analysis tool or a model (the rules are designed from the
// vulnerability and its fix alone); nor does any rule file.
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
	byID := map[string]Rule{}
	for _, r := range rs {
		byID[r.ID] = r
	}
	caseRe := regexp.MustCompile("`bench/cves/((?:CVE|GHSA)-[A-Za-z0-9-]+)\\.toml`")
	tools := regexp.MustCompile(`(?i)\b(semgrep|opengrep|codeql|snyk|sonar\w*|bandit|psalm|phpstan|nuclei|brakeman|gosec|gpt[\w.-]*|chatgpt|claude|gemini|llms?|copilot|openai|anthropic)\b`)
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
		text := string(b)
		if m := tools.FindString(text); m != "" {
			t.Errorf("%s: names another tool (%q)", base, m)
		}
		id, _, ok := strings.Cut(strings.TrimSuffix(base, ".md"), "--")
		if !ok {
			t.Errorf("%s: name is not <rule id>--<short name>.md", base)
			continue
		}
		r, ok := byID[id]
		if !ok {
			t.Errorf("%s: no rule %q", base, id)
			continue
		}
		_, after, ok := strings.Cut(text, "\n## Case\n")
		section, _, _ := strings.Cut(after, "\n## ")
		m := caseRe.FindStringSubmatch(section)
		if !ok || m == nil {
			t.Errorf("%s: the Case section names no bench/cves case", base)
			continue
		}
		c := m[1]
		if !slices.Contains(r.Refs, c) {
			t.Errorf("%s: %s does not cite %s in refs", base, id, c)
		}
		if _, err := os.Stat(filepath.Join("..", "bench", "cves", c+".toml")); err != nil {
			t.Errorf("%s: %s is not a bench/cves case", base, c)
		}
		if _, err := os.Stat(filepath.Join("..", "bench", "holdout", c+".toml")); err == nil {
			t.Errorf("%s: %s is a hold-out case", base, c)
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
		if m := tools.FindString(string(b)); m != "" {
			t.Errorf("%s: names another tool or a model (%q)", f, m)
		}
	}
}
