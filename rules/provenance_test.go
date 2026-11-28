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
	provenanceKindLate = regexp.MustCompile(`(?mi)^[ \t]*kind[ \t]*:[ \t]*(cve|precision)[ \t]*$`) // a kind line out of place (not a YAML kind: Deployment)
	provenanceKindLine = regexp.MustCompile(`(?mi)^[ \t]*kind[ \t]*:.*$`)                          // any spelling, to refuse the wrong ones
	provenanceKind     = regexp.MustCompile(`^Kind: (cve|precision)$`)
	provenanceCase     = regexp.MustCompile("`bench/cves/((?:CVE|GHSA)-[A-Za-z0-9-]+)\\.toml`")
	provenanceID       = regexp.MustCompile(`\b(?:CVE-\d{4}-\d+|GHSA(?:-[A-Za-z0-9]{4}){3})\b`)
	provenanceRule     = regexp.MustCompile(`(?m)^\|[ \t:]*-{3,}`)               // a table's separator row
	provenanceNumbers  = regexp.MustCompile(`(?m)^\|[^\n]*[0-9][^\n]*\|[ \t]*$`) // a table row holding a number
)

// provenanceLegacyFrozen is provenance-legacy.txt as it was first written (the
// rules and route models older than the records): the file may only shrink, so
// it must stay a subset of this list. Never add to it.
var provenanceLegacyFrozen = []string{
	"django-urls",
	"elementor-widget-settings",
	"elementor-widget-settings-raw",
	"express-handler",
	"fastapi-route",
	"flask-route",
	"js-cmdi-exec",
	"js-cmdi-promisified-exec",
	"js-cmdi-spawn-sh-c",
	"js-cmdi-spawn-shell",
	"js-code-eval-eval",
	"js-code-eval-template-options",
	"js-deserialization-node-serialize",
	"js-deserialization-yaml-load",
	"js-file-upload-client-name",
	"js-hardcoded-secret-credentials",
	"js-ldapi-filter",
	"js-nosqli-mongo-query",
	"js-open-redirect-framework",
	"js-open-redirect-host-header",
	"js-open-redirect-location-header",
	"js-open-redirect-next",
	"js-open-redirect-redirect",
	"js-path-traversal-archive-extract",
	"js-path-traversal-exists-probe",
	"js-path-traversal-fs-ops",
	"js-path-traversal-send-file",
	"js-sqli-node-http-query",
	"js-sqli-object-input",
	"js-sqli-raw-interpolation",
	"js-sqli-sequelize-literal",
	"js-ssrf-host-header",
	"js-ssrf-http-request",
	"js-weak-crypto-cipher",
	"js-weak-crypto-password-hash",
	"js-xss-dom",
	"js-xss-response",
	"js-xss-response-url",
	"js-xxe-libxmljs-noent",
	"laravel-route-closure",
	"php-cmdi-mail-params",
	"php-cmdi-process-shell-commandline",
	"php-cmdi-shell-exec",
	"php-code-eval-dynamic-callback",
	"php-code-eval-eval",
	"php-code-eval-smarty-string",
	"php-code-eval-template-string",
	"php-deserialization-phar-wrapper",
	"php-deserialization-wp-maybe-unserialize",
	"php-file-upload-client-name",
	"php-file-upload-wp-upload-bits",
	"php-hardcoded-secret-credentials",
	"php-hardcoded-secret-crypto-key",
	"php-ldapi-filter",
	"php-nosqli-mongo-query",
	"php-open-redirect-redirect",
	"php-path-traversal-file-include",
	"php-path-traversal-file-read",
	"php-path-traversal-file-write",
	"php-path-traversal-joomla-file",
	"php-path-traversal-laravel-storage",
	"php-path-traversal-symfony-file-response",
	"php-path-traversal-wp-filesystem",
	"php-path-traversal-wp-template-loader",
	"php-sqli-codeigniter-query",
	"php-sqli-doctrine-query-text",
	"php-sqli-drupal-db-query",
	"php-sqli-joomla-query",
	"php-sqli-laravel-raw",
	"php-sqli-orderby-identifier",
	"php-sqli-prepare-identifier",
	"php-sqli-prepare-query-text",
	"php-sqli-wpdb-unprepared",
	"php-sqli-yii-query",
	"php-ssrf-http-client",
	"php-ssrf-http-request",
	"php-ssrf-socket-connect",
	"php-ssrf-url-readers",
	"php-weak-crypto-cipher",
	"php-weak-crypto-password-hash",
	"php-xss-drupal-markup-create",
	"php-xss-echo-attribute",
	"php-xss-echo-html",
	"php-xss-echo-script",
	"php-xss-echo-url",
	"php-xss-shortcode-attribute",
	"php-xss-shortcode-script",
	"php-xxe-libxml-dtdload",
	"php-xxe-libxml-noent",
	"python-cmdi-argument-injection",
	"python-cmdi-argv-from-input",
	"python-cmdi-shell",
	"python-cmdi-shell-built",
	"python-code-eval-dynamic-import",
	"python-code-eval-eval",
	"python-code-eval-jinja-unsandboxed",
	"python-code-eval-numexpr",
	"python-code-eval-template-injection",
	"python-deserialization-downloaded-pickle",
	"python-deserialization-pickle",
	"python-deserialization-torch-load",
	"python-deserialization-yaml-load",
	"python-file-upload-client-name",
	"python-hardcoded-secret-credentials",
	"python-ldapi-filter",
	"python-nosqli-mongo-query",
	"python-path-traversal-archive-extract",
	"python-path-traversal-image-open",
	"python-path-traversal-send-file",
	"python-path-traversal-upload-filename",
	"python-sqli-dbapi-format",
	"python-sqli-django-kwargs-alias",
	"python-sqli-orm-raw-query",
	"python-sqli-pandas-read-sql",
	"python-sqli-sqlalchemy-text",
	"python-ssrf-async-client",
	"python-ssrf-http-request",
	"python-weak-crypto-cipher",
	"python-weak-crypto-md5-hash",
	"python-weak-crypto-password-hash",
	"python-xss-aiohttp-text-attr",
	"python-xss-aiohttp-text-html",
	"python-xss-format-html-preformatted",
	"python-xss-mark-safe",
	"python-xss-response",
	"python-xss-starlette-attr",
	"python-xss-starlette-html",
	"python-xss-starlette-js",
	"python-xss-starlette-url",
	"python-xss-tornado-write-attr",
	"python-xss-tornado-write-html",
	"python-xss-tornado-write-js",
	"python-xss-tornado-write-url",
	"python-xxe-parser-entities",
	"wp-attachment-local-path",
	"wp-rest-permission",
	"wp-rest-route",
	"wp-shortcode",
	"wp-stored-lookups",
}

// section is the body of the "## name" section of a record, and whether it has one.
func section(text, name string) (string, bool) {
	_, after, ok := strings.Cut(text, "\n## "+name+"\n")
	body, _, _ := strings.Cut(after, "\n## ")
	return body, ok
}

// provenanceSet holds what the records are checked against.
type provenanceSet struct {
	refs   map[string][]string // each rule's and route model's refs, by id
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
	if i := len(head); i < len(text) && provenanceKindLate.MatchString(text[i:]) {
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
//     name>.md for a rule or route model that has refs and already has a cve
//     record (or is in provenance-legacy.txt). A Measured on section names the cases
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
		case len(cited) == 0:
			bad = append(bad, fmt.Sprintf("%s has no refs: a new rule or route model needs a cve record, not a precision one", id))
		case !ps.cveFor[id] && !ps.legacy[id]:
			bad = append(bad, fmt.Sprintf("%s has no cve record: a precision record comes after its cve record", id))
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

// checkLegacy checks the legacy list's entries: each is in frozen (the list may
// only shrink, so swapping one id for another is caught too), names a rule or
// route model that still exists, and one that has no cve record yet.
func checkLegacy(entries, frozen []string, refs map[string][]string, cveFor map[string]bool) []string {
	var bad []string
	for _, l := range entries {
		_, exists := refs[l]
		switch {
		case !slices.Contains(frozen, l):
			bad = append(bad, fmt.Sprintf("%s was not in the list first written: it may only shrink (a new rule or route model needs a cve record)", l))
		case !exists:
			bad = append(bad, fmt.Sprintf("%s is no rule or route model (take it out)", l))
		case cveFor[l]:
			bad = append(bad, fmt.Sprintf("%s has a cve record now (take it out)", l))
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
	ps := provenanceSet{refs: map[string][]string{}, cveFor: map[string]bool{}, legacy: map[string]bool{}, bench: filepath.Join("..", "bench")}
	for _, r := range rs {
		ps.refs[r.ID] = r.Refs
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
	var entries []string
	for _, l := range strings.Split(string(b), "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			entries = append(entries, l)
		}
	}
	for _, e := range checkLegacy(entries, provenanceLegacyFrozen, ps.refs, ps.cveFor) {
		t.Errorf("provenance-legacy.txt: %s", e)
	}
	for _, l := range entries {
		ps.legacy[l] = true
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
			"php-sqli-string-concat": {"CVE-2026-56738"},                                                     // has a cve record
			"php-ssrf-url-readers":   {"CVE-2026-38001"},                                                     // legacy: no record yet
			"php-new-rule":           {},                                                                     // a new rule, no refs
			"php-new-cited":          {"CVE-2026-56738"},                                                     // a new rule citing a case, no cve record
			"elementor-route":        {"CVE-2025-13393"},                                                     // a route model, no cve record
			"elementor-cited":        {"CVE-2025-13393"},                                                     // a route model with a cve record
			"wp-shortcode":           {"https://developer.wordpress.org/reference/functions/add_shortcode/"}, // a legacy route model
			"route-norefs":           {},                                                                     // a route model without refs
		},
		cveFor: map[string]bool{"php-sqli-string-concat": true, "elementor-cited": true},
		legacy: map[string]bool{"php-ssrf-url-readers": true, "wp-shortcode": true},
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
		{"precision on a route model without a cve record", "elementor-route--fp.md", pre + "- CVE-2026-56738\n" + table, false},
		{"precision on a legacy route model", "wp-shortcode--fp.md", pre + "- CVE-2026-56738\n" + table, true},
		{"precision on a route model with a cve record", "elementor-cited--fp.md", pre + "- CVE-2026-56738\n" + table, true},
		{"precision on a route model without refs", "route-norefs--fp.md", pre + "- CVE-2026-56738\n" + table, false},
		{"a YAML kind in a code block", "engine--x.md", pre + "- CVE-2026-56738\n" + table + "\n## Probes\n```yaml\nkind: Deployment\n```\n", true},
		{"kind: precision in a later section, lower case", "engine--x.md", pre + "- CVE-2026-56738\n" + table + "\n## Probes\nkind: precision\n", false},
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

// The legacy list may only shrink: an id swapped in for one taken out is caught.
func TestCheckLegacy(t *testing.T) {
	frozen := []string{"a-rule", "b-rule", "c-route"}
	refs := map[string][]string{"a-rule": {"CVE-1"}, "b-rule": {"CVE-2"}, "c-route": {"https://x"}, "d-rule": {"CVE-4"}}
	if bad := checkLegacy([]string{"a-rule", "c-route"}, frozen, refs, nil); len(bad) != 0 {
		t.Errorf("a subset: %v", bad)
	}
	if bad := checkLegacy([]string{"a-rule", "d-rule"}, frozen, refs, nil); len(bad) != 1 {
		t.Errorf("b-rule swapped for d-rule: %v, want one problem", bad)
	}
	if bad := checkLegacy([]string{"a-rule"}, frozen, refs, map[string]bool{"a-rule": true}); len(bad) != 1 {
		t.Errorf("a-rule has a cve record now: %v, want one problem", bad)
	}
	if bad := checkLegacy([]string{"b-rule"}, frozen, map[string][]string{"a-rule": {"CVE-1"}}, nil); len(bad) != 1 {
		t.Errorf("b-rule no longer exists: %v, want one problem", bad)
	}
}
