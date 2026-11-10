package rules

import (
	"path"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// These tests check the format: every rule parses, is complete, is unique, and
// carries the samples that rules/engine is tested against (engine/samples_test.go).

var (
	langs   = map[string]bool{"php": true, "python": true, "js": true}
	classes = map[string][]string{
		"sqli":             {"CWE-89"},
		"cmdi":             {"CWE-77", "CWE-78", "CWE-88"},
		"path-traversal":   {"CWE-22", "CWE-23", "CWE-36", "CWE-73", "CWE-98"},
		"deserialization":  {"CWE-502"},
		"code-eval":        {"CWE-94", "CWE-95", "CWE-1336"},
		"xss":              {"CWE-79", "CWE-80"},
		"ssrf":             {"CWE-918"},
		"open-redirect":    {"CWE-601"},
		"xxe":              {"CWE-611", "CWE-776"},
		"ldapi":            {"CWE-90"},
		"nosqli":           {"CWE-943"},
		"file-upload":      {"CWE-434"},
		"weak-crypto":      {"CWE-327", "CWE-328", "CWE-916"},
		"hardcoded-secret": {"CWE-798", "CWE-259", "CWE-321"},
	}
	contexts   = map[string]bool{"html": true, "attr": true, "url": true, "js": true}
	severities = map[string]bool{"critical": true, "high": true, "medium": true, "low": true}
	frameworks = map[string]bool{"laravel": true, "wordpress": true, "django": true, "flask": true, "express": true}

	refRe = regexp.MustCompile(`^(CVE-\d{4}-\d{4,}|GHSA(-[23456789cfghjmpqrvwx]{4}){3})$`)
	idRe  = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)+$`)
)

func TestRulesLoad(t *testing.T) {
	rs, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) == 0 {
		t.Fatal("no rules found")
	}
}

func TestRulesValid(t *testing.T) {
	rs, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]string{}
	for _, r := range rs {
		f := r.File
		if prev, dup := seen[r.ID]; dup {
			t.Errorf("%s: id %q already used by %s", f, r.ID, prev)
		}
		seen[r.ID] = f
		for k, v := range map[string]string{"id": r.ID, "lang": r.Lang, "class": r.Class, "cwe": r.CWE,
			"severity": r.Severity, "title": r.Title, "fix": r.Fix} {
			if strings.TrimSpace(v) == "" {
				t.Errorf("%s: %s is empty", f, k)
			}
		}
		for _, s := range r.Sources {
			if strings.TrimSpace(s) == "" {
				t.Errorf("%s: blank entry in sources", f)
			}
		}
		for k, v := range map[string][]string{"sinks": r.Sinks, "refs": r.Refs} {
			if len(v) == 0 {
				t.Errorf("%s: %s is empty", f, k)
			}
			for _, s := range v {
				if strings.TrimSpace(s) == "" {
					t.Errorf("%s: blank entry in %s", f, k)
				}
			}
		}
		if !idRe.MatchString(r.ID) || !strings.HasPrefix(r.ID, r.Lang+"-"+r.Class+"-") {
			t.Errorf("%s: id %q must be <lang>-<class>-<slug> in lowercase", f, r.ID)
		}
		if want := path.Join(r.Lang, r.Class, r.ID+".toml"); f != want {
			t.Errorf("%s: file must be at %s", f, want)
		}
		if !langs[r.Lang] {
			t.Errorf("%s: lang %q not allowed", f, r.Lang)
		}
		cwes, ok := classes[r.Class]
		if !ok {
			t.Errorf("%s: class %q not allowed", f, r.Class)
		} else if !slices.Contains(cwes, r.CWE) {
			t.Errorf("%s: cwe %q does not belong to class %s (allowed %v)", f, r.CWE, r.Class, cwes)
		}
		if !severities[r.Severity] {
			t.Errorf("%s: severity %q not allowed", f, r.Severity)
		}
		if r.Tier != "info" && r.Tier != "alert" {
			t.Errorf("%s: tier %q must be info or alert", f, r.Tier)
		}
		for _, fw := range r.Frameworks {
			if !frameworks[fw] {
				t.Errorf("%s: framework %q not allowed", f, fw)
			}
		}
		refs := map[string]bool{}
		for _, ref := range r.Refs {
			if !refRe.MatchString(ref) {
				t.Errorf("%s: ref %q must be CVE-YYYY-NNNN or GHSA-xxxx-xxxx-xxxx", f, ref)
			}
			if refs[ref] {
				t.Errorf("%s: ref %q listed twice", f, ref)
			}
			refs[ref] = true
		}
		checkText(t, r)
		checkArgs(t, r)
		checkSourceArgs(t, r)
		checkSamples(t, r)
	}
}

// checkText: every text entry is one of the rule's sources or sinks.
func checkText(t *testing.T, r Rule) {
	for _, s := range r.Text {
		if strings.TrimSpace(s) == "" {
			t.Errorf("%s: blank entry in text", r.File)
		} else if !slices.Contains(r.Sources, s) && !slices.Contains(r.Sinks, s) {
			t.Errorf("%s: text %q is not one of the sources or sinks", r.File, s)
		}
	}
}

// checkArgs: each [[args]] entry says something, names only the rule's own sinks,
// and no sink gets two entries; arg 0 (the receiver) needs a method sink.
func checkArgs(t *testing.T, r Rule) {
	covered := map[string]bool{}
	for i, a := range r.Args {
		if a.Arg == nil && len(a.When) == 0 && len(a.Unless) == 0 && !a.Whole && !a.Leading && len(a.Context) == 0 && !a.Literal && a.Key == "" && !a.Keys && len(a.Receiver) == 0 {
			t.Errorf("%s: args %d sets none of arg, when, unless, whole, leading, context, literal, key, keys, receiver", r.File, i)
		}
		if (a.MinLen != 0 || len(a.Exclude) > 0) && !a.Literal {
			t.Errorf("%s: args %d: min_len and exclude need literal", r.File, i)
		}
		if a.MinLen < 0 {
			t.Errorf("%s: args %d: min_len must not be negative", r.File, i)
		}
		if a.Keys && a.Key != "" {
			t.Errorf("%s: args %d: keys and key do not go together", r.File, i)
		}
		for _, c := range a.Context {
			if !contexts[c] {
				t.Errorf("%s: args %d: context %q must be html, attr, url or js", r.File, i, c)
			}
		}
		if a.Literal && a.Arg == nil && !hasOption(a.When) {
			t.Errorf("%s: args %d: literal needs arg or a when option (password=, secret:)", r.File, i)
		}
		if a.Arg != nil && (*a.Arg < 0 || *a.Arg > 10) {
			t.Errorf("%s: args %d: arg %d must be 0 (receiver) to 10", r.File, i, *a.Arg)
		}
		sinks := a.Sinks
		if len(sinks) == 0 {
			sinks = r.Sinks
		}
		for _, s := range sinks {
			if !slices.Contains(r.Sinks, s) {
				t.Errorf("%s: args %d: %q is not one of the sinks", r.File, i, s)
			}
			if covered[s] {
				t.Errorf("%s: args %d: sink %q already has conditions", r.File, i, s)
			}
			covered[s] = true
			if len(a.Receiver) > 0 && !strings.HasPrefix(s, ".") && !strings.HasPrefix(s, "->") {
				t.Errorf("%s: args %d: receiver needs a method sink starting with . or ->, not %q", r.File, i, s)
			}
			if a.Arg != nil && *a.Arg == 0 && !strings.HasPrefix(s, ".") && !strings.HasPrefix(s, "->") {
				t.Errorf("%s: args %d: arg 0 (the receiver) needs a method sink starting with . or ->, not %q", r.File, i, s)
			}
		}
		for _, f := range append(append([]string{}, a.When...), a.Unless...) {
			if strings.TrimSpace(f) == "" {
				t.Errorf("%s: args %d: blank entry in when or unless", r.File, i)
			}
		}
	}
}

// checkSourceArgs: each [[source_args]] entry names call sources of the rule,
// an argument from 1 and at least one value.
func checkSourceArgs(t *testing.T, r Rule) {
	for i, sa := range r.SourceArgs {
		if sa.Arg < 1 || sa.Arg > 10 || len(sa.Values) == 0 || len(sa.Sources) == 0 {
			t.Errorf("%s: source_args %d needs sources, arg 1 to 10 and values", r.File, i)
		}
		for _, s := range sa.Sources {
			if !slices.Contains(r.Sources, s) || !strings.HasSuffix(s, "(") {
				t.Errorf("%s: source_args %d: %q is not one of the call sources", r.File, i, s)
			}
		}
	}
}

// checkSamples needs one vulnerable and one safe sample, and each vulnerable sample
// must actually contain one of the rule's sources and one of its sinks, so a sample
// cannot drift away from the rule it is meant to test.
func checkSamples(t *testing.T, r Rule) {
	n := map[string]int{}
	for i, s := range r.Samples {
		n[s.Kind]++
		if s.Kind != "vulnerable" && s.Kind != "safe" {
			t.Errorf("%s: sample %d kind %q must be vulnerable or safe", r.File, i, s.Kind)
		}
		if strings.TrimSpace(s.Code) == "" {
			t.Errorf("%s: sample %d has no code", r.File, i)
		}
		if s.Kind == "vulnerable" {
			if len(r.Sources) > 0 && !containsAny(s.Code, r.Sources) {
				t.Errorf("%s: vulnerable sample %d uses none of the sources", r.File, i)
			}
			if !containsAny(s.Code, r.Sinks) && !chainedSink(s.Code, r.Sinks) {
				t.Errorf("%s: vulnerable sample %d uses none of the sinks", r.File, i)
			}
		}
	}
	if n["vulnerable"] == 0 || n["safe"] == 0 {
		t.Errorf("%s: needs at least one vulnerable and one safe sample (has %d, %d)", r.File, n["vulnerable"], n["safe"])
	}
}

func hasOption(when []string) bool {
	for _, w := range when {
		if strings.HasSuffix(w, "=") || strings.HasSuffix(w, ":") {
			return true
		}
	}
	return false
}

func containsAny(code string, needles []string) bool {
	for _, n := range needles {
		if i := strings.Index(n, "[*]"); i > 0 {
			n = n[:i] // $_FILES[*]['name']: any index of $_FILES
		}
		if strings.Contains(code, n) {
			return true
		}
	}
	return false
}

// chainedSink: a PHP sink written as a static call (Process::run() also matches
// at the end of a chain from that class (Process::timeout(30)->run()).
func chainedSink(code string, sinks []string) bool {
	for _, s := range sinks {
		cls, method, ok := strings.Cut(strings.TrimSuffix(s, "("), "::")
		if ok && strings.HasSuffix(s, "(") && strings.Contains(code, cls+"::") && strings.Contains(code, "->"+method+"(") {
			return true
		}
	}
	return false
}
