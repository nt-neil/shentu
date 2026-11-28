package rules

import (
	"fmt"
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
		"crlf":             {"CWE-93", "CWE-77"},

		"prototype-pollution": {"CWE-1321"},
	}
	contexts   = map[string]bool{"html": true, "attr": true, "url": true, "js": true}
	severities = map[string]bool{"critical": true, "high": true, "medium": true, "low": true}
	frameworks = map[string]bool{"laravel": true, "wordpress": true, "django": true, "flask": true, "express": true, "nestjs": true, "nextjs": true, "symfony": true, "doctrine": true, "koa": true, "fastify": true, "hapi": true}

	refRe = regexp.MustCompile(`^(CVE-\d{4}-\d{4,}|GHSA(-[23456789cfghjmpqrvwx]{4}){3})$`)
	idRe  = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)+$`)
)

// tierProblem is what is wrong with a rule's tier, or "". A reference rule is
// about how a call is made, not about input: it must have no sources.
func tierProblem(r Rule) string {
	switch r.Tier {
	case "info", "alert":
		return ""
	case "reference":
		if len(r.Sources) > 0 {
			return fmt.Sprintf("tier reference is for a rule with no sources (sources = []), not %d", len(r.Sources))
		}
		return ""
	}
	return fmt.Sprintf("tier %q must be info, alert or reference", r.Tier)
}

func TestTierProblem(t *testing.T) {
	for _, c := range []struct {
		tier    string
		sources []string
		bad     bool
	}{
		{"info", nil, false},
		{"info", []string{"$_GET"}, false},
		{"alert", []string{"$_GET"}, false},
		{"reference", nil, false},
		{"reference", []string{}, false},
		{"reference", []string{"$_GET"}, true}, // a reference rule that reads input
		{"warning", nil, true},
	} {
		if got := tierProblem(Rule{Tier: c.tier, Sources: c.sources}); (got != "") != c.bad {
			t.Errorf("tier %q, sources %v: %q, want a problem %v", c.tier, c.sources, got, c.bad)
		}
	}
}

func TestRulesLoad(t *testing.T) {
	rs, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) == 0 {
		t.Fatal("no rules found")
	}
}

var (
	tierRank = map[string]int{"reference": -1, "info": 0, "alert": 1}
	sevRank  = map[string]int{"low": 0, "medium": 1, "high": 2, "critical": 3}
)

// A route model naming its first argument twice (path and hooks), or hooks
// with no register call to apply to, is refused when the models load.
func TestRouteCheck(t *testing.T) {
	for _, r := range []Route{
		{ID: "both", Register: []string{"add_action"}, Path: true, Hooks: []string{"init"}},
		{ID: "no-register", Hooks: []string{"init"}},
		{ID: "blank", Register: []string{"add_action"}, Hooks: []string{" init"}},
	} {
		if r.check() == nil {
			t.Errorf("%s: accepted", r.ID)
		}
	}
	if err := (Route{ID: "ok", Register: []string{"add_action"}, Hooks: []string{"init"}}).check(); err != nil {
		t.Errorf("ok: %v", err)
	}
}

func TestRulesValid(t *testing.T) {
	rs, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	routes, err := LoadRoutes()
	if err != nil {
		t.Fatal(err)
	}
	members := map[string]bool{} // lang/member a route model makes input
	routeIDs := map[string]bool{}
	for _, rt := range routes {
		if rt.Path && len(rt.Hooks) > 0 {
			t.Errorf("%s: route %s has both path and hooks", rt.File, rt.ID)
		}
		routeIDs[rt.ID] = true
		for _, m := range rt.Members {
			members[rt.Lang+"/"+m] = true
		}
	}
	seen := map[string]string{}
	byID := map[string]Rule{}
	for _, r := range rs {
		byID[r.ID] = r
	}
	for _, r := range rs {
		for _, id := range r.YieldsTo {
			o, ok := byID[id]
			switch {
			case !ok:
				t.Errorf("%s: yields_to %q is no rule", r.File, id)
			case id == r.ID:
				t.Errorf("%s: yields_to names the rule itself", r.File)
			case o.Lang != r.Lang || o.CWE != r.CWE:
				t.Errorf("%s: yields_to %q is another language or CWE", r.File, id)
			case tierRank[r.Tier] > tierRank[o.Tier] || sevRank[r.Severity] > sevRank[o.Severity]:
				// the patrol report pushes alert findings only: a line an alert rule
				// leaves to an info one would no longer be pushed
				t.Errorf("%s: yields_to %q, whose tier or severity (%s, %s) is below this rule's (%s, %s)", r.File, id, o.Tier, o.Severity, r.Tier, r.Severity)
			}
		}
	}
	// no cycle: two rules yielding to each other would both leave the sink out
	var reach func(from, to string, depth int) bool
	reach = func(from, to string, depth int) bool {
		if depth > len(rs) {
			return true
		}
		for _, id := range byID[from].YieldsTo {
			if id == to || reach(id, to, depth+1) {
				return true
			}
		}
		return false
	}
	for _, r := range rs {
		if len(r.YieldsTo) > 0 && reach(r.ID, r.ID, 0) {
			t.Errorf("%s: yields_to makes a cycle", r.File)
		}
	}
	for _, r := range rs {
		f := r.File
		for _, m := range r.RouteMembers {
			if !members[r.Lang+"/"+m] {
				t.Errorf("%s: route_members %q is no member a %s route model makes input", f, m, r.Lang)
			}
		}
		for _, id := range r.RoutesNot {
			if !routeIDs[id] {
				t.Errorf("%s: routes_not %q is no route model", f, id)
			}
		}
		for _, n := range r.RouteOnly {
			if m, name, ok := strings.Cut(n, "."); !ok || name == "" || !members[r.Lang+"/"+m] {
				t.Errorf("%s: route_only %q is not member.name of a member a %s route model makes input", f, n, r.Lang)
			}
		}
		for _, n := range r.RouteNot {
			if m, name, ok := strings.Cut(n, "."); !ok || name == "" || !members[r.Lang+"/"+m] && !sourceEndsIn(r.Sources, m) {
				t.Errorf("%s: route_not %q is not member.name of a member a %s route model makes input or one of the rule's sources ends in", f, n, r.Lang)
			}
		}
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
		if msg := tierProblem(r); msg != "" {
			t.Errorf("%s: %s", f, msg)
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
// and a sink with several entries has an arg in each further one; arg 0 (the
// receiver) needs a method sink.
func checkArgs(t *testing.T, r Rule) {
	covered := map[string]bool{}
	for i, a := range r.Args {
		if a.Arg == nil && len(a.When) == 0 && len(a.Unless) == 0 && !a.Whole && !a.Leading && len(a.Context) == 0 && !a.Literal && !a.NotLiteral && !a.FixedExt && a.Key == "" && !a.Keys && len(a.Receiver) == 0 && len(a.NotReceiver) == 0 && len(a.ReceiverFrom) == 0 && !a.IdentPlaceholder && len(a.UnlessAfter) == 0 {
			t.Errorf("%s: args %d sets none of arg, when, unless, whole, leading, context, literal, not_literal, fixed_ext, key, keys, receiver, not_receiver, receiver_from, ident_placeholder, unless_after", r.File, i)
		}
		if a.IdentPlaceholder && (a.Arg != nil || a.Name != "") {
			t.Errorf("%s: args %d: ident_placeholder picks the values itself, with no arg", r.File, i)
		}
		if len(a.ReceiverNames) > 0 && len(a.ReceiverFrom) == 0 || len(a.ReceiverFrom) > 0 && r.Lang != "python" {
			t.Errorf("%s: args %d: receiver_names needs receiver_from, which is for Python", r.File, i)
		}
		if a.UnlessAt != "" && (a.UnlessAt != "start" && a.UnlessAt != "top" || len(a.Unless) == 0) {
			t.Errorf("%s: args %d: unless_at must be start or top, with unless", r.File, i)
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
		if a.NotLiteral && (a.Arg == nil || a.Literal || len(r.Sources) > 0) {
			t.Errorf("%s: args %d: not_literal needs arg, not literal, and a rule with no sources", r.File, i)
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
			if covered[s] && a.Arg == nil {
				t.Errorf("%s: args %d: sink %q has another block; each further block must name its arg", r.File, i, s)
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

// checkSourceArgs: each [[source_args]] entry names call or index sources of
// the rule (an index source, ending with "[", takes arg 1), an argument from 1
// and at least one value.
func checkSourceArgs(t *testing.T, r Rule) {
	for i, sa := range r.SourceArgs {
		if sa.Arg < 1 || sa.Arg > 10 || len(sa.Values) == 0 || len(sa.Sources) == 0 {
			t.Errorf("%s: source_args %d needs sources, arg 1 to 10 and values", r.File, i)
		}
		for _, s := range sa.Sources {
			if !slices.Contains(r.Sources, s) || !strings.HasSuffix(s, "(") && !(strings.HasSuffix(s, "[") && sa.Arg == 1) {
				t.Errorf("%s: source_args %d: %q is not one of the call or index sources (an index source takes arg 1)", r.File, i, s)
			}
		}
	}
}

// checkSamples needs one vulnerable and one safe sample, and each vulnerable sample
// must actually contain one of the rule's sources and one of its sinks, so a sample
// cannot drift away from the rule it is meant to test. A JavaScript sink may be
// spelled another way the engine reads as the same call (fs.promises.readFile,
// a destructured alias): then its function name must appear as a word.
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
		if s.Dialect != "" && (r.Lang != "js" || s.Dialect != "ts" && s.Dialect != "tsx") {
			t.Errorf("%s: sample %d dialect %q: only js rules have the dialects ts and tsx", r.File, i, s.Dialect)
		}
		if s.Kind == "vulnerable" {
			if len(r.Sources) > 0 && !containsAny(s.Code, r.Sources) {
				t.Errorf("%s: vulnerable sample %d uses none of the sources", r.File, i)
			}
			if !containsAny(s.Code, r.Sinks) && !(r.Lang == "js" && containsSinkName(s.Code, r.Sinks)) && !chainedSink(s.Code, r.Sinks) {
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
		if pre, post, ok := strings.Cut(n, "(*)"); ok { // httpx.Client(*).get(: any arguments
			if regexp.MustCompile(regexp.QuoteMeta(pre) + `\([^()]*(\([^()]*\)[^()]*)*\)` + regexp.QuoteMeta(post)).MatchString(code) {
				return true
			}
			continue
		}
		if pre, ok := strings.CutSuffix(n, "->*"); ok { // $request->*: a member read as a value ($request->sort)
			if regexp.MustCompile(regexp.QuoteMeta(pre) + `->[A-Za-z_]\w*\b(?:\s*[^\s(\[\-?]|\s*$)`).MatchString(code) {
				return true
			}
			continue
		}
		if strings.Contains(code, strings.TrimPrefix(n, "^")) {
			return true
		}
	}
	return false
}

var wordRe = regexp.MustCompile(`[A-Za-z_$][A-Za-z0-9_$]*`)

// containsSinkName reports whether the last name of one of the sinks occurs in
// code as a whole word.
func containsSinkName(code string, sinks []string) bool {
	words := map[string]bool{}
	for _, w := range wordRe.FindAllString(code, -1) {
		words[w] = true
	}
	for _, s := range sinks {
		if ns := wordRe.FindAllString(s, -1); len(ns) > 0 && words[ns[len(ns)-1]] {
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

// sourceEndsIn reports whether one of sources ends in the member m (route_not
// leaves its names out of those too): req.headers, ctx.request.header[, @Headers(.
func sourceEndsIn(sources []string, m string) bool {
	for _, s := range sources {
		s = strings.TrimRight(s, "[(")
		if i := strings.LastIndexAny(s, ".@^"); strings.EqualFold(s[i+1:], m) {
			return true
		}
	}
	return false
}

// A rule whose sinks leave input after ORDER BY to php-sqli-orderby-identifier
// (unless_after) must not read input that rule does not: otherwise that input
// in an ORDER BY would be reported by neither.
// orderBySafe: sanitizers after which a value is safe as an ORDER BY
// identifier, so php-sqli-orderby-identifier may clean with them where a rule
// handing it ORDER BY does not (that rule reads them elsewhere in the query
// too, where an allowlist of its own values may not apply). Adding to this
// list needs a reason here.
var orderBySafe = map[string]bool{
	"in_array":             true, // checked against a list (the documented fix for ORDER BY)
	"Rule::in":             true, // Laravel's validation against a list
	"sanitize_sql_orderby": true, // WordPress: an ORDER BY clause of names and ASC/DESC only
	"absint":               true, // integers
	"intval":               true,
	"(int)":                true,
	"count(":               true,
	"sizeof(":              true,
}

func TestUnlessAfterOwnerReads(t *testing.T) {
	rs, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	var owner *Rule
	for i := range rs {
		if rs[i].ID == "php-sqli-orderby-identifier" {
			owner = &rs[i]
		}
	}
	if owner == nil {
		t.Fatal("php-sqli-orderby-identifier not found")
	}
	n := 0
	for _, r := range rs {
		hands := false
		for _, a := range r.Args {
			hands = hands || slices.ContainsFunc(a.UnlessAfter, func(s string) bool { return strings.EqualFold(s, "ORDER BY") })
		}
		if !hands || r.Lang != owner.Lang {
			continue
		}
		n++
		for _, s := range r.Sources {
			if !slices.Contains(owner.Sources, s) && !slices.Contains(owner.Sources, s+"(") { // get_query_var is read as get_query_var(
				t.Errorf("%s hands ORDER BY to %s, which does not read its source %q", r.ID, owner.ID, s)
			}
		}
		// what the owner cleans the handing rule cleans too, but for the
		// values an ORDER BY identifier is safe as: an integer, or one checked
		// against a list (a quote escape such as esc_sql is not one)
		for _, s := range owner.Sanitizers {
			if !slices.Contains(r.Sanitizers, s) && !slices.Contains(r.Sanitizers, s+"(") && !orderBySafe[s] {
				t.Errorf("%s hands ORDER BY to %s, which cleans with %q and it does not", r.ID, owner.ID, s)
			}
		}
		// and the owner takes a route handler's input wherever it does
		if owner.RouteInput != nil && !*owner.RouteInput && (r.RouteInput == nil || *r.RouteInput) {
			t.Errorf("%s hands ORDER BY to %s, which takes no route input", r.ID, owner.ID)
		}
		for _, id := range owner.RoutesNot {
			if !slices.Contains(r.RoutesNot, id) {
				t.Errorf("%s hands ORDER BY to %s, which leaves out route model %s", r.ID, owner.ID, id)
			}
		}
		for _, x := range owner.RouteNot {
			if !slices.Contains(r.RouteNot, x) {
				t.Errorf("%s hands ORDER BY to %s, which leaves out the route's %s", r.ID, owner.ID, x)
			}
		}
		if owner.RouteMembers != nil {
			for _, m := range r.RouteMembers {
				if !slices.Contains(owner.RouteMembers, m) {
					t.Errorf("%s hands ORDER BY to %s, which leaves out the route's %s", r.ID, owner.ID, m)
				}
			}
			if r.RouteMembers == nil {
				t.Errorf("%s hands ORDER BY to %s, which takes only some route members", r.ID, owner.ID)
			}
		}
	}
	if n == 0 {
		t.Error("no rule hands ORDER BY to php-sqli-orderby-identifier")
	}
}

// TestNestRequestAlias: NestJS's @Request() is @Req() by another name (the
// TypeScript lowering reads both as the handler's request), so a rule that
// takes one as a source takes the other, in sources and in source_args.
func TestNestRequestAlias(t *testing.T) {
	rs, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, r := range rs {
		lists := [][]string{r.Sources}
		for _, sa := range r.SourceArgs {
			lists = append(lists, sa.Sources)
		}
		for _, l := range lists {
			if req, request := slices.Contains(l, "@Req("), slices.Contains(l, "@Request("); req != request {
				t.Errorf("%s: lists only one of @Req( and @Request(", r.File)
			} else if req {
				n++
			}
		}
	}
	if n == 0 {
		t.Error("no rule takes NestJS's @Req() as a source")
	}
}
