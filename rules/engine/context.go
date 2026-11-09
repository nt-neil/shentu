package engine

import "strings"

// literalArg reports whether the argument a literal condition names is a
// non-empty string written in the code: the arg-th argument, or the value of a
// when option (password=, secret:).
func (a *analysis) literalArg(st state, cond *argCond, region []Token, open int) bool {
	var isLit func(v []Token, depth int) bool
	isLit = func(v []Token, depth int) bool {
		if len(v) == 1 && v[0].Kind == Str && len(v[0].Parts) == 0 && v[0].Flags&(FlagShell|FlagRegex) == 0 && v[0].Text != "" {
			return true
		}
		// a name holding such a string: assigned in this function, a module-level
		// constant (SECRET_KEY = "..."), or a PHP constant defined in this file;
		// followed a few names deep, so A = B; B = A cannot loop
		if depth >= 4 || len(v) != 1 || v[0].Kind != Ident && v[0].Kind != Var {
			return false
		}
		name := v[0].Text
		if lv := a.litOf(st, name); lv != nil {
			return len(lv) == 1 && isLit(lv, depth+1)
		}
		if constName(name) {
			if lv := a.lits[name]; len(lv) == 1 {
				return isLit(lv, depth+1)
			}
			if d, ok := a.defs[name]; ok {
				return d != ""
			}
		}
		return false
	}
	if cond.arg != nil {
		if open < 0 {
			return false
		}
		args := splitTop(region, isComma)
		n := *cond.arg
		return n >= 1 && n <= len(args) && isLit(stripParens(args[n-1]), 0)
	}
	for _, p := range cond.when {
		for i := range region {
			if p.at(region, i, false) {
				if v := optionValue(p, region, i); v != nil && isLit(v, 0) {
					return true
				}
			}
		}
	}
	return false
}

// noSources: a rule without sources is about how a call is made, so every sink
// call whose argument conditions hold is reported.
func (a *analysis) noSources() bool { return len(a.r.sources) == 0 && len(a.r.textSources) == 0 }

// netClasses are the classes whose leading condition is about a URL's host:
// there a prefix is fixed only when it keeps the request on a known host.
var netClasses = map[string]bool{"ssrf": true, "open-redirect": true, "xss": true}

// fixedText reports whether literal text, put before any input, is a fixed
// prefix for the rule. For a path or a stream (include, phar) it must name no
// scheme (notScheme). For a URL it must also fix the host: a scheme and host
// followed by "/", "?" or "#" (https://api.example.com/), a path from the root
// whose next character is neither "/" nor "\" ("/account", not "/" that the
// input turns into //evil.com), or a relative path ("users.php?id=", "?page=").
func (a *analysis) fixedText(text string) bool {
	if !netClasses[a.r.rule.Class] {
		return notScheme(text)
	}
	switch {
	case fixedHost(text):
		return true
	case strings.HasPrefix(text, "/"):
		return len(text) >= 2 && text[1] != '/' && text[1] != '\\'
	case strings.HasPrefix(text, "\\"):
		return false
	}
	return notScheme(text)
}

// fixedHost reports whether text starts with a scheme and a host that the input
// after it cannot change ("https://api.example.com/v1?q="): the host ends with
// "/", "?" or "#" already, so the input picks only the path or the query.
func fixedHost(text string) bool {
	i := strings.Index(text, "://")
	if i <= 0 {
		return false
	}
	for k := 0; k < i; k++ {
		if c := text[k]; !isAlnum(c) && c != '+' && c != '-' && c != '.' {
			return false
		}
	}
	rest := text[i+3:]
	end := strings.IndexAny(rest, "/?#")
	return end > 0 && !strings.ContainsAny(rest[:end], "@\\")
}

// textLeading reports, for a text sink with a leading condition, whether a fixed
// part follows the matched text before any input: "Location: /account?r=" . $x
// can only stay on the site, "Location: " . $x cannot.
func (a *analysis) textLeading(st state, t []Token, k, end int) bool {
	tk := t[k]
	stop := len(tk.Text)
	var next []Token
	for _, p := range tk.Parts {
		if p.Off >= end {
			stop, next = p.Off, p.Toks
			break
		}
	}
	if lit := strings.TrimLeft(tk.Text[min(end, stop):stop], " \t"); lit != "" {
		return a.fixedText(lit)
	}
	if next != nil {
		return a.fixedStart(st, next)
	}
	if stop < len(tk.Text) || k+1 >= len(t) {
		return false
	}
	rest := t[k+1:]
	if rest[0].op(".") || rest[0].op("+") {
		rest = rest[1:]
	}
	for j, depth := 0, 0; j < len(rest); j++ {
		if isOpen(rest[j]) {
			depth++
		} else if isClose(rest[j]) {
			if depth == 0 {
				rest = rest[:j]
				break
			}
			depth--
		} else if depth == 0 && (rest[j].op(",") || rest[j].op(";")) {
			rest = rest[:j]
			break
		}
	}
	return len(rest) > 0 && a.fixedStart(st, rest)
}

// Keys that mark, in a state, the guards that ran on every path to here (san:
// merge keeps a key only when both paths have it).
const (
	nonceKey      = "\x00nonce"       // any WordPress nonce check
	adminNonceKey = "\x00admin-nonce" // check_admin_referer: admin screens only
	capKey        = "\x00cap"         // current_user_can: a logged-in user with a capability
)

// nonceFuncs check a WordPress CSRF nonce; current_user_can checks the user.
var nonceFuncs = map[string]bool{"check_admin_referer": true, "check_ajax_referer": true, "wp_verify_nonce": true}

// nonced reports whether the request here is the site's own: a nonce check ran
// on every path to here, so a third party's link or form cannot have made it,
// and request values read here and sinks reached here are not theirs to choose.
// A rule that also lists current_user_can trusts a nonce from check_ajax_referer
// or wp_verify_nonce only together with a capability check, since a logged-out
// visitor can get a valid nonce for public AJAX handlers.
func (a *analysis) nonced(st state) bool {
	has := func(k string) bool { e, ok := st[k]; return ok && e.san }
	switch {
	case has(adminNonceKey):
		return true
	case !has(nonceKey):
		return false
	}
	return !a.hasSanitizerWord("current_user_can") || has(capKey)
}

func (a *analysis) markGuard(st state, name string) {
	switch {
	case !a.hasSanitizerWord(name):
	case name == "current_user_can":
		st[capKey] = entry{san: true}
	default:
		st[nonceKey] = entry{san: true}
		if name == "check_admin_referer" {
			st[adminNonceKey] = entry{san: true}
		}
	}
}

// nonceStmt records a nonce check that is a statement of its own:
// check_admin_referer('action') and check_ajax_referer('action') stop a request
// without a valid nonce: check_ajax_referer only when its third argument is true
// or left out, check_admin_referer only with an action (without one, or with -1,
// it checks only the referer). Only in the rules that list the check.
func (a *analysis) nonceStmt(st state, t []Token) {
	if !a.php || len(t) < 3 || t[0].Kind != Ident || !t[1].op("(") || closeOf(t, 1) != len(t)-1 && !(closeOf(t, 1) == len(t)-2 && t[len(t)-1].op(";")) {
		return
	}
	args := splitTop(inside(t, 1, closeOf(t, 1)), isComma)
	for _, x := range args {
		if len(x) > 1 && x[0].Kind == Ident && x[1].op(":") {
			return // a named argument (die: false): do not guess whether it stops
		}
	}
	switch name := t[0].Text; name {
	case "check_ajax_referer":
		if len(args) >= 3 && !(len(args[2]) == 1 && args[2][0].word("true")) {
			return // stops only when the third argument is true or left out
		}
		fallthrough
	case "check_admin_referer":
		if len(args) == 0 || len(args[0]) == 0 || len(args[0]) <= 2 && args[0][len(args[0])-1].Text == "1" {
			return // no action (-1) checks only the referer
		}
		a.markGuard(st, name)
	}
}

// nonceCond records, on the branch of an if where it holds, that a nonce or
// capability check in the condition passed: if (wp_verify_nonce(...)) { here }
// and if (!current_user_can('x')) { wp_die(); } here.
func (a *analysis) nonceCond(st state, cond []Token, truth bool) {
	if !a.php {
		return
	}
	split := func(t Token) bool { return t.op("||") || t.word("or") }
	if truth {
		split = func(t Token) bool { return t.op("&&") || t.word("and") }
	}
	for _, atom := range splitTop(stripParens(cond), split) {
		pos := true
		atom = stripParens(atom)
		for len(atom) > 0 && atom[0].op("!") {
			pos, atom = !pos, stripParens(atom[1:])
		}
		if pos == truth && len(atom) > 2 && atom[0].Kind == Ident && (nonceFuncs[atom[0].Text] || atom[0].Text == "current_user_can") &&
			atom[1].op("(") && closeOf(atom, 1) == len(atom)-1 {
			a.markGuard(st, atom[0].Text)
		}
	}
}

// stripAllAt reports whether t[i:] starts with a call that deletes every
// character outside letters, digits, "_" and "-" from its subject:
// preg_replace('/[^a-z0-9_-]/i', ”, $x) in PHP, re.sub(r'[^\w-]', ”, x) in
// Python, with exactly those three arguments (a limit or count would leave
// characters in place). It returns where the call ends, or -1.
func (a *analysis) stripAllAt(t []Token, i int) int {
	open := -1
	switch {
	case a.php && t[i].Text == "preg_replace" && i+1 < len(t) && t[i+1].op("("):
		open = i + 1
	case a.py && t[i].Text == "re" && i+3 < len(t) && t[i+1].op(".") && t[i+2].word("sub") && t[i+3].op("("):
		open = i + 3
	default:
		return -1
	}
	c := closeOf(t, open)
	args := splitTop(inside(t, open, c), isComma)
	if len(args) != 3 || len(args[0]) != 1 || args[0][0].Kind != Str || len(args[0][0].Parts) > 0 ||
		len(args[1]) != 1 || args[1][0].Kind != Str || args[1][0].Text != "" {
		return -1
	}
	re := args[0][0].Text
	if a.php {
		body, flags, ok := phpDelimited(re)
		if !ok || strings.Trim(flags, "iu") != "" {
			return -1
		}
		re = body
	}
	if items, ok := regexItems(re); !ok || len(items) != 1 || !items[0] {
		return -1
	}
	return c + 1
}

// keysKey marks a variable assigned the result of a stripping preg_replace on
// input: its values are clean, but on an array the keys are kept as they were.
const keysKey = "\x00keys:"

// stripKeys records, for $x = preg_replace(...) that strips input, that the keys
// of $x are still input; any other assignment to $x forgets it.
func (a *analysis) stripKeys(st state, t []Token) {
	if !a.php || len(t) < 3 || t[0].Kind != Var || !t[1].op("=") {
		return
	}
	delete(st, keysKey+t[0].Text)
	if end := a.stripAllAt(t, 2); end >= 0 && (end == len(t) || end == len(t)-1 && t[end].op(";")) {
		if args := splitTop(inside(t, 3, end-1), isComma); len(args) == 3 && a.hits(a.expr(st, args[2], false)) {
			st[keysKey+t[0].Text] = entry{taint: true}
		}
	}
	if end := a.mapSanAt(t, 2); end >= 0 && (end == len(t) || end == len(t)-1 && t[end].op(";")) {
		if args := splitTop(inside(t, 3, end-1), isComma); len(args) == 2 && a.hits(a.expr(st, args[1], false)) {
			st[keysKey+t[0].Text] = entry{taint: true} // array_map keeps the keys of a single array
		}
	}
}

// keysTainted reports whether the keys of the array iter are input though its
// values were stripped clean.
func (a *analysis) keysTainted(st state, iter []Token) bool {
	iter = stripParens(iter)
	if !a.php || len(iter) == 0 {
		return false
	}
	if len(iter) == 1 && iter[0].Kind == Var {
		e, ok := st[keysKey+iter[0].Text]
		return ok && e.taint
	}
	if end := a.stripAllAt(iter, 0); end == len(iter) {
		args := splitTop(inside(iter, 1, end-1), isComma)
		return len(args) == 3 && a.hits(a.expr(st, args[2], false))
	}
	return false
}

// allValidate returns the values that every one of the alternatives validates
// where it holds (empty($x) || 'a' === $x || admin_url() === $x: $x).
func (a *analysis) allValidate(st state, parts [][]Token) []keyRef {
	var common map[string]keyRef
	for _, p := range parts {
		pos, keys := a.guard(st, p)
		if keys == nil || !pos {
			return nil
		}
		next := map[string]keyRef{}
		for _, k := range keys {
			if common == nil || common[k.key] != (keyRef{}) {
				next[k.key] = k
			}
		}
		common = next
		if len(common) == 0 {
			return nil
		}
	}
	var out []keyRef
	for _, k := range common {
		out = append(out, k)
	}
	return out
}

// equalsClean reads $x === expr, where expr holds no input and is not a literal
// (literals are read by guard itself): where it holds, $x is that clean value.
// Only strict comparison: loose == can hold between different strings in PHP.
func (a *analysis) equalsClean(st state, lhs, rhs []Token, op string) []keyRef {
	if !(op == "===" || op == "!==" || a.py && (op == "==" || op == "!=")) {
		return nil
	}
	for _, pr := range [2][2][]Token{{lhs, rhs}, {rhs, lhs}} {
		x, y := stripParens(pr[0]), stripParens(pr[1])
		if _, _, ok := a.pathKey(x); !ok || len(y) == 0 || isLiteral(y) {
			continue
		}
		if !a.rawInput(st, y) {
			return a.keysOf(x)
		}
	}
	return nil
}

// Markers for output rules, kept in the state next to the variables.
const (
	ctrKey = "\x00ctr:" // the variable holds an array or object literal, or a whole request array
	resKey = "\x00res:" // the variable holds what an unknown call returned (a structure it built)
)

// splitters return the input's own parts, and merges the elements of the arrays
// they are given: their fields are still the input.
var splitters = words("json_decode unserialize maybe_unserialize explode str_getcsv preg_split parse_url pathinfo " +
	"shortcode_atts wp_array_slice_assoc array_merge array_replace array_merge_recursive array_replace_recursive " +
	"wp_parse_args wp_parse_str parse_str wp_unslash stripslashes_deep compact func_get_args getallheaders " +
	"filter_input_array str_split mb_str_split loads parse_qs urlparse split")

// markAssign records, in output rules, what kind of value $x = ... gives $x.
func (a *analysis) markAssign(st state, t []Token) {
	if !a.r.output || len(t) < 3 || !(t[0].Kind == Var || t[0].Kind == Ident && !a.kw[t[0].Text]) {
		return
	}
	if t[1].op("[") || memberOp(a.php, t[1]) {
		delete(st, resKey+t[0].Text) // $r['x'] = ...: a field written here may be the input
		return
	}
	if !t[1].op("=") {
		return
	}
	name := t[0].Text
	delete(st, ctrKey+name)
	delete(st, resKey+name)
	rhs := stripParens(t[2:])
	if n := len(rhs); n > 0 && rhs[n-1].op(";") {
		rhs = rhs[:n-1]
	}
	if len(rhs) == 0 {
		return
	}
	if a.fieldOfResult(st, rhs) {
		e := st[name] // $m = $r['message']: the same as reading $r['message'] in place
		e.taint, e.raw = false, false
		st[name] = e
		return
	}
	switch {
	case rhs[0].op("[") || rhs[0].op("{") || a.php && (rhs[0].word("array") || rhs[0].word("compact")):
		st[ctrKey+name] = entry{taint: true}
	case len(rhs) == 1 && (rhs[0].Text == "$_GET" || rhs[0].Text == "$_POST" || rhs[0].Text == "$_REQUEST" || rhs[0].Text == "$_COOKIE"):
		st[ctrKey+name] = entry{taint: true}
	case rhs[len(rhs)-1].op(")") && a.chainStart(rhs, len(rhs)) == 0:
		open := openOf(rhs, len(rhs)-1)
		if open >= 1 && rhs[open-1].Kind == Ident && !splitters[rhs[open-1].Text] && !formatFuncs[rhs[open-1].Text] {
			if _, esc := escapers[rhs[open-1].Text]; !esc {
				st[resKey+name] = entry{taint: true}
			}
		}
	}
}

func marked(st state, key string) bool {
	e, ok := st[key]
	return ok && e.taint
}

// container reports whether arg is an array or object: a literal, a whole
// request array, or a variable assigned one.
func (a *analysis) container(st state, arg []Token) bool {
	if len(arg) == 0 {
		return false
	}
	switch {
	case arg[0].op("[") || arg[0].op("{") || a.php && (arg[0].word("array") || arg[0].word("compact")):
		return true
	case len(arg) == 1 && (arg[0].Kind == Var || arg[0].Kind == Ident):
		return marked(st, ctrKey+arg[0].Text) || arg[0].Text == "$_GET" || arg[0].Text == "$_POST" || arg[0].Text == "$_REQUEST"
	}
	return false
}

// fieldOfResult reports whether op reads a named field of what an unknown call
// returned ($result['password_message'], $api->name): a structure that call
// built, not the input it was given.
func (a *analysis) fieldOfResult(st state, op []Token) bool {
	if len(op) < 3 || op[0].Kind != Var && op[0].Kind != Ident || !marked(st, resKey+op[0].Text) {
		return false
	}
	switch { // exactly one field read, nothing joined to it or called on it
	case len(op) == 4 && op[1].op("[") && op[2].Kind == Str && len(op[2].Parts) == 0 && op[3].op("]"):
		return true
	case len(op) == 3 && memberOp(a.php, op[1]) && op[2].Kind == Ident:
		return true
	}
	return false
}

// mapSanAt reports whether t[i:] starts with array_map('cb', $x) where cb is a
// sanitizer of the rule or a number cast (absint, intval, sanitize_key): every
// value of the result went through it. It returns where the call ends, or -1.
// The keys of $x are kept (see stripKeys).
func (a *analysis) mapSanAt(t []Token, i int) int {
	if !a.php || a.raw || t[i].Text != "array_map" || i+1 >= len(t) || !t[i+1].op("(") {
		return -1
	}
	c := closeOf(t, i+1)
	args := splitTop(inside(t, i+1, c), isComma)
	if len(args) != 2 || len(args[0]) != 1 || args[0][0].Kind != Str || len(args[0][0].Parts) > 0 {
		return -1
	}
	cb := args[0][0].Text
	if !a.hasSanitizerWord(cb) && !numericFuncs["php"][cb] {
		return -1
	}
	return c + 1
}

// extractStmt follows extract(shortcode_atts(array('id' => 0, ...), $atts)) and
// extract(array(...)): each literal key becomes a variable holding what the
// array holds.
func (a *analysis) extractStmt(st state, t []Token) {
	if !a.php || len(t) < 4 || !t[0].word("extract") || !t[1].op("(") {
		return
	}
	c := closeOf(t, 1)
	args := splitTop(inside(t, 1, c), isComma)
	if len(args) == 0 {
		return
	}
	inner := stripParens(args[0])
	lit := inner
	if len(inner) > 2 && inner[0].word("shortcode_atts") && inner[1].op("(") {
		if xs := splitTop(inside(inner, 1, closeOf(inner, 1)), isComma); len(xs) > 0 {
			lit = stripParens(xs[0])
		}
	}
	var body []Token
	switch {
	case len(lit) > 1 && lit[0].op("["):
		body = inside(lit, 0, closeOf(lit, 0))
	case len(lit) > 2 && lit[0].word("array") && lit[1].op("("):
		body = inside(lit, 1, closeOf(lit, 1))
	default:
		return
	}
	v := a.expr(st, inner, false)
	for _, item := range splitTop(body, isComma) {
		if len(item) > 2 && item[0].Kind == Str && len(item[0].Parts) == 0 && item[1].op("=>") && isIdentName(item[0].Text) {
			a.setTarget(st, []Token{{Kind: Var, Text: "$" + item[0].Text, Line: t[0].Line}}, v, "=", false)
		}
	}
}

func isIdentName(s string) bool {
	if s == "" || !isIdentStart(s[0]) {
		return false
	}
	for i := 1; i < len(s); i++ {
		if !isIdentChar(s[i]) {
			return false
		}
	}
	return true
}

// litKey marks, in a state, that a variable holds a value written in the code
// with no input in it ($o = ['test_form' => false], const opts = { shell: true },
// $f = LIBXML_NOENT); the value is kept in a.lits. One key per name, so the state
// does not grow with every assignment; a name given two different values in the
// file counts as not known.
const litKey = "\x00lit:"

// recordLit records x = <value with no input> for the argument conditions of
// the sinks, and forgets it on any other assignment to x.
func (a *analysis) recordLit(st state, t []Token) {
	for len(t) > 0 && t[0].Kind == Ident && declWords[t[0].Text] {
		t = t[1:]
	}
	if len(t) < 3 || !(t[0].Kind == Var || t[0].Kind == Ident && !a.kw[t[0].Text]) || !t[1].op("=") {
		return
	}
	name := t[0].Text
	rhs := t[2:]
	if n := len(rhs); n > 0 && rhs[n-1].op(";") {
		rhs = rhs[:n-1]
	}
	if len(rhs) == 0 || len(rhs) > 256 || len(rhs) == 1 && rhs[0].Text == name || a.rawInput(st, rhs) {
		if _, ok := st[litKey+name]; ok {
			delete(st, litKey+name)
		}
		return
	}
	if a.lits == nil {
		a.lits = map[string][]Token{}
	}
	if old, seen := a.lits[name]; seen && (old == nil || !tokensEqual(old, rhs)) {
		a.lits[name] = nil // two different values: not known
	} else {
		a.lits[name] = rhs
	}
	st[litKey+name] = entry{san: true}
}

// expandLits returns region with each argument that is a variable recorded by
// recordLit replaced by its value, so when and unless see the options it holds.
func (a *analysis) expandLits(st state, region []Token) []Token {
	if len(a.lits) == 0 {
		return region
	}
	var out []Token
	changed := false
	for _, arg := range splitTop(region, isComma) {
		if len(out) > 0 {
			out = append(out, Token{Kind: Op, Text: ","})
		}
		if len(arg) == 1 && (arg[0].Kind == Var || arg[0].Kind == Ident) {
			if v := a.litOf(st, arg[0].Text); v != nil {
				out = append(out, v...)
				changed = true
				continue
			}
		}
		out = append(out, arg...)
	}
	if !changed {
		return region
	}
	return out
}

func (a *analysis) litOf(st state, name string) []Token {
	if e, ok := st[litKey+name]; ok && e.san {
		return a.lits[name] // nil when the name was given different values
	}
	return nil
}

// textMatch finds a text pattern in a string literal's text, outside its
// interpolations: in "SELECT * FROM t $where" the $where is a variable, not text.
func textMatch(p *pat, tk Token) []int {
	for _, loc := range p.text.FindAllStringIndex(tk.Text, -1) {
		inside := false
		for _, part := range tk.Parts {
			if loc[0] >= part.Off && loc[0] < skipInterp(tk.Text, min(part.Off, len(tk.Text))) {
				inside = true
				break
			}
		}
		if !inside {
			return loc
		}
	}
	return nil
}

// localFunc reports whether a function or method of this name is defined in the
// file: then what it returns is not guessed from its name (get_, render_): it
// passes on an argument that is the input, unless its summary says otherwise.
func (a *analysis) localFunc(name string) bool {
	if a.sc == nil {
		return false
	}
	if a.locals == nil {
		a.locals = map[string]bool{}
		for _, infos := range a.sc.funcs {
			for _, fi := range infos {
				a.locals[fi.f.name] = true
			}
		}
	}
	return a.locals[name]
}

// condAssign follows assignments written in a condition: if ($x = $_GET['y']),
// if ($x === 'a' || ($x = f())).
func (a *analysis) condAssign(st state, cond []Token) {
	var walk func(t []Token, depth int)
	walk = func(t []Token, depth int) {
		t = stripParens(t)
		if depth > 8 || len(t) == 0 {
			return
		}
		parts := splitTop(t, func(x Token) bool { return x.op("&&") || x.op("||") || x.word("and") || x.word("or") })
		if len(parts) > 1 {
			for _, p := range parts {
				walk(p, depth+1)
			}
			return
		}
		for len(t) > 0 && t[0].op("!") {
			t = stripParens(t[1:])
		}
		if i := indexTop(t, 0, isAssignOp); i > 0 && t[i].Text == "=" {
			a.assignStmt(st, t)
		}
	}
	walk(cond, 0)
}

// phpDefines reads define('NAME', 'text') with literal arguments in a PHP file.
func phpDefines(lang string, toks []Token) map[string]string {
	if lang != "php" {
		return nil
	}
	var out map[string]string
	for i := 0; i+5 < len(toks); i++ {
		if !toks[i].word("define") || !toks[i+1].op("(") || toks[i+2].Kind != Str || !toks[i+3].op(",") || toks[i+4].Kind != Str ||
			len(toks[i+4].Parts) > 0 || !toks[i+5].op(")") || i > 0 && memberOp(true, toks[i-1]) {
			continue
		}
		if out == nil {
			out = map[string]string{}
		}
		if _, dup := out[toks[i+2].Text]; dup {
			out[toks[i+2].Text] = "" // defined twice: not known
			continue
		}
		out[toks[i+2].Text] = toks[i+4].Text
	}
	return out
}

// constName reports whether name is written as a constant (SECRET_KEY, JWT_KEY).
func constName(name string) bool {
	upper := false
	for i := 0; i < len(name); i++ {
		switch c := name[i]; {
		case c >= 'A' && c <= 'Z':
			upper = true
		case c >= '0' && c <= '9' || c == '_':
		default:
			return false
		}
	}
	return upper
}

// netPrefixOK: in ssrf, open-redirect and xss a prefix check must compare with a
// prefix that keeps the request on a known host (fixedText). startswith('/') lets
// "//evil.com" through, and excluding "//" and "/\\" as well is not enough: the
// browser drops tabs and newlines from a URL, so "/\t/evil.com" becomes
// "//evil.com". Only a host check (url_has_allowed_host_and_scheme,
// wp_validate_redirect, Uri::isInternal) makes the target safe.
func (a *analysis) netPrefixOK(st state, args [][]Token) bool {
	if !netClasses[a.r.rule.Class] {
		return true
	}
	for _, arg := range args {
		if len(arg) == 1 && arg[0].Kind == Str && len(arg[0].Parts) == 0 && a.fixedText(arg[0].Text) {
			return true
		}
	}
	return false
}

// plainSubject returns the key of the value a prefix check is about, when it is
// a plain variable or path: urlparse(u).path.startswith('/app/') checks a part
// of u, so it cleans nothing, and neither do the names in the prefix.
func (a *analysis) plainSubject(args [][]Token) []keyRef {
	if len(args) == 0 {
		return nil
	}
	subject := stripParens(args[0])
	if _, _, ok := a.pathKey(subject); !ok {
		return nil
	}
	for _, t := range subject {
		if t.op("(") {
			return nil // a call in the path
		}
	}
	return a.keysOf(subject)
}

// keyValue returns the value under key (any case) in an object, dict or array
// literal: { Location: v }, {'Location': v}, ['Location' => v], array(...), or
// nil when arg is not such a literal or has no such key.
func keyValue(arg []Token, key string) []Token {
	arg = stripParens(arg)
	var body []Token
	switch {
	case len(arg) > 1 && (arg[0].op("{") || arg[0].op("[")) && closeOf(arg, 0) == len(arg)-1:
		body = inside(arg, 0, len(arg)-1)
	case len(arg) > 2 && arg[0].word("array") && arg[1].op("(") && closeOf(arg, 1) == len(arg)-1:
		body = inside(arg, 1, len(arg)-1)
	default:
		return nil
	}
	for _, item := range splitTop(body, isComma) {
		if len(item) < 3 || !(item[1].op(":") || item[1].op("=>")) || item[0].Kind != Ident && item[0].Kind != Str {
			continue
		}
		if strings.EqualFold(item[0].Text, key) {
			return item[2:]
		}
	}
	return nil
}

// configStart reports whether a string starts with an interpolated value that
// holds no input (a configured base: process.env.API, settings.BASE_URL, a
// constant) and the literal text right after it starts a path, a query or a
// fragment: `${process.env.API}/v1?q=${x}`. The base decides the host; the input
// after the path cannot. As the base may be empty or a bare path, that path must
// be a fixed prefix by itself (fixedText): `${base}/${x}` is not.
func (a *analysis) configStart(st state, tk Token) bool {
	if tk.Kind != Str || len(tk.Parts) == 0 || tk.Parts[0].Off != 0 && !(tk.Parts[0].Off == 1 && tk.Text[0] == '$') {
		return false
	}
	p := tk.Parts[0]
	if len(p.Toks) == 0 || a.rawInput(st, p.Toks) {
		return false
	}
	from := min(skipInterp(tk.Text, 0), len(tk.Text))
	to := len(tk.Text)
	if len(tk.Parts) > 1 {
		to = max(from, min(tk.Parts[1].Off, len(tk.Text)))
	}
	seg := tk.Text[from:to] // the literal text between the base and the next value
	// the base may be empty or a bare path, so the text after it must hold on its
	// own: "/posts?slug=" does, "/" (then //evil.example) does not
	return seg != "" && strings.IndexByte("/?#", seg[0]) >= 0 && a.fixedText(seg)
}
