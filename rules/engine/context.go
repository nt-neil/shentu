package engine

import "strings"

// Output contexts. An output sink (echo, res.send) writes into an HTML page, and
// which escaping makes a value safe depends on where in the page it lands:
// esc_html is enough between tags, not in an href (javascript:) nor in an
// onclick handler. A rule's [[args]] context lists the contexts it is about, and
// the engine reads the context from the literal HTML written before the value:
// the inline HTML before a PHP echo or <?= (the lexer keeps it on the echo
// token), and the literal text joined before the value in the same output.
const (
	ctxHTML uint8 = iota // between tags (also the default when nothing is known)
	ctxAttr              // inside a tag: an attribute value, or where an attribute could start
	ctxURL               // at the start of a URL attribute value (href, src, action, ...)
	ctxJS                // inside <script>, an on* handler, or after javascript:
)

var contextNames = map[string]uint8{"html": ctxHTML, "attr": ctxAttr, "url": ctxURL, "js": ctxJS}

var urlAttrs = map[string]bool{"href": true, "src": true, "action": true, "formaction": true, "poster": true,
	"data": true, "background": true, "cite": true, "xlink:href": true, "srcdoc": true}

const htmlKeep = 2048 // bytes of inline HTML kept to read the context from

// inlineHTML records a run of PHP inline HTML and the context the next output
// writes into.
func (s *scanner) inlineHTML(h string) {
	s.html += h
	if len(s.html) > htmlKeep {
		s.html = s.html[len(s.html)-htmlKeep:]
	}
	s.htmlCtx = htmlContext(s.html)
}

// htmlContext returns the context of text written right after h.
func htmlContext(h string) uint8 {
	low := strings.ToLower(h)
	if i := strings.LastIndex(low, "<script"); i >= 0 && !strings.Contains(low[i:], "</script") && strings.Contains(low[i:], ">") {
		open := low[i : i+strings.Index(low[i:], ">")]
		if !strings.Contains(open, "type=\"text/") && !strings.Contains(open, "type='text/") || strings.Contains(open, "text/javascript") {
			return ctxJS
		}
		// <script type="text/html">, "text/template": markup kept for later, read as HTML
		low = low[strings.Index(low[i:], ">")+i+1:]
	}
	lt := strings.LastIndex(low, "<")
	if lt < 0 || lt < strings.LastIndex(low, ">") {
		return ctxHTML
	}
	tag := low[lt+1:]
	if tag == "" || !isAlnum(tag[0]) {
		return ctxHTML // "a < b" in text, "</" or "<!--"
	}
	name, value, inValue := openAttr(tag)
	switch {
	case !inValue:
		return ctxAttr
	case strings.HasPrefix(name, "on"):
		return ctxJS
	case urlAttrs[name]:
		v := strings.TrimSpace(value)
		if strings.HasPrefix(v, "javascript:") {
			return ctxJS
		}
		if !notScheme(v) {
			return ctxURL // nothing yet, or a start the value can turn into a scheme
		}
	}
	return ctxAttr
}

// openAttr reads the attributes of a tag that is still open (tag is the text
// after "<") and reports the attribute whose value is still open, if any.
func openAttr(tag string) (name, value string, inValue bool) {
	i := 0
	for i < len(tag) && !isSpace(tag[i]) {
		i++ // the tag name
	}
	for i < len(tag) {
		for i < len(tag) && (isSpace(tag[i]) || tag[i] == '/') {
			i++
		}
		start := i
		for i < len(tag) && !isSpace(tag[i]) && tag[i] != '=' {
			i++
		}
		name = tag[start:i]
		for i < len(tag) && isSpace(tag[i]) {
			i++
		}
		if i >= len(tag) || tag[i] != '=' {
			continue
		}
		i++
		for i < len(tag) && isSpace(tag[i]) {
			i++
		}
		if i >= len(tag) {
			return name, "", true // value=<?php echo ... ?>, unquoted
		}
		if q := tag[i]; q == '"' || q == '\'' {
			end := strings.IndexByte(tag[i+1:], q)
			if end < 0 {
				return name, tag[i+1:], true
			}
			i += end + 2
			continue
		}
		start = i
		for i < len(tag) && !isSpace(tag[i]) {
			i++
		}
		if i >= len(tag) {
			return name, tag[start:], true
		}
	}
	return "", "", false
}

func isSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' }

// contextTaint reports whether out, written by an output sink whose token is
// sinkTok, writes user input into one of the contexts in want. The operands of
// out are read in order (joined with "." or "+", or listed with ","); the literal
// text before an operand decides its context.
func (a *analysis) contextTaint(st state, sinkTok Token, out []Token, want []uint8) bool {
	if a.py && len(out) > 1 && out[0].Kind == Ident && out[1].op("=") {
		if out[0].Text != "content" {
			return false // status=, headers=: not what the page shows
		}
		out = out[2:]
	}
	base := sinkTok.Flags >> flagCtxShift & 3
	join := "+"
	if a.php {
		join = "."
	}
	lit := ""
	inAt := func(text string, op []Token) bool {
		c := base
		if text != "" && (base == ctxHTML || strings.ContainsAny(text, "<>")) {
			c = htmlContext(text)
		}
		if c == ctxURL && op != nil && a.r.leading && a.fixedStart(st, op) {
			c = ctxAttr // the value starts with a fixed part ('install.php?l=' . $l): not a scheme
		}
		for _, w := range want {
			if w == c {
				return true
			}
		}
		return false
	}
	for _, op := range splitTop(stripParens(out), func(t Token) bool { return t.op(join) || t.op(",") }) {
		if len(op) == 1 && op[0].Kind == Str && op[0].Flags&(FlagShell|FlagRegex) == 0 {
			tk := op[0]
			for _, p := range tk.Parts {
				if a.hits(a.expr(st, p.Toks, false)) && inAt(lit+tk.Text[:min(p.Off, len(tk.Text))], p.Toks) {
					return true
				}
			}
			lit += tk.Text
			continue
		}
		if !a.php && len(op) > 0 && (op[0].op("{") || op[0].op("[")) {
			continue // an object or a list is sent as JSON, not as markup
		}
		if !a.opaqueCall(op) && a.hits(a.expr(st, op, false)) && inAt(lit, op) {
			return true
		}
	}
	return false
}

// literalArg reports whether the argument a literal condition names is a
// non-empty string written in the code: the arg-th argument, or the value of a
// when option (password=, secret:).
func (a *analysis) literalArg(cond *argCond, region []Token, open int) bool {
	isLit := func(v []Token) bool {
		return len(v) == 1 && v[0].Kind == Str && len(v[0].Parts) == 0 && v[0].Flags&(FlagShell|FlagRegex) == 0 && v[0].Text != ""
	}
	if cond.arg != nil {
		if open < 0 {
			return false
		}
		args := splitTop(region, isComma)
		n := *cond.arg
		return n >= 1 && n <= len(args) && isLit(stripParens(args[n-1]))
	}
	for _, p := range cond.when {
		for i := range region {
			if p.at(region, i, false) {
				if v := optionValue(p, region, i); v != nil && isLit(v) {
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

// fixedHost reports whether text starts with a scheme and a host that the input
// after it cannot change ("https://api.example.com/v1?q="): the request goes to
// that host, and the input picks only the path or the query.
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
		return notScheme(lit)
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

// passOn are the calls whose result written to a page still carries the input
// they were given: string edits, decoding, formatting and joining. The result of
// any other call (shell_exec, file_get_contents, a template loader) is what that
// call produced, not the request value, so in an output rule (every sink has a
// context condition) the call's result is clean.
var passOn = words("trim ltrim rtrim strtolower strtoupper ucfirst ucwords lcfirst stripslashes stripcslashes wp_unslash " +
	"urldecode rawurldecode base64_decode html_entity_decode htmlspecialchars_decode sprintf vsprintf implode join " +
	"str_replace str_ireplace preg_replace substr mb_substr str_pad nl2br wpautop print_r var_export strval " +
	"__ _x apply_filters wp_specialchars_decode stripslashes_deep str_repeat strrev wordwrap " +
	"decodeURIComponent decodeURI unescape String toString toUpperCase toLowerCase replace replaceAll slice substring " +
	"concat format str upper lower strip capitalize title unquote unquote_plus get getlist sub subn " +
	// escaping for one context leaves the value unsafe in another (the rules list the ones that suffice)
	"esc_html esc_attr esc_textarea esc_js esc_url esc_url_raw esc_html__ esc_attr__ htmlspecialchars htmlentities " +
	"strip_tags wp_strip_all_tags wp_kses wp_kses_post wp_kses_data sanitize_text_field sanitize_textarea_field " +
	"urlencode rawurlencode json_encode wp_json_encode addslashes escape escapeHtml encodeURIComponent encodeURI")

// opaqueCall reports whether op is one call (a function, method or static
// method) whose result is not the input itself (see passOn).
func (a *analysis) opaqueCall(op []Token) bool {
	n := len(op)
	if n < 3 || !op[n-1].op(")") {
		return false
	}
	open := openOf(op, n-1)
	if open < 1 || a.chainStart(op, n) != 0 || op[open-1].Kind != Ident {
		return false
	}
	return a.opaqueAt(op, open)
}

// opaqueAt reports whether the call whose "(" is at j has a result that is not
// the input it was given (see passOn).
func (a *analysis) opaqueAt(t []Token, j int) bool {
	return j > 0 && t[j-1].Kind == Ident && !a.kw[t[j-1].Text] && !passOn[t[j-1].Text]
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
// check_admin_referer(...) and check_ajax_referer(...) stop a request without a
// valid nonce (unless check_ajax_referer's third argument is false). Only in the
// rules that list the check as a sanitizer.
func (a *analysis) nonceStmt(st state, t []Token) {
	if !a.php || len(t) < 3 || t[0].Kind != Ident || !t[1].op("(") || closeOf(t, 1) != len(t)-1 && !(closeOf(t, 1) == len(t)-2 && t[len(t)-1].op(";")) {
		return
	}
	switch name := t[0].Text; name {
	case "check_ajax_referer":
		if args := splitTop(inside(t, 1, closeOf(t, 1)), isComma); len(args) >= 3 && len(args[2]) == 1 && falsy(args[2]) {
			return // returns false instead of stopping
		}
		fallthrough
	case "check_admin_referer":
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
