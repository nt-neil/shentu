package engine

import "strings"

// Output contexts. An output sink (echo, res.send) writes into an HTML page, and
// which escaping makes a value safe depends on where in the page it lands:
// esc_html is enough between tags, not in an href (javascript:), not in an
// unquoted attribute (a space starts a new attribute) and not in an onclick
// handler (the browser decodes entities before the script runs). A rule's
// [[args]] context names the contexts it is about; the engine reads the context
// from the HTML written before the value: the inline HTML before a PHP <?php or
// <?= block (the lexer keeps it on every echo and print of the block), and the
// literal text joined before the value in the same output.
const (
	ctxHTML     uint8 = iota // between tags (also when nothing is known)
	ctxAttr                  // a double-quoted attribute value
	ctxAttrSQ                // a single-quoted attribute value
	ctxAttrBare              // an unquoted attribute value, where an attribute name goes, or srcdoc
	ctxURL                   // the start of a URL attribute value (href, src, action, ...)
	ctxJS                    // code inside <script>, not in a string
	ctxJSStr                 // inside a JavaScript string literal (in <script> or a handler)
	ctxJSAttr                // code in an on* handler or after javascript:, not in a string; also CSS (<style>, style=)
)

// contextNames are the rule format's names for groups of contexts.
var contextNames = map[string][]uint8{"html": {ctxHTML}, "attr": {ctxAttr, ctxAttrSQ, ctxAttrBare},
	"url": {ctxURL}, "js": {ctxJS, ctxJSStr, ctxJSAttr}}

var urlAttrs = map[string]bool{"href": true, "src": true, "action": true, "formaction": true, "poster": true,
	"data": true, "background": true, "cite": true, "xlink:href": true}

const (
	hsText = iota
	hsLT
	hsTag
	hsRaw // the body of <script> or <style>
	hsComment
)

// htmlScan follows HTML text in order, a byte at a time, with no buffer of what
// it read, so the cost is linear however long the page is.
type htmlScan struct {
	mode     uint8
	closing  bool   // reading a closing tag
	named    bool   // the tag name is read
	tag      string // lower-case tag name (first 12 bytes)
	attr     string // current attribute name (first 24 bytes)
	attrEnd  bool   // the name ended (a space after it)
	afterEq  bool   // "=" read, the value has not started
	inVal    bool
	quote    byte   // the value's quote, 0 when unquoted
	val      string // the value so far (first 64 bytes)
	typ      string // the type attribute of the tag being read
	raw      string // "script" or "style" while in its body
	scriptJS bool   // the open <script> runs JavaScript
	end      int    // bytes of "</script" or "</style" matched
	jsq      byte   // the quote of the JavaScript string we are in, in a script or a handler
	jsEsc    bool
	jsCom    uint8 // 1: in a // comment, 2: in a /* */ comment
	jsStar   bool  // the last byte of a block comment was "*"
	jsRe     bool  // in a regular expression literal
	jsClass  bool  // in a [...] class of one
	jsSlash  bool  // a "/" was read in code: a comment, a regular expression or a division
	jsPrev   byte  // the last code byte that was not blank
}

func lowerByte(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}

func (h *htmlScan) feed(s string) {
	for i := 0; i < len(s); i++ {
		c, l := s[i], lowerByte(s[i])
		switch h.mode {
		case hsRaw:
			pat := "</" + h.raw
			switch {
			case l == pat[h.end]:
				h.end++
				if h.end == len(pat) {
					h.mode, h.closing, h.named, h.tag, h.end, h.raw = hsTag, true, true, h.raw, 0, ""
					h.resetJS()
					continue
				}
			case l == '<':
				h.end = 1
			default:
				h.end = 0
			}
			if h.raw == "script" {
				h.js(c)
			}
		case hsText:
			if c == '<' {
				h.mode = hsLT
			}
		case hsLT:
			switch {
			case l >= 'a' && l <= 'z':
				h.mode, h.closing, h.named, h.tag = hsTag, false, false, string(l)
				h.resetAttr()
			case c == '/':
				h.mode, h.closing, h.named, h.tag = hsTag, true, false, ""
			case c == '!' || c == '?':
				h.mode = hsComment
			case c != '<':
				h.mode = hsText
			}
		case hsComment:
			if c == '>' {
				h.mode = hsText
			}
		case hsTag:
			h.tagByte(c, l)
		}
	}
}

func (h *htmlScan) resetAttr() {
	h.attr, h.attrEnd, h.afterEq, h.inVal, h.quote, h.val = "", false, false, false, 0, ""
	h.resetJS()
}

// js follows JavaScript strings, template literals, comments and regular
// expression literals, so a quote inside a comment or a regex does not open a
// string.
func (h *htmlScan) js(c byte) {
	switch {
	case h.jsCom == 1:
		if c == '\n' {
			h.jsCom = 0
		}
		return
	case h.jsCom == 2:
		if h.jsStar && c == '/' {
			h.jsCom = 0
		}
		h.jsStar = c == '*'
		return
	case h.jsq != 0:
		switch {
		case h.jsEsc:
			h.jsEsc = false
		case c == '\\':
			h.jsEsc = true
		case c == h.jsq:
			h.jsq = 0
			h.jsPrev = 'a'
		}
		return
	case h.jsRe:
		switch {
		case h.jsEsc:
			h.jsEsc = false
		case c == '\\':
			h.jsEsc = true
		case h.jsClass:
			h.jsClass = c != ']'
		case c == '[':
			h.jsClass = true
		case c == '/':
			h.jsRe, h.jsPrev = false, 'a'
		}
		return
	}
	if h.jsSlash {
		h.jsSlash = false
		switch {
		case c == '/':
			h.jsCom = 1
			return
		case c == '*':
			h.jsCom, h.jsStar = 2, false
			return
		case h.jsPrev == 0 || strings.IndexByte("(,=:[!&|?{};+-*%<>~^", h.jsPrev) >= 0:
			h.jsRe = true // a "/" where a value starts: a regular expression
			h.js(c)
			return
		}
		h.jsPrev = '/'
	}
	switch {
	case c == '/':
		h.jsSlash = true
	case c == '\'' || c == '"' || c == '`':
		h.jsq = c
	case !isSpace(c):
		h.jsPrev = c
	}
}

func (h *htmlScan) resetJS() {
	h.jsq, h.jsEsc, h.jsCom, h.jsStar, h.jsRe, h.jsClass, h.jsSlash, h.jsPrev = 0, false, 0, false, false, false, false, 0
}

func (h *htmlScan) tagByte(c, l byte) {
	if h.inVal {
		if h.quote != 0 && c == h.quote || h.quote == 0 && (isSpace(c) || c == '>') {
			if h.attr == "type" {
				h.typ = strings.ToLower(h.val)
			}
			h.resetAttr()
			if c == '>' {
				h.closeTag()
			}
			return
		}
		if len(h.val) < 64 {
			h.val += string(c)
		}
		if strings.HasPrefix(h.attr, "on") || strings.HasPrefix(strings.TrimSpace(strings.ToLower(h.val)), "javascript:") {
			h.js(c)
		}
		return
	}
	if !h.named {
		if isSpace(c) || c == '/' || c == '>' {
			h.named = true
			if c == '>' {
				h.closeTag()
			}
		} else if len(h.tag) < 12 {
			h.tag += string(l)
		}
		return
	}
	switch {
	case c == '>':
		h.closeTag()
	case h.afterEq:
		if isSpace(c) {
			return
		}
		h.afterEq, h.inVal = false, true
		if c == '"' || c == '\'' {
			h.quote = c
		} else {
			h.val = string(c)
		}
	case c == '=':
		h.afterEq = true
	case isSpace(c) || c == '/':
		h.attrEnd = h.attr != ""
	default:
		if h.attrEnd {
			h.attr, h.attrEnd = "", false
		}
		if len(h.attr) < 24 {
			h.attr += string(l)
		}
	}
}

func (h *htmlScan) closeTag() {
	h.mode = hsText
	if !h.closing && (h.tag == "script" || h.tag == "style") {
		h.mode, h.raw, h.end = hsRaw, h.tag, 0
		h.resetJS()
		t := h.typ
		h.scriptJS = h.tag == "script" && (t == "" || strings.Contains(t, "javascript") || strings.Contains(t, "ecmascript") || t == "module")
	}
	h.typ = ""
	h.resetAttr()
}

// ctx is the context of text written now.
func (h *htmlScan) ctx() uint8 {
	switch h.mode {
	case hsRaw:
		switch {
		case h.raw == "style":
			return ctxJSAttr // CSS: only what holds no quote, space or parenthesis is safe
		case !h.scriptJS:
			return ctxHTML // <script type="text/html">: markup kept for later
		}
		return h.jsCtx(ctxJS)
	case hsLT:
		return ctxAttrBare // <<?= $x ?>: the tag name
	case hsTag:
		name := h.attr
		switch {
		case h.closing || !h.inVal && !h.afterEq:
			return ctxAttrBare // where an attribute name goes
		case strings.HasPrefix(name, "on"):
			return h.jsCtx(ctxJSAttr)
		case name == "style":
			return ctxJSAttr // CSS
		case name == "srcdoc":
			return ctxAttrBare // markup in an attribute: entities are decoded, then parsed as HTML
		case urlAttrs[name]:
			v := strings.TrimSpace(strings.ToLower(h.val))
			if strings.HasPrefix(v, "javascript:") {
				return h.jsCtx(ctxJSAttr)
			}
			if !notScheme(v) {
				return ctxURL // nothing yet, or a start the value can turn into a scheme
			}
		}
		if h.inVal && h.quote == '"' {
			return ctxAttr
		}
		if h.inVal && h.quote == '\'' {
			return ctxAttrSQ
		}
		return ctxAttrBare
	}
	return ctxHTML
}

// jsCtx is the context inside JavaScript whose code context is code: a string,
// or a template literal (where ${ runs code and only URL-encoding is safe).
func (h *htmlScan) jsCtx(code uint8) uint8 {
	switch {
	case h.jsq == '`':
		return ctxJSAttr
	case h.jsq != 0:
		return ctxJSStr
	}
	return code
}

func isSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' }

// inlineHTML records a run of PHP inline HTML; the echo and print statements of
// the code block that follows write into the context it ends in.
func (s *scanner) inlineHTML(h string) {
	s.hs.feed(h)
	s.htmlCtx = s.hs.ctx() + 1
}

func ctxBits(cs ...uint8) uint16 {
	var m uint16
	for _, c := range cs {
		m |= 1 << c
	}
	return m
}

var (
	textAttr = ctxBits(ctxHTML, ctxAttr, ctxAttrSQ)
	anyCtx   = ctxBits(ctxHTML, ctxAttr, ctxAttrSQ, ctxAttrBare, ctxURL, ctxJS, ctxJSStr, ctxJSAttr)
	encoded  = ctxBits(ctxHTML, ctxAttr, ctxAttrSQ, ctxAttrBare, ctxURL, ctxJSStr, ctxJSAttr) // URL-encoding: no quote, space, < or :
	uriComp  = ctxBits(ctxHTML, ctxAttr, ctxAttrBare, ctxURL)                                 // encodeURIComponent keeps ' ( ) ! * ~
)

// escapers are the escaping functions and the contexts each one makes a value
// safe in. A call to one of them is judged by this table in every output rule;
// in another context the escaped value is still the input.
var escapers = map[string]uint16{
	// PHP and WordPress
	"esc_html": textAttr, "esc_attr": textAttr, "esc_textarea": textAttr,
	// before PHP 8.1 the default flags leave ' alone: single quotes count only with ENT_QUOTES (escaperCall)
	"htmlspecialchars": ctxBits(ctxHTML, ctxAttr), "htmlentities": ctxBits(ctxHTML, ctxAttr),
	"esc_html__": textAttr, "esc_attr__": textAttr,
	"esc_url": ctxBits(ctxHTML, ctxAttr, ctxAttrSQ, ctxURL),
	// esc_url_raw and sanitize_url drop " < > and spaces but keep ': only a double-quoted
	// attribute that is not a URL (in a URL, the quote of the attribute is not known)
	"esc_url_raw": ctxBits(ctxAttr), "sanitize_url": ctxBits(ctxAttr),
	"esc_js":         ctxBits(ctxJSStr),
	"wp_json_encode": ctxBits(ctxJS), "json_encode": ctxBits(ctxJS),
	"urlencode": encoded, "rawurlencode": encoded,
	"wp_kses": ctxBits(ctxHTML), "wp_kses_post": ctxBits(ctxHTML), "wp_kses_data": ctxBits(ctxHTML),
	"strip_tags": ctxBits(ctxHTML), "wp_strip_all_tags": ctxBits(ctxHTML),
	"sanitize_text_field": ctxBits(ctxHTML), "sanitize_textarea_field": ctxBits(ctxHTML),
	"sanitize_key": anyCtx, "sanitize_html_class": anyCtx, "sanitize_title": encoded,
	"e": textAttr, // Laravel
	// Python
	"escape": textAttr, "html.escape": textAttr, "markupsafe.escape": textAttr, "Markup.escape": textAttr,
	"conditional_escape": textAttr, "format_html": textAttr,
	"xhtml_escape": ctxBits(ctxHTML, ctxAttr), "escape.xhtml_escape": ctxBits(ctxHTML, ctxAttr), "tornado.escape.xhtml_escape": ctxBits(ctxHTML, ctxAttr), "bleach.clean": ctxBits(ctxHTML), "escapejs": ctxBits(ctxJSStr),
	"quote": encoded, "quote_plus": encoded, "urllib.parse.quote": encoded, "urllib.parse.quote_plus": encoded, "parse.quote": encoded,
	// JavaScript
	"escapeHtml": textAttr, "he.encode": textAttr, "he.escape": textAttr, "validator.escape": textAttr, "_.escape": textAttr,
	"DOMPurify.sanitize": ctxBits(ctxHTML), "sanitizeHtml": ctxBits(ctxHTML), "xss": ctxBits(ctxHTML),
	"encodeURIComponent": uriComp, "serialize": ctxBits(ctxJS, ctxJSStr), "jsesc": ctxBits(ctxJSStr),
}

// escaperCall reads op as one call of an escaper and returns the contexts it is
// safe in and the value it escapes. The callee is looked up by its full name
// (html.escape, he.encode) and, for the names that only escape, by its own name.
func (a *analysis) escaperCall(op []Token) (safe uint16, arg []Token, ok bool) {
	n := len(op)
	if n < 3 || !op[n-1].op(")") || a.chainStart(op, n) != 0 {
		return 0, nil, false
	}
	open := openOf(op, n-1)
	if open < 1 || op[open-1].Kind != Ident {
		return 0, nil, false
	}
	var full strings.Builder
	for _, t := range op[:open] {
		switch {
		case t.Kind == Ident:
			full.WriteString(t.Text)
		case memberOp(a.php, t):
			full.WriteByte('.')
		default:
			return 0, nil, false
		}
	}
	if safe, ok = escapers[full.String()]; !ok {
		return 0, nil, false
	}
	args := splitTop(inside(op, open, n-1), isComma)
	if name := op[open-1].Text; name == "htmlspecialchars" || name == "htmlentities" {
		for _, x := range args[min(1, len(args)):] {
			for _, t := range x {
				if t.word("ENT_QUOTES") {
					safe |= ctxBits(ctxAttrSQ)
				}
			}
		}
	}
	for _, x := range args {
		for _, t := range x {
			switch {
			case t.word("ENT_NOQUOTES") || len(x) == 3 && x[0].word("quote") && x[2].word("False"):
				safe &= ctxBits(ctxHTML) // quotes left as they are: not for attributes
			case t.word("JSON_UNESCAPED_SLASHES") && !hasWord(args, "JSON_HEX_TAG"):
				safe &^= ctxBits(ctxJS) // "</script>" stays as it is (JSON_HEX_TAG would encode < and >)
			}
		}
		if len(x) == 3 && x[0].word("safe") && x[1].op("=") && x[2].Kind == Str && strings.ContainsAny(x[2].Text, ":<>\"'") {
			safe &^= ctxBits(ctxURL) // quote(x, safe=':/') keeps "javascript:"
		}
	}
	if len(args) > 0 {
		arg = args[0]
	}
	return safe, arg, true
}

// ctxHits reports whether op, written in context c, is user input there.
func (a *analysis) ctxHits(st state, op []Token, c uint8, depth int) bool {
	op = stripParens(op)
	if safe, arg, ok := a.escaperCall(op); ok && depth < 8 {
		if safe&(1<<c) != 0 {
			return false
		}
		return arg != nil && a.ctxHits(st, arg, c, depth+1) // escaped for another context: still the input
	}
	return !a.fieldOfResult(st, op) && a.hits(a.expr(st, op, false)) // calls are judged where they are read (postfix)
}

// skipInterp returns where the interpolation at off in a string's text ends:
// {...} and ${...} to the matching brace, a PHP $name with ->name and [...].
func skipInterp(text string, off int) int {
	i := off
	if i < len(text) && text[i] == '$' && i+1 < len(text) && text[i+1] == '{' {
		i++
	}
	if i < len(text) && text[i] == '{' {
		for depth := 0; i < len(text); i++ {
			switch text[i] {
			case '{':
				depth++
			case '}':
				depth--
				if depth == 0 {
					return i + 1
				}
			}
		}
		return len(text)
	}
	if i < len(text) && text[i] == '$' {
		i++
	}
	for i < len(text) && isIdentChar(text[i]) {
		i++
	}
	for i < len(text) {
		switch {
		case strings.HasPrefix(text[i:], "->"):
			i += 2
			for i < len(text) && isIdentChar(text[i]) {
				i++
			}
		case text[i] == '[':
			if j := strings.IndexByte(text[i:], ']'); j > 0 {
				i += j + 1
				continue
			}
			return len(text)
		default:
			return i
		}
	}
	return i
}

// contextTaint reports whether out, written by an output sink whose token is
// sinkTok, writes user input into one of the contexts in want. The operands of
// out are read in order (joined with "." or "+", or listed with ","), and the
// literal text before each one, fed to an HTML scanner, decides its context.
func (a *analysis) contextTaint(st state, sinkTok Token, out []Token, want []uint8) bool {
	if a.py && len(out) > 1 && out[0].Kind == Ident && out[1].op("=") {
		switch out[0].Text {
		case "content", "text", "body": // Django content=, aiohttp web.Response(text=, body=)
		default:
			return false // status=, headers=: not what the page shows
		}
		out = out[2:]
	}
	base := sinkTok.Flags >> flagCtxShift & 7
	var hs htmlScan
	fresh := base == ctxHTML // no inline HTML before: read the literal text as the start of a page
	prefix := ""             // literal text written before, in the base context (first 64 bytes)
	feed := func(text string) {
		switch {
		case text == "":
		case fresh:
			hs.feed(text)
		case strings.ContainsAny(text, "<>"):
			fresh = true // markup written here: read it as a page of its own
			hs.feed(text)
		default:
			if len(prefix) < 64 {
				prefix += text
			}
		}
	}
	at := func(op []Token) uint8 {
		c := base
		if fresh {
			c = hs.ctx()
		} else if p := strings.ToLower(strings.TrimSpace(prefix)); p != "" && c == ctxURL {
			switch {
			case strings.HasPrefix(p, "javascript:"):
				c = ctxJSAttr
			case notScheme(p):
				c = ctxAttrSQ // href="<?php echo '/x?' . $v ?>": a fixed start, no scheme (quote unknown)
			}
		}
		if c == ctxURL && op != nil && a.r.leading && a.fixedStart(st, op) {
			c = ctxAttrSQ // the value starts with a fixed part ('install.php?l=' . $l): not a scheme (quote unknown)
		}
		return c
	}
	in := func(c uint8) bool {
		for _, w := range want {
			if w == c {
				return true
			}
		}
		return false
	}
	join := "+"
	if a.php {
		join = "."
	}
	for _, op := range splitTop(stripParens(out), func(t Token) bool { return t.op(join) || t.op(",") }) {
		if !a.php && len(op) > 0 && (op[0].op("{") || op[0].op("[")) {
			continue // an object or a list is sent as JSON, not as markup
		}
		if len(op) == 1 && op[0].Kind == Str && op[0].Flags&(FlagShell|FlagRegex) == 0 {
			tk := op[0]
			prev := 0
			for _, p := range tk.Parts {
				feed(tk.Text[min(prev, p.Off):min(p.Off, len(tk.Text))])
				if c := at(p.Toks); in(c) && a.ctxHits(st, p.Toks, c, 0) {
					return true
				}
				prev = skipInterp(tk.Text, min(p.Off, len(tk.Text)))
			}
			feed(tk.Text[min(prev, len(tk.Text)):])
			continue
		}
		if c := at(op); in(c) && a.ctxHits(st, op, c, 0) {
			return true
		}
	}
	return false
}

// cleanResult are calls whose result, written to a page, is not the request
// value they were given: command output, file contents, a count, a hash, a fixed
// attribute, a yes-or-no answer (is_*, has_*, ctype_*) or stored data looked up
// with it (get_*, wp_get_*: get_users($args), get_the_title($id)). Any
// other call keeps its arguments' taint in an output rule, except escapers
// (above) and template renderers (a name with "render" or "template").
var cleanResult = words("shell_exec exec system passthru file_get_contents fread fgets file readfile " +
	"wp_remote_retrieve_body curl_exec count strlen sizeof md5 sha1 hash crc32 uniqid wp_create_nonce " +
	"number_format date gmdate human_time_diff readFile readFileSync " +
	// WordPress form helpers return a fixed attribute (" selected='selected'") or ""
	"selected checked disabled wp_readonly readonly " +
	// WordPress Walker classes render objects to markup; the arguments are depth and paging
	"walk paged_walk")

// opaqueCall reports whether op is one call (a function, method or static
// method) whose result is not the input itself (see cleanResult).
func (a *analysis) opaqueCall(st0 state, op []Token) bool {
	n := len(op)
	if n < 3 || !op[n-1].op(")") {
		return false
	}
	open := openOf(op, n-1)
	if open < 1 || a.chainStart(op, n) != 0 || op[open-1].Kind != Ident {
		return false
	}
	recv := false
	if open >= 2 && memberOp(a.php, op[open-2]) {
		recv = a.hits(a.expr(st0, op[:open-2], false))
	}
	return a.opaqueAt(st0, op, open, recv)
}

// opaqueAt reports whether the call whose "(" is at j has a result that is not
// the input it was given.
func (a *analysis) opaqueAt(st0 state, t []Token, j int, recvTaint bool) bool {
	if j == 0 || t[j-1].Kind != Ident || a.kw[t[j-1].Text] {
		return false
	}
	name := t[j-1].Text
	if a.php && j >= 3 && memberOp(true, t[j-2]) && !(t[j-2].Text == "::" && t[j-3].word("Str")) {
		// PHP strings have no methods: $query->query($args) returns what the object made
		// (Laravel's Str:: helpers are string edits and pass the input on)
		if !recvTaint {
			return true
		}
	}
	low := strings.ToLower(name)
	return cleanResult[name] || strings.Contains(low, "render") || strings.Contains(low, "template") ||
		strings.HasPrefix(name, "is_") || strings.HasPrefix(name, "has_") || strings.HasPrefix(name, "ctype_") || // yes or no
		strings.HasPrefix(name, "get_") || strings.HasPrefix(name, "wp_get_") // getters return what is stored (a source pattern still applies)
}

// joiners format or join the containers they are given, so the input inside an
// array argument is in their result: implode(', ', $tags), print_r($a, true),
// json_encode($a), JSON.stringify({ q }), json.dumps({...}).
var joiners = words("implode join print_r var_export var_dump vsprintf sprintf http_build_query serialize json_encode " +
	"wp_json_encode stringify dumps format str_replace str_ireplace preg_replace strtr")

// wholeArg reports whether one of a call's arguments is the input itself, not an
// array or object literal holding it: mb_strtolower($q) and JSON.stringify(q)
// return the input changed, plugins_api('info', ['slug' => $s]) returns what it
// looked up. In an output rule only the first kind passes the input on, except
// for the calls that format or join containers (joiners, array_*).
func (a *analysis) wholeArg(st state, inner []Token, name string) bool {
	joins := joiners[name] || strings.HasPrefix(name, "array_")
	args := splitTop(inner, isComma)
	if a.php && name == "apply_filters" {
		args = args[min(len(args), 1):min(len(args), 2)] // returns the filtered value, the second argument
	}
	for _, arg := range args {
		arg = stripParens(arg)
		if a.container(st, arg) {
			if joins && a.hits(a.argVal(st, arg, false)) {
				return true
			}
			continue // array('slug' => $s), [...], $_GET, a variable holding one: a container, not the text
		}
		if a.hits(a.argVal(st, arg, true)) {
			return true
		}
	}
	return false
}

// echoText gives an echo or print the context the page is in, and feeds the
// literal text an echo writes (outside brackets: not a call's arguments) to the
// scanner, so echo '<a href="'; echo esc_attr($u); is read as one tag.
func (s *scanner) echoText(t *Token) {
	switch {
	case t.Kind == Ident && (t.Text == "echo" || t.Text == "print") && s.depth == 0:
		t.Flags |= (s.htmlCtx - 1) << flagCtxShift
		s.inEcho, s.echoPar = true, 0
	case !s.inEcho:
	case t.Kind == Op && t.Text == ";":
		s.inEcho = false
	case isOpen(*t):
		s.echoPar++
	case isClose(*t):
		s.echoPar--
	case t.Kind == Str && s.echoPar == 0 && s.depth == 0 && t.Flags&FlagShell == 0:
		prev := 0
		for _, p := range t.Parts {
			s.hs.feed(t.Text[min(prev, p.Off):min(p.Off, len(t.Text))])
			prev = skipInterp(t.Text, min(p.Off, len(t.Text)))
		}
		s.hs.feed(t.Text[min(prev, len(t.Text)):])
		s.htmlCtx = s.hs.ctx() + 1
	}
}

func hasWord(args [][]Token, w string) bool {
	for _, x := range args {
		for _, t := range x {
			if t.word(w) {
				return true
			}
		}
	}
	return false
}
