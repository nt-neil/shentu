package engine

import "strings"

// WordPress plugins often keep the global $wpdb in a property and query
// through it: $this->wpdb = $wpdb (or =& $wpdb, = &$wpdb) in a constructor,
// then $this->wpdb->get_results($sql); self::$mysqli =& $wpdb, then
// self::$mysqli->get_results($sql). wpdbProps rewrites such a property, where
// it is used as an object (followed by ->), to $wpdb, so the rules' $wpdb
// sinks and sanitizers ($wpdb->prepare) match it. Only a property every
// assignment of the file gives $wpdb is rewritten: the file must show it. A
// name (db, wpdb) alone says nothing, and a property set in another file (a
// parent class's constructor) is not seen.
func wpdbProps(toks []Token) []Token {
	only := map[string]bool{} // property → every assignment of the file gives it $wpdb
	for i := range toks {
		key, n := wpdbPropAt(toks, i)
		if n == 0 || i+n >= len(toks) {
			continue
		}
		op := toks[i+n]
		if op.Kind != Op || !phpAssignOps[op.Text] {
			continue
		}
		k := i + n + 1
		if op.Text == "=" && k < len(toks) && toks[k].op("&") {
			k++ // = &$wpdb
		}
		ok := op.Text == "=" && k < len(toks) && toks[k].Kind == Var && toks[k].Text == "$wpdb" &&
			(k+1 == len(toks) || toks[k+1].op(";"))
		if prev, seen := only[key]; seen {
			ok = ok && prev
		}
		only[key] = ok
	}
	var out []Token
	for i := 0; i < len(toks); i++ {
		if key, n := wpdbPropAt(toks, i); n > 0 && only[key] && i+n < len(toks) && toks[i+n].op("->") {
			if out == nil {
				out = append(make([]Token, 0, len(toks)), toks[:i]...)
			}
			out = append(out, Token{Kind: Var, Text: "$wpdb", Line: toks[i].Line})
			i += n - 1
			continue
		}
		if out != nil {
			out = append(out, toks[i])
		}
	}
	if out == nil {
		return toks
	}
	return out
}

// wpdbPropAt reads a property at toks[i]: $this->name (not a method call) or
// self::$name, static::$name. It returns the property's key and its length in
// tokens, 0 for none.
func wpdbPropAt(toks []Token, i int) (string, int) {
	if i+2 >= len(toks) || i > 0 && (toks[i-1].op("->") || toks[i-1].op("::") || toks[i-1].op("?->")) {
		return "", 0
	}
	switch {
	case toks[i].Kind == Var && toks[i].Text == "$this" && toks[i+1].op("->") && toks[i+2].Kind == Ident:
		if i+3 < len(toks) && toks[i+3].op("(") {
			return "", 0 // $this->name(): a method
		}
		return "this:" + toks[i+2].Text, 3
	case toks[i].Kind == Ident && (strings.EqualFold(toks[i].Text, "self") || strings.EqualFold(toks[i].Text, "static")) &&
		toks[i+1].op("::") && toks[i+2].Kind == Var:
		return "static:" + toks[i+2].Text, 3
	}
	return "", 0
}

// phpAssignOps are the operators assigning to what is on their left.
var phpAssignOps = map[string]bool{"=": true, ".=": true, "+=": true, "-=": true, "*=": true, "/=": true, "%=": true,
	"**=": true, "??=": true, "|=": true, "&=": true, "^=": true, "<<=": true, ">>=": true}
