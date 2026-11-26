package engine

import (
	"strconv"
	"strings"
)

// WordPress plugins often keep the global $wpdb in a property and query
// through it: $this->wpdb = $wpdb (or =& $wpdb, = &$wpdb) in a constructor,
// then $this->wpdb->get_results($sql); self::$mysqli =& $wpdb, then
// self::$mysqli->get_results($sql). wpdbProps rewrites such a property, where
// it is used as an object (followed by ->), to $wpdb, so the rules' $wpdb
// sinks and sanitizers ($wpdb->prepare) match it.
//
// Only a property every assignment gives $wpdb is rewritten, and the file must
// show it: a name (db, wpdb) alone says nothing, and a property set in another
// file (a parent class's constructor) is not seen. A property is the class's
// (or trait's) it is written in: another class of the file with a property of
// that name neither makes it $wpdb nor keeps it from being one. A class also
// has the properties of the traits of the file it uses. self:: and static::
// name one property. A destructuring ([$this->db] = ..., list($this->db) =
// ...), a reference (&$this->db) or a foreach target (as $this->db) counts as
// giving it something else. ClassName::$db, parent::$db and $GLOBALS['wpdb']
// are not read.
func wpdbProps(toks []Token) []Token {
	scope, traits := phpClassScopes(toks)
	only := map[string]bool{} // scope + property → every assignment gives it $wpdb
	set := func(key string, ok bool) {
		if prev, seen := only[key]; seen {
			ok = ok && prev
		}
		only[key] = ok
	}
	for i := range toks {
		prop, n := wpdbPropAt(toks, i)
		if n == 0 || i+n >= len(toks) {
			continue
		}
		key := scope[i] + "\x00" + prop
		if indirectWrite(toks, i, n) {
			set(key, false)
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
		set(key, op.Text == "=" && k < len(toks) && toks[k].Kind == Var && toks[k].Text == "$wpdb" &&
			(k+1 == len(toks) || toks[k+1].op(";")))
	}
	// is reports whether the property is $wpdb in the scope: assigned there or
	// in the traits it uses, and only ever $wpdb.
	is := func(sc, prop string) bool {
		ok, any := true, false
		for _, s := range append([]string{sc}, traits[sc]...) {
			if v, seen := only[s+"\x00"+prop]; seen {
				ok, any = ok && v, true
			}
		}
		return ok && any
	}
	var out []Token
	for i := 0; i < len(toks); i++ {
		if prop, n := wpdbPropAt(toks, i); n > 0 && i+n < len(toks) && toks[i+n].op("->") && is(scope[i], prop) {
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
// self::$name, static::$name. It returns the property and its length in
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

// indirectWrite reports whether the property at toks[i:i+n] is written some
// other way than by an assignment operator after it: taken by reference
// (&$this->db), a foreach target (as $this->db) or a destructured item
// ([$this->db] = ..., list($a, $this->db) = ...).
func indirectWrite(toks []Token, i, n int) bool {
	if i == 0 {
		return false
	}
	prev := toks[i-1]
	if prev.op("&") || prev.word("as") {
		return true
	}
	if !prev.op("[") && !prev.op(",") && !prev.op("(") && !prev.op("=>") {
		return false
	}
	depth := 0
	for j := i - 1; j >= 0 && i-j < 256; j-- {
		switch {
		case isClose(toks[j]):
			depth++
		case isOpen(toks[j]) && depth > 0:
			depth--
		case isOpen(toks[j]):
			if toks[j].op("[") && j > 0 && (toks[j-1].Kind == Var || toks[j-1].Kind == Ident || toks[j-1].op("]") || toks[j-1].op(")") || toks[j-1].op("}")) {
				return false // $rows[$this->db]: an index, read
			}
			c := closeOf(toks, j)
			assigned := c+1 < len(toks) && toks[c+1].op("=")
			return assigned && (toks[j].op("[") || toks[j].op("(") && j > 0 && toks[j-1].word("list"))
		}
	}
	return false
}

// phpClassScopes names, for each token, the class, trait, interface or enum
// it is written in ("" outside any; an anonymous class by its position), and
// gives each scope the traits of the file it uses (use T1, T2; in its body).
func phpClassScopes(toks []Token) (scope []string, traits map[string][]string) {
	scope = make([]string, len(toks))
	traits = map[string][]string{}
	var fill func(from, to int, name string)
	fill = func(from, to int, name string) {
		for i := from; i < to && i < len(toks); i++ {
			scope[i] = name
			tk := toks[i]
			if !(tk.word("class") || tk.word("trait") || tk.word("interface") || tk.word("enum")) || i > 0 && toks[i-1].op("::") {
				continue
			}
			inner := ""
			switch {
			case i+1 < len(toks) && toks[i+1].Kind == Ident && !(i > 0 && toks[i-1].word("new")):
				inner = toks[i+1].Text
			case tk.word("class") && i > 0 && toks[i-1].word("new"):
				inner = "new@" + strconv.Itoa(i)
			default:
				continue
			}
			open := i + 1
			for open < len(toks) && !toks[open].op("{") && !toks[open].op(";") {
				open++
			}
			if open >= len(toks) || !toks[open].op("{") {
				continue
			}
			end := closeOf(toks, open)
			for j := i; j < open; j++ {
				scope[j] = name
			}
			// use T1, \N\T2; at the top of the body
			for j := open + 1; j < end; j++ {
				if toks[j].op("{") {
					j = closeOf(toks, j)
					continue
				}
				if toks[j].word("use") && j+1 < end && !toks[j+1].op("(") {
					last := ""
					for k := j + 1; k < end && !toks[k].op(";") && !toks[k].op("{"); k++ {
						if toks[k].Kind == Ident {
							last = toks[k].Text
						}
						if toks[k+1].op(",") || toks[k+1].op(";") || toks[k+1].op("{") {
							if last != "" {
								traits[inner] = append(traits[inner], last)
							}
							last = ""
						}
					}
				}
			}
			fill(open, end+1, inner)
			i = end
		}
	}
	fill(0, len(toks), "")
	return scope, traits
}

// phpAssignOps are the operators assigning to what is on their left.
var phpAssignOps = map[string]bool{"=": true, ".=": true, "+=": true, "-=": true, "*=": true, "/=": true, "%=": true,
	"**=": true, "??=": true, "|=": true, "&=": true, "^=": true, "<<=": true, ">>=": true}
