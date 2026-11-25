package engine

// numberOnly reports a rule a number cannot inject into: SQL and markup, where
// a value needs a quote, a keyword or a tag to change what the text means. A
// path rule is not one: a number can still name another file (log1 . $n).
func (a *analysis) numberOnly() bool {
	c := a.r.rule.Class
	return c == "sqli" || c == "xss"
}

// arithmetic reports an expression whose result is a number: its operators at
// the top level are all arithmetic, with at least one. PHP's + - * / % ** give
// an int or a float whatever the operands (PHP 8 throws on a string that is
// no number; PHP 7 reads its leading digits), but + of two arrays joins them, so
// a binary + counts only next to a number literal ($page + 1). JavaScript's - * / % ** and unary
// + and - give a number; its binary + joins strings. Python's - and / count
// only next to a number literal (n - 1), like PHP's +: - of two sets or two
// Counters is their difference (set(request.args.getlist('id')) - {"0"}), a
// unary - of a Counter is a Counter, and both hold the input's own strings. Its
// // gives a number or raises; its * repeats and % formats a string, + joins.
// Bitwise operators are left out (PHP's | & ^ on two strings give a string),
// and so are ++ and -- ("a"++ is "b" in PHP).
func (a *analysis) arithmetic(t []Token) bool {
	found := false
	for i := 0; i < len(t); i++ {
		tk := t[i]
		if isOpen(tk) {
			if c := closeOf(t, i); c > i {
				i = c
				continue
			}
			return false
		}
		if tk.Kind != Op {
			continue
		}
		switch x := tk.Text; {
		case a.memberOrScope(tk):
		case x == "-" || x == "/":
			if a.py && !numNext(t, i) {
				return false
			}
			found = true
		case x == "*" || x == "%" || x == "**":
			if a.py && x != "**" {
				return false
			}
			found = true
		case x == "+":
			unary := i == 0 || t[i-1].Kind == Op && !isClose(t[i-1])
			switch {
			case a.py || a.js && !unary:
				return false
			case a.php && !unary && !numNext(t, i):
				return false // $a + $b of two arrays is their union, the input's own values
			}
			found = true
		case x == "//" && a.py:
			found = true
		default:
			return false
		}
	}
	return found
}

// numNext reports a number literal right before or after the operator at i.
func numNext(t []Token, i int) bool {
	return i > 0 && t[i-1].Kind == Num || i+1 < len(t) && t[i+1].Kind == Num
}

// memberOrScope reports an operator that reads a member or names a scope, which
// leaves the value a term: $o->n, A::$x, o.n, o?.n, \A\f.
func (a *analysis) memberOrScope(tk Token) bool {
	switch tk.Text {
	case "->", "?->", "::", "\\", ".", "?.":
		return tk.Text != "." || !a.php
	}
	return false
}
