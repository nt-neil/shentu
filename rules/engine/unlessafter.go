package engine

// onlyAfter reports whether the input in a sink's arguments all comes after
// one of the texts (unless_after) in a string written there: in
// $wpdb->get_results("SELECT * FROM t ORDER BY $col") the input is only an
// ORDER BY identifier, which php-sqli-orderby-identifier reports at that text.
// Each argument is read as its concatenation ("." in PHP, "+" elsewhere): a
// string's interpolated parts and the operands after a string holding the text
// are after it. Input anywhere else (before the text, in a variable built
// elsewhere) keeps the sink.
func (a *analysis) onlyAfter(st state, texts []*pat, region []Token) bool {
	concat := "+"
	if a.php {
		concat = "."
	}
	found := func(s string) bool {
		for _, p := range texts {
			if p.text.MatchString(s) {
				return true
			}
		}
		return false
	}
	any := false
	for _, arg := range splitTop(region, isComma) {
		seen := false
		for _, op := range splitTop(arg, isOp(concat)) {
			op = stripParens(op)
			if len(op) == 1 && op[0].Kind == Str {
				tk := op[0]
				for _, p := range tk.Parts {
					seen = seen || found(tk.Text[:min(p.Off, len(tk.Text))])
					if a.expr(st, p.Toks, false).taint {
						if !seen {
							return false
						}
						any = true
					}
				}
				seen = seen || found(tk.Text)
				continue
			}
			if a.expr(st, op, false).taint {
				if !seen {
					return false
				}
				any = true
			}
		}
	}
	return any
}
