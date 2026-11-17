package engine

// onlyAfter reports whether the input in a sink's arguments all comes after
// one of the texts (unless_after) in a string written there: in
// $wpdb->get_results("SELECT * FROM t ORDER BY $col") the input is only an
// ORDER BY identifier, which php-sqli-orderby-identifier reports at that text.
// Each argument is read as its concatenation ("." in PHP, "+" elsewhere): a
// string's interpolated parts and the operands after a string holding the text
// are after it. A call written there (DB::raw("... ORDER BY " . $col)) is read
// by its own arguments. Input anywhere else (before the text, in a variable
// built elsewhere) keeps the sink.
func (a *analysis) onlyAfter(st state, texts []*pat, region []Token) bool {
	ok, any := a.afterIn(st, texts, region)
	return ok && any
}

// afterIn is onlyAfter's walk: ok is false when input comes before the texts,
// any reports input after them.
func (a *analysis) afterIn(st state, texts []*pat, region []Token) (ok, any bool) {
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
	for _, arg := range splitTop(region, isComma) {
		seen := false
		for _, op := range splitTop(arg, isOp(concat)) {
			// ("... ORDER BY ") . $c: php-sqli-orderby-identifier's text sink does
			// not read past the ")", so a string in parentheses does not count
			// as the text and the sink keeps the input after it.
			if len(op) == 1 && op[0].Kind == Str {
				tk := op[0]
				for _, p := range tk.Parts {
					seen = seen || found(tk.Text[:min(p.Off, len(tk.Text))])
					if a.expr(st, p.Toks, false).taint {
						if !seen {
							return false, any
						}
						any = true
					}
				}
				seen = seen || found(tk.Text)
				continue
			}
			if a.expr(st, op, false).taint {
				if !seen {
					open := callOpen(op)
					if open < 0 {
						return false, any
					}
					sub, subAny := a.afterIn(st, texts, inside(op, open, len(op)-1))
					if !sub || !subAny {
						return false, any
					}
				}
				any = true
			}
		}
	}
	return true, any
}

// callOpen returns the index of the "(" of op when op is one call, name(...)
// or A::name(...), and -1 otherwise.
func callOpen(op []Token) int {
	for j, tk := range op {
		if tk.op("(") {
			if j == 0 || closeOf(op, j) != len(op)-1 {
				return -1
			}
			return j
		}
		if tk.Kind != Ident && !tk.op("::") && !tk.op("\\") {
			return -1
		}
	}
	return -1
}
