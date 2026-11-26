package engine

// identArgs is the ident_placeholder condition of a prepare()-style call
// ($wpdb->prepare($format, ...)): the indexes in args of the values whose
// placeholder the format puts inside backticks. $wpdb->prepare quotes a %s
// value as a string, which is safe between quotes or standing alone, but
// inside backticks the value is an identifier (a column or table name) and
// escaping it as a string does not stop it: UPDATE t SET `%s` = 1. Sequential
// placeholders (%s) take the values in order, numbered ones (%2$s) the value
// they name. The format is read from the strings written in the first argument
// (or held by a variable assigned only a literal); its other parts are not
// read, so a placeholder they would hold is not seen.
func (a *analysis) identArgs(st state, splitArgs [][]Token) []int {
	if len(splitArgs) < 2 {
		return nil
	}
	f := a.formatText(st, splitArgs[0])
	var out []int
	seq := 0
	var quote byte
	for i := 0; i < len(f); i++ {
		c := f[i]
		switch {
		case c == '\\' && quote != '`':
			i++ // an escaped character in an SQL string
		case c == '\'' || c == '"' || c == '`':
			switch quote {
			case 0:
				quote = c
			case c:
				quote = 0
			}
		case c == '%':
			if i+1 < len(f) && f[i+1] == '%' {
				i++
				continue
			}
			j, n := i+1, 0
			for j < len(f) && f[j] >= '0' && f[j] <= '9' {
				n = n*10 + int(f[j]-'0')
				j++
			}
			if j < len(f) && f[j] == '$' && j > i+1 {
				j++
			} else {
				j, n = i+1, 0 // no number: a sequential placeholder
			}
			for j < len(f) && (f[j] == '-' || f[j] == '+' || f[j] == ' ' || f[j] == '0' || f[j] == '.' || f[j] >= '1' && f[j] <= '9') {
				j++ // flags, width and precision
			}
			if j >= len(f) || !(f[j] == 's' || f[j] == 'd' || f[j] == 'f' || f[j] == 'F' || f[j] == 'i') {
				continue
			}
			if n == 0 {
				seq++
				n = seq
			}
			if f[j] == 's' && quote == '`' && n < len(splitArgs) {
				out = append(out, n)
			}
			i = j
		}
	}
	return out
}

// formatText joins the strings written in a format argument, each part that is
// no string standing for one unknown character.
func (a *analysis) formatText(st state, arg []Token) string {
	concat := "."
	if !a.php {
		concat = "+"
	}
	var b []byte
	for _, op := range splitTop(a.expandLits(st, arg), isOp(concat)) {
		op = stripParens(op)
		if len(op) != 1 || op[0].Kind != Str {
			b = append(b, 0)
			continue
		}
		tk := op[0]
		at := 0
		for _, p := range tk.Parts {
			off := min(max(p.Off, at), len(tk.Text))
			b = append(b, tk.Text[at:off]...)
			b = append(b, 0) // an interpolated value
			at = off
		}
		b = append(b, tk.Text[at:]...)
	}
	return string(b)
}
