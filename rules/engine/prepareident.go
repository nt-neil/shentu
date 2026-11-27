package engine

import "strings"

// identArgs is the ident_placeholder condition of a prepare()-style call
// ($wpdb->prepare($format, ...)): the indexes in args of the values whose
// placeholder the format puts inside backticks. $wpdb->prepare quotes a %s
// value as a string, which is safe between quotes or standing alone, but
// inside backticks the value is an identifier (a column or table name) and
// escaping it as a string does not stop it: UPDATE t SET `%s` = 1. Sequential
// placeholders (%s) take the values in order, numbered ones (%2$s) the value
// they name. The format is read from the strings written in the first argument
// (or held by a variable assigned only a literal); its other parts are not
// read, so a placeholder they would hold is not seen. In SQL comments (/* */,
// -- and # to the end of the line) quotes are no SQL's, but prepare() still
// fills their placeholders, which take their values in turn; MySQL runs the
// text of a /*! ... */ one, which is read as SQL.
// A number past the values names none (%0$s, %99999999999999999999$s).
func (a *analysis) identArgs(st state, splitArgs [][]Token) []int {
	if len(splitArgs) < 2 {
		return nil
	}
	f := a.formatText(st, splitArgs[0])
	var out []int
	seq := 0
	var quote byte
	// placeholder reads the one at f[i] ('%') and returns where it ends; one
	// in backticks (ident) whose value is a request's is listed.
	placeholder := func(i int, ident bool) int {
		if i+1 < len(f) && f[i+1] == '%' {
			return i + 1
		}
		j, n, numbered := i+1, 0, false
		for j < len(f) && f[j] >= '0' && f[j] <= '9' {
			if n <= len(splitArgs) { // past the values the number names none: it stops growing (no overflow)
				n = n*10 + int(f[j]-'0')
			}
			j++
		}
		if j < len(f) && f[j] == '$' && j > i+1 {
			j, numbered = j+1, true
		} else {
			j, n = i+1, 0 // no number: a sequential placeholder
		}
		for j < len(f) && (f[j] == '-' || f[j] == '+' || f[j] == ' ' || f[j] == '0' || f[j] == '.' || f[j] >= '1' && f[j] <= '9') {
			j++ // flags, width and precision
		}
		if j >= len(f) || !(f[j] == 's' || f[j] == 'd' || f[j] == 'f' || f[j] == 'F' || f[j] == 'i') {
			return i
		}
		if !numbered {
			seq++
			n = seq
		}
		if ident && f[j] == 's' && n >= 1 && n < len(splitArgs) { // %0$s names no value
			out = append(out, n)
		}
		return j
	}
	comment := -1 // inside an SQL comment up to this index: quotes are no SQL's, placeholders still take values
	for i := 0; i < len(f); i++ {
		c := f[i]
		if i < comment {
			if c == '%' {
				i = placeholder(i, false)
			}
			continue
		}
		switch {
		case quote == 0 && c == '/' && i+1 < len(f) && f[i+1] == '*' && !(i+2 < len(f) && f[i+2] == '!'):
			comment = len(f)
			if end := strings.Index(f[i+2:], "*/"); end >= 0 {
				comment = i + 2 + end + 2
			}
			i++
		case quote == 0 && (c == '#' || c == '-' && i+1 < len(f) && f[i+1] == '-' && (i+2 == len(f) || f[i+2] == ' ' || f[i+2] == '\t' || f[i+2] == '\n')):
			comment = len(f)
			if end := strings.IndexByte(f[i:], '\n'); end >= 0 {
				comment = i + end
			}
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
			i = placeholder(i, quote == '`')
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
			b = a.unescapeStr(b, tk.Text[at:off], tk.Flags)
			b = append(b, 0) // an interpolated value
			at = off
		}
		b = a.unescapeStr(b, tk.Text[at:], tk.Flags)
	}
	return string(b)
}

// unescapeStr appends a string literal's text as the string holds it: the
// lexer keeps PHP's escapes, which are not SQL's. A '...' string has only \\
// and \'; a nowdoc none; a "..." string or heredoc the double-quoted ones (\\,
// \", \$, \n, \t, \r, \v, \e, \f, \xHH, octal \NNN, \u{...}), where \' stays
// two characters.
func (a *analysis) unescapeStr(b []byte, s string, flags uint16) []byte {
	if !a.php || flags&flagPHPNowdoc != 0 {
		return append(b, s...)
	}
	single := flags&flagPHPSingle != 0
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 == len(s) {
			b = append(b, s[i])
			continue
		}
		c := s[i+1]
		if single {
			if c == '\\' || c == '\'' {
				b, i = append(b, c), i+1
			} else {
				b = append(b, '\\')
			}
			continue
		}
		switch c {
		case '\\', '"', '$':
			b, i = append(b, c), i+1
		case 'n', 't', 'r', 'v', 'e', 'f':
			b, i = append(b, phpEscapes[c]), i+1
		case 'x':
			j, v := i+2, 0
			for ; j < len(s) && j < i+4 && isHexDigit(s[j]); j++ {
				v = v*16 + hexVal(s[j])
			}
			if j == i+2 {
				b = append(b, '\\') // \x without a digit stays
				continue
			}
			b, i = append(b, byte(v)), j-1
		case '0', '1', '2', '3', '4', '5', '6', '7':
			j, v := i+1, 0
			for ; j < len(s) && j < i+4 && s[j] >= '0' && s[j] <= '7'; j++ {
				v = v*8 + int(s[j]-'0')
			}
			b, i = append(b, byte(v)), j-1
		case 'u':
			if i+2 < len(s) && s[i+2] == '{' {
				if end := strings.IndexByte(s[i+3:], '}'); end >= 0 {
					cp, ok := 0, end > 0
					for _, h := range []byte(s[i+3 : i+3+end]) {
						if !isHexDigit(h) || cp > 0x10ffff {
							ok = false
							break
						}
						cp = cp*16 + hexVal(h)
					}
					if ok && cp < 0x80 {
						b = append(b, byte(cp)) // \u{60} is a backtick
					} else {
						b = append(b, 0) // past ASCII: no quote of SQL's
					}
					i += 3 + end
					continue
				}
			}
			b = append(b, '\\')
		default:
			b = append(b, '\\') // not an escape: the backslash stays, the next character is read next
		}
	}
	return b
}

// phpEscapes are the one-letter escapes of a PHP "..." string.
var phpEscapes = map[byte]byte{'n': '\n', 't': '\t', 'r': '\r', 'v': '\v', 'e': 0x1b, 'f': '\f'}

func isHexDigit(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func hexVal(c byte) int {
	switch {
	case c >= 'a':
		return int(c-'a') + 10
	case c >= 'A':
		return int(c-'A') + 10
	}
	return int(c - '0')
}
