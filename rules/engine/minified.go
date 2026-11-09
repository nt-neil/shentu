package engine

import "bytes"

const (
	minifiedLine = 1000    // non-blank bytes; a line longer than this is generated, not written by hand
	minifiedSize = 8 << 10 // a smaller file is read whole, whatever its lines
)

// Minified reports whether a JavaScript file is minified or bundled: it is at
// least minifiedSize bytes and at least half of its non-blank bytes are in lines
// with more than minifiedLine non-blank bytes. Blank padding does not count, so
// a padded line in a hand-written file does not make it look generated. Scan
// then reads the file without its long lines (dropLong) and returns ErrMinified
// with what it found, joined with ErrPartial or ErrLimit when the shortened
// file has an unterminated string or hits a limit.
func Minified(src []byte) bool {
	if len(src) < minifiedSize {
		return false
	}
	long, all := 0, 0
	for rest := src; len(rest) > 0; {
		i := bytes.IndexByte(rest, '\n')
		if i < 0 {
			i = len(rest)
		}
		n := nonBlank(rest[:i])
		all += n
		if n > minifiedLine {
			long += n
		}
		rest = rest[min(i+1, len(rest)):]
	}
	return all > 0 && 2*long >= all
}

func nonBlank(line []byte) int {
	n := 0
	for _, c := range line {
		if !isSpace(c) && c != '\v' {
			n++
		}
	}
	return n
}

// dropLong blanks every line with more than minifiedLine non-blank bytes,
// keeping the line breaks, so line numbers stay the same.
func dropLong(src []byte) []byte {
	out := make([]byte, 0, len(src)/4)
	for rest := src; len(rest) > 0; {
		i := bytes.IndexByte(rest, '\n')
		if i < 0 {
			i = len(rest)
		}
		if nonBlank(rest[:i]) <= minifiedLine {
			out = append(out, rest[:i]...)
		}
		if i < len(rest) {
			out = append(out, '\n')
		}
		rest = rest[min(i+1, len(rest)):]
	}
	return out
}
