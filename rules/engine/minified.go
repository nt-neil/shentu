package engine

import "bytes"

const (
	minifiedLine = 1000    // non-blank bytes; a line longer than this is generated, not written by hand
	minifiedSize = 8 << 10 // a smaller file is read whole, whatever its lines
)

// Minified reports whether a JavaScript file is minified or bundled: it is at
// least minifiedSize bytes and at least half of its non-blank bytes are in lines
// with more than minifiedLine non-blank bytes. Blank padding does not count.
// Such a file is read like any other, every line of it; when it stops early,
// Scan joins ErrMinified to ErrLimit or ErrPartial.
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
