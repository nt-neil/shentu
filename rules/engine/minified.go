package engine

import "bytes"

const minifiedLine = 1000 // bytes; a line longer than this is generated, not written by hand

// Minified reports whether a JavaScript file is minified or bundled: at least
// half of its bytes are in lines longer than minifiedLine. The share, not a name
// (.min.js) or a single long line, decides. Scan then analyses the file without
// its long lines (dropLong) and returns ErrMinified with what it found, so the
// audit lists the file as not fully analysed and hand-written lines in it are
// still read.
func Minified(src []byte) bool {
	long := 0
	for rest := src; len(rest) > 0; {
		i := bytes.IndexByte(rest, '\n')
		if i < 0 {
			i = len(rest)
		}
		if i > minifiedLine {
			long += i
		}
		rest = rest[min(i+1, len(rest)):]
	}
	return len(src) > 0 && 2*long >= len(src)
}

// dropLong blanks every line longer than minifiedLine, keeping the line breaks.
func dropLong(src []byte) []byte {
	out := make([]byte, 0, len(src)/4)
	for rest := src; len(rest) > 0; {
		i := bytes.IndexByte(rest, '\n')
		if i < 0 {
			i = len(rest)
		}
		if i <= minifiedLine {
			out = append(out, rest[:i]...)
		}
		if i < len(rest) {
			out = append(out, '\n')
		}
		rest = rest[min(i+1, len(rest)):]
	}
	return out
}
