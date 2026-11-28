package hostenv

import (
	"path"
	"strings"
)

// winPaths are a Windows host's path operations on any OS (v0.5.9, plan
// t15): drive letters and UNC volumes, "\" (and "/") between elements, as
// filepath does on Windows, so a Windows recording replayed on Linux or
// macOS is read as Windows reads it. On Windows itself filepath is used;
// TestWinPathsAsFilepath holds the two to the same answers there.
var winPaths = PathOps{winJoin, winDir, winBase, winClean, winExt, winMatch, winFromSlash, winIsAbs, `\`}

func winSep(c byte) bool { return c == '\\' || c == '/' }

func winFromSlash(p string) string { return strings.ReplaceAll(p, "/", `\`) }

// winVolume is p's volume: "C:", or a UNC "\\host\share" (either slash).
func winVolume(p string) string {
	if len(p) >= 2 && p[1] == ':' && (p[0]|0x20 >= 'a' && p[0]|0x20 <= 'z') {
		return p[:2]
	}
	if len(p) >= 5 && winSep(p[0]) && winSep(p[1]) && !winSep(p[2]) && p[2] != '.' && p[2] != '?' {
		// \\host\share: the host, then the share, each up to a separator.
		n := 2
		for n < len(p) && !winSep(p[n]) {
			n++
		}
		if n < len(p) {
			m := n + 1
			for m < len(p) && !winSep(p[m]) {
				m++
			}
			if m > n+1 {
				return p[:m]
			}
		}
	}
	return ""
}

func winClean(p string) string {
	vol := winVolume(p)
	rest := winFromSlash(p[len(vol):])
	vol = winFromSlash(vol)
	if rest == "" {
		if len(vol) > 2 { // a UNC share
			return vol
		}
		return vol + "."
	}
	rooted := rest[0] == '\\'
	var out []string
	for _, e := range strings.Split(rest, `\`) {
		switch e {
		case "", ".":
		case "..":
			if len(out) > 0 && out[len(out)-1] != ".." {
				out = out[:len(out)-1]
			} else if !rooted {
				out = append(out, "..")
			}
		default:
			out = append(out, e)
		}
	}
	s := strings.Join(out, `\`)
	switch {
	case rooted:
		s = `\` + s
	case s == "":
		s = "."
	}
	return vol + s
}

func winJoin(elem ...string) string {
	var parts []string
	for _, e := range elem {
		if e != "" {
			parts = append(parts, e)
		}
	}
	if len(parts) == 0 {
		return ""
	}
	// A drive alone ("C:") and a relative element: relative to that
	// drive's current folder, as filepath.Join gives "C:x".
	if len(parts[0]) == 2 && parts[0][1] == ':' && winVolume(parts[0]) == parts[0] {
		if len(parts) == 1 {
			return winClean(parts[0])
		}
		return winClean(parts[0] + strings.Join(parts[1:], `\`))
	}
	return winClean(strings.Join(parts, `\`))
}

func winDir(p string) string {
	vol := winVolume(p)
	i := len(p) - 1
	for i >= len(vol) && !winSep(p[i]) {
		i--
	}
	dir := winClean(p[len(vol) : i+1])
	if dir == "." && len(vol) > 2 {
		return winFromSlash(vol)
	}
	return winFromSlash(vol) + dir
}

func winBase(p string) string {
	if p == "" {
		return "."
	}
	for len(p) > 0 && winSep(p[len(p)-1]) {
		p = p[:len(p)-1]
	}
	p = p[len(winVolume(p)):]
	i := len(p) - 1
	for i >= 0 && !winSep(p[i]) {
		i--
	}
	if i >= 0 {
		p = p[i+1:]
	}
	if p == "" {
		return `\`
	}
	return p
}

func winExt(p string) string {
	for i := len(p) - 1; i >= 0 && !winSep(p[i]); i-- {
		if p[i] == '.' {
			return p[i:]
		}
	}
	return ""
}

func winIsAbs(p string) bool {
	vol := winVolume(p)
	if vol == "" {
		return false
	}
	if len(vol) > 2 { // UNC
		return true
	}
	rest := p[len(vol):]
	return rest != "" && winSep(rest[0])
}

// winMatch is filepath.Match as on Windows: "\" separates, never escapes.
func winMatch(pattern, name string) (bool, error) {
	return path.Match(strings.ReplaceAll(pattern, `\`, "/"), strings.ReplaceAll(name, `\`, "/"))
}
