package sig

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/nt-neil/shentu/hostenv"
)

// The version orders of OS packages (plan 0743f0, P5): Debian's (dpkg, as
// Debian policy 5.6.12 and dpkg's verrevcmp give it) and rpm's (rpmvercmp,
// hostenv.CompareEVR). An ecosystem's release after ":" (OSV's Debian:12)
// is the same order.

// ComparesVersions says whether ranges of ecosystem are compared: a
// signature's range for one that is not is refused, and its packages'
// versions are never ordered (a candidate is VersionUnknown).
func ComparesVersions(ecosystem string) bool { return ecosystemKind(ecosystem) != "" }

// ecosystemKind is the version order of ecosystem: "semver" (npm,
// Packagist, WordPress), "dpkg", "rpm", or "" for one not compared.
func ecosystemKind(ecosystem string) string {
	base, _, _ := strings.Cut(strings.ToLower(strings.TrimSpace(ecosystem)), ":")
	switch base {
	case "npm", "packagist", "wordpress":
		return "semver"
	case "debian", "ubuntu":
		return "dpkg"
	case "red hat", "redhat", "rocky linux", "almalinux", "amazon linux", "centos", "fedora", "opensuse", "suse", "sles":
		return "rpm"
	}
	return ""
}

var (
	// [epoch:]upstream[-revision]: upstream starts with a digit and holds
	// letters, digits and . + ~ - : (policy 5.6.12); the revision letters,
	// digits and + . ~.
	dpkgRe = regexp.MustCompile(`^(?:(\d+):)?([0-9][A-Za-z0-9.+~:-]*?)(?:-([A-Za-z0-9.+~]+))?$`)
	// [epoch:]version[-release], rpm's characters.
	rpmRe = regexp.MustCompile(`^(?:\d+:)?[A-Za-z0-9._+~^]+(?:-[A-Za-z0-9._+~^]+)?$`)
)

// validOS: v is a version of the ecosystem kind's syntax.
func validOS(kind, v string) bool {
	switch kind {
	case "dpkg":
		return dpkgRe.MatchString(v)
	case "rpm":
		return rpmRe.MatchString(v)
	}
	return false
}

// DpkgCompare compares two Debian versions as dpkg does: -1, 0 or 1.
func DpkgCompare(a, b string) int {
	ea, ua, ra := dpkgSplit(a)
	eb, ub, rb := dpkgSplit(b)
	if ea != eb {
		return cmpInt(ea, eb)
	}
	if c := verrevcmp(ua, ub); c != 0 {
		return c
	}
	return verrevcmp(ra, rb)
}

// dpkgSplit is a version's epoch (0 when none), upstream and revision
// (after the last -, "" when none).
func dpkgSplit(v string) (int, string, string) {
	epoch := 0
	if e, rest, ok := strings.Cut(v, ":"); ok {
		if n, err := strconv.Atoi(e); err == nil {
			epoch, v = n, rest
		}
	}
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		return epoch, v[:i], v[i+1:]
	}
	return epoch, v, ""
}

// order is a character's weight in dpkg's comparison: ~ before the end,
// the end before letters, letters before anything else.
func order(s string, i int) int {
	if i >= len(s) {
		return 0
	}
	c := s[i]
	switch {
	case c >= '0' && c <= '9':
		return 0
	case c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z':
		return int(c)
	case c == '~':
		return -1
	}
	return int(c) + 256
}

func isDigit(s string, i int) bool { return i < len(s) && s[i] >= '0' && s[i] <= '9' }

// verrevcmp is dpkg's: runs of non-digits by order, runs of digits as
// numbers.
func verrevcmp(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		for i < len(a) && !isDigit(a, i) || j < len(b) && !isDigit(b, j) {
			if ac, bc := order(a, i), order(b, j); ac != bc {
				return cmpInt(ac, bc)
			}
			i, j = i+1, j+1
		}
		for i < len(a) && a[i] == '0' {
			i++
		}
		for j < len(b) && b[j] == '0' {
			j++
		}
		first := 0
		for isDigit(a, i) && isDigit(b, j) {
			if first == 0 {
				first = cmpInt(int(a[i]), int(b[j]))
			}
			i, j = i+1, j+1
		}
		if isDigit(a, i) {
			return 1
		}
		if isDigit(b, j) {
			return -1
		}
		if first != 0 {
			return first
		}
	}
	return 0
}

// compareOS compares a and b of an OS ecosystem kind; ok is false for a
// version not of its syntax.
func compareOS(kind, a, b string) (int, bool) {
	if !validOS(kind, a) || !validOS(kind, b) {
		return 0, false
	}
	if kind == "dpkg" {
		return DpkgCompare(a, b), true
	}
	return hostenv.CompareEVR(a, b), true
}
