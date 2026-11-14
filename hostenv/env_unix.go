//go:build !windows

package hostenv

// fixedEnv is the whole environment a command sees: no tokens, no proxies,
// no user PATH, and C locale so parsers see stable output.
func fixedEnv() []string {
	return []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "LANG=C"}
}
