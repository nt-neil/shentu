package hostenv

// Web servers on Linux: the folders nginx and Apache serve, read from
// their configuration. Moved from tools/codeaudit.go (Phase 1c), rules
// unchanged.

import (
	"path"
	"regexp"
	"sort"
	"strings"
)

var (
	nginxRoot   = regexp.MustCompile(`(?m)^\s*root\s+["']?([^"';\s]+)`)
	apacheRoot  = regexp.MustCompile(`(?mi)^\s*DocumentRoot\s+["']?([^"'\s]+)`)
	webConfGlob = []string{
		"/etc/nginx/nginx.conf", "/etc/nginx/sites-enabled/*", "/etc/nginx/conf.d/*.conf",
		"/etc/apache2/sites-enabled/*", "/etc/httpd/conf/httpd.conf", "/etc/httpd/conf.d/*.conf",
	}
)

// MaxWebConfBytes skips configuration files larger than this.
const MaxWebConfBytes = 1 << 20

// ParseWebRoots returns the absolute, variable-free roots that an nginx
// "root" or Apache "DocumentRoot" line names.
func ParseWebRoots(b []byte) []string {
	var out []string
	for _, re := range []*regexp.Regexp{nginxRoot, apacheRoot} {
		for _, m := range re.FindAllSubmatch(b, -1) {
			p := path.Clean(string(m[1]))
			if strings.HasPrefix(p, "/") && !strings.Contains(p, "$") {
				out = append(out, p)
			}
		}
	}
	return out
}

// WebRoots reads the nginx and Apache configuration for the folders they
// serve, sorted. A configuration file is read only if it is a regular file
// of at most MaxWebConfBytes and not a symlink, as tools did (Debian's
// sites-enabled entries are links, so they are skipped: see the 1c notes).
func (LinuxCollector) WebRoots(src Source) []string {
	seen := map[string]bool{}
	var out []string
	for _, g := range webConfGlob {
		for _, f := range Glob(src, g) {
			b, err := ReadFileNoFollow(src, f)
			if err != nil || len(b) > MaxWebConfBytes {
				continue
			}
			for _, p := range ParseWebRoots(b) {
				if !seen[p] {
					seen[p] = true
					out = append(out, p)
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

// Web is the web fact: which server is configured and what it serves.
func (c LinuxCollector) Web(src Source) Obs[Web] {
	w := Web{WebRoots: c.WebRoots(src)}
	switch {
	case exists(src, "/etc/nginx/nginx.conf"):
		w.Server = "nginx"
	case exists(src, "/etc/apache2/apache2.conf"):
		w.Server = "apache"
	case exists(src, "/etc/httpd/conf/httpd.conf"):
		w.Server = "apache"
	}
	return OK(w)
}
