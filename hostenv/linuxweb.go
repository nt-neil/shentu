package hostenv

// Web servers on Linux: the folders nginx and Apache serve, read from
// their configuration. Moved from tools/codeaudit.go (Phase 1c), rules
// unchanged.

import (
	"errors"
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
// serve, sorted. A configuration file is read if it is a regular file of at
// most MaxWebConfBytes. A symlink (Debian's and Ubuntu's sites-enabled
// entries are links to sites-available) is followed only to a target that
// is still under /etc, owned by root and not group or world writable: what
// only root can change is what nginx itself trusts.
func (LinuxCollector) WebRoots(src Source) []string {
	seen := map[string]bool{}
	var out []string
	for _, g := range webConfGlob {
		for _, f := range Glob(src, g) {
			b, err := ReadFileNoFollow(src, f)
			if errors.Is(err, ErrSymlink) || isLink(src, f) {
				b, err = readTrustedLink(src, f)
			}
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

// isLink reports a symlink for Sources that cannot open without following.
func isLink(src Source, p string) bool {
	_, err := src.Readlink(p)
	return err == nil
}

// ErrUntrustedLink refuses a configuration link that leaves /etc, or whose
// target a non-root user could have written.
var ErrUntrustedLink = errors.New("hostenv: configuration link not trusted")

// readTrustedLink follows a configuration symlink to a target under /etc
// that root owns and only root can write.
func readTrustedLink(src Source, p string) ([]byte, error) {
	real, err := EvalSymlinks(src, p)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(real, "/etc/") {
		return nil, ErrUntrustedLink
	}
	st, err := Stat(src, real)
	if err != nil {
		return nil, err
	}
	if !st.Mode.IsRegular() || st.UID != 0 || st.Mode.Perm()&0o022 != 0 {
		return nil, ErrUntrustedLink
	}
	return ReadFileNoFollow(src, real)
}
