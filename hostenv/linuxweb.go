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

// WebConf says where web server configuration may live: the files a
// symlink in it may point to are regular files under Root, owned by Owner,
// that only their owner can write (Debian and Ubuntu enable a site by a
// symlink in sites-enabled).
type WebConf struct {
	Globs []string
	Root  string
	Owner int
}

// DefaultWebConf is the real machine's.
var DefaultWebConf = WebConf{Globs: webConfGlob, Root: "/etc", Owner: 0}

// WebRoots returns the folders nginx or Apache serve, sorted.
func (c LinuxCollector) WebRoots(src Source) []string {
	roots, _ := c.WebRootsReport(src, DefaultWebConf)
	return roots
}

// WebRootsReport returns the folders the configuration names, and the
// configuration files it could not read, each as "path (why)": the roots
// they name are missing. (tools/codeaudit.go webRootsFrom as of v0.2.5.)
func (LinuxCollector) WebRootsReport(src Source, conf WebConf) (roots, unreadable []string) {
	seen := map[string]bool{}
	for _, g := range conf.Globs {
		for _, f := range Glob(src, g) {
			b, why := readWebConf(src, f, conf)
			if why != "" {
				unreadable = append(unreadable, f+" ("+why+")")
				continue
			}
			for _, p := range ParseWebRoots(b) {
				if !seen[p] {
					seen[p] = true
					roots = append(roots, p)
				}
			}
		}
	}
	sort.Strings(roots)
	return roots, unreadable
}

// readWebConf reads one configuration file, following a symlink only to a
// trusted target (see WebConf); why says what kept it from being read.
func readWebConf(src Source, p string, conf WebConf) (b []byte, why string) {
	target := p
	if _, err := src.Readlink(p); err == nil {
		real, err := EvalSymlinks(src, p)
		if err != nil { // a loop ends here too
			return nil, "symlink: " + whyUnread(err)
		}
		target = real
		if !underDir(target, conf.Root) {
			return nil, "symlink to " + target + ", outside " + conf.Root
		}
		st, err := Stat(src, target)
		if err != nil {
			return nil, whyUnread(err)
		}
		switch {
		case !st.Mode.IsRegular():
			return nil, "symlink to " + target + ", not a regular file"
		case st.UID != conf.Owner:
			return nil, "symlink to " + target + ", not owned by root"
		case st.Mode.Perm()&0o022 != 0:
			return nil, "symlink to " + target + ", writable by others than its owner"
		}
	} else if _, err := Stat(src, p); err != nil && !errors.Is(err, ErrNoStat) && !errors.Is(err, ErrNotRecorded) {
		return nil, whyUnread(err)
	}
	b, err := ReadFileNoFollow(src, target) // no symlink left
	if err != nil || len(b) > MaxWebConfBytes {
		return nil, "not a regular file of at most 1 MiB, or changed while read"
	}
	return b, ""
}

// underDir reports whether p is dir or below it.
func underDir(p, dir string) bool {
	dir = strings.TrimSuffix(path.Clean(dir), "/")
	return p == dir || strings.HasPrefix(p, dir+"/")
}

// Web is the web fact: which server is configured, what it serves, and
// which configuration files could not be read.
func (c LinuxCollector) Web(src Source) Obs[Web] {
	roots, unread := c.WebRootsReport(src, DefaultWebConf)
	w := Web{WebRoots: roots, ConfigUnreadable: unread}
	switch {
	case exists(src, "/etc/nginx/nginx.conf"):
		w.Server = "nginx"
	case exists(src, "/etc/apache2/apache2.conf"):
		w.Server = "apache"
	case exists(src, "/etc/httpd/conf/httpd.conf"):
		w.Server = "apache"
	}
	if len(unread) > 0 {
		return Partial(w, ReasonPermission, "some web server configuration unread; its web roots are missing")
	}
	return OK(w)
}
