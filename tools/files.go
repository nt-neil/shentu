package tools

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nt-neil/shentu/hostenv"
)

var fileChanges = Tool{
	Name:        "file_changes",
	Description: "Files under the watched directories that were created or modified recently. Web script files are also scanned for webshell patterns (eval of request data, base64-decoded code, system/exec calls).",
	Params: schema(`{"type":"object","properties":{
		"since_hours":{"type":"number","description":"look back this many hours (default 24)"},
		"path":{"type":"string","description":"only this directory (must be inside a watched path)"}}}`),
	Run: func(ctx context.Context, env *Env, args json.RawMessage) (any, error) {
		var a struct {
			SinceHours float64 `json:"since_hours"`
			Path       string  `json:"path"`
		}
		if err := decode(args, &a); err != nil {
			return nil, err
		}
		roots := env.WatchPaths
		if a.Path != "" {
			if !insideAny(a.Path, env.WatchPaths) {
				return nil, errors.New("path is not inside the watched paths: " + strings.Join(env.WatchPaths, ", "))
			}
			roots = []string{a.Path}
		}
		return FileChanges(ctx, roots, hoursAgo(a.SinceHours, 24))
	},
}

// Changed is one recently changed file.
type Changed struct {
	Path     string    `json:"path"`
	Size     int64     `json:"size"`
	Mode     string    `json:"mode"`
	Owner    string    `json:"owner"`
	Modified time.Time `json:"modified"`
	Webshell []string  `json:"webshell_patterns,omitempty"`
}

var webExt = map[string]bool{".php": true, ".phtml": true, ".php5": true, ".jsp": true, ".jspx": true, ".asp": true, ".aspx": true, ".cgi": true, ".pl": true, ".py": true, ".sh": true,
	".js": true, ".mjs": true, ".cjs": true, ".ts": true}

var webshellPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)eval\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)`),
	regexp.MustCompile(`(?i)(assert|eval)\s*\(\s*(base64_decode|gzinflate|str_rot13)`),
	regexp.MustCompile(`(?i)(system|shell_exec|passthru|exec|popen|proc_open)\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)`),
	regexp.MustCompile(`(?i)Runtime\.getRuntime\(\)\.exec\(\s*request\.getParameter`),
	regexp.MustCompile(`(?i)preg_replace\s*\(\s*["'].*/e["']`),
	// Node.js: request data straight into a shell, eval or Function.
	regexp.MustCompile(`(?:exec|execSync|spawn|spawnSync|execFile)\s*\(\s*req\.(?:query|body|params|headers)`),
	regexp.MustCompile(`(?:eval|new\s+Function)\s*\(\s*req\.(?:query|body|params|headers)`),
	regexp.MustCompile(`eval\s*\(\s*Buffer\.from\s*\([^)]*,\s*['"]base64['"]\s*\)`),
	// Python (Flask/Django style): request data into os/subprocess/eval/exec.
	regexp.MustCompile(`(?:os\.system|os\.popen|subprocess\.\w+|eval|exec)\s*\(\s*request\.(?:args|form|values|GET|POST|data|json)`),
	regexp.MustCompile(`exec\s*\(\s*(?:base64\.b64decode|zlib\.decompress|marshal\.loads)`),
}

// FileChanges walks roots and returns files whose mtime or ctime is after since.
func FileChanges(ctx context.Context, roots []string, since time.Time) (map[string]any, error) {
	names := userNames()
	var out []Changed
	var unread, missing []string
	truncated := false
	src := hostSource() // the host read, not the machine running the check (host-source PR-2c)
	for _, root := range roots {
		// A root that is a link is walked where it leads (N-183-2: macOS's
		// /etc is a link to /private/etc, and a walk does not follow a
		// link given as its root), the paths shown under the root as set.
		real, err := hostenv.EvalSymlinks(src, root)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			missing = append(missing, root) // not on this host: not "unread" (S-183-1)
			continue
		case err != nil:
			if len(unread) < maxUnread {
				unread = append(unread, root)
			}
			continue
		}
		shown := func(p string) string {
			if real == root {
				return p
			}
			return filepath.Clean(root) + strings.TrimPrefix(p, real) // no "//" from a trailing slash
		}
		hostenv.Walk(src, real, func(p string, st hostenv.FileStat, err error) error {
			if err != nil {
				// Not read is not unchanged (M0: much of macOS's tree is
				// closed to a user; a replay without the path): said, up
				// to a few. Gone meanwhile is not.
				if !errors.Is(err, fs.ErrNotExist) && len(unread) < maxUnread {
					unread = append(unread, shown(p))
				}
				return nil
			}
			if ctx.Err() != nil {
				return fs.SkipAll
			}
			if st.Mode.IsDir() {
				if p == "/proc" || p == "/sys" || p == "/dev" {
					return fs.SkipDir
				}
				return nil
			}
			if !st.Mode.IsRegular() {
				return nil
			}
			mt := st.ModTime
			if st.CTime != nil && st.CTime.After(mt) {
				mt = *st.CTime // a changed mtime is easy to fake; ctime is not
			}
			owner := ""
			if st.UID >= 0 && !slices.Contains(st.NotApplicable, "uid") {
				owner = names[strconv.Itoa(st.UID)]
			}
			if mt.Before(since) {
				return nil
			}
			if len(out) >= 300 {
				truncated = true
				return fs.SkipAll
			}
			c := Changed{Path: shown(p), Size: st.Size, Mode: st.Mode.String(), Owner: owner, Modified: mt}
			if (webExt[strings.ToLower(filepath.Ext(p))] || aspPage(p)) && st.Size < 512*1024 {
				if b, ok := readHead(src, p, 512*1024); ok {
					for _, re := range webshellPatterns {
						if m := re.Find(b); m != nil {
							c.Webshell = append(c.Webshell, string(m))
						}
					}
					c.Webshell = append(c.Webshell, aspWebshellMatches(p, b)...)
				}
			}
			out = append(out, c)
			return nil
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if (len(out[i].Webshell) > 0) != (len(out[j].Webshell) > 0) {
			return len(out[i].Webshell) > 0
		}
		return out[i].Modified.After(out[j].Modified)
	})
	res := map[string]any{"since": since, "roots": roots, "files": out, "truncated": truncated}
	if len(unread) > 0 {
		res["unread"] = unread // what could not be read is not unchanged
	}
	if len(missing) > 0 {
		res["missing"] = missing // watched paths this host does not have
	}
	return res, nil
}

// maxUnread bounds the unreadable paths file_changes lists.
const maxUnread = 20

func insideAny(p string, roots []string) bool {
	for _, r := range roots {
		if inside(p, r) {
			return true
		}
	}
	return false
}

// inside reports whether p is root or below it. filepath.Rel uses the OS's
// own separator and, on Windows, compares without case, so C:\inetpub and
// c:\INETPUB\wwwroot agree and "/var/www-old" is not inside "/var/www".
func inside(p, root string) bool {
	// A filesystem root (/, C:\) contains only itself, as in v0.2.5: a
	// path list of "/" must not open the whole machine.
	if r := filepath.Clean(root); filepath.Dir(r) == r {
		return filepath.Clean(p) == r
	}
	rel, err := filepath.Rel(filepath.Clean(root), filepath.Clean(p))
	if err != nil || filepath.IsAbs(rel) {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

var certExpiry = Tool{
	Name:        "cert_expiry",
	Description: "TLS certificate expiry for the configured host:port targets and for certificates under /etc/letsencrypt/live.",
	Params:      schema(noParams),
	Run: func(ctx context.Context, env *Env, args json.RawMessage) (any, error) {
		return CertExpiry(ctx, env.CertTargets), nil
	},
}

// Cert is one certificate.
type Cert struct {
	Target   string    `json:"target"`
	Subject  string    `json:"subject,omitempty"`
	NotAfter time.Time `json:"not_after,omitempty"`
	DaysLeft int       `json:"days_left"`
	Error    string    `json:"error,omitempty"`
}

// CertExpiry checks network targets and local Let's Encrypt certificates.
// certbotGlobs are where certbot keeps the live certificates.
var certbotGlobs = []string{"/etc/letsencrypt/live/*/cert.pem", "/opt/homebrew/etc/letsencrypt/live/*/cert.pem", "/usr/local/etc/letsencrypt/live/*/cert.pem"}

func CertExpiry(ctx context.Context, targets []string) []Cert {
	var out []Cert
	for _, t := range targets {
		c := Cert{Target: t}
		// Verification is skipped on purpose: we only read the expiry date, and an
		// expired or self-signed certificate is exactly what we need to report.
		d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 5 * time.Second}, Config: &tls.Config{InsecureSkipVerify: true}}
		conn, err := d.DialContext(ctx, "tcp", t)
		if err != nil {
			c.Error = err.Error()
			out = append(out, c)
			continue
		}
		certs := conn.(*tls.Conn).ConnectionState().PeerCertificates
		conn.Close()
		if len(certs) > 0 {
			c = certInfo(t, certs[0])
		}
		out = append(out, c)
	}
	var files []string
	// certbot's Linux place, and Homebrew's on macOS (Apple silicon, Intel): M0
	for _, g := range certbotGlobs {
		m, _ := filepath.Glob(g)
		files = append(files, m...)
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		if blk, _ := pem.Decode(b); blk != nil {
			if cert, err := x509.ParseCertificate(blk.Bytes); err == nil {
				out = append(out, certInfo(f, cert))
			}
		}
	}
	return out
}

func certInfo(target string, c *x509.Certificate) Cert {
	return Cert{Target: target, Subject: c.Subject.CommonName, NotAfter: c.NotAfter, DaysLeft: int(time.Until(c.NotAfter).Hours() / 24)}
}

var logSearch = Tool{
	Name:        "log_search",
	Description: "Search a log file for a regular expression (RE2 syntax). Only files matching the configured log_paths may be read. Returns the most recent matching lines. On macOS sshd and most system events are in the unified log, not in these files: no match here says nothing about SSH logins.",
	Params: schema(`{"type":"object","required":["pattern","path"],"properties":{
		"pattern":{"type":"string","description":"RE2 regular expression"},
		"path":{"type":"string","description":"log file path; must match a configured log path"},
		"limit":{"type":"integer","description":"max lines to return (default 50, max 200)"}}}`),
	Run: func(ctx context.Context, env *Env, args json.RawMessage) (any, error) {
		var a struct {
			Pattern string `json:"pattern"`
			Path    string `json:"path"`
			Limit   int    `json:"limit"`
		}
		if err := decode(args, &a); err != nil {
			return nil, err
		}
		if onWindows() {
			return winLogSearch(a.Path, a.Pattern, a.Limit)
		}
		if !allowedLog(a.Path, env.LogPaths) {
			return nil, errors.New("path is not in the allowed log paths: " + strings.Join(env.LogPaths, ", "))
		}
		// A symlink inside a log directory must not lead outside the allowlist.
		src := hostSource()
		real, err := hostenv.EvalSymlinks(src, a.Path)
		if err != nil {
			return nil, err
		}
		st, err := hostenv.Stat(src, real)
		if err != nil || !st.Mode.IsRegular() || !allowedLog(real, env.LogPaths) && !(onMac() && allowedLog(macUnprivate(real), env.LogPaths)) {
			return nil, errors.New("path resolves outside the allowed log files: " + real)
		}
		// A hard link is not a symlink: EvalSymlinks does not see it. A user
		// who can write to a log directory (Homebrew's; Linux without
		// protected_hardlinks) could link a root-only file there, owner and
		// all, for log_search run as root to read; logs have one link
		// (S-186-1). A swap after this check is not ruled out.
		if st.NLink != nil && *st.NLink > 1 {
			return nil, fmt.Errorf("%s has %d hard links: log_search reads a log file with one only", real, *st.NLink)
		}
		a.Path = real
		re, err := regexp.Compile(a.Pattern)
		if err != nil {
			return nil, err
		}
		if a.Limit <= 0 || a.Limit > 200 {
			a.Limit = 50
		}
		// The last a.Limit matches, kept in a ring while the file streams by:
		// memory is the ring, not the log.
		ring := make([]string, a.Limit)
		n := 0
		err = hostenv.ScanLines(hostSource(), a.Path, func(l string) {
			if re.MatchString(l) {
				if len(l) > 500 {
					l = Cut(l, 500)
				}
				ring[n%a.Limit] = l
				n++
			}
		})
		if err != nil {
			return nil, err
		}
		hits := []string{}
		for i := max(0, n-a.Limit); i < n; i++ {
			hits = append(hits, ring[i%a.Limit])
		}
		if len(hits) == 0 {
			hits = nil
		}
		return map[string]any{"path": a.Path, "matches": hits}, nil
	},
}

// macUnprivate maps a resolved path under macOS's /private/var, /private/etc
// or /private/tmp back to the /var, /etc or /tmp the system links name it
// by, so a configured /var/log/system.log matches what EvalSymlinks gives.
// Only those three root-owned links: any other link is still resolved and
// must match on its own.
func macUnprivate(p string) string {
	for _, d := range []string{"/private/var/", "/private/etc/", "/private/tmp/"} {
		if strings.HasPrefix(p, d) {
			return strings.TrimPrefix(p, "/private")
		}
	}
	return p
}

func allowedLog(p string, patterns []string) bool {
	p = filepath.Clean(p)
	for _, pat := range patterns {
		for _, cand := range []string{pat, pat + ".1", pat + ".*.gz"} {
			if ok, _ := filepath.Match(cand, p); ok {
				return true
			}
		}
	}
	return false
}
