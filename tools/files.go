package tools

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
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

var webExt = map[string]bool{".php": true, ".phtml": true, ".php5": true, ".jsp": true, ".jspx": true, ".asp": true, ".aspx": true, ".cgi": true, ".pl": true, ".py": true, ".sh": true}

var webshellPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)eval\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)`),
	regexp.MustCompile(`(?i)(assert|eval)\s*\(\s*(base64_decode|gzinflate|str_rot13)`),
	regexp.MustCompile(`(?i)(system|shell_exec|passthru|exec|popen|proc_open)\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)`),
	regexp.MustCompile(`(?i)Runtime\.getRuntime\(\)\.exec\(\s*request\.getParameter`),
	regexp.MustCompile(`(?i)preg_replace\s*\(\s*["'].*/e["']`),
}

// FileChanges walks roots and returns files whose mtime or ctime is after since.
func FileChanges(ctx context.Context, roots []string, since time.Time) (map[string]any, error) {
	names := userNames()
	var out []Changed
	truncated := false
	for _, root := range roots {
		filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil || ctx.Err() != nil {
				return nil
			}
			if d.IsDir() {
				if p == "/proc" || p == "/sys" || p == "/dev" {
					return filepath.SkipDir
				}
				return nil
			}
			info, err := d.Info()
			if err != nil || !info.Mode().IsRegular() {
				return nil
			}
			mt := info.ModTime()
			owner := ""
			if ct, uid, ok := ctimeUID(info); ok {
				if ct.After(mt) {
					mt = ct // a changed mtime is easy to fake; ctime is not
				}
				owner = names[itoa(uid)]
			}
			if mt.Before(since) {
				return nil
			}
			if len(out) >= 300 {
				truncated = true
				return filepath.SkipAll
			}
			c := Changed{Path: p, Size: info.Size(), Mode: info.Mode().String(), Owner: owner, Modified: mt}
			if webExt[strings.ToLower(filepath.Ext(p))] && info.Size() < 512*1024 {
				if b, err := os.ReadFile(p); err == nil {
					for _, re := range webshellPatterns {
						if m := re.Find(b); m != nil {
							c.Webshell = append(c.Webshell, string(m))
						}
					}
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
	return map[string]any{"since": since, "roots": roots, "files": out, "truncated": truncated}, nil
}

func itoa(u uint32) string {
	b := []byte{}
	if u == 0 {
		return "0"
	}
	for u > 0 {
		b = append([]byte{byte('0' + u%10)}, b...)
		u /= 10
	}
	return string(b)
}

func insideAny(p string, roots []string) bool {
	p = filepath.Clean(p)
	for _, r := range roots {
		r = filepath.Clean(r)
		if p == r || strings.HasPrefix(p, r+"/") {
			return true
		}
	}
	return false
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
	files, _ := filepath.Glob("/etc/letsencrypt/live/*/cert.pem")
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
	Description: "Search a log file for a regular expression (RE2 syntax). Only files matching the configured log_paths may be read. Returns the most recent matching lines.",
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
		if !allowedLog(a.Path, env.LogPaths) {
			return nil, errors.New("path is not in the allowed log paths: " + strings.Join(env.LogPaths, ", "))
		}
		re, err := regexp.Compile(a.Pattern)
		if err != nil {
			return nil, err
		}
		if a.Limit <= 0 || a.Limit > 200 {
			a.Limit = 50
		}
		lines, err := readLines(a.Path)
		if err != nil {
			return nil, err
		}
		var hits []string
		for i := len(lines) - 1; i >= 0 && len(hits) < a.Limit; i-- {
			if re.MatchString(lines[i]) {
				l := lines[i]
				if len(l) > 500 {
					l = l[:500] + "…"
				}
				hits = append(hits, l)
			}
		}
		for i, j := 0, len(hits)-1; i < j; i, j = i+1, j-1 {
			hits[i], hits[j] = hits[j], hits[i]
		}
		return map[string]any{"path": a.Path, "matches": hits}, nil
	},
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
