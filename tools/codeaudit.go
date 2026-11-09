package tools

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/nt-neil/shentu/rules"
	"github.com/nt-neil/shentu/rules/engine"
)

var appCodeAudit = Tool{
	Name: "app_code_audit",
	Description: "Offline audit of the web applications' own files under the app paths: secrets and backups the web server would serve " +
		"(.env, .git, SQL dumps, archives, phpinfo), debug mode left on (Django, Laravel, Flask, PHP display_errors), webshells and " +
		"PHP files in upload folders, keys or passwords written into the code (reported by file, line and type; the value is never shown), " +
		"and injection flaws in PHP, Python and JavaScript found by Shentu's rules (rule, CWE, file and line; no code is shown). " +
		"Each finding has a fix. It reads files only and sends nothing anywhere.",
	Params: schema(`{"type":"object","properties":{
		"path":{"type":"string","description":"only audit under this directory (must be inside the app paths)"}}}`),
	Run: func(ctx context.Context, env *Env, args json.RawMessage) (any, error) {
		var a struct {
			Path string `json:"path"`
		}
		if err := decode(args, &a); err != nil {
			return nil, err
		}
		roots := env.AppPaths
		if a.Path != "" {
			clean := filepath.Clean(a.Path)
			if !insideAny(clean, env.AppPaths) {
				return nil, fmt.Errorf("path is not inside the app paths: %s", strings.Join(env.AppPaths, ", "))
			}
			roots = []string{clean}
		}
		return AppCodeAudit(ctx, roots, WebRoots()), nil
	},
}

// CodeFinding is one problem in an application's files.
type CodeFinding struct {
	Kind     string   `json:"kind"`     // exposed, debug, webshell, upload_script, secret, injection
	Severity string   `json:"severity"` // critical, warning, or info (files the injection rules could not finish)
	Path     string   `json:"path,omitempty"`
	Line     int      `json:"line,omitempty"`
	Detail   string   `json:"detail"`
	Fix      string   `json:"fix"`
	Rule     string   `json:"rule,omitempty"`  // injection: the rule id
	CWE      string   `json:"cwe,omitempty"`   // injection: the weakness
	Tier     string   `json:"tier,omitempty"`  // injection: "info" is not pushed by the patrol report, "alert" is
	Paths    []string `json:"paths,omitempty"` // the files an info finding is about (at most 10)
}

// CodeAudit is the result of AppCodeAudit.
type CodeAudit struct {
	WebRoots  []string      `json:"web_roots"`
	Files     int           `json:"files_read"`
	Findings  []CodeFinding `json:"findings"`
	Truncated bool          `json:"truncated,omitempty"`
}

const (
	auditMaxFiles = 20000 // files read per audit
	auditMaxSize  = 1 << 20
	auditMaxDepth = 8
)

var (
	nginxRoot   = regexp.MustCompile(`(?m)^\s*root\s+["']?([^"';\s]+)`)
	apacheRoot  = regexp.MustCompile(`(?mi)^\s*DocumentRoot\s+["']?([^"'\s]+)`)
	webConfGlob = []string{
		"/etc/nginx/nginx.conf", "/etc/nginx/sites-enabled/*", "/etc/nginx/conf.d/*.conf",
		"/etc/apache2/sites-enabled/*", "/etc/httpd/conf/httpd.conf", "/etc/httpd/conf.d/*.conf",
	}
	webDirNames = map[string]bool{"public": true, "public_html": true, "html": true, "htdocs": true, "www": true, "webroot": true}
)

// WebRoots returns the folders nginx or Apache serve, read from their configuration.
func WebRoots() []string {
	seen := map[string]bool{}
	var out []string
	for _, g := range webConfGlob {
		files, _ := filepath.Glob(g)
		for _, f := range files {
			b, ok := readSmallRegular(f, 1<<20, nil)
			if !ok {
				continue
			}
			for _, re := range []*regexp.Regexp{nginxRoot, apacheRoot} {
				for _, m := range re.FindAllSubmatch(b, -1) {
					p := filepath.Clean(string(m[1]))
					if strings.HasPrefix(p, "/") && !strings.Contains(p, "$") && !seen[p] {
						seen[p] = true
						out = append(out, p)
					}
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

// served reports whether p is inside a folder the web server serves. Without any
// server configuration, folders named like public/, html/ or www/ count as served.
func served(p string, webRoots []string) bool {
	if len(webRoots) > 0 {
		return insideAny(p, webRoots)
	}
	dir := filepath.Dir(p)
	// /var/www holds one folder per site, so its own "www" does not make a path served.
	if dir == "/var/www" || strings.HasPrefix(dir, "/var/www/") {
		dir = dir[len("/var/www"):]
	}
	for _, part := range strings.Split(dir, "/") {
		if webDirNames[part] {
			return true
		}
	}
	return false
}

var exposedNames = []struct {
	match    func(name string) bool
	severity string
	detail   string
	fix      string
}{
	{func(n string) bool {
		return (n == ".env" || strings.HasPrefix(n, ".env.")) && !hasSuffix(n, ".example", ".sample", ".dist")
	}, "critical",
		"environment file with secrets inside the web root; anyone can download it",
		"move it out of the web root, rotate every secret in it, and deny dotfiles in the web server"},
	{func(n string) bool { return n == ".git" }, "critical",
		"git repository inside the web root; the source code and its history can be downloaded",
		"remove the .git folder from the web root (deploy without it) or deny /.git in the web server"},
	{func(n string) bool {
		return hasSuffix(n, ".sql", ".sql.gz", ".sql.bz2", ".sql.zip", ".dump", ".sqlite", ".sqlite3", ".db")
	}, "critical",
		"database file or dump inside the web root; anyone can download the data",
		"move it out of the web root and delete copies that are not needed"},
	{func(n string) bool {
		return hasSuffix(n, ".zip", ".tar", ".tar.gz", ".tgz", ".rar", ".7z", ".bak", ".old", ".orig", ".swp", "~")
	}, "warning",
		"backup or archive inside the web root; it may contain source code or secrets",
		"move it out of the web root"},
}

func hasSuffix(n string, sfx ...string) bool {
	n = strings.ToLower(n)
	for _, s := range sfx {
		if strings.HasSuffix(n, s) {
			return true
		}
	}
	return false
}

// Files whose content is read: code, templates and configuration.
var auditExt = map[string]bool{".php": true, ".phtml": true, ".php5": true, ".inc": true, ".py": true, ".js": true, ".mjs": true,
	".cjs": true, ".ts": true, ".json": true, ".yml": true, ".yaml": true, ".ini": true, ".conf": true, ".cfg": true, ".toml": true,
	".xml": true, ".properties": true, ".htaccess": true, ".user.ini": true, ".env": true}

var uploadDir = regexp.MustCompile(`(?i)/(uploads?|files|media|images|attachments|storage/app/public)/`)

var (
	phpinfoCall  = regexp.MustCompile(`(?i)\bphpinfo\s*\(`)
	djangoDebug  = regexp.MustCompile(`^\s*DEBUG\s*=\s*True\b`)
	flaskDebug   = regexp.MustCompile(`\.run\s*\([^)]*debug\s*=\s*True`)
	laravelDebug = regexp.MustCompile(`(?i)^\s*APP_DEBUG\s*=\s*"?true"?\s*$`)
	flaskEnv     = regexp.MustCompile(`(?i)^\s*FLASK_DEBUG\s*=\s*"?(1|true)"?\s*$`)
	phpDisplay   = regexp.MustCompile(`(?i)^\s*(php_flag\s+display_errors\s+on|display_errors\s*=\s*"?(on|1|true)"?)\s*$`)
)

// Secret patterns; only the type is reported, never the value.
var secretPatterns = []struct {
	kind string
	re   *regexp.Regexp
}{
	{"private key", regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)},
	{"AWS access key", regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)},
	{"GitHub token", regexp.MustCompile(`\b(gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{20,})`)},
	{"Slack token", regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9-]{10,}`)},
	{"Stripe live key", regexp.MustCompile(`\b[sr]k_live_[0-9A-Za-z]{20,}`)},
	{"Google API key", regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`)},
	{"password in a connection URL", regexp.MustCompile(`\b(mysql|postgres(ql)?|mongodb(\+srv)?|redis|amqp)://[^/\s:@"']+:[^/\s@"']{3,}@`)},
}

// Files the injection rules read, by extension.
var injectionLang = map[string]string{".php": "php", ".py": "python", ".js": "js", ".mjs": "js", ".cjs": "js", ".jsx": "js"}

const partialListMax = 10

// injectionMaxTime caps the time the injection rules take in one audit (each file
// is also capped by the engine's own limits). Files left when it runs out are
// listed in the partial summary.
var injectionMaxTime = 2 * time.Minute

var engineScan = (*engine.Engine).Scan // replaced in tests

// injectionScan runs the engine on one file. A panic counts as an unfinished file,
// so one malformed file cannot stop the audit or the patrol.
func injectionScan(e *engine.Engine, lang, p string, b []byte) (found []engine.Finding, err error) {
	defer func() {
		if recover() != nil {
			found, err = nil, engine.ErrLimit
		}
	}()
	return engineScan(e, lang, p, b)
}

var (
	rulesOnce sync.Once
	rulesEng  *engine.Engine
	rulesErr  error
)

// injectionEngine compiles the rules embedded in the binary once.
func injectionEngine() (*engine.Engine, error) {
	rulesOnce.Do(func() {
		rs, err := rules.Load()
		if err == nil {
			rulesEng, err = engine.New(rs)
		}
		rulesErr = err
	})
	return rulesEng, rulesErr
}

// injectionFindings turns the engine's findings for one file into code findings.
// They carry the rule, never the code.
func injectionFindings(found []engine.Finding, add func(CodeFinding)) {
	for _, f := range found {
		sev := "warning"
		if f.Severity == "critical" {
			sev = "critical"
		}
		add(CodeFinding{Kind: "injection", Severity: sev, Path: f.Path, Line: f.Line, Detail: f.Title,
			Fix: f.Fix, Rule: f.RuleID, CWE: f.CWE, Tier: f.Tier})
	}
}

// finding is a code finding of the checks that are not rules.
func finding(kind, severity, path string, line int, detail, fix string) CodeFinding {
	return CodeFinding{Kind: kind, Severity: severity, Path: path, Line: line, Detail: detail, Fix: fix}
}

// partialFinding sums up the files the injection rules did not check to the end.
func partialFinding(paths []string) CodeFinding {
	f := CodeFinding{Kind: "injection", Severity: "info", Tier: "info",
		Detail: fmt.Sprintf("%d file(s) were too large or too complex for the injection rules, or came after the audit's time limit for them; they were checked only in part or not at all", len(paths)),
		Fix:    "review these files by hand, or split them into smaller files"}
	f.Paths = paths[:min(len(paths), partialListMax)]
	return f
}

// AppCodeAudit reads the application files under roots and reports problems.
// webRoots are the folders the web server serves (see WebRoots).
func AppCodeAudit(ctx context.Context, roots, webRoots []string) CodeAudit {
	res := CodeAudit{WebRoots: webRoots, Findings: []CodeFinding{}}
	add := func(f CodeFinding) { res.Findings = append(res.Findings, f) }
	eng, err := injectionEngine()
	if err != nil {
		add(CodeFinding{Kind: "injection", Severity: "info", Tier: "info", Detail: "the injection rules could not be loaded: " + err.Error(),
			Fix: "report this as a Shentu bug; the other checks ran"})
	}
	var partial []string
	deadline := time.Now().Add(injectionMaxTime)
	for _, root := range roots {
		base := strings.Count(filepath.Clean(root), "/")
		filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil || ctx.Err() != nil {
				return nil
			}
			name := d.Name()
			if d.IsDir() {
				if name == ".git" && served(p, webRoots) {
					add(finding("exposed", "critical", p, 0, exposedNames[1].detail, exposedNames[1].fix))
				}
				if skipDirs[name] || strings.Count(p, "/")-base > auditMaxDepth {
					return filepath.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() {
				return nil
			}
			web := served(p, webRoots)
			if web {
				for i, e := range exposedNames {
					if i != 1 && e.match(name) {
						add(finding("exposed", e.severity, p, 0, e.detail, e.fix))
						break
					}
				}
			}
			ext := strings.ToLower(filepath.Ext(name))
			isPHP := ext == ".php" || ext == ".phtml" || ext == ".php5"
			if isPHP && uploadDir.MatchString(p) {
				add(finding("upload_script", "critical", p, 0, "PHP file in an upload folder; uploads should never be scripts",
					"check the file, delete it if it is not yours, and stop PHP from running in the upload folder"))
			}
			lang := injectionLang[ext]
			if !auditExt[ext] && !auditExt[name] && !strings.HasPrefix(name, ".env") && name != "settings.py" && lang == "" {
				return nil
			}
			if res.Files >= auditMaxFiles {
				res.Truncated = true
				return filepath.SkipAll
			}
			info, err := d.Info()
			if err != nil {
				return nil
			}
			b, ok := readSmallRegular(p, auditMaxSize, info)
			if !ok || bytes.IndexByte(b, 0) >= 0 {
				if lang != "" && eng != nil && info.Size() > auditMaxSize {
					partial = append(partial, p)
				}
				return nil
			}
			res.Files++
			auditContent(p, name, b, web, isPHP, add)
			switch {
			case lang == "" || eng == nil:
			case time.Now().After(deadline):
				partial = append(partial, p)
			default:
				found, err := injectionScan(eng, lang, p, b)
				injectionFindings(found, add)
				if errors.Is(err, engine.ErrLimit) || errors.Is(err, engine.ErrPartial) {
					partial = append(partial, p)
				}
			}
			return nil
		})
	}
	if len(partial) > 0 {
		add(partialFinding(partial))
	}
	sort.SliceStable(res.Findings, func(i, j int) bool {
		if res.Findings[i].Severity != res.Findings[j].Severity {
			return res.Findings[i].Severity == "critical"
		}
		return res.Findings[i].Path < res.Findings[j].Path
	})
	return res
}

// auditContent checks one file's lines. Secrets are matched but never copied out.
func auditContent(p, name string, b []byte, web, isPHP bool, add func(CodeFinding)) {
	envFile := name == ".env" || strings.HasPrefix(name, ".env.")
	if webExt[strings.ToLower(filepath.Ext(name))] {
		for _, re := range webshellPatterns {
			if loc := re.FindIndex(b); loc != nil {
				add(finding("webshell", "critical", p, lineAt(b, loc[0]),
					"code that runs commands or code taken straight from the request (webshell pattern)",
					"check the file now; if you did not write it, take the site offline, delete it and look for how it got there"))
				break
			}
		}
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64*1024), auditMaxSize)
	n := 0
	for sc.Scan() {
		n++
		line := sc.Text()
		switch {
		case isPHP && web && phpinfoCall.MatchString(line) && !commented(line):
			add(finding("exposed", "warning", p, n, "phpinfo() in a served file shows the server's configuration to anyone",
				"delete the file or remove the phpinfo() call"))
		case name == "settings.py" && djangoDebug.MatchString(line):
			add(finding("debug", "warning", p, n, "Django DEBUG = True: errors show code, settings and SQL to visitors",
				"set DEBUG = False in production (read it from the environment) and set ALLOWED_HOSTS"))
		case strings.HasSuffix(name, ".py") && flaskDebug.MatchString(line) && !commented(line):
			add(finding("debug", "critical", p, n, "Flask debug=True: the debugger lets visitors run Python code",
				"remove debug=True and run the app with a WSGI server such as gunicorn"))
		case envFile && laravelDebug.MatchString(line):
			add(finding("debug", "warning", p, n, "Laravel APP_DEBUG=true: errors show code and environment values to visitors",
				"set APP_DEBUG=false and APP_ENV=production, then run php artisan config:cache"))
		case envFile && flaskEnv.MatchString(line):
			add(finding("debug", "critical", p, n, "FLASK_DEBUG is on: the debugger lets visitors run Python code",
				"set FLASK_DEBUG=0 in production"))
		case (name == ".htaccess" || name == ".user.ini" || name == "php.ini") && phpDisplay.MatchString(line):
			add(finding("debug", "warning", p, n, "PHP display_errors is on: errors show paths and code to visitors",
				"set display_errors = Off and log errors instead (log_errors = On)"))
		}
		if envFile {
			continue // an env file is where secrets belong; exposure is checked separately
		}
		for _, s := range secretPatterns {
			if s.re.MatchString(line) {
				add(finding("secret", "warning", p, n, s.kind+" written in the file (value not shown)",
					"move it to an environment variable or a secrets file outside the code, and rotate it if the code was ever shared"))
				break
			}
		}
	}
}

func commented(line string) bool {
	t := strings.TrimSpace(line)
	return strings.HasPrefix(t, "#") || strings.HasPrefix(t, "//") || strings.HasPrefix(t, "*") || strings.HasPrefix(t, "/*")
}

func lineAt(b []byte, off int) int { return bytes.Count(b[:off], []byte("\n")) + 1 }
