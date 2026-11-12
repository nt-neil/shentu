package tools

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
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
		web, unread := WebRootsReport()
		res := AppCodeAudit(ctx, roots, web)
		res.WebConfigUnreadable = unread
		return res, nil
	},
}

// CodeFinding is one problem in an application's files.
type CodeFinding struct {
	Kind      string           `json:"kind"`     // exposed, debug, webshell, upload_script, secret, injection
	Severity  string           `json:"severity"` // critical, warning, or info (files the injection rules could not finish)
	Path      string           `json:"path,omitempty"`
	Line      int              `json:"line,omitempty"`
	Detail    string           `json:"detail"`
	Fix       string           `json:"fix"`
	Rule      string           `json:"rule,omitempty"`      // injection: the rule id
	CWE       string           `json:"cwe,omitempty"`       // injection: the weakness
	Tier      string           `json:"tier,omitempty"`      // injection: "info" is not pushed by the patrol report, "alert" is
	Files     []UnfinishedFile `json:"files,omitempty"`     // the files the summary of unfinished files is about (at most 10)
	TestPath  bool             `json:"test_path,omitempty"` // injection: the file is under tests/, test/, examples/ or __tests__/
	Generated bool             `json:"generated,omitempty"` // injection: the file is minified or bundled JavaScript
}

// UnfinishedFile is a file the injection rules did not check to the end, and why:
// "size" (over the size limit, not read), "limit" (too large, slow or deeply nested
// for the engine), "unterminated" (a string or comment runs to the end of the file),
// "time" (after the audit's time limit for the rules), "panic" (an engine error) or
// "minified-unterminated" or "minified-limit" (minified or bundled JavaScript that
// stopped early for that reason).
type UnfinishedFile struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// CodeAudit is the result of AppCodeAudit.
type CodeAudit struct {
	WebRoots []string `json:"web_roots"`
	// Web server configuration files that could not be read, with why: the
	// web roots they name are missing from WebRoots.
	WebConfigUnreadable []string      `json:"web_config_unreadable,omitempty"`
	Files               int           `json:"files_read"`
	Findings            []CodeFinding `json:"findings"`            // the summaries (kind "audit", and injection ones without a rule) first
	Truncated           bool          `json:"truncated,omitempty"` // files or findings over the caps were left out
	// The audit's time ran out before the end: what was found until then is
	// listed, and a summary names what was not checked.
	Unfinished bool `json:"unfinished,omitempty"`
	// Injection findings, counted apart for files under test and example folders.
	Injection          int `json:"injection_findings"`
	InjectionTestPaths int `json:"injection_findings_in_test_paths"`
	InjectionGenerated int `json:"injection_findings_in_generated_code"` // minified or bundled JavaScript
	// The memory the audit kept to: its heap budget and Go's memory limit
	// while it ran (MiB).
	MemoryBudgetMB int `json:"memory_budget_mb"`
	MemoryLimitMB  int `json:"go_memory_limit_mb"`
}

const (
	auditMaxFiles    = 20000 // files read per audit
	auditMaxFindings = 2000  // findings listed per audit
	auditMaxPerFile  = 20    // findings listed per rule (or check) in one file
	auditMaxSize     = 1 << 20
	auditMaxDepth    = 8
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
	roots, _ := WebRootsReport()
	return roots
}

// WebRootsReport returns the folders nginx or Apache serve, and the
// configuration files it could not read, each with why ("path (why)").
func WebRootsReport() (roots, unreadable []string) { return webRootsFrom(webConfGlob) }

// The configuration a symlink in it may point to: a regular file under
// webConfRoot, owned by webConfOwner (root), that only its owner can write
// (Debian and Ubuntu enable a site by a symlink in sites-enabled). Variables
// for the tests.
var (
	webConfRoot  = "/etc"
	webConfOwner = uint32(0)
)

// readWebConf reads one web server configuration file. Unlike readSmallRegular
// elsewhere, it follows a symlink, to a file webConfRoot holds and only root
// can write; why says what kept it from being read.
func readWebConf(p string) (b []byte, why string) {
	li, err := os.Lstat(p)
	if err != nil {
		return nil, errWhy(err)
	}
	target := p
	if li.Mode()&os.ModeSymlink != 0 {
		if target, err = filepath.EvalSymlinks(p); err != nil { // a loop ends here too
			return nil, "symlink: " + errWhy(err)
		}
		if !insideAny(target, []string{webConfRoot}) {
			return nil, "symlink to " + target + ", outside " + webConfRoot
		}
		st, err := os.Lstat(target)
		if err != nil {
			return nil, errWhy(err)
		}
		sys, ok := st.Sys().(*syscall.Stat_t)
		switch {
		case !st.Mode().IsRegular():
			return nil, "symlink to " + target + ", not a regular file"
		case !ok || sys.Uid != webConfOwner:
			return nil, "symlink to " + target + ", not owned by root"
		case st.Mode().Perm()&0o022 != 0:
			return nil, "symlink to " + target + ", writable by others than its owner"
		}
		li = st
	}
	b, ok := readSmallRegular(target, 1<<20, li) // no symlink left; the file the checks saw
	if !ok {
		return nil, "not a regular file of at most 1 MiB, or changed while read"
	}
	return b, ""
}

func errWhy(err error) string {
	if pe := (*fs.PathError)(nil); errors.As(err, &pe) {
		return pe.Err.Error()
	}
	return err.Error()
}

func webRootsFrom(globs []string) (out, unreadable []string) {
	seen := map[string]bool{}
	for _, g := range globs {
		files, _ := filepath.Glob(g)
		for _, f := range files {
			b, why := readWebConf(f)
			if why != "" {
				unreadable = append(unreadable, f+" ("+why+")")
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
	return out, unreadable
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
	".cjs": true, ".ts": true, ".mts": true, ".cts": true, ".tsx": true, ".json": true, ".yml": true, ".yaml": true, ".ini": true, ".conf": true, ".cfg": true, ".toml": true,
	".xml": true, ".properties": true, ".htaccess": true, ".user.ini": true, ".env": true}

// Folders uploads land in: wp-content/uploads (WordPress), sites/*/files
// (Drupal), pub/media (Magento), storage/app/public (Laravel), wherever the
// site is; else a folder named so (in any case) right under the site's root.
// Only the path below the site's root counts: /usr/src/app/wp-content/uploads
// holds uploads, and a site whose root is itself named files is not one.
var uploadNames = map[string]bool{"uploads": true, "upload": true, "files": true, "media": true, "images": true, "attachments": true}

// uploadFolder reports whether p is in a folder uploads land in. Under one of
// webRoots (the folders the web server serves) the folder is right under that
// root; elsewhere (an app path the server's configuration does not name) right
// under one named like public/ or www/, or under a site folder of /var/www.
func uploadFolder(p string, webRoots []string) bool {
	segs := strings.Split(filepath.ToSlash(filepath.Dir(p)), "/")
	low := make([]string, len(segs))
	for i, s := range segs {
		low[i] = strings.ToLower(s)
	}
	at := func(i int, names ...string) bool {
		for j, n := range names {
			if i+j >= len(low) || n != "*" && low[i+j] != n {
				return false
			}
		}
		return true
	}
	code := len(low) // below wp-content/plugins, themes and the like: code, not uploads
	for i := range low {
		switch {
		case at(i, "wp-content", "uploads"), at(i, "sites", "*", "files"), at(i, "pub", "media"), at(i, "storage", "app", "public"):
			return true
		case low[i] == "wp-content" && code == len(low):
			code = i
		}
	}
	root := ""
	for _, r := range webRoots {
		if insideAny(p, []string{r}) && len(r) > len(root) {
			root = filepath.ToSlash(r)
		}
	}
	for i := 1; i < len(segs); i++ {
		if !uploadNames[low[i]] || i > code {
			continue
		}
		parent := strings.Join(segs[:i], "/")
		if root != "" {
			if parent == root {
				return true
			}
			continue
		}
		if webDirNames[low[i-1]] && parent != "/var/www" || filepath.Dir(parent) == "/var/www" {
			return true
		}
	}
	return false
}

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

const partialListMax = 10

// injectionMaxTime caps the time the injection rules take in one audit (each file
// is also capped by the engine's own limits). Files left when it runs out are
// listed in the partial summary.
var injectionMaxTime = 2 * time.Minute

// auditWrapUp is the share of the caller's time left when the injection rules
// stop, for following calls to end and the result to be put together; at
// most auditWrapUpMax.
const (
	auditWrapUp    = 10
	auditWrapUpMax = 15 * time.Second
)

var (
	engineScan  = (*engine.Engine).ScanTimed      // replaced in tests
	projectScan = (*engine.Project).ScanCallsPart // replaced in tests
)

var errPanic = errors.New("engine panic")

// injectionScan runs the engine on one file. A panic counts as an unfinished
// file, so one malformed file cannot stop the audit or the patrol.
// timed: a time limit cut it short (the result is not kept for the next audit).
func injectionScan(e *engine.Engine, lang, p string, b []byte) (found []engine.Finding, timed bool, err error) {
	defer func() {
		if recover() != nil {
			found, timed, err = nil, false, errPanic
		}
	}()
	return engineScan(e, lang, p, b)
}

// injectionCalls follows one file's calls into the project's other files.
func injectionCalls(pr *engine.Project, p string, b []byte, skip map[string]bool) (res engine.CallsPart, err error) {
	defer func() {
		if recover() != nil {
			res, err = engine.CallsPart{}, errPanic
		}
	}()
	return projectScan(pr, p, b, skip)
}

// codeIndexFile is where the index of the scanned code is cached between audits
// (file and function names, never code; mode 0600): the state directory when it
// can be written (the service runs as root), else the user's cache directory.
var codeIndexFile = func() string {
	if info, err := os.Stat("/var/lib/shentu"); err == nil && info.IsDir() && os.Geteuid() == 0 {
		return "/var/lib/shentu/codeindex.json"
	}
	if d, err := os.UserCacheDir(); err == nil {
		return filepath.Join(d, "shentu", "codeindex.json")
	}
	return ""
}

// crossFileFinding tells that calls were followed across files for only part
// of the files; every file was still checked on its own.
// slowTries is how many audits in a row the clock may cut one rule of one
// file short before that rule is left out for the file, until it changes.
const slowTries = 3

// Results kept from earlier audits count: covered files had their calls
// followed in this audit (now of them) or an earlier one, done of them to the
// end; slowRules rules of slowFiles of the covered files were left out as too
// slow for one audit. waiting are the files whose calls across files are not
// covered yet, in the order the next audits take them.
// allOwn: every file was checked on its own (the audit's time did not run out first).
func crossFileFinding(done, covered, now, total, slowRules, slowFiles int, reason string, waiting []UnfinishedFile, allOwn bool) CodeFinding {
	if covered == total {
		reason = "the rest were cut short by the size limits or by names that could not be pinned to one file"
	}
	slow := ""
	if slowFiles > 0 {
		slow = fmt.Sprintf(", %d of them with %d rule(s) left out as too slow for one audit's time (cut short %d audits in a row; tried again when the file changes)",
			slowFiles, slowRules, slowTries)
	}
	own := "every file was checked on its own"
	if !allOwn {
		own = "the files in the summary of unfinished files were not all checked on their own"
	}
	f := CodeFinding{Kind: "injection", Severity: "info", Tier: "info",
		Detail: fmt.Sprintf("the injection rules followed calls across files for %d of %d file(s) (%s); %s. "+
			"Calls across files are covered for %d of %d file(s) (%.1f%%) so far%s, %d of them in this audit; "+
			"unchanged files keep their results and the next audits go on from there",
			done, total, reason, own, covered, total, 100*float64(covered)/float64(max(total, 1)), slow, now),
		Fix:   "nothing to do; a smaller audit root or a quieter server lets the next audit follow more",
		Files: waiting[:min(len(waiting), partialListMax)]}
	if strings.Contains(reason, "memory limit") {
		// The files and summaries a chain of calls needs at once did not fit:
		// going on would not make them fit.
		f.Fix = "give the audit more memory: [tools] audit_max_memory_mb = 512 or more (following calls across files needs " +
			"the files on a chain of calls at once); the next audits go on from the files listed"
	}
	return f
}

var (
	rulesOnce   sync.Once
	rulesEng    *engine.Engine
	rulesErr    error
	rulesDigest string // of the rules as loaded: kept results are of these rules
)

// injectionEngine compiles the rules embedded in the binary once.
func injectionEngine() (*engine.Engine, error) {
	rulesOnce.Do(func() {
		rs, err := rules.Load()
		if err == nil {
			rulesEng, err = engine.New(rs)
		}
		if b, jerr := json.Marshal(rs); jerr == nil {
			sum := sha256.Sum256(b)
			rulesDigest = hex.EncodeToString(sum[:])
		}
		rulesErr = err
	})
	return rulesEng, rulesErr
}

// generated reports whether a file is minified or bundled JavaScript.
func generated(lang string, b []byte) bool {
	return (lang == "js" || lang == "jsx" || lang == "ts" || lang == "tsx") && engine.Minified(b)
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
			Fix: f.Fix, Rule: f.RuleID, CWE: f.CWE, Tier: f.Tier, TestPath: testPath(f.Path)})
	}
}

var testDirs = map[string]bool{"tests": true, "test": true, "examples": true, "__tests__": true}

// testPath reports whether p is under a test or example folder. Findings there
// are kept, marked and counted apart: such code is rarely deployed, but may be.
func testPath(p string) bool {
	for _, seg := range strings.Split(filepath.ToSlash(filepath.Dir(p)), "/") {
		if testDirs[strings.ToLower(seg)] {
			return true
		}
	}
	return false
}

// finding is a code finding of the checks that are not rules.
func finding(kind, severity, path string, line int, detail, fix string) CodeFinding {
	return CodeFinding{Kind: kind, Severity: severity, Path: path, Line: line, Detail: detail, Fix: fix}
}

// partialFinding sums up the files the injection rules did not check to the end,
// counted by reason.
func partialFinding(files []UnfinishedFile) CodeFinding {
	count := map[string]int{}
	for _, f := range files {
		count[f.Reason]++
	}
	var parts []string
	for _, r := range []struct{ reason, text string }{
		{"size", "over the size limit"}, {"limit", "too large, slow or deeply nested for the engine"},
		{"unterminated", "with a string or comment that never ends"}, {"time", "after the audit's time limit"},
		{"panic", "stopped by an engine error"}, {"minified-unterminated", "minified JavaScript with a string or comment that never ends"},
		{"minified-limit", "minified JavaScript too large or slow for the engine"},
		{"calls", "checked function by function, its calls not followed to the end (a time or size limit)"},
	} {
		if n := count[r.reason]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, r.text))
		}
	}
	return CodeFinding{Kind: "injection", Severity: "info", Tier: "info",
		Detail: fmt.Sprintf("%d file(s) were checked by the injection rules only in part or not at all: %s", len(files), strings.Join(parts, ", ")),
		Fix:    "review these files by hand, or split them into smaller files",
		Files:  files[:min(len(files), partialListMax)]}
}

// unfinishedReason names why the engine stopped early, or "" when it did not.
func unfinishedReason(err error) string {
	switch {
	case errors.Is(err, errPanic):
		return "panic"
	case errors.Is(err, engine.ErrMinified) && errors.Is(err, engine.ErrLimit):
		return "minified-limit"
	case errors.Is(err, engine.ErrMinified) && errors.Is(err, engine.ErrPartial):
		return "minified-unterminated"
	case errors.Is(err, engine.ErrLimit):
		return "limit"
	case errors.Is(err, engine.ErrPartial):
		return "unterminated"
	case errors.Is(err, engine.ErrCalls):
		return "calls"
	}
	return ""
}

// stoppedFinding tells that the audit's time ran out before the end: walk are
// the roots not walked to the end (reason "walk") or not walked at all because
// another audit held the turn (reason "wait"); files is how many rule-language
// files the injection rules had not reached.
func stoppedFinding(walk []UnfinishedFile, files int) CodeFinding {
	var parts []string
	if len(walk) > 0 {
		parts = append(parts, fmt.Sprintf("%d folder(s) not walked to the end (listed)", len(walk)))
	}
	if files > 0 {
		parts = append(parts, fmt.Sprintf("%d file(s) the injection rules had not reached (in the summary of unfinished files)", files))
	}
	detail := "the audit is unfinished: its time ran out before the end; the findings listed are those found until then. Not checked: " +
		strings.Join(parts, ", ")
	if len(walk) > 0 && walk[0].Reason == "wait" {
		detail = "the audit is unfinished: it waited for another audit to end and its time ran out first; nothing was checked"
	}
	return CodeFinding{Kind: "audit", Severity: "info", Detail: detail,
		Fix:   "run the audit again (it goes on from the results kept), or audit a smaller folder",
		Files: walk[:min(len(walk), partialListMax)]}
}

// AppCodeAudit reads the application files under roots and reports problems.
// webRoots are the folders the web server serves (see WebRoots). It waits for
// an audit already running to end.
func AppCodeAudit(ctx context.Context, roots, webRoots []string) CodeAudit {
	unlock, err := lockAudit(ctx)
	if err != nil {
		var walk []UnfinishedFile
		for _, r := range roots {
			walk = append(walk, UnfinishedFile{r, "wait"})
		}
		return CodeAudit{WebRoots: webRoots, Findings: []CodeFinding{stoppedFinding(walk, 0)}, Unfinished: true}
	}
	defer unlock()
	return auditUnlocked(ctx, roots, webRoots)
}

func auditUnlocked(ctx context.Context, roots, webRoots []string) CodeAudit {
	res := CodeAudit{WebRoots: webRoots, Findings: []CodeFinding{}}
	var notes []CodeFinding // summaries: listed first, never left out
	// At most auditMaxPerFile findings of one rule or check in one file and
	// auditMaxFindings in all are listed; the injection counts take them all.
	perFile, left := map[string]int{}, 0
	var ranks [6]int // listed findings by listRank
	worst := 0       // the lowest rank listed
	add := func(f CodeFinding) {
		if f.Kind == "injection" {
			switch {
			case f.TestPath:
				res.InjectionTestPaths++
			case f.Generated:
				res.InjectionGenerated++
			default:
				res.Injection++
			}
		}
		k := f.Kind + "\x00" + f.Rule + "\x00" + f.Path
		if perFile[k] >= auditMaxPerFile {
			left++
			return
		}
		if len(res.Findings) >= auditMaxFindings {
			// Full: a finding of a higher rank takes the place of one of the
			// lowest listed, so alerts are never left out for info-tier
			// findings, nor critical ones for warnings.
			r := listRank(f)
			if r >= worst {
				left++
				return
			}
			for i := len(res.Findings) - 1; i >= 0; i-- {
				if g := res.Findings[i]; listRank(g) == worst {
					perFile[g.Kind+"\x00"+g.Rule+"\x00"+g.Path]--
					res.Findings = slices.Delete(res.Findings, i, i+1)
					ranks[worst]--
					break
				}
			}
			left++
			for worst > 0 && ranks[worst] == 0 {
				worst--
			}
		}
		perFile[k]++
		ranks[listRank(f)]++
		worst = max(worst, listRank(f))
		res.Findings = append(res.Findings, f)
	}
	// Findings the cap per rule and file left out before they were listed:
	// counted, never kept (one file can hold hundreds of thousands).
	over := map[string]int{} // file → the most any pass left out
	addOver := func(p string, n int) { over[p] = max(over[p], n) }
	countOver := func(p string, n int) {
		if testPath(p) {
			res.InjectionTestPaths += n
		} else {
			res.Injection += n
		}
		left += n
	}
	eng, err := injectionEngine()
	if err != nil {
		notes = append(notes, CodeFinding{Kind: "injection", Severity: "info", Tier: "info", Detail: "the injection rules could not be loaded: " + err.Error(),
			Fix: "report this as a Shentu bug; the other checks ran"})
	}
	var partial []UnfinishedFile
	var walkCut []UnfinishedFile // roots the walk did not finish: the audit's time ran out
	notReached := 0              // rule-language files the injection rules had not reached when it did
	late := 0                    // ... nor before their own time limit
	var code []string            // rule-language files, scanned once all are known
	seen := map[string]fs.FileInfo{}
	hash := map[string]string{} // content of the rule-language files, for the results kept between audits
	deadline := time.Now().Add(injectionMaxTime)
	// The rules stop before the caller's time does, so what they found is put
	// together and returned.
	if d, ok := ctx.Deadline(); ok {
		if end := d.Add(-min(time.Until(d)/auditWrapUp, auditWrapUpMax)); end.Before(deadline) {
			deadline = end
		}
	}
	budget := currentBudget()
	// While the audit runs the GC keeps the process under the budget's limit
	// (never raising a lower one set before).
	if prev := debug.SetMemoryLimit(-1); budget.limit > 0 && uint64(prev) > budget.limit {
		debug.SetMemoryLimit(int64(budget.limit))
		defer debug.SetMemoryLimit(prev)
	}
	res.MemoryBudgetMB, res.MemoryLimitMB = int(budget.heap>>20), int(debug.SetMemoryLimit(-1)>>20)
	// The walk stops at the rules' deadline too: an audit holds the turn of
	// the others for a bounded time.
	stop := func() bool { return ctx.Err() != nil || time.Now().After(deadline) }
	for _, root := range roots {
		if stop() {
			walkCut = append(walkCut, UnfinishedFile{root, "walk"})
			continue
		}
		base := strings.Count(filepath.Clean(root), "/")
		filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if stop() {
				walkCut = append(walkCut, UnfinishedFile{root, "walk"})
				return filepath.SkipAll
			}
			if err != nil {
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
			if isPHP && uploadFolder(p, webRoots) {
				add(finding("upload_script", "critical", p, 0, "PHP file in an upload folder; uploads should never be scripts",
					"check the file, delete it if it is not yours, and stop PHP from running in the upload folder"))
			}
			lang := engine.LangOf(name)
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
			// A rule-language file is read even with a NUL byte: PHP runs such a file.
			if !ok || lang == "" && bytes.IndexByte(b, 0) >= 0 {
				if lang != "" && eng != nil && info.Size() > auditMaxSize {
					partial = append(partial, UnfinishedFile{p, "size"})
				}
				return nil
			}
			res.Files++
			auditContent(p, name, b, web, isPHP, add)
			if lang != "" && eng != nil || name == "composer.json" {
				code = append(code, p)
				seen[p] = info
				if lang != "" {
					sum := sha256.Sum256(b)
					hash[p] = hex.EncodeToString(sum[:])
				}
			}
			return nil
		})
	}
	if eng != nil && len(code) > 0 {
		// Read again the way the walk did (no symlinks, regular files under the
		// size cap), and only the file the walk saw: one swapped since is skipped.
		read := func(p string) ([]byte, error) {
			b, ok := readSmallRegular(p, auditMaxSize, seen[p])
			if !ok {
				return nil, errors.New("not read")
			}
			// Results are kept under the hash the walk took: a file rewritten
			// since is not scanned under it.
			if h := hash[p]; h != "" {
				if sum := sha256.Sum256(b); hex.EncodeToString(sum[:]) != h {
					return nil, errors.New("changed during the audit")
				}
			}
			return b, nil
		}
		var files []string
		for _, p := range code {
			if engine.LangOf(p) != "" {
				files = append(files, p)
			}
		}
		stateFile := callStateFile(roots)
		st := loadCallState(stateFile, auditBuild(eng))
		// A walk the clock cut short says nothing of the files it did not reach:
		// their kept results stay (the bot and the patrol share them).
		walked := len(walkCut) == 0
		stale := st.dropStale(hash, walked) // before this audit's results replace the old ones
		// First every file on its own (calls inside the file are followed): all
		// files get this before any time goes to calls across files.
		reported := map[string]bool{}
		addNew := func(found []engine.Finding, gen bool) {
			var fresh []engine.Finding
			for _, f := range found {
				k := f.RuleID + "\x00" + f.Path + "\x00" + fmt.Sprint(f.Line)
				if !reported[k] {
					reported[k] = true
					fresh = append(fresh, f)
				}
			}
			injectionFindings(fresh, func(f CodeFinding) { f.Generated = gen; add(f) })
		}
		// Files are scanned on several cores; results are taken in file order.
		type scanned struct {
			found               []engine.Finding // at most auditMaxPerFile of a rule
			over                int              // those left out
			err                 error
			late, unread, timed bool
			ran                 bool // taken by a worker before the audit's time ran out
			gen                 bool // minified or bundled JavaScript
			kept                *passResult
		}
		out := make([]scanned, len(files))
		var next atomic.Int64
		var wg sync.WaitGroup
		for range budget.workers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					i := int(next.Add(1) - 1)
					if i >= len(files) || ctx.Err() != nil {
						return
					}
					p := files[i]
					out[i].ran = true
					if k := st.own(p, hash[p]); k != nil {
						out[i].kept = k // unchanged since an audit that finished it
						continue
					}
					if time.Now().After(deadline) {
						out[i].late = true
						continue
					}
					b, err := read(p)
					if err != nil {
						out[i].unread = true
						continue
					}
					lang := engine.LangOf(p)
					var found []engine.Finding
					found, out[i].timed, out[i].err = injectionScan(eng, lang, p, b)
					out[i].found, out[i].over = capFound(found)
					out[i].gen = generated(lang, b)
				}
			}()
		}
		wg.Wait()
		for i, p := range files {
			switch r := out[i]; {
			case r.unread:
			case !r.ran: // the caller's time ran out: what was scanned is kept
				notReached++
				partial = append(partial, UnfinishedFile{p, "time"})
			case r.late:
				late++
				partial = append(partial, UnfinishedFile{p, "time"})
			default:
				k := r.kept
				if k == nil {
					k = &passResult{Found: r.found, Over: r.over, Reason: unfinishedReason(r.err), Gen: r.gen}
					if !r.timed && k.Reason != "panic" {
						st.entry(p, hash[p]).Own = k
					}
				}
				addNew(k.Found, k.Gen)
				addOver(p, k.Over)
				if k.Reason != "" { // "calls": its own calls were cut short
					partial = append(partial, UnfinishedFile{p, k.Reason})
				}
			}
		}
		// Then, with the time left, calls across files: index the files, follow
		// each one's calls into the others. What runs out of time stays checked on
		// its own, and the summary says how far this got.
		// Results kept from earlier audits are taken while the file, the files its
		// calls reached and the names the project declares are unchanged; the
		// time goes to the other files, in order, those never tried before those
		// the clock cut short.
		done, covered, now, reason, cut := 0, 0, 0, "", false
		fresh := map[string]bool{}   // files whose calls were all followed in this audit
		var waiting []UnfinishedFile // calls across files not covered yet
		slowRules, slowFiles := 0, 0
		if left := time.Until(deadline); left > 0 && ctx.Err() == nil {
			pr := eng.NewProject(code, read, engine.ProjectOptions{CacheFile: codeIndexFile(), MaxTime: left,
				MaxHeap: budget.heap, MaxTokens: budget.projectTokens()})
			st.useDigests(pr, []string{"php", "python", "js"})
			order := make([]string, 0, len(files))
			var retry []string
			for _, p := range files {
				if fs := st.Files[p]; fs != nil && fs.Hash == hash[p] && fs.Calls == nil && fs.Part != nil {
					retry = append(retry, p)
				} else {
					order = append(order, p)
				}
			}
			for _, p := range append(order, retry...) {
				var k *passResult
				var part *partResult
				var slow []string
				if fs := st.Files[p]; fs != nil && fs.Hash == hash[p] && !stale[p] {
					k, part, slow = fs.Calls, fs.Part, fs.Slow
				}
				if k == nil && !cut && ctx.Err() == nil && !time.Now().After(deadline) && pr.Stopped() == "" {
					if b, err := read(p); err == nil {
						gen := generated(engine.LangOf(p), b)
						// A file the clock cut short before goes on from the rules it had
						// done; a rule too slow for an audit's time is left out.
						skip := map[string]bool{}
						for _, r := range slow {
							skip[r] = true
						}
						if part == nil {
							part = &partResult{}
						}
						for _, r := range part.Rules {
							skip[r] = true
						}
						res, err := injectionCalls(pr, p, b, skip)
						found, n := capFound(append(slices.Clone(part.Found), res.Found...))
						n += part.Over
						addOver(p, n)
						switch {
						case errors.Is(err, errPanic):
							addNew(found, gen)
							continue
						case pr.Unsteady(): // a callee changed during the audit: holds now, not kept
							addNew(found, gen)
							continue
						case res.Timed:
							// The clock or the heap ran out: what the finished rules found
							// is kept, and the next audit goes on from there. Only the
							// audit's clock or heap stops the other files: a file over its
							// own time limit (a busy server, a large file) waits for the
							// next audit, and this one goes on with the rest.
							addNew(found, gen)
							fs := st.entry(p, hash[p])
							next := &partResult{Rules: append(slices.Clone(part.Rules), res.Done...), Found: found, Over: n,
								Cut: part.Cut || res.Cut, Tries: maps.Clone(part.Tries)}
							if res.At != "" {
								if next.Tries == nil {
									next.Tries = map[string]int{}
								}
								if next.Tries[res.At]++; next.Tries[res.At] >= slowTries {
									fs.Slow = append(fs.Slow, res.At)
									delete(next.Tries, res.At)
								}
							}
							fs.Part = next
							cut = !res.FileTime
							continue
						}
						k = &passResult{Found: found, Over: n, Reason: unfinishedReason(err), Gen: gen}
						if k.Reason == "" && (part.Cut || res.Cut || len(slow) > 0) {
							k.Reason = "calls"
						}
						fs := st.entry(p, hash[p])
						fs.Calls, fs.Part = k, nil
						if len(part.Rules) == 0 {
							fresh[p] = true // every rule followed in this audit: its files replace the old ones
						}
						now++
					}
				}
				if k == nil {
					waiting = append(waiting, UnfinishedFile{p, "calls"})
					continue
				}
				addNew(k.Found, k.Gen)
				addOver(p, k.Over)
				covered++
				if k.Reason != "calls" {
					done++ // limits of the file itself were reported by the first pass
				}
				if len(slow) > 0 {
					slowFiles++
					slowRules += len(slow)
				}
			}
			for _, p := range files {
				if fresh[p] {
					st.entry(p, hash[p]).setDeps(pr.Deps(p))
				} else if deps := pr.Deps(p); len(deps) > 0 {
					st.entry(p, hash[p]).addDeps(deps)
				}
			}
			reason = pr.Stopped()
			if reason == "" && done < len(files) {
				reason = "some files' calls were cut short by the time or size limits"
			}
		} else {
			reason = "no time was left for it"
		}
		if walked {
			st.keepOnly(hash)
		}
		saveCallState(stateFile, st)
		if done < len(files) {
			notes = append(notes, crossFileFinding(done, covered, now, len(files), slowRules, slowFiles, reason, waiting, notReached+late == 0))
		}
		for p, n := range over {
			countOver(p, n)
		}
	}

	if len(partial) > 0 {
		// Files left unchecked come first in the list; those checked function by
		// function after them.
		sort.SliceStable(partial, func(i, j int) bool { return partial[i].Reason != "calls" && partial[j].Reason == "calls" })
		notes = append([]CodeFinding{partialFinding(partial)}, notes...)
	}
	if left > 0 {
		res.Truncated = true
		notes = append([]CodeFinding{{Kind: "audit", Severity: "info",
			Detail: fmt.Sprintf("%d more finding(s) are not listed: at most %d of one rule or check in one file and %d in all are; "+
				"the injection counts take them all", left, auditMaxPerFile, auditMaxFindings),
			Fix: "fix the files listed and audit again, or audit a smaller folder"}}, notes...)
	}
	if len(walkCut) > 0 || notReached > 0 {
		res.Unfinished = true
		notes = append([]CodeFinding{stoppedFinding(walkCut, notReached)}, notes...)
	}
	sort.SliceStable(res.Findings, func(i, j int) bool {
		a, b := res.Findings[i], res.Findings[j]
		if ra, rb := severityRank(a.Severity), severityRank(b.Severity); ra != rb {
			return ra < rb
		}
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		return a.Line < b.Line
	})
	// The summaries come first, so a reader who cuts the list short keeps them.
	res.Findings = append(notes, res.Findings...)
	return res
}

// capFound keeps at most auditMaxPerFile findings of one rule in one file, the
// first ones; over is how many it left out.
func capFound(found []engine.Finding) (kept []engine.Finding, over int) {
	n := map[string]int{}
	for _, f := range found {
		k := f.RuleID + "\x00" + f.Path
		if n[k] >= auditMaxPerFile {
			over++
			continue
		}
		n[k]++
		kept = append(kept, f)
	}
	if over == 0 {
		return found, 0
	}
	return kept, over
}

// listRank orders findings for the list's cap: alerts before info-tier
// injection findings (and those in test or generated code), then by severity.
func listRank(f CodeFinding) int {
	r := severityRank(f.Severity)
	if f.Kind == "injection" && (f.Tier != "alert" || f.TestPath || f.Generated) {
		r += 3
	}
	return r
}

func severityRank(s string) int {
	switch s {
	case "critical":
		return 0
	case "warning":
		return 1
	}
	return 2
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
