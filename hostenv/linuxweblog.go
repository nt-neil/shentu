package hostenv

// The logs web servers and PHP-FPM write on Linux, as their configuration
// names them, and whether what is in them can be trusted: shentu detect
// reads them for attempts on this host's vulnerabilities. Discovery and
// description only; reading the logs is detect's.

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// LogSource is one log file (or destination) a web server or PHP-FPM
// writes to.
type LogSource struct {
	Path   string `json:"path"`   // absolute; for a pipe or syslog the destination as written
	Server string `json:"server"` // nginx, apache, php-fpm
	Kind   string `json:"kind"`   // access, error, slow, php_error
	// Format is the format's name (combined, main, vhost_combined), empty
	// for one written out in place or an error log. Spec is the format as
	// defined: nginx's log_format strings joined, Apache's LogFormat string.
	// Empty Spec with a Format: the name is defined nowhere read, and the
	// reader must say format_unrecognized rather than guess.
	Format string `json:"format,omitempty"`
	Spec   string `json:"format_spec,omitempty"`
	Escape string `json:"escape,omitempty"` // nginx log_format escape= (json, none); empty is nginx's default
	// Vhosts: server_name / ServerName of the blocks writing to it; none for
	// the main server.
	Vhosts []string `json:"vhosts,omitempty"`
	Config string   `json:"config"` // file:line naming it, or "default" for the server's built-in path
	// Verified: only root can have written the file (LogTrust). Reason says
	// why not, or why the file is not there to read.
	Verified bool   `json:"verified"`
	Reason   Reason `json:"reason,omitempty"`
	Detail   string `json:"detail,omitempty"`
}

// Reasons a log source is not verified or not readable, beside the
// general ones (ReasonPermission, ReasonUntrusted, ReasonNotRegular).
const (
	// ReasonWebUserWritable: the web server's or PHP's own user owns the
	// file (nginx's logrotate creates it so on Debian, Ubuntu and Rocky).
	// Still unverified, but forging it takes the web application already
	// compromised, not any local user.
	ReasonWebUserWritable Reason = "web_user_writable"
	ReasonLoggingDisabled Reason = "logging_disabled" // access_log off
	ReasonNotAFile        Reason = "not_a_file"       // syslog:, a pipe, stderr: nothing to read here
	ReasonVariablePath    Reason = "variable_path"    // the path holds a variable or is relative: not known which file
	ReasonNotFound        Reason = "not_found"        // named, but not there (not written yet, or removed)
)

// WebUserWritableMeaning is what an alert on a web_user_writable source must
// say, in English and in Chinese.
const (
	WebUserWritableMeaning   = "this log is owned by the web server's user: forging its lines is only possible if the web application is already compromised"
	WebUserWritableMeaningZh = "這個 log 由 web 伺服器的使用者擁有：只有 web 應用已經被入侵時，才可能偽造其中的內容"
)

// Bounds on reading the configuration: includes may not loop or fan out
// without end.
const (
	maxLogConfFiles = 256
	maxLogConfDepth = 8
	maxLogSources   = 1024
	maxNgxNest      = 64
)

// defaultWebUsers are the accounts web servers and PHP run as on the
// distributions shentu supports, beside those the configuration names.
var defaultWebUsers = []string{"www-data", "nginx", "apache", "httpd", "nobody", "wwwrun", "http", "lighttpd", "php-fpm"}

// defaultWebGroups are their groups that are not also an account's name.
var defaultWebGroups = []string{"nogroup", "www"}

// WebLogs is the logs nginx, Apache and PHP-FPM are configured to write,
// sorted by path, each with its trust. Partial when some configuration
// could not be read: the logs it names are missing.
func (c LinuxCollector) WebLogs(src Source) Obs[[]LogSource] {
	l := &logLoader{src: src, conf: DefaultWebConf, out: map[string]*LogSource{}}
	l.nginx()
	l.apache()
	l.phpFPM()
	web := l.webAccounts()
	var out []LogSource
	for _, s := range l.out {
		if s.Reason == "" {
			s.Verified, s.Reason, s.Detail = LogTrust(src, s.Path, web)
		}
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].Kind < out[j].Kind
	})
	if len(l.unread) > 0 {
		return Partial(out, ReasonPermission, "web server or PHP-FPM configuration unread, the logs it names are missing: "+strings.Join(l.unread, "; "))
	}
	if l.cut {
		return Partial(out, ReasonTruncated, fmt.Sprintf("more than %d log sources: the rest are missing", maxLogSources))
	}
	return OK(out)
}

// WebAccounts are the accounts and groups web servers and PHP run as, by
// uid and gid: a file or directory of theirs is web_user_writable.
type WebAccounts struct {
	UIDs map[int]string
	GIDs map[int]string
}

// LogTrust says whether only root can have written p: it, after its links,
// is a regular file owned by root that neither group nor others can write,
// and every directory above it and above the link is root's, not writable
// by others, and writable by its group only when that group is none of
// the web server's or PHP's (Ubuntu's /var/log, 775 root:syslog, passes; a
// 775 root:www-data one does not: the web user could swap the file). A
// sticky directory lets no one but a file's owner replace it. A directory
// whose group is not known (Windows, an old fixture) and that its group
// may write is not trusted.
func LogTrust(src Source, p string, web WebAccounts) (verified bool, why Reason, detail string) {
	real, err := EvalSymlinks(src, p)
	if err != nil {
		return false, statReason(err), whyUnread(err)
	}
	st, err := Stat(src, real)
	if err != nil {
		return false, statReason(err), whyUnread(err)
	}
	switch {
	case !st.Mode.IsRegular():
		return false, ReasonNotRegular, real + " is not a regular file"
	case st.UID != 0:
		if name, ok := web.UIDs[st.UID]; ok {
			return false, ReasonWebUserWritable, fmt.Sprintf("%s is owned by %s (uid %d): %s", real, name, st.UID, WebUserWritableMeaning)
		}
		return false, ReasonUntrusted, fmt.Sprintf("%s is owned by uid %d, not root", real, st.UID)
	case st.Mode.Perm()&0o022 != 0:
		return false, ReasonUntrusted, fmt.Sprintf("%s is writable by group or others (%v)", real, st.Mode.Perm())
	}
	links, err := linkChain(src, p)
	if err != nil {
		return false, ReasonUnverified, whyUnread(err)
	}
	dirs := map[string]bool{}
	for _, f := range append([]string{p, real}, links...) { // whoever may write a directory holding a link may repoint it
		for d := path.Dir(f); ; d = path.Dir(d) {
			dirs[d] = true
			if d == "/" {
				break
			}
		}
	}
	names := make([]string, 0, len(dirs))
	for d := range dirs {
		names = append(names, d)
	}
	sort.Strings(names)
	for _, d := range names {
		ds, err := Stat(src, d)
		if err != nil {
			return false, ReasonUnverified, "directory " + d + ": " + whyUnread(err)
		}
		sticky := ds.Mode&fs.ModeSticky != 0
		switch {
		case ds.UID != 0:
			if name, ok := web.UIDs[ds.UID]; ok {
				return false, ReasonWebUserWritable, fmt.Sprintf("directory %s is owned by %s (uid %d): %s", d, name, ds.UID, WebUserWritableMeaning)
			}
			return false, ReasonUntrusted, fmt.Sprintf("directory %s is owned by uid %d, not root", d, ds.UID)
		case ds.Mode.Perm()&0o002 != 0 && !sticky:
			return false, ReasonUntrusted, "directory " + d + " is writable by others"
		case ds.Mode.Perm()&0o020 != 0 && !sticky:
			if ds.GID == nil {
				return false, ReasonUnverified, "directory " + d + " is writable by its group, and which group is not known"
			}
			if name, ok := web.GIDs[*ds.GID]; ok {
				return false, ReasonWebUserWritable, fmt.Sprintf("directory %s is writable by group %s (gid %d): %s", d, name, *ds.GID, WebUserWritableMeaning)
			}
		}
	}
	return true, "", ""
}

// linkChain is every symbolic link resolving p goes through, in order,
// links in its directories included: each one's directory must be trusted
// as much as the file's.
func linkChain(src Source, p string) ([]string, error) {
	var links []string
	cur := path.Clean(p)
	for hops := 0; hops <= 40; hops++ {
		parts := strings.Split(strings.Trim(cur, "/"), "/")
		dir, moved := "/", false
		for i, part := range parts {
			next := path.Join(dir, part)
			t, err := src.Readlink(next)
			if err != nil {
				dir = next
				continue
			}
			links = append(links, next)
			if !strings.HasPrefix(t, "/") {
				t = path.Join(dir, t)
			}
			cur, moved = path.Join(append([]string{t}, parts[i+1:]...)...), true
			break
		}
		if !moved {
			return links, nil
		}
	}
	return nil, errors.New("too many links")
}

// statReason is the Reason for a log file that could not be looked at.
func statReason(err error) Reason {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return ReasonNotFound
	case errors.Is(err, fs.ErrPermission):
		return ReasonPermission
	}
	return ReasonUnverified // a fixture or a source that cannot stat: not known who wrote it
}

// logLoader reads the configuration with readWebConf's checks and gathers
// the log sources.
type logLoader struct {
	src    Source
	conf   WebConf
	files  int
	unread []string
	out    map[string]*LogSource // server\x00kind\x00path
	cut    bool
	users  []string // accounts the configuration runs the servers as
	groups []string // and groups
}

// read reads one configuration file, counting it against the bound.
func (l *logLoader) read(p string) ([]byte, bool) {
	p = path.Clean(p)
	switch {
	case !underDir(p, l.conf.Root):
		l.unread = append(l.unread, p+" (outside "+l.conf.Root+")")
		return nil, false
	case l.files >= maxLogConfFiles:
		l.unread = append(l.unread, fmt.Sprintf("%s (over %d configuration files)", p, maxLogConfFiles))
		return nil, false
	}
	l.files++
	b, why := readWebConf(l.src, p, l.conf)
	if why != "" {
		l.unread = append(l.unread, p+" ("+why+")")
		return nil, false
	}
	return b, true
}

// include is the files an include names: a glob relative to dir, or every
// file of a directory (Apache).
func (l *logLoader) include(dir, arg string, optional bool) []string {
	p := arg
	if !strings.HasPrefix(p, "/") {
		p = path.Join(dir, p)
	}
	if names, err := l.src.ReadDir(p); err == nil && !strings.ContainsAny(p, "*?[") {
		var out []string
		for _, n := range names {
			out = append(out, path.Join(p, n))
		}
		return out
	}
	m := Glob(l.src, p)
	if len(m) == 0 && !optional && !strings.ContainsAny(p, "*?[") {
		l.unread = append(l.unread, p+" (included, not found)")
	}
	return m
}

// add records a log source, merging the vhosts of one already seen.
func (l *logLoader) add(s LogSource) {
	k := s.Server + "\x00" + s.Kind + "\x00" + s.Path
	if o, ok := l.out[k]; ok {
		for _, v := range s.Vhosts {
			if !contains(o.Vhosts, v) {
				o.Vhosts = append(o.Vhosts, v)
			}
		}
		if o.Format != s.Format || o.Spec != s.Spec {
			o.Format, o.Spec, o.Escape = "", "", ""
			o.Detail = "written in more than one format"
			if o.Reason == "" {
				o.Reason = ReasonParse
			}
		}
		return
	}
	if len(l.out) >= maxLogSources {
		l.cut = true
		return
	}
	if s.Reason == "" {
		switch {
		case strings.Contains(s.Path, "$"):
			s.Reason, s.Detail = ReasonVariablePath, "the path holds a variable"
		case !strings.HasPrefix(s.Path, "/"):
			s.Reason, s.Detail = ReasonVariablePath, "a relative path"
		}
	}
	l.out[k] = &s
}

// webAccounts is the uids and gids of the web servers' and PHP's accounts
// and groups: the defaults and those the configuration names, and each
// such account's primary group.
func (l *logLoader) webAccounts() WebAccounts {
	w := WebAccounts{UIDs: map[int]string{}, GIDs: map[int]string{}}
	users, groups := map[string]bool{}, map[string]bool{}
	for _, u := range append(append([]string{}, defaultWebUsers...), l.users...) {
		users[u] = true
	}
	for _, g := range append(append(append([]string{}, defaultWebUsers...), defaultWebGroups...), l.groups...) {
		groups[g] = true
	}
	primary := map[int]bool{}
	if b, err := l.src.ReadFile("/etc/passwd"); err == nil {
		for _, e := range ParsePasswd(b) {
			uid, err := strconv.Atoi(e.UID)
			if err != nil || uid == 0 || !users[e.Name] {
				continue
			}
			w.UIDs[uid] = e.Name
			if gid, err := strconv.Atoi(e.GID); err == nil && gid != 0 {
				primary[gid] = true
			}
		}
	}
	if b, err := l.src.ReadFile("/etc/group"); err == nil {
		for _, ln := range strings.Split(string(b), "\n") {
			f := strings.Split(ln, ":")
			if len(f) < 3 || strings.HasPrefix(f[0], "#") {
				continue
			}
			gid, err := strconv.Atoi(f[2])
			if err != nil || gid == 0 {
				continue
			}
			if groups[f[0]] || primary[gid] {
				w.GIDs[gid] = f[0]
			}
		}
	}
	for gid := range primary { // a primary group /etc/group does not list
		if _, ok := w.GIDs[gid]; !ok {
			w.GIDs[gid] = "gid " + strconv.Itoa(gid)
		}
	}
	return w
}

func at(file string, line int) string { return file + ":" + strconv.Itoa(line) }

// --- nginx ---

// ngxDir is one nginx directive; block is set for one with a { } block.
type ngxDir struct {
	name     string
	args     []string
	file     string
	line     int
	block    []*ngxDir
	hasBlock bool
}

type ngxTok struct {
	s     string
	line  int
	punct byte // ';', '{', '}' or 0 for a word
}

// ngxLex splits nginx configuration into words and punctuation, as nginx
// reads it: # starts a comment at a word's start, quotes group, ${var}
// keeps its braces.
func ngxLex(b []byte) []ngxTok {
	var out []ngxTok
	line := 1
	for i := 0; i < len(b); {
		c := b[i]
		switch {
		case c == '\n':
			line++
			i++
		case c == ' ' || c == '\t' || c == '\r':
			i++
		case c == '#':
			for i < len(b) && b[i] != '\n' {
				i++
			}
		case c == ';' || c == '{' || c == '}':
			out = append(out, ngxTok{line: line, punct: c})
			i++
		case c == '"' || c == '\'':
			start := line
			var sb strings.Builder
			for i++; i < len(b) && b[i] != c; i++ {
				if b[i] == '\\' && i+1 < len(b) {
					i++
					switch b[i] {
					case 't':
						sb.WriteByte('\t')
					case 'n':
						sb.WriteByte('\n')
					case 'r':
						sb.WriteByte('\r')
					case '"', '\'', '\\':
						sb.WriteByte(b[i])
					default:
						sb.WriteByte('\\')
						sb.WriteByte(b[i])
					}
					continue
				}
				if b[i] == '\n' {
					line++
				}
				sb.WriteByte(b[i])
			}
			i++
			out = append(out, ngxTok{s: sb.String(), line: start})
		default:
			start := i
			for i < len(b) && !strings.ContainsRune(" \t\r\n;{}", rune(b[i])) {
				if b[i] == '$' && i+1 < len(b) && b[i+1] == '{' {
					for i < len(b) && b[i] != '}' {
						i++
					}
				}
				i++
			}
			out = append(out, ngxTok{s: string(b[start:min(i, len(b))]), line: line})
		}
	}
	return out
}

// ngxParse builds the directives of toks from *i to the closing brace.
func ngxParse(toks []ngxTok, i *int, file string, depth int) []*ngxDir {
	var out []*ngxDir
	var cur *ngxDir
	for *i < len(toks) {
		t := toks[*i]
		*i++
		switch t.punct {
		case ';':
			if cur != nil {
				out, cur = append(out, cur), nil
			}
		case '{':
			if cur == nil {
				cur = &ngxDir{file: file, line: t.line}
			}
			cur.hasBlock = true
			if depth < maxNgxNest {
				cur.block = ngxParse(toks, i, file, depth+1)
			} else { // too deep: skip the block whole
				for n := 1; *i < len(toks) && n > 0; *i++ {
					switch toks[*i].punct {
					case '{':
						n++
					case '}':
						n--
					}
				}
			}
			out, cur = append(out, cur), nil
		case '}':
			if cur != nil {
				out = append(out, cur)
			}
			return out
		default:
			if cur == nil {
				cur = &ngxDir{name: t.s, file: file, line: t.line}
			} else {
				cur.args = append(cur.args, t.s)
			}
		}
	}
	if cur != nil {
		out = append(out, cur)
	}
	return out
}

// ngxFile reads and parses one file, its includes put in place.
func (l *logLoader) ngxFile(p string, depth int) []*ngxDir {
	b, ok := l.read(p)
	if !ok {
		return nil
	}
	i := 0
	return l.ngxIncludes(ngxParse(ngxLex(b), &i, p, 0), depth)
}

func (l *logLoader) ngxIncludes(ds []*ngxDir, depth int) []*ngxDir {
	var out []*ngxDir
	for _, d := range ds {
		if d.name == "include" && len(d.args) == 1 && !d.hasBlock {
			if depth >= maxLogConfDepth {
				l.unread = append(l.unread, fmt.Sprintf("%s (included more than %d deep)", d.args[0], maxLogConfDepth))
				continue
			}
			for _, f := range l.include("/etc/nginx", d.args[0], false) {
				out = append(out, l.ngxFile(f, depth+1)...)
			}
			continue
		}
		if d.hasBlock {
			d.block = l.ngxIncludes(d.block, depth)
		}
		out = append(out, d)
	}
	return out
}

// ngxCombined is nginx's predefined format.
const ngxCombined = `$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"`

type ngxFormat struct{ spec, escape string }

// nginx gathers the logs nginx.conf names: each server's access logs (its
// own, else the http block's, else nginx's default), the error logs, and
// those of locations.
func (l *logLoader) nginx() {
	const conf = "/etc/nginx/nginx.conf"
	if !exists(l.src, conf) {
		return
	}
	main := l.ngxFile(conf, 0)
	formats := map[string]ngxFormat{"combined": {spec: ngxCombined}}
	var mainErr []*ngxDir
	var https []*ngxDir
	for _, d := range main {
		switch d.name {
		case "user": // user www-data [group]
			if len(d.args) > 0 {
				l.users = append(l.users, d.args[0])
			}
			if len(d.args) > 1 {
				l.groups = append(l.groups, d.args[1])
			}
		case "error_log":
			mainErr = append(mainErr, d)
		case "http":
			https = append(https, d)
		}
	}
	for _, h := range https {
		for _, d := range h.block {
			if d.name == "log_format" && len(d.args) >= 2 {
				f := ngxFormat{}
				rest := d.args[1:]
				if e, ok := strings.CutPrefix(rest[0], "escape="); ok {
					f.escape, rest = e, rest[1:]
				}
				f.spec = strings.Join(rest, "")
				formats[d.args[0]] = f
			}
		}
	}
	errs := func(ds []*ngxDir, vhosts []string) {
		for _, d := range ds {
			if len(d.args) > 0 {
				l.ngxLog(d, "error", d.args[0], "", formats, vhosts)
			}
		}
	}
	if len(https) == 0 {
		errs(mainErr, nil)
	}
	for _, h := range https {
		var acc, errl []*ngxDir
		var servers []*ngxDir
		for _, d := range h.block {
			switch d.name {
			case "access_log":
				acc = append(acc, d)
			case "error_log":
				errl = append(errl, d)
			case "server":
				servers = append(servers, d)
			}
		}
		if len(errl) == 0 {
			errl = mainErr
		}
		if len(errl) == 0 {
			l.add(LogSource{Path: "/var/log/nginx/error.log", Server: "nginx", Kind: "error", Config: "default"})
		}
		errs(errl, nil)
		def := &ngxDir{name: "access_log", args: []string{"/var/log/nginx/access.log", "combined"}}
		for _, s := range servers {
			var names []string
			var sAcc, sErr []*ngxDir
			var nested []*ngxDir
			for _, d := range s.block {
				switch d.name {
				case "server_name":
					for _, n := range d.args {
						if n != "_" && n != "" {
							names = append(names, n)
						}
					}
				case "access_log":
					sAcc = append(sAcc, d)
				case "error_log":
					sErr = append(sErr, d)
				default:
					if d.hasBlock {
						nested = append(nested, d)
					}
				}
			}
			if len(sAcc) == 0 {
				sAcc = acc
			}
			if len(sAcc) == 0 {
				sAcc = []*ngxDir{def}
			}
			for _, d := range sAcc {
				l.ngxAccess(d, formats, names)
			}
			errs(sErr, names)
			var walk func(ds []*ngxDir, depth int)
			walk = func(ds []*ngxDir, depth int) {
				if depth > maxNgxNest {
					return
				}
				for _, d := range ds {
					switch d.name {
					case "access_log":
						l.ngxAccess(d, formats, names)
					case "error_log":
						errs([]*ngxDir{d}, names)
					}
					if d.hasBlock {
						walk(d.block, depth+1)
					}
				}
			}
			for _, d := range nested {
				walk(d.block, 0)
			}
		}
		if len(servers) == 0 {
			for _, d := range acc {
				l.ngxAccess(d, formats, nil)
			}
		}
	}
}

func (l *logLoader) ngxAccess(d *ngxDir, formats map[string]ngxFormat, vhosts []string) {
	if len(d.args) == 0 {
		return
	}
	name := "combined"
	if len(d.args) > 1 && !strings.Contains(d.args[1], "=") && d.args[1] != "gzip" {
		name = d.args[1]
	}
	l.ngxLog(d, "access", d.args[0], name, formats, vhosts)
}

func (l *logLoader) ngxLog(d *ngxDir, kind, dest, format string, formats map[string]ngxFormat, vhosts []string) {
	s := LogSource{Path: dest, Server: "nginx", Kind: kind, Vhosts: vhosts, Config: "default"}
	if d.file != "" {
		s.Config = at(d.file, d.line)
	}
	if kind == "access" {
		s.Format = format
		if f, ok := formats[format]; ok {
			s.Spec, s.Escape = f.spec, f.escape
		}
	}
	switch {
	case dest == "off":
		s.Reason, s.Detail = ReasonLoggingDisabled, kind+"_log off"
	case strings.HasPrefix(dest, "syslog:"), strings.HasPrefix(dest, "memory:"), dest == "stderr", dest == "/dev/stderr", dest == "/dev/stdout", dest == "/dev/null":
		s.Reason, s.Detail = ReasonNotAFile, "written to "+dest
	}
	l.add(s)
}

// --- Apache ---

// apacheCLF is the format TransferLog writes without a LogFormat.
const apacheCLF = `%h %l %u %t "%r" %>s %b`

type apacheDecl struct {
	dest, format, file string
	line               int
	transfer           bool
}

type apacheScope struct {
	names        []string
	custom, errs []apacheDecl
}

type apacheState struct {
	root          string
	env           map[string]string
	formats       map[string]string
	defaultFormat string
	main          apacheScope
	vhosts        []*apacheScope
	cur           *apacheScope
}

var apacheEnvLine = regexp.MustCompile(`^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$`)

// apache gathers the logs of the main server and every VirtualHost: a
// VirtualHost without its own CustomLog or ErrorLog writes to the main
// server's.
func (l *logLoader) apache() {
	st := &apacheState{env: map[string]string{}, formats: map[string]string{}}
	var conf string
	switch {
	case exists(l.src, "/etc/apache2/apache2.conf"):
		conf, st.root = "/etc/apache2/apache2.conf", "/etc/apache2"
		if b, ok := l.read("/etc/apache2/envvars"); ok {
			for _, ln := range strings.Split(string(b), "\n") {
				if m := apacheEnvLine.FindStringSubmatch(ln); m != nil {
					v := strings.Trim(strings.TrimSpace(m[2]), `"'`)
					st.env[m[1]] = strings.ReplaceAll(v, "$SUFFIX", "") // apache2ctl's multi-instance suffix, empty for the main one
				}
			}
		}
	case exists(l.src, "/etc/httpd/conf/httpd.conf"):
		conf, st.root = "/etc/httpd/conf/httpd.conf", "/etc/httpd"
	default:
		return
	}
	st.cur = &st.main
	l.apacheFile(st, conf, 0)
	emit := func(sc *apacheScope, inherit *apacheScope) {
		custom, errs := sc.custom, sc.errs
		if inherit != nil {
			if len(custom) == 0 {
				custom = inherit.custom
			}
			if len(errs) == 0 {
				errs = inherit.errs
			}
		}
		for _, d := range custom {
			s := LogSource{Path: st.path(d.dest), Server: "apache", Kind: "access", Vhosts: sc.names, Config: at(d.file, d.line)}
			switch {
			case d.transfer:
				s.Spec = st.defaultFormat
				if s.Spec == "" {
					s.Spec = apacheCLF
				}
			case strings.Contains(d.format, "%"):
				s.Spec = d.format
			default:
				s.Format, s.Spec = d.format, st.formats[d.format]
			}
			l.apacheDest(&s, d.dest)
			l.add(s)
		}
		for _, d := range errs {
			s := LogSource{Path: st.path(d.dest), Server: "apache", Kind: "error", Vhosts: sc.names, Config: at(d.file, d.line)}
			l.apacheDest(&s, d.dest)
			l.add(s)
		}
	}
	if len(st.main.errs) == 0 { // Apache's own default: logs/error_log under ServerRoot
		st.main.errs = []apacheDecl{{dest: "logs/error_log", file: "default"}}
	}
	emit(&st.main, nil)
	for _, v := range st.vhosts {
		emit(v, &st.main)
	}
	for _, s := range l.out {
		if s.Config == "default:0" {
			s.Config = "default"
		}
	}
}

// apacheDest marks a pipe or syslog destination.
func (l *logLoader) apacheDest(s *LogSource, dest string) {
	switch {
	case strings.HasPrefix(dest, "|"):
		s.Path, s.Reason, s.Detail = dest, ReasonNotAFile, "piped to a program"
	case strings.HasPrefix(dest, "syslog"):
		s.Path, s.Reason, s.Detail = dest, ReasonNotAFile, "written to syslog"
	}
}

// path is a log path with ${VAR} expanded and made absolute under
// ServerRoot, as Apache does.
func (st *apacheState) path(p string) string {
	if strings.HasPrefix(p, "|") || strings.HasPrefix(p, "syslog") {
		return p
	}
	p = st.expand(p)
	if !strings.HasPrefix(p, "/") && !strings.Contains(p, "$") {
		p = path.Join(st.root, p)
	}
	return p
}

func (st *apacheState) expand(s string) string {
	for i := 0; i < 16 && strings.Contains(s, "${"); i++ {
		a := strings.Index(s, "${")
		b := strings.Index(s[a:], "}")
		if b < 0 {
			break
		}
		v, ok := st.env[s[a+2:a+b]]
		if !ok {
			break // left as it is: the path is reported as holding a variable
		}
		s = s[:a] + v + s[a+b+1:]
	}
	return s
}

// apacheFile reads one file line by line, following Include in place.
func (l *logLoader) apacheFile(st *apacheState, p string, depth int) {
	b, ok := l.read(p)
	if !ok {
		return
	}
	lines := strings.Split(string(b), "\n")
	for n := 0; n < len(lines); n++ {
		first := n + 1
		ln := strings.TrimSpace(lines[n])
		for strings.HasSuffix(ln, "\\") && n+1 < len(lines) { // a continued line
			n++
			ln = strings.TrimSuffix(ln, "\\") + " " + strings.TrimSpace(lines[n])
		}
		if ln == "" || ln[0] == '#' {
			continue
		}
		if ln[0] == '<' {
			f := strings.Fields(strings.Trim(ln, "<>"))
			if len(f) == 0 {
				continue
			}
			switch strings.ToLower(f[0]) {
			case "virtualhost":
				v := &apacheScope{}
				st.vhosts = append(st.vhosts, v)
				st.cur = v
			case "/virtualhost":
				st.cur = &st.main
			}
			continue // other sections (IfModule, Directory) are read as if open
		}
		args := apacheWords(ln)
		if len(args) == 0 {
			continue
		}
		name, args := strings.ToLower(args[0]), args[1:]
		switch name {
		case "include", "includeoptional":
			if len(args) == 0 {
				continue
			}
			if depth >= maxLogConfDepth {
				l.unread = append(l.unread, fmt.Sprintf("%s (included more than %d deep)", args[0], maxLogConfDepth))
				continue
			}
			for _, f := range l.include(st.root, st.expand(args[0]), name == "includeoptional") {
				l.apacheFile(st, f, depth+1)
			}
		case "serverroot":
			if len(args) > 0 && st.cur == &st.main {
				st.root = st.expand(args[0])
			}
		case "define":
			if len(args) >= 2 {
				st.env[args[0]] = args[1]
			}
		case "user":
			if len(args) > 0 {
				l.users = append(l.users, st.expand(args[0]))
			}
		case "group":
			if len(args) > 0 {
				l.groups = append(l.groups, st.expand(args[0]))
			}
		case "servername", "serveralias":
			for _, a := range args {
				if !contains(st.cur.names, a) {
					st.cur.names = append(st.cur.names, a)
				}
			}
		case "logformat":
			switch len(args) {
			case 1:
				st.defaultFormat = args[0]
			default:
				if len(args) >= 2 {
					st.formats[args[1]] = args[0]
				}
			}
		case "customlog":
			if len(args) >= 2 {
				st.cur.custom = append(st.cur.custom, apacheDecl{dest: args[0], format: args[1], file: p, line: first})
			}
		case "transferlog":
			if len(args) >= 1 {
				st.cur.custom = append(st.cur.custom, apacheDecl{dest: args[0], file: p, line: first, transfer: true})
			}
		case "errorlog":
			if len(args) >= 1 {
				st.cur.errs = append(st.cur.errs, apacheDecl{dest: args[0], file: p, line: first})
			}
		}
	}
}

// apacheWords splits a directive line as Apache does: quotes group, a
// backslash escapes the quote inside them.
func apacheWords(s string) []string {
	var out []string
	for i := 0; i < len(s); {
		for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
			i++
		}
		if i >= len(s) {
			break
		}
		if q := s[i]; q == '"' || q == '\'' {
			var sb strings.Builder
			for i++; i < len(s) && s[i] != q; i++ {
				if s[i] == '\\' && i+1 < len(s) && (s[i+1] == q || s[i+1] == '\\') {
					i++
				}
				sb.WriteByte(s[i])
			}
			i++
			out = append(out, sb.String())
			continue
		}
		start := i
		for i < len(s) && s[i] != ' ' && s[i] != '\t' {
			i++
		}
		out = append(out, s[start:i])
	}
	return out
}

// --- PHP-FPM ---

var phpFPMConfs = []string{"/etc/php/*/fpm/php-fpm.conf", "/etc/php-fpm.conf"}

// phpFPM gathers PHP-FPM's own error log, each pool's access and slow logs,
// and the error_log a pool sets for PHP (written by the pool's user).
func (l *logLoader) phpFPM() {
	for _, g := range phpFPMConfs {
		for _, f := range Glob(l.src, g) {
			l.fpmFile(f, "global", 0)
		}
	}
}

func (l *logLoader) fpmFile(p, section string, depth int) string {
	b, ok := l.read(p)
	if !ok {
		return section
	}
	for n, ln := range strings.Split(string(b), "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || ln[0] == ';' || ln[0] == '#' {
			continue
		}
		if strings.HasPrefix(ln, "[") && strings.HasSuffix(ln, "]") {
			section = strings.TrimSpace(ln[1 : len(ln)-1])
			continue
		}
		k, v, ok := strings.Cut(ln, "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.Trim(strings.TrimSpace(v), `"'`)
		v = strings.ReplaceAll(v, "$pool", section)
		src := LogSource{Path: v, Server: "php-fpm", Config: at(p, n+1)}
		if section != "global" {
			src.Vhosts = []string{"pool " + section}
		}
		switch k {
		case "include":
			if depth >= maxLogConfDepth {
				l.unread = append(l.unread, fmt.Sprintf("%s (included more than %d deep)", v, maxLogConfDepth))
				continue
			}
			for _, f := range l.include(path.Dir(p), v, false) {
				section = l.fpmFile(f, section, depth+1)
			}
		case "user":
			if section != "global" {
				l.users = append(l.users, v)
			}
		case "group", "listen.group":
			if section != "global" {
				l.groups = append(l.groups, v)
			}
		case "error_log":
			if section == "global" {
				src.Kind = "error"
				if v == "syslog" {
					src.Reason, src.Detail = ReasonNotAFile, "written to syslog"
				}
				l.add(src)
			}
		case "slowlog":
			src.Kind = "slow"
			l.add(src)
		case "access.log":
			src.Kind = "access"
			l.add(src)
		case "php_admin_value[error_log]", "php_value[error_log]":
			src.Kind = "php_error"
			l.add(src)
		}
	}
	return section
}
