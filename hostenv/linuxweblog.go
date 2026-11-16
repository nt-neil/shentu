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
	"syscall"
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
	// HostnameLookups: Apache looks up names (HostnameLookups On or Double
	// anywhere in its configuration): %h is then a PTR name, not an address.
	HostnameLookups bool `json:"hostname_lookups,omitempty"`
	// IdentityCheck: Apache asks the client's identd (IdentityCheck On):
	// %l is then what the client's host answers.
	IdentityCheck bool `json:"identity_check,omitempty"`
	// Vhosts: server_name / ServerName of the blocks writing to it; none for
	// the main server.
	Vhosts []string `json:"vhosts,omitempty"`
	Config string   `json:"config"` // file:line naming it, or "default" for the server's built-in path
	// Verified: only root can change the file (LogTrust), and no process of
	// a web account holds it open for writing where it could be made to
	// write (mod_php, ptrace). Reason says why not, or why the file is not
	// there to read.
	Verified bool   `json:"verified"`
	Reason   Reason `json:"reason,omitempty"`
	Detail   string `json:"detail,omitempty"`
	// FileID is the device:inode judged: a reader opening the path must find
	// the same file (and still root's) for its lines to be verified.
	FileID string `json:"file_id,omitempty"`
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
	// ReasonClientFromHeader: the server takes the client address from a
	// request header (nginx's realip, Apache's mod_remoteip): the logged
	// address is what a proxy, or the client, wrote.
	ReasonClientFromHeader Reason = "client_from_header"
	// ReasonCustomFormat: the access log is not in one of the standard
	// formats (nginx combined and RHEL's main, Apache combined and common,
	// with %h, %a or %{c}a). Its lines are parsed and matched, but how a
	// field the client writes may shift the others is not ruled out.
	ReasonCustomFormat Reason = "custom_format"
)

// WebUserWritableMeaning is what an alert on a web_user_writable source must
// say, in English and in Chinese.
const (
	WebUserWritableMeaning   = "the web server's own account can write what this log holds: forging its lines is only possible if the web application is already compromised"
	WebUserWritableMeaningZh = "web 伺服器自己的帳號可以寫入這個 log 的內容：只有 web 應用已經被入侵時，才可能偽造其中的紀錄"
)

// ReasonMeaningZh says, for an administrator reading a Telegram alert, why a
// log is not verified, and so why blocking cannot be approved from Telegram.
var ReasonMeaningZh = map[Reason]string{
	ReasonWebUserWritable:  "這個 log（或它所在的目錄、或寫它的程序）可以被 web 伺服器的帳號改動：只有 web 應用已經被入侵時才可能偽造，但 shentu 無法證明沒有，所以不能從 Telegram 放行封鎖",
	ReasonUntrusted:        "這個 log 或它所在的目錄可以被 root 以外的帳號改動，內容可能是偽造的，所以不能從 Telegram 放行封鎖",
	ReasonUnverified:       "shentu 無法確認只有 root 能改動這個 log（例如群組成員、ACL 或帳號來源讀不到），依規則一律不信任，所以不能從 Telegram 放行封鎖",
	ReasonNotRegular:       "這個 log 不是一般檔案，無法確認它的內容來源",
	ReasonNotFound:         "設定裡寫的 log 不存在（還沒寫入或被刪除），這段期間沒有可讀的紀錄",
	ReasonPermission:       "shentu 沒有權限讀這個 log 或它的上層目錄",
	ReasonLoggingDisabled:  "這個 log 在設定裡被關閉了，這部分的攻擊不會留下紀錄",
	ReasonNotAFile:         "這個 log 寫到 syslog 或程式（pipe），不是 shentu 能直接讀的檔案",
	ReasonVariablePath:     "log 路徑裡有變數或是相對路徑，shentu 無法確定是哪個檔案",
	ReasonCustomFormat:     "這個 access log 用的是自訂格式，不是 nginx 或 Apache 的標準格式：shentu 照樣解析並比對，但無法排除用戶端寫的欄位讓其他欄位錯位，所以不能從 Telegram 放行封鎖",
	ReasonClientFromHeader: "web 伺服器從請求的 header（例如 X-Forwarded-For）取用戶端位址，log 裡的 IP 可能是代理或攻擊者自己寫的，所以不能從 Telegram 放行封鎖",
}

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
var defaultWebUsers = []string{"www-data", "nginx", "apache", "httpd", "nobody", "wwwrun", "http", "lighttpd", "php-fpm", "caddy", "uwsgi"}

// logGroupNames are the groups a log directory may be writable by and still
// be trusted (Ubuntu's /var/log is 775 root:syslog), provided none of
// their members is a web account.
var logGroupNames = map[string]bool{"syslog": true, "adm": true, "log": true}

// logMemberNames are the only accounts a log group may hold: root and the
// log daemons (an account made with useradd -r is no proof of anything).
var logMemberNames = map[string]bool{"root": true, "syslog": true, "rsyslog": true, "systemd-journal": true}

// defaultWebGroups are their groups that are not also an account's name.
var defaultWebGroups = []string{"nogroup", "www"}

// WebLogs is the logs nginx, Apache and PHP-FPM are configured to write,
// sorted by path, each with its trust. Partial when some configuration
// could not be read: the logs it names are missing, and none is verified.
//
// Known limits: it reads the configuration on disk, not the one running
// (nginx -c, /etc/sysconfig/httpd OPTIONS, several instances, a change not
// yet reloaded); and group membership comes from /etc/group, so a userdb
// membership record (nss-systemd, /etc/userdb/*.membership) adding an
// account to a log group is not seen.
func (c LinuxCollector) WebLogs(src Source) Obs[[]LogSource] {
	l := &logLoader{src: src, conf: logConf, out: map[string]*LogSource{}}
	l.nginx()
	l.apache()
	l.phpFPM()
	l.lighttpd()
	l.unitUsers(c, src)
	web := l.webAccounts()
	for _, p := range l.extraRead { // outside /etc: every directory above it must be root's alone too
		if why := dirsTrusted(src, p, web); why != "" {
			l.unread = append(l.unread, p+" ("+why+")")
		}
	}
	scoped, scopeWhy := ptraceScoped(src)
	var out []LogSource
	for _, s := range l.out {
		if s.Reason == "" {
			t := JudgeLog(src, s.Path, web)
			s.Verified, s.Reason, s.Detail = t.Verified, t.Reason, t.Detail
			if t.Verified {
				s.FileID = t.File.ID
			}
		}
		if s.Verified {
			// The file is root's, but processes running as a web account
			// hold it open or feed it: whoever can make them write can.
			// v0.4.0 trusts only nginx's and Apache's access logs, and
			// those only while no application code runs in their workers.
			no := func(r Reason, d string) { s.Verified, s.Reason, s.Detail, s.FileID = false, r, d, "" }
			switch {
			case s.Kind != "access" || (s.Server != "nginx" && s.Server != "apache"):
				no(ReasonWebUserWritable, "an error or slow log, or PHP-FPM's: it takes what workers, FastCGI and PHP write (their stderr, a script's name): "+WebUserWritableMeaning)
			case !standardFormat(s):
				no(ReasonCustomFormat, "the access log's format is not a standard one (nginx combined or main, Apache combined or common): parsed and matched, not verified")
			case s.Server == "nginx" && l.ngxRealIP:
				no(ReasonClientFromHeader, "nginx takes the client address from a request header (set_real_ip_from / real_ip_header): the logged address is what a proxy, or the client, wrote")
			case s.Server == "apache" && l.apacheRemoteIP:
				no(ReasonClientFromHeader, "Apache takes the client address from a request header (mod_remoteip, RemoteIPHeader): the logged address is what a proxy, or the client, wrote")
			case s.Server == "apache" && len(l.apacheApp) > 0:
				no(ReasonWebUserWritable, "Apache runs application code in its own children ("+strings.Join(l.apacheApp, ", ")+"), which hold the log open: "+WebUserWritableMeaning)
			case s.Server == "nginx" && len(l.ngxApp) > 0:
				no(ReasonWebUserWritable, "nginx runs application code in its workers ("+strings.Join(l.ngxApp, ", ")+"), which hold the log open: "+WebUserWritableMeaning)
			case !scoped:
				no(ReasonWebUserWritable, scopeWhy+": the web account can ptrace the server's workers, which hold the log open; "+WebUserWritableMeaning)
			}
		}
		out = append(out, *s)
	}
	// One file named twice (an FPM access.log pointed at Apache's): the
	// worst judgment holds for every entry of it.
	key := func(s *LogSource) string { // the file, however its path is written
		if real, err := EvalSymlinks(src, s.Path); err == nil {
			return real
		}
		return path.Clean(s.Path)
	}
	worst := map[string]*LogSource{}
	for i := range out {
		if w, ok := worst[key(&out[i])]; !ok || (w.Verified && !out[i].Verified) {
			worst[key(&out[i])] = &out[i]
		}
	}
	for i := range out {
		if w := worst[key(&out[i])]; out[i].Verified && !w.Verified {
			out[i].Verified, out[i].Reason, out[i].FileID = false, w.Reason, ""
			out[i].Detail = "the same file is also PHP-FPM's or another server's " + w.Kind + " log: " + w.Detail
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].Kind < out[j].Kind
	})
	if len(l.unread) > 0 || l.cut {
		// What was not read may load a module, take the client from a
		// header, or name another user: no log is verified.
		why := "the configuration was not read in full (" + strings.Join(l.unread, "; ") + ")"
		if l.cut {
			why = fmt.Sprintf("more than %d log sources", maxLogSources)
		}
		for i := range out {
			if out[i].Verified {
				out[i].Verified, out[i].Reason, out[i].FileID, out[i].Detail = false, ReasonUnverified, "", why
			}
		}
	}
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
	// LogGIDs are the log groups (logGroupNames) /etc/group lists whose
	// members, listed or by primary group, are none of the web accounts: a
	// directory only they may write is still trusted.
	LogGIDs map[int]string
	// Complete: /etc/passwd and /etc/group were read and are where every
	// account and group comes from (nsswitch: files, compat, systemd).
	// Otherwise (sssd, LDAP, unread) no group-writable directory is trusted.
	Complete bool
}

// TrustResult is what JudgeLog found: the file it judged, by its stat.
type TrustResult struct {
	Verified bool
	Reason   Reason
	Detail   string
	File     FileStat // the file after its links, as stat saw it
}

// LogTrust is JudgeLog without the stat.
func LogTrust(src Source, p string, web WebAccounts) (verified bool, why Reason, detail string) {
	t := JudgeLog(src, p, web)
	return t.Verified, t.Reason, t.Detail
}

// JudgeLog says whether only root can change p. It, after its links, is a
// regular file owned by root that neither group nor others can write;
// every link on the way is root's own; every directory above it and above
// each link is root's, not writable by others, and writable by its group
// only when that group is a log group (WebAccounts.LogGIDs, the account
// databases complete) with no ACL widening it. A sticky directory lets no
// one but a file's owner replace it. Anything that cannot be told (a
// group, an ACL, a link's owner) is unverified: judging fails closed. The
// web accounts only make the reason precise.
func JudgeLog(src Source, p string, web WebAccounts) TrustResult {
	no := func(r Reason, d string) TrustResult { return TrustResult{Reason: r, Detail: d} }
	real, err := EvalSymlinks(src, p)
	if err != nil {
		return no(statReason(err), whyUnread(err))
	}
	st, err := Stat(src, real)
	if err != nil {
		return no(statReason(err), whyUnread(err))
	}
	switch {
	case !st.Mode.IsRegular():
		return no(ReasonNotRegular, real+" is not a regular file")
	case st.UID != 0:
		if name, ok := web.UIDs[st.UID]; ok {
			return no(ReasonWebUserWritable, fmt.Sprintf("%s is owned by %s (uid %d): %s", real, name, st.UID, WebUserWritableMeaning))
		}
		return no(ReasonUntrusted, fmt.Sprintf("%s is owned by uid %d, not root", real, st.UID))
	case st.Mode.Perm()&0o022 != 0:
		return no(ReasonUntrusted, fmt.Sprintf("%s is writable by group or others (%v)", real, st.Mode.Perm()))
	}
	links, err := linkChain(src, p)
	if err != nil {
		return no(ReasonUnverified, whyUnread(err))
	}
	for _, ln := range links { // a link is repointed by its owner, wherever it sits
		ls, err := Lstat(src, ln)
		if err != nil {
			return no(ReasonUnverified, "link "+ln+": "+whyUnread(err))
		}
		if ls.UID != 0 {
			if name, ok := web.UIDs[ls.UID]; ok {
				return no(ReasonWebUserWritable, fmt.Sprintf("link %s is owned by %s (uid %d): %s", ln, name, ls.UID, WebUserWritableMeaning))
			}
			return no(ReasonUntrusted, fmt.Sprintf("link %s is owned by uid %d, not root", ln, ls.UID))
		}
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
			return no(ReasonUnverified, "directory "+d+": "+whyUnread(err))
		}
		sticky := ds.Mode&fs.ModeSticky != 0
		switch {
		case ds.UID != 0:
			if name, ok := web.UIDs[ds.UID]; ok {
				return no(ReasonWebUserWritable, fmt.Sprintf("directory %s is owned by %s (uid %d): %s", d, name, ds.UID, WebUserWritableMeaning))
			}
			return no(ReasonUntrusted, fmt.Sprintf("directory %s is owned by uid %d, not root", d, ds.UID))
		case ds.Mode.Perm()&0o002 != 0 && !sticky:
			return no(ReasonUntrusted, "directory "+d+" is writable by others")
		case ds.Mode.Perm()&0o020 != 0 && !sticky:
			if r, d := groupWritable(src, d, ds, web); r != "" {
				return no(r, d)
			}
		}
	}
	return TrustResult{Verified: true, File: st}
}

// dirsTrusted says why a directory above p is not root's alone ("" if all
// are): owned by another, writable by others, or by a group that is not a
// log group (groupWritable).
func dirsTrusted(src Source, p string, web WebAccounts) string {
	for d := path.Dir(p); ; d = path.Dir(d) {
		ds, err := Stat(src, d)
		if err != nil {
			return "directory " + d + ": " + whyUnread(err)
		}
		sticky := ds.Mode&fs.ModeSticky != 0
		switch {
		case ds.UID != 0:
			return fmt.Sprintf("directory %s is owned by uid %d", d, ds.UID)
		case ds.Mode.Perm()&0o002 != 0 && !sticky:
			return "directory " + d + " is writable by others"
		case ds.Mode.Perm()&0o020 != 0 && !sticky:
			if r, why := groupWritable(src, d, ds, web); r != "" {
				return why
			}
		}
		if d == "/" {
			return ""
		}
	}
}

// groupWritable judges a directory its group may write: "" when the group
// is a log group of complete account databases and no ACL lets anyone
// else in; otherwise why not.
func groupWritable(src Source, d string, ds FileStat, web WebAccounts) (Reason, string) {
	if ds.GID == nil {
		return ReasonUnverified, "directory " + d + " is writable by its group, and which group is not known"
	}
	gid := *ds.GID
	if name, ok := web.GIDs[gid]; ok {
		return ReasonWebUserWritable, fmt.Sprintf("directory %s is writable by group %s (gid %d): %s", d, name, gid, WebUserWritableMeaning)
	}
	switch name, ok := web.LogGIDs[gid]; {
	case gid == 0:
		return ReasonUnverified, "directory " + d + " is writable by group root, whose members are not known to be root"
	case !web.Complete:
		return ReasonUnverified, fmt.Sprintf("directory %s is writable by gid %d, and the account databases could not all be read (or are not only files)", d, gid)
	case !ok:
		return ReasonUnverified, fmt.Sprintf("directory %s is writable by gid %d, not a log group known to hold no web account", d, gid)
	default:
		has, err := HasACL(src, d)
		if err != nil {
			return ReasonUnverified, "directory " + d + " is writable by group " + name + ", and its ACL could not be read: " + whyUnread(err)
		}
		if has {
			return ReasonUnverified, "directory " + d + " has an ACL: its group bits are only the mask, a named user may write it"
		}
	}
	return "", ""
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
				if !errors.Is(err, syscall.EINVAL) && !errors.Is(err, fs.ErrNotExist) {
					return nil, err // ELOOP, EIO, EACCES...: not known whether it is a link
				}
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
	modPHP bool     // Apache loads PHP as a module
	// extraRead: files read from logConf.Extra, whose directories are
	// judged once the web accounts are known.
	extraRead []string
	// apacheApp, ngxApp: the modules or directives that run application
	// code in the server's own workers (not on the list known not to).
	apacheApp, ngxApp []string
	// ngxRealIP, apacheRemoteIP: the client address may come from a header.
	ngxRealIP, apacheRemoteIP bool
	// catchWorkers: a PHP-FPM pool sets catch_workers_output, so the root
	// master logs what its workers write.
	catchWorkers bool
}

// read reads one configuration file, counting it against the bound.
func (l *logLoader) read(p string) ([]byte, bool) {
	p = path.Clean(p)
	switch {
	case underAny(p, l.conf.Extra):
		st, err := Stat(l.src, p)
		if err == nil && (st.UID != l.conf.Owner || st.Mode.Perm()&0o022 != 0) {
			l.unread = append(l.unread, p+" (not root's, or writable by others)")
			return nil, false
		}
		l.extraRead = append(l.extraRead, p)
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
	if real, err := EvalSymlinks(l.src, p); err == nil && real != p && underAny(real, l.conf.Extra) {
		l.extraRead = append(l.extraRead, real) // a link from /etc into a package directory
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

// WebAccounts is the web servers' and PHP's accounts and groups, as their
// configuration and the defaults give them: what LogTrust is given.
func (c LinuxCollector) WebAccounts(src Source) WebAccounts {
	l := &logLoader{src: src, conf: logConf, out: map[string]*LogSource{}}
	l.nginx()
	l.apache()
	l.phpFPM()
	l.lighttpd()
	l.unitUsers(c, src)
	return l.webAccounts()
}

var lighttpdAccount = regexp.MustCompile(`(?m)^\s*server\.(username|groupname)\s*=\s*"([^"]+)"`)

// lighttpd adds the account lighttpd.conf runs it as.
func (l *logLoader) lighttpd() {
	const conf = "/etc/lighttpd/lighttpd.conf"
	if !exists(l.src, conf) {
		return
	}
	b, ok := l.read(conf)
	if !ok {
		return
	}
	for _, m := range lighttpdAccount.FindAllStringSubmatch(string(b), -1) {
		if m[1] == "username" {
			l.users = append(l.users, m[2])
		} else {
			l.groups = append(l.groups, m[2])
		}
	}
}

// unitUsers adds the User= of the application units (gunicorn, uwsgi,
// node...): their processes are the web application too.
func (l *logLoader) unitUsers(c LinuxCollector, src Source) {
	for _, u := range c.AppUnits(src).Value {
		if u.User != "" {
			l.users = append(l.users, u.User)
		}
	}
}

// iniValue is a php-fpm.conf value: quotes taken off, or an inline
// comment (" ; ...") cut from an unquoted one.
func iniValue(v string) string {
	v = strings.TrimSpace(v)
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') {
		if end := strings.IndexByte(v[1:], v[0]); end >= 0 {
			return v[1 : end+1]
		}
	}
	if i := strings.IndexAny(v, ";#"); i >= 0 {
		v = v[:i]
	}
	return strings.TrimSpace(v)
}

// ptraceScoped: kernel.yama.ptrace_scope is 1 or more, so a web account
// cannot ptrace the server's workers (running as it, holding the logs
// open). Otherwise (0, no Yama, unread) why not.
func ptraceScoped(src Source) (bool, string) {
	b, err := src.ReadFile("/proc/sys/kernel/yama/ptrace_scope")
	if err != nil {
		return false, "kernel.yama.ptrace_scope unread (" + whyUnread(err) + ")"
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || n < 1 {
		return false, "kernel.yama.ptrace_scope is " + strings.TrimSpace(string(b))
	}
	return true, ""
}

// webAccounts is the uids and gids of the web servers' and PHP's accounts
// and groups: the defaults and those the configuration names, and each
// such account's primary group.
func (l *logLoader) webAccounts() WebAccounts {
	w := WebAccounts{UIDs: map[int]string{}, GIDs: map[int]string{}}
	users, groups := map[string]bool{}, map[string]bool{}
	numUIDs := map[int]bool{}
	for _, u := range append(append([]string{}, defaultWebUsers...), l.users...) {
		if id, ok := numericID(u); ok { // User #33, user = 33: kept by number, and looked up below
			if id != 0 {
				w.UIDs[id] = "uid " + strconv.Itoa(id)
				numUIDs[id] = true
			}
			continue
		}
		users[u] = true
	}
	for _, g := range append(append(append([]string{}, defaultWebUsers...), defaultWebGroups...), l.groups...) {
		if id, ok := numericID(g); ok {
			if id != 0 {
				w.GIDs[id] = "gid " + strconv.Itoa(id)
			}
			continue
		}
		groups[g] = true
	}
	primary := map[int]bool{}
	byPrimary := map[int][]string{} // gid -> accounts with it as primary group
	nameUID := map[string]int{}
	passwdOK, groupOK, nis := false, false, false
	if b, err := l.src.ReadFile("/etc/passwd"); err == nil {
		passwdOK = true
		nis = nis || nisLines(b)
		entries := ParsePasswd(b)
		for _, e := range entries {
			if gid, err := strconv.Atoi(e.GID); err == nil {
				byPrimary[gid] = append(byPrimary[gid], e.Name)
			}
			if uid, err := strconv.Atoi(e.UID); err == nil {
				nameUID[e.Name] = uid
			}
		}
		for _, e := range entries { // a numeric user's name, for its group memberships
			if uid, err := strconv.Atoi(e.UID); err == nil && numUIDs[uid] {
				users[e.Name] = true
			}
		}
		for _, e := range entries {
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
	w.LogGIDs = map[int]string{}
	if b, err := l.src.ReadFile("/etc/group"); err == nil {
		groupOK = true
		nis = nis || nisLines(b)
		for _, ln := range strings.Split(string(b), "\n") {
			f := strings.Split(ln, ":")
			if len(f) < 3 || strings.HasPrefix(f[0], "#") {
				continue
			}
			gid, err := strconv.Atoi(f[2])
			if err != nil || gid == 0 {
				continue
			}
			member := false // a web user in the group's list: it may write what the group may
			if len(f) > 3 {
				for _, m := range strings.Split(f[3], ",") {
					if users[strings.TrimSpace(m)] {
						member = true
					}
				}
			}
			if groups[f[0]] || primary[gid] || member {
				w.GIDs[gid] = f[0]
			}
			if logGroupNames[f[0]] && !member && !primary[gid] && !groups[f[0]] {
				// Every member, listed or by primary group, must be a system
				// account (uid < 1000) or root's own: a deploy account in
				// syslog running gunicorn under supervisor is not known to be
				// a web account, and is not let pass.
				var members []string
				if len(f) > 3 && f[3] != "" {
					members = strings.Split(f[3], ",")
				}
				clean := true
				for _, a := range append(members, byPrimary[gid]...) {
					a = strings.TrimSpace(a)
					_, known := nameUID[a]
					if users[a] || !known || !logMemberNames[a] {
						clean = false
					}
				}
				if clean {
					w.LogGIDs[gid] = f[0]
				}
			}
		}
	}
	w.Complete = passwdOK && groupOK && !nis && filesOnlyNSS(l.src)
	for gid := range primary { // a primary group /etc/group does not list
		if _, ok := w.GIDs[gid]; !ok {
			w.GIDs[gid] = "gid " + strconv.Itoa(gid)
		}
	}
	return w
}

// filesOnlyNSS: nsswitch.conf takes accounts and groups only from the
// files (or compat), or from systemd, whose module adds only dynamic and
// userdb accounts, none a member of a log group. Without nsswitch.conf,
// glibc reads the files.
func filesOnlyNSS(src Source) bool {
	b, err := src.ReadFile("/etc/nsswitch.conf")
	if errors.Is(err, fs.ErrNotExist) {
		return true
	}
	if err != nil {
		return false
	}
	for _, ln := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(ln), ":")
		switch strings.TrimSpace(k) {
		case "passwd", "group", "initgroups", "passwd_compat", "group_compat":
		default:
			continue
		}
		if !ok {
			continue
		}
		if i := strings.IndexByte(v, '#'); i >= 0 {
			v = v[:i]
		}
		for _, src := range strings.Fields(v) {
			if strings.HasPrefix(src, "[") {
				continue // an action, [NOTFOUND=return]
			}
			if src != "files" && src != "compat" && src != "systemd" {
				return false
			}
		}
	}
	return true
}

// nisLines: the file has +/- lines, which compat mode answers from NIS.
func nisLines(b []byte) bool {
	for _, ln := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(ln, "+") || strings.HasPrefix(ln, "-") {
			return true
		}
	}
	return false
}

// standardSpecs are the access log formats verified lines may come in:
// nginx's combined and RHEL's main; Apache's combined and common as
// Debian (%O) and RHEL (%b) write them, with %h, %a or %{c}a.
var standardSpecs = map[string]map[string]bool{"nginx": {}, "apache": {}}

func init() {
	standardSpecs["nginx"][ngxCombined] = true
	standardSpecs["nginx"][`$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" "$http_x_forwarded_for"`] = true
	for _, h := range []string{"%h", "%a", "%{c}a"} {
		for _, b := range []string{"%O", "%b"} {
			common := h + ` %l %u %t "%r" %>s ` + b
			standardSpecs["apache"][common] = true
			standardSpecs["apache"][common+` "%{Referer}i" "%{User-Agent}i"`] = true
		}
	}
}

// standardFormat: an access log in a standard format, and for Apache, %h
// an address (HostnameLookups off).
func standardFormat(s *LogSource) bool {
	if !standardSpecs[s.Server][s.Spec] || s.Escape != "" {
		return false
	}
	if s.Server == "apache" && s.IdentityCheck { // %l is the client's identd's answer
		return false
	}
	return !(s.Server == "apache" && s.HostnameLookups && strings.HasPrefix(s.Spec, "%h "))
}

// logConf is where the log configuration is read from: /etc, and the
// directories nginx's packages keep module snippets in (Debian links
// modules-enabled there; Rocky includes /usr/share/nginx/modules/*.conf).
var logConf = WebConf{Root: "/etc", Owner: 0, Extra: []string{"/usr/share/nginx/modules", "/usr/share/nginx/modules-available"}}

// numericID is a user or group given by number: #33 (Apache) or 33.
func numericID(s string) (int, bool) {
	n, err := strconv.Atoi(strings.TrimPrefix(s, "#"))
	return n, err == nil && n >= 0
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
			} else { // too deep: skip the block whole, and leave a mark: what it holds is not known
				cur.block = []*ngxDir{{name: ngxTooDeep, file: file, line: t.line}}
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

// apacheSafeModules are the Apache modules known to run no application
// code in the children that hold the logs open. Any other (php, wsgi,
// perl, lua, passenger, cgi...) makes Apache's logs web_user_writable.
var apacheSafeModules = map[string]bool{}

func init() {
	for _, m := range strings.Fields(`access_compat_module alias_module allowmethods_module auth_basic_module auth_digest_module
		authn_core_module authn_file_module authz_core_module authz_groupfile_module authz_host_module authz_user_module
		autoindex_module brotli_module cache_module cache_disk_module cache_socache_module deflate_module dir_module env_module
		expires_module filter_module headers_module http2_module info_module lbmethod_byrequests_module log_config_module
		logio_module mime_module mime_magic_module mpm_event_module mpm_prefork_module mpm_worker_module negotiation_module
		proxy_module proxy_ajp_module proxy_balancer_module proxy_fcgi_module proxy_http_module proxy_http2_module
		proxy_wstunnel_module reqtimeout_module request_module rewrite_module setenvif_module slotmem_shm_module
		socache_shmcb_module ssl_module status_module substitute_module systemd_module unique_id_module unixd_module
		version_module watchdog_module`) {
		apacheSafeModules[m] = true
	}
}

// ngxSafeModules are the dynamic nginx modules known to run no application
// code; any other load_module, or a perl, lua or njs directive, makes
// nginx's logs web_user_writable.
var ngxSafeModules = map[string]bool{
	"ngx_http_geoip_module.so": true, "ngx_http_geoip2_module.so": true, "ngx_stream_geoip_module.so": true,
	"ngx_stream_geoip2_module.so": true, "ngx_http_image_filter_module.so": true, "ngx_http_xslt_filter_module.so": true,
	"ngx_mail_module.so": true, "ngx_stream_module.so": true, "ngx_http_brotli_filter_module.so": true,
	"ngx_http_brotli_static_module.so": true, "ngx_http_headers_more_filter_module.so": true,
	"ngx_http_cache_purge_module.so": true, "ngx_http_auth_pam_module.so": true, "ngx_http_dav_ext_module.so": true,
	"ngx_http_echo_module.so": true, "ngx_http_upstream_fair_module.so": true, "ngx_http_subs_filter_module.so": true,
}

var ngxAppDirective = regexp.MustCompile(`^(?:perl|perl_\w+|js_\w+|lua_\w+|\w+_by_lua(?:_block|_file)?|\w+_by_njs|mruby_\w+|wasm_\w+|proxy_wasm\w*)$`)

// apacheAppDirective: directives of modules running application code,
// built in (httpd -l) or loaded some way LoadModule does not show.
var apacheAppDirective = regexp.MustCompile(`^(?:lua|perl|wsgi|passenger|php_|mod_ruby|ruby)`)

// ngxTooDeep stands for directives nested past maxNgxNest, not read.
const ngxTooDeep = "\x00nested too deep"

// ngxWalk calls fn for every directive, nested ones included; past
// maxNgxNest, once with ngxTooDeep.
func ngxWalk(ds []*ngxDir, depth int, fn func(*ngxDir)) {
	if depth > maxNgxNest {
		fn(&ngxDir{name: ngxTooDeep})
		return
	}
	for _, d := range ds {
		fn(d)
		if d.hasBlock {
			ngxWalk(d.block, depth+1, fn)
		}
	}
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
	ngxWalk(main, 0, func(d *ngxDir) {
		switch {
		case d.name == "set_real_ip_from" || d.name == "real_ip_header":
			l.ngxRealIP = true
		case d.name == ngxTooDeep: // what is nested deeper may run code or take the client from a header
			if !contains(l.ngxApp, "configuration nested deeper than 64 levels, not read") {
				l.ngxApp = append(l.ngxApp, "configuration nested deeper than 64 levels, not read")
			}
		case ngxAppDirective.MatchString(d.name) && !contains(l.ngxApp, d.name):
			l.ngxApp = append(l.ngxApp, d.name)
		}
	})
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
			} else if len(d.args) == 1 { // no group: nginx takes the user's name
				l.groups = append(l.groups, d.args[0])
			}
		case "load_module":
			if len(d.args) > 0 && !ngxSafeModules[path.Base(d.args[0])] && !contains(l.ngxApp, path.Base(d.args[0])) {
				l.ngxApp = append(l.ngxApp, path.Base(d.args[0]))
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
	identity      bool // IdentityCheck On somewhere
	remoteIP      bool // mod_remoteip loaded
	lookups       bool // HostnameLookups On or Double somewhere
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
			s := LogSource{Path: st.path(d.dest), Server: "apache", Kind: "access", Vhosts: sc.names, Config: at(d.file, d.line), HostnameLookups: st.lookups, IdentityCheck: st.identity}
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
		if apacheAppDirective.MatchString(name) && !contains(l.apacheApp, name) {
			l.apacheApp = append(l.apacheApp, name)
		}
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
		case "identitycheck":
			if len(args) > 0 && !strings.EqualFold(args[0], "off") {
				st.identity = true
			}
		case "hostnamelookups":
			if len(args) > 0 && !strings.EqualFold(args[0], "off") {
				st.lookups = true
			}
		case "assignuserid", "suexecusergroup", "ruidgid": // mpm-itk, suEXEC, mod_ruid2: a vhost's own account
			if len(args) > 0 {
				l.users = append(l.users, st.expand(args[0]))
			}
			if len(args) > 1 {
				l.groups = append(l.groups, st.expand(args[1]))
			}
		case "loadmodule":
			if len(args) > 1 {
				m := strings.ToLower(args[0])
				if strings.Contains(m, "php") || strings.Contains(strings.ToLower(args[1]), "libphp") {
					l.modPHP = true
				}
				if m == "remoteip_module" {
					st.remoteIP = true
				} else if !apacheSafeModules[m] && !contains(l.apacheApp, m) {
					l.apacheApp = append(l.apacheApp, m)
				}
			}
		case "loadfile": // a library loaded into the server's own processes (libpython for mod_wsgi)
			if len(args) > 0 && !contains(l.apacheApp, "LoadFile "+args[0]) {
				l.apacheApp = append(l.apacheApp, "LoadFile "+args[0])
			}
		case "remoteipheader", "remoteipproxyprotocol":
			if st.remoteIP {
				l.apacheRemoteIP = true
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

// phpFPMConfs: Debian and Ubuntu, RHEL and Fedora, Remi's and Software
// Collections' parallel PHPs, Arch, Alpine.
var phpFPMConfs = []string{"/etc/php/*/fpm/php-fpm.conf", "/etc/php-fpm.conf", "/etc/opt/remi/*/php-fpm.conf",
	"/etc/opt/rh/*/php-fpm.conf", "/etc/php/php-fpm.conf", "/etc/php*/php-fpm.conf"}

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
		k, v = strings.TrimSpace(k), iniValue(v)
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
		case "catch_workers_output":
			if b := strings.ToLower(v); b == "yes" || b == "on" || b == "true" || b == "1" {
				l.catchWorkers = true
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
