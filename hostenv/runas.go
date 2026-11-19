package hostenv

import (
	"errors"
	"io/fs"
	"path"
	"strconv"
	"strings"
)

// Who else programs run as, beside the units, linger and crontabs
// (runAsAccounts): supervisord's programs, sudo's run-as accounts, and the
// processes running now. A server's account among them is not apart.

// supervisorConfs are supervisord's own files (RHEL's, Debian's) and the
// directories packages and operators put programs in.
var (
	supervisorConfs = []string{"/etc/supervisord.conf", "/etc/supervisor/supervisord.conf", "/usr/local/etc/supervisord.conf", "/usr/local/supervisord.conf"}
	supervisorDirs  = []string{"/etc/supervisord.d", "/etc/supervisor/conf.d"}
)

// maxRunAsFiles bounds the supervisord and sudoers files read; more
// leaves no server apart.
const maxRunAsFiles = 256

// supervisordRunning: the configuration files running supervisords read,
// the absolute -c (or --configuration) they were given. lost: /proc could
// not all be read, or a supervisord's file is not told: no -c (its search
// starts in the directory it started in, not known now), a relative one,
// another option, another root or mount namespace.
func supervisordRunning(src Source) (confs []string, lost bool) {
	names, err := src.ReadDir("/proc")
	if err != nil {
		return nil, true
	}
	for _, n := range names {
		if !numeric(n) {
			continue
		}
		dir := "/proc/" + n
		b, err := src.ReadFile(dir + "/cmdline")
		if err != nil {
			lost = lost || !gone(err)
			continue
		}
		argv := strings.Split(strings.TrimRight(string(b), "\x00"), "\x00")
		at := -1 // supervisord's own argument: its program, or python's -m module
		for i, a := range argv {
			if strings.Contains(a, "supervisor") && path.Base(a) != "supervisorctl" { // its program, python's -m module, a script
				at = i
				break
			}
		}
		if at < 0 {
			continue
		}
		root, err := src.Readlink(dir + "/root")
		ns, err2 := src.Readlink(dir + "/ns/mnt")
		initNS, err3 := src.Readlink("/proc/1/ns/mnt")
		if err != nil || err2 != nil || err3 != nil || root != "/" || ns != initNS {
			lost = true // another root or mount namespace, or not read: its paths are not ours
			continue
		}
		c := ""
		for i := at + 1; i < len(argv); i++ {
			switch a := argv[i]; {
			case a == "-n" || a == "--nodaemon":
			case (shortC(a) && len(a) == 2 || a == "--configuration") && i+1 < len(argv):
				c = argv[i+1]
				i++
			case strings.HasPrefix(a, "--configuration="):
				c = strings.TrimPrefix(a, "--configuration=")
			case shortC(a) && len(a) > 2:
				c = a[2:]
			default:
				lost = true // an option not told (an abbreviation, grouped flags...)
			}
		}
		switch {
		case c != "" && path.IsAbs(c):
			confs = append(confs, path.Clean(c))
		default:
			lost = true // relative to its working directory, or its own search from where it started
		}
	}
	return confs, lost
}

// shortC: a supervisord argument starting with its -c option (read from
// /proc, never built into a command).
func shortC(a string) bool { return len(a) >= 2 && a[0] == '-' && a[1] == 'c' }

func gone(err error) bool { return errors.Is(err, fs.ErrNotExist) || errors.Is(err, ErrNotRecorded) }

// supervisorAccounts adds every user= of supervisord's files, and of the
// files their [include] names: a program (a queue worker, say) run as a
// server's account.
func (l *logLoader) supervisorAccounts() {
	seen := map[string]bool{}
	var queue []string
	add := func(p string) {
		if !seen[p] {
			seen[p] = true
			queue = append(queue, p)
		}
	}
	for _, p := range supervisorConfs {
		add(p)
	}
	confs, lost := supervisordRunning(l.src) // the -c a running supervisord was given
	l.runAsLost = l.runAsLost || lost
	for _, p := range confs {
		add(p)
	}
	for _, d := range supervisorDirs {
		names, err := l.src.ReadDir(d)
		if err != nil && !gone(err) {
			l.runAsLost = true
		}
		for _, n := range names {
			add(path.Join(d, n))
		}
	}
	for len(queue) > 0 {
		p := queue[0]
		queue = queue[1:]
		if len(seen) > maxRunAsFiles {
			l.runAsLost = true
			return
		}
		b, err := l.src.ReadFile(p)
		if err != nil {
			l.runAsLost = l.runAsLost || !gone(err)
			continue
		}
		section := ""
		for _, raw := range strings.Split(string(b), "\n") {
			ln := strings.TrimSpace(raw)
			if ln == "" || strings.HasPrefix(ln, ";") || strings.HasPrefix(ln, "#") {
				continue
			}
			if raw[0] == ' ' || raw[0] == '\t' { // configparser: a value going on, or more; not told
				l.runAsLost = true
				continue
			}
			if strings.HasPrefix(ln, "[") {
				name, _, _ := strings.Cut(ln[1:], "]") // to the first ]: a comment may follow
				section = strings.ToLower(strings.TrimSpace(name))
				continue
			}
			i := strings.IndexAny(ln, "=:") // configparser's delimiters, the first one
			if i < 0 {
				l.runAsLost = true // supervisord would not start; not told what it means
				continue
			}
			k, v := ln[:i], ln[i+1:]
			if i := strings.Index(v, " ;"); i >= 0 { // an inline comment
				v = v[:i]
			}
			k, v = strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v)
			switch {
			case k == "user":
				if strings.Contains(v, "%(") { // %(ENV_X)s, %(program_name)s...
					l.runAsLost = true
				} else if v != "" {
					l.runAs = append(l.runAs, v)
				}
			case k == "files" && section == "include":
				for _, g := range strings.Fields(v) {
					if !path.IsAbs(g) {
						g = path.Join(path.Dir(p), g)
					}
					dir, pat := path.Split(g)
					if strings.ContainsAny(dir, "*?[%") {
						l.runAsLost = true
						continue
					}
					names, err := l.src.ReadDir(path.Clean(dir))
					if err != nil && !gone(err) {
						l.runAsLost = true
					}
					for _, n := range names {
						if m, err := path.Match(pat, n); err != nil {
							l.runAsLost = true
						} else if m {
							add(path.Join(dir, n))
						}
					}
				}
			}
		}
	}
}

// sudoersAccounts adds the accounts and groups sudo may run commands as
// (the run-as lists, Runas_Alias, runas_default) in /etc/sudoers and what
// it includes. A run-as of ALL for every command is root's own power,
// out of scope; ALL for some commands only is not told apart, and leaves
// no server apart. So does sudoers read from elsewhere than the files.
func (l *logLoader) sudoersAccounts() {
	if b, err := l.src.ReadFile("/etc/nsswitch.conf"); err == nil {
		for _, ln := range strings.Split(string(b), "\n") {
			k, v, ok := strings.Cut(strings.TrimSpace(ln), ":")
			if !ok || strings.TrimSpace(k) != "sudoers" {
				continue
			}
			if i := strings.IndexByte(v, '#'); i >= 0 {
				v = v[:i]
			}
			for _, s := range strings.Fields(v) {
				if s != "files" && !strings.HasPrefix(s, "[") {
					l.runAsLost = true // sss, ldap
				}
			}
		}
	}
	seen := map[string]bool{}
	var users, groups []string
	aliases := map[string]bool{}
	var read func(p string, depth int)
	read = func(p string, depth int) {
		if seen[p] {
			return
		}
		seen[p] = true
		if depth > 8 || len(seen) > maxRunAsFiles {
			l.runAsLost = true
			return
		}
		b, err := l.src.ReadFile(p)
		if err != nil {
			l.runAsLost = l.runAsLost || !gone(err)
			return
		}
		for _, ln := range sudoersLines(string(b)) {
			f := strings.Fields(ln)
			if len(f) == 0 {
				continue
			}
			switch kw := strings.TrimPrefix(f[0], "@"); {
			case strings.HasPrefix(f[0], "#include") || strings.HasPrefix(f[0], "@include"):
				if len(f) < 2 || strings.Contains(ln, "%") {
					l.runAsLost = true
					continue
				}
				q := strings.Trim(strings.Join(f[1:], " "), `"`)
				if !path.IsAbs(q) {
					q = path.Join(path.Dir(p), q)
				}
				if strings.HasSuffix(kw, "includedir") || strings.HasSuffix(f[0], "includedir") {
					names, err := l.src.ReadDir(q)
					if err != nil && !gone(err) {
						l.runAsLost = true
					}
					for _, n := range names {
						read(path.Join(q, n), depth+1)
					}
				} else {
					read(q, depth+1)
				}
			case strings.HasPrefix(f[0], "Defaults"):
				for _, part := range strings.Split(ln, ",") {
					if k, v, ok := strings.Cut(part, "="); ok && strings.HasSuffix(strings.TrimSpace(k), "runas_default") {
						users = append(users, strings.Trim(strings.TrimSpace(v), `"`))
					}
				}
			case f[0] == "Runas_Alias":
				for _, def := range strings.Split(strings.TrimSpace(strings.TrimPrefix(ln, "Runas_Alias")), ":") {
					name, list, ok := strings.Cut(def, "=")
					if !ok {
						l.runAsLost = true
						continue
					}
					aliases[strings.TrimSpace(name)] = true
					users = append(users, strings.Split(list, ",")...)
				}
			case f[0] == "User_Alias" || f[0] == "Host_Alias" || f[0] == "Cmnd_Alias" || f[0] == "Cmd_Alias":
			default: // a user specification: who host = (runas) commands, ...
				_, rest, ok := strings.Cut(ln, "=")
				for ok {
					open := strings.IndexByte(rest, '(')
					if open < 0 {
						break
					}
					end := strings.IndexByte(rest[open:], ')')
					if end < 0 {
						l.runAsLost = true
						break
					}
					spec := rest[open+1 : open+end]
					rest = rest[open+end+1:]
					us, gs, _ := strings.Cut(spec, ":")
					all, neg := false, false
					for _, u := range strings.Split(us, ",") {
						u = strings.TrimSpace(u)
						neg = neg || strings.HasPrefix(u, "!")
						switch {
						case u == "" || strings.HasPrefix(u, "!"):
						case u == "ALL":
							all = true
						case strings.HasPrefix(u, "%:") || strings.HasPrefix(u, "+"):
							l.runAsLost = true // a non-Unix group, a netgroup
						case strings.HasPrefix(u, "%"):
							groups = append(groups, strings.TrimPrefix(strings.TrimPrefix(u, "%"), "#"))
						default:
							users = append(users, strings.TrimPrefix(u, "#"))
						}
					}
					for _, g := range strings.Split(gs, ",") {
						g = strings.TrimSpace(g)
						neg = neg || strings.HasPrefix(g, "!")
						switch {
						case g == "" || strings.HasPrefix(g, "!"):
						case g == "ALL":
							all = true
						default:
							groups = append(groups, strings.TrimPrefix(g, "#"))
						}
					}
					if all && (neg || !allCommands(rest)) {
						l.runAsLost = true // any account for some commands, or all but some: (ALL, !root) is not root's power
					}
				}
			}
		}
	}
	read("/etc/sudoers", 0)
	for _, u := range users {
		if u = strings.TrimSpace(u); u != "" && !aliases[u] && !strings.HasPrefix(u, "!") && u != "ALL" {
			l.runAs = append(l.runAs, u)
		} else if u == "ALL" {
			l.runAsLost = true // runas_default=ALL, or an alias of ALL: not told
		}
	}
	for _, g := range groups {
		if !aliases[g] {
			l.runAsGroups = append(l.runAsGroups, g)
		}
	}
}

// doasConfs: opendoas's configuration (EPEL's, and a build's own).
var doasConfs = []string{"/etc/doas.conf", "/usr/local/etc/doas.conf"}

// doasAccounts adds the targets of doas's permit rules (as <user>); a rule
// with no target runs as root, out of scope. A line not told leaves no
// server apart.
func (l *logLoader) doasAccounts() {
	for _, p := range doasConfs {
		b, err := l.src.ReadFile(p)
		if err != nil {
			l.runAsLost = l.runAsLost || !gone(err)
			continue
		}
		for _, ln := range strings.Split(strings.ReplaceAll(string(b), "\\\n", " "), "\n") {
			if i := strings.IndexByte(ln, '#'); i >= 0 {
				ln = ln[:i]
			}
			if strings.ContainsAny(ln, `"'`) {
				l.runAsLost = true // quoted words: not told
				continue
			}
			f := strings.Fields(ln)
			if len(f) == 0 || f[0] == "deny" { // a deny only takes away
				continue
			}
			if f[0] != "permit" {
				l.runAsLost = true
				continue
			}
			for i := 1; i < len(f); i++ {
				if f[i] == "{" { // setenv { ... }
					for i < len(f) && f[i] != "}" {
						i++
					}
					if i == len(f) {
						l.runAsLost = true // not closed
					}
					continue
				}
				if strings.ContainsAny(f[i], "{}") {
					l.runAsLost = true // a brace not spaced: not told
					break
				}
				if f[i] == "cmd" {
					break // the command and its args: not targets
				}
				if f[i] == "as" {
					if i+1 >= len(f) {
						l.runAsLost = true
					} else {
						l.runAs = append(l.runAs, f[i+1])
					}
					break
				}
			}
		}
	}
}

// sudoersLines: the file's lines, continuations joined and comments cut
// (a # before a digit is a uid, and #include is a directive).
func sudoersLines(s string) []string {
	var out []string
	cur := ""
	for _, ln := range strings.Split(s, "\n") {
		if strings.HasSuffix(ln, "\\") {
			cur += strings.TrimSuffix(ln, "\\") + " "
			continue
		}
		ln = cur + ln
		cur = ""
		t := strings.TrimSpace(ln)
		if strings.HasPrefix(t, "#include") {
			out = append(out, t)
			continue
		}
		for i := 0; i < len(t); i++ {
			if t[i] == '#' && (i+1 == len(t) || t[i+1] < '0' || t[i+1] > '9') {
				t = t[:i]
				break
			}
		}
		out = append(out, strings.TrimSpace(t))
	}
	return out
}

// allCommands: what follows a run-as list is ALL commands, past any tags
// (NOPASSWD:, SETENV:...).
func allCommands(rest string) bool {
	f := strings.Fields(strings.ReplaceAll(rest, ",", " , "))
	for len(f) > 0 && strings.HasSuffix(f[0], ":") && strings.ToUpper(f[0]) == f[0] {
		f = f[1:]
	}
	return len(f) > 0 && f[0] == "ALL"
}

// loginShells: an account with another shell may be logged in to (or su'd
// to), and run anything.
var noLoginShells = map[string]bool{"/sbin/nologin": true, "/usr/sbin/nologin": true, "/bin/false": true, "/usr/bin/false": true}

// serverExes: the programs a server's own processes run, by server.
var serverExes = map[string]map[string]bool{
	"nginx":  {"nginx": true, "openresty": true},
	"apache": {"httpd": true, "apache2": true, "httpd.worker": true, "httpd.event": true},
}

// othersRun: a process now runs with one of uids or gids (real,
// effective, saved, filesystem or supplementary) that is not the server's
// own program (root's, by name), or /proc could not all be read. root's
// processes are root's whatever groups they keep.
func othersRun(src Source, server string, uids, gids map[int]bool) bool {
	names, err := src.ReadDir("/proc")
	if err != nil {
		return true
	}
	for _, n := range names {
		if !numeric(n) {
			continue
		}
		b, err := src.ReadFile("/proc/" + n + "/status")
		if err != nil {
			if gone(err) {
				continue // exited while we looked
			}
			return true
		}
		pu, pg, ok := procIDs(b)
		if !ok {
			return true
		}
		match, root := false, false
		for _, u := range pu {
			root = root || u == 0
			match = match || uids[u]
		}
		for _, g := range pg {
			match = match || gids[g]
		}
		if !match || root {
			continue
		}
		exe, err := src.Readlink("/proc/" + n + "/exe")
		if err != nil || !serverExes[server][path.Base(exe)] || !path.IsAbs(exe) {
			return true // a zombie, a deleted (upgraded) program, or another
		}
		st, err := Stat(src, exe)
		if err != nil || st.UID != 0 || st.Mode.Perm()&0o022 != 0 {
			return true
		}
	}
	return false
}

// procIDs: the uids and gids of a /proc/<pid>/status.
func procIDs(b []byte) (uids, gids []int, ok bool) {
	seen := 0
	for _, ln := range strings.Split(string(b), "\n") {
		k, v, found := strings.Cut(ln, ":")
		if !found || (k != "Uid" && k != "Gid" && k != "Groups") {
			continue
		}
		seen++
		for _, f := range strings.Fields(v) {
			id, err := strconv.Atoi(f)
			if err != nil {
				return nil, nil, false
			}
			if k == "Uid" {
				uids = append(uids, id)
			} else {
				gids = append(gids, id)
			}
		}
	}
	return uids, gids, seen >= 2 && len(uids) > 0
}
