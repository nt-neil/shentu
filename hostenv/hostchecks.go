package hostenv

import (
	"path"
	"regexp"
	"slices"
	"sort"
	"strings"
)

// SudoNoPass is what sudoers says about running commands with no password.
type SudoNoPass struct {
	Rules  []SudoRule
	Unread []string // files, folders and sources not read: whether more rules are there is not known
}

// SudoRule is one rule that runs commands with no password: commands under
// a NOPASSWD tag (up to a PASSWD tag), or Defaults !authenticate.
type SudoRule struct {
	File, Line string
	Who        string   // the user list, spaces around commas dropped: a user, %group, an alias, ALL, a list
	Runas      []string // the accounts they run as ("" for root, sudo's default)
	Cmds       []string // the commands with no password, aliases expanded; nil for every command
	All        bool     // every command: ALL among them, an alias not told, or a Defaults !authenticate for all
	Defaults   bool     // a Defaults !authenticate
	// CloudDefault: in /etc/sudoers.d/90-cloud-init-users, for cloud-init's
	// default_user (cloud.cfg, cloud.cfg.d/*.cfg).
	CloudDefault bool
}

// OneUser: the rule is for one user by name, not a %group, a +netgroup,
// a User_Alias (upper case), ALL or a list.
func (r SudoRule) OneUser() bool {
	w := r.Who
	return !r.Defaults && w != "" && w != "ALL" && !strings.ContainsAny(w, "%+,:!#") && w != strings.ToUpper(w)
}

func (r SudoRule) String() string { return r.File + ": " + r.Line }

// cloudInitSudoers is the file cloud-init writes for the image's default
// user; only this path (a file of the same name included from elsewhere is
// not it).
const cloudInitSudoers = "/etc/sudoers.d/90-cloud-init-users"

var (
	reCommaSpace = regexp.MustCompile(`\s*,\s*`)
	reNoAuth     = regexp.MustCompile(`(^|[\s,])!\s*authenticate\b`)
	reCmndAlias  = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
	reSudoOption = regexp.MustCompile(`^[A-Z_]+=\S*\s*`)
)

// sudoRaw is a rule as read, told once every file (and Cmnd_Alias) is read.
type sudoRaw struct {
	file, line string
	defaults   bool
}

// SudoNopasswd reads /etc/sudoers and what it includes (#include, @include,
// #includedir, @includedir; at most 8 deep and maxRunAsFiles files) for
// rules that run commands with no password. sudoers from sss or ldap
// (nsswitch.conf) is not read, and said.
func SudoNopasswd(src Source) SudoNoPass {
	var s SudoNoPass
	if b, err := src.ReadFile("/etc/nsswitch.conf"); err == nil {
		for _, ln := range strings.Split(string(b), "\n") {
			k, v, ok := strings.Cut(strings.TrimSpace(ln), ":")
			if !ok || strings.TrimSpace(k) != "sudoers" {
				continue
			}
			if i := strings.IndexByte(v, '#'); i >= 0 {
				v = v[:i]
			}
			for _, x := range strings.Fields(v) {
				if x != "files" && !strings.HasPrefix(x, "[") {
					s.Unread = append(s.Unread, "sudoers from "+x+" (nsswitch.conf)")
				}
			}
		}
	}
	aliases := map[string][]string{}
	var raws []sudoRaw
	seen := map[string]bool{}
	var read func(p string, depth int)
	read = func(p string, depth int) {
		if seen[p] {
			return
		}
		seen[p] = true
		if depth > 8 || len(seen) > maxRunAsFiles {
			s.Unread = append(s.Unread, p+" (past the bounds of includes read)")
			return
		}
		b, err := src.ReadFile(p)
		if err != nil {
			if !gone(err) {
				s.Unread = append(s.Unread, p+" ("+whyUnread(err)+")")
			}
			return
		}
		for _, ln := range sudoersLines(string(b)) {
			f := strings.Fields(ln)
			if len(f) == 0 {
				continue
			}
			switch {
			case strings.HasPrefix(f[0], "#include") || strings.HasPrefix(f[0], "@include"):
				if len(f) < 2 || strings.Contains(ln, "%") {
					s.Unread = append(s.Unread, p+": "+ln+" (an include named by host or user)")
					continue
				}
				q := strings.Trim(strings.Join(f[1:], " "), `"`)
				if !path.IsAbs(q) {
					q = path.Join(path.Dir(p), q)
				}
				if strings.HasSuffix(f[0], "includedir") {
					names, err := src.ReadDir(q)
					if err != nil && !gone(err) {
						s.Unread = append(s.Unread, q+" ("+whyUnread(err)+")")
					}
					for _, n := range names {
						// sudo skips names ending in ~ or holding a dot
						if !strings.HasSuffix(n, "~") && !strings.Contains(n, ".") {
							read(path.Join(q, n), depth+1)
						}
					}
				} else {
					read(q, depth+1)
				}
			case strings.HasPrefix(f[0], "Defaults"):
				if reNoAuth.MatchString(ln) {
					raws = append(raws, sudoRaw{p, ln, true})
				}
			case f[0] == "Cmnd_Alias" || f[0] == "Cmd_Alias":
				for _, def := range strings.Split(strings.TrimSpace(strings.TrimPrefix(ln, f[0])), ":") {
					if name, list, ok := strings.Cut(def, "="); ok {
						aliases[strings.TrimSpace(name)] = splitSudoList(list)
					}
				}
			case f[0] == "User_Alias" || f[0] == "Host_Alias" || f[0] == "Runas_Alias":
			default:
				if strings.Contains(ln, "NOPASSWD") {
					raws = append(raws, sudoRaw{p, ln, false})
				}
			}
		}
	}
	read("/etc/sudoers", 0)
	def := ""
	for _, r := range raws {
		if r.file == cloudInitSudoers && def == "" {
			def = CloudDefaultUser(src)
			break
		}
	}
	for _, r := range raws {
		if rule, ok := sudoRule(r, aliases); ok {
			rule.CloudDefault = r.file == cloudInitSudoers && def != "" && rule.Who == def
			s.Rules = append(s.Rules, rule)
		}
	}
	return s
}

// sudoRule tells a rule's commands with no password. A user
// specification's commands carry the run-as list and the tags before
// them (NOPASSWD up to a PASSWD); a command alias is expanded, and one not
// told (not defined, too deep) counts as every command.
func sudoRule(r sudoRaw, aliases map[string][]string) (SudoRule, bool) {
	rule := SudoRule{File: r.file, Line: r.line, Defaults: r.defaults}
	ln := reCommaSpace.ReplaceAllString(r.line, ",")
	f := strings.Fields(ln)
	if r.defaults {
		// Defaults:user, Defaults>runas, Defaults!cmnd, or for everyone
		kw := f[0]
		switch {
		case strings.HasPrefix(kw, "Defaults!"):
			rule.Cmds, rule.All = expandCmds(splitSudoList(strings.TrimPrefix(kw, "Defaults!")), aliases, 0)
		case strings.HasPrefix(kw, "Defaults:"):
			rule.Who, rule.All = strings.TrimPrefix(kw, "Defaults:"), true
		case strings.HasPrefix(kw, "Defaults>"):
			rule.Runas, rule.All = splitSudoList(strings.TrimPrefix(kw, "Defaults>")), true
		default:
			rule.All = true
		}
		if rule.All {
			rule.Cmds = nil
		}
		return rule, true
	}
	if len(f) == 0 {
		rule.All = true
		return rule, true
	}
	rule.Who = f[0]
	spec := strings.TrimPrefix(ln, f[0])
	// Read as split into host parts, and, when it splits, as one part too:
	// the worse of the two stands, so a ':' taken for a separator wrongly
	// cannot hide a command (fail closed).
	readings := [][]string{hostSpecs(spec)}
	if len(readings[0]) > 1 {
		readings = append(readings, []string{spec})
	}
	var cmds []string
	for _, specs := range readings {
		c, runas, told := nopassCmds(specs)
		if !told {
			rule.All = true
			return rule, true
		}
		for _, x := range c {
			if !slices.Contains(cmds, x) {
				cmds = append(cmds, x)
			}
		}
		for _, a := range runas {
			if !slices.Contains(rule.Runas, a) {
				rule.Runas = append(rule.Runas, a)
			}
		}
	}
	if len(cmds) == 0 {
		// NOPASSWD on the line, yet no command told under it: every
		// command, never dropped (fail closed)
		rule.All = true
		return rule, reNoPassTag.MatchString(r.line)
	}
	rule.Cmds, rule.All = expandCmds(cmds, aliases, 0)
	if rule.All {
		rule.Cmds = nil
	}
	return rule, true
}

// nopassCmds are the commands with no password of host parts ("host =
// commands"), each part's tags and run-as starting anew; told is false
// when a part cannot be read (no '=', a run-as list not closed).
func nopassCmds(specs []string) (cmds, runasList []string, told bool) {
	for _, spec := range specs {
		_, rest, ok := strings.Cut(spec, "=")
		if !ok {
			return nil, nil, false
		}
		nopass, runas := false, ""
		for _, item := range splitSudoList(rest) {
			if strings.HasPrefix(item, "(") {
				end := strings.IndexByte(item, ')')
				if end < 0 {
					return nil, nil, false
				}
				runas, item = strings.TrimSpace(item[1:end]), strings.TrimSpace(item[end+1:])
			}
			for {
				if m := reSudoOption.FindString(item); m != "" {
					item = strings.TrimSpace(item[len(m):])
					continue
				}
				i := strings.IndexByte(item, ':')
				if i < 0 || !sudoTags[strings.TrimSpace(item[:i])] {
					break
				}
				switch strings.TrimSpace(item[:i]) {
				case "NOPASSWD":
					nopass = true
				case "PASSWD":
					nopass = false
				}
				item = strings.TrimSpace(item[i+1:])
			}
			if nopass && item != "" {
				cmds = append(cmds, item)
				if !slices.Contains(runasList, runas) {
					runasList = append(runasList, runas)
				}
			}
		}
	}
	return cmds, runasList, true
}

var (
	reNoPassTag  = regexp.MustCompile(`\bNOPASSWD\s*:`)
	reHostSpecAt = regexp.MustCompile(`^\s*[^=():!]+?\s*=`)
	reTagBefore  = regexp.MustCompile(`([A-Za-z0-9_]+)\s*$`)
	sudoDigests  = map[string]bool{"sha224": true, "sha256": true, "sha384": true, "sha512": true}
)

// hostSpecs splits a user specification past its user list into its
// "host = commands" parts: at a ':' outside parentheses, not escaped,
// not ending a tag (NOPASSWD:), and followed by a host list and '='.
func hostSpecs(s string) []string {
	var out []string
	depth, start := 0, 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case '(':
			depth++
		case ')':
			depth--
		case ':':
			if depth != 0 {
				continue
			}
			// a tag's colon (NOPASSWD: CWD=/x, NOPASSWD: env A=1) is not
			// one, nor a digest's (sha256:<base64>= /bin/x)
			if m := reTagBefore.FindStringSubmatch(s[start:i]); m != nil && (sudoTags[m[1]] || sudoDigests[strings.ToLower(m[1])]) {
				continue
			}
			if !reHostSpecAt.MatchString(s[i+1:]) {
				continue
			}
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

// expandCmds expands command aliases; all: ALL among them, an alias not
// told, or a command masked. A negated command (!cmd) takes nothing away here.
func expandCmds(cmds []string, aliases map[string][]string, depth int) ([]string, bool) {
	var out []string
	for _, c := range cmds {
		c = strings.TrimSpace(c)
		if strings.HasPrefix(c, "!") {
			continue
		}
		name := strings.Fields(c)
		switch {
		case c == "ALL":
			return nil, true
		case strings.Contains(c, "[REDACTED"):
			// MaskSecrets keeps a NOPASSWD: tag before ALL, a path, ! or a
			// tag; before an alias or an option it masks what follows as a
			// password would be: not told, so every command
			return nil, true
		case len(name) == 1 && reCmndAlias.MatchString(c):
			list, ok := aliases[c]
			if !ok || depth > 8 {
				return nil, true
			}
			sub, all := expandCmds(list, aliases, depth+1)
			if all {
				return nil, true
			}
			out = append(out, sub...)
		default:
			out = append(out, c)
		}
	}
	return out, false
}

// splitSudoList splits a sudoers list at commas not escaped (\,).
func splitSudoList(s string) []string {
	var out []string
	cur := strings.Builder{}
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '\\' && i+1 < len(s):
			cur.WriteByte(s[i])
			cur.WriteByte(s[i+1])
			i++
		case s[i] == ',':
			out = append(out, strings.TrimSpace(cur.String()))
			cur.Reset()
		default:
			cur.WriteByte(s[i])
		}
	}
	if t := strings.TrimSpace(cur.String()); t != "" || len(out) > 0 {
		out = append(out, t)
	}
	return out
}

// CloudDefaultUser is the name of cloud-init's default_user (system_info's,
// or top-level) in /etc/cloud/cloud.cfg and /etc/cloud/cloud.cfg.d/*.cfg,
// the last one read winning as cloud-init merges them; "" when none is
// set or a file could not be read. user-data is not read.
func CloudDefaultUser(src Source) string {
	files := []string{"/etc/cloud/cloud.cfg"}
	names, err := src.ReadDir("/etc/cloud/cloud.cfg.d")
	if err != nil && !gone(err) {
		return ""
	}
	for _, n := range names {
		if strings.HasSuffix(n, ".cfg") {
			files = append(files, "/etc/cloud/cloud.cfg.d/"+n)
		}
	}
	name := ""
	for _, p := range files {
		b, err := src.ReadFile(p)
		if err != nil {
			if gone(err) {
				continue
			}
			return ""
		}
		if n := cfgDefaultUser(string(b)); n != "" {
			name = n
		}
	}
	return name
}

// cfgDefaultUser finds default_user's name in one cloud-init YAML file:
// default_user: (top level or under system_info:), then name: inside it.
func cfgDefaultUser(s string) string {
	indent := func(l string) int { return len(l) - len(strings.TrimLeft(l, " ")) }
	in, at, parent := false, 0, ""
	for _, l := range strings.Split(s, "\n") {
		t := strings.TrimSpace(l)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		d := indent(l)
		if in {
			if d <= at {
				in = false
			} else if v, ok := strings.CutPrefix(t, "name:"); ok {
				return strings.Trim(strings.TrimSpace(v), `"'`)
			}
		}
		if d == 0 {
			parent = strings.TrimSuffix(t, ":")
		}
		if t == "default_user:" && (d == 0 || parent == "system_info") {
			in, at = true, d
		}
	}
	return ""
}

// RebootPending is whether the host waits for a reboot to run what an
// update installed.
type RebootPending struct {
	Pending bool
	Why     string // what says so: the packages, or the kernel installed
	Unread  string // what could not be read: pending or not is not known
}

var reLetters = regexp.MustCompile(`[a-z]+`)

// kernelFlavor is a kernel release's letters (el, uek, x, debug, default...):
// one flavor's releases differ in their numbers only.
func kernelFlavor(v string) string {
	return strings.Join(reLetters.FindAllString(strings.ToLower(v), -1), ",")
}

// Reboot tells a pending reboot: on Debian and Ubuntu /run/reboot-required
// (its .pkgs names the packages); elsewhere, a kernel in /boot newer than
// the running one (kernel, Platform.Kernel) of the same flavor. A running
// kernel not in /boot (a container, a kernel from outside) is not compared.
func Reboot(src Source, family, kernel string) RebootPending {
	if family == "debian" {
		for _, p := range []string{"/run/reboot-required", "/var/run/reboot-required"} {
			_, err := ReadFileMax(src, p, 4096)
			if gone(err) {
				continue
			}
			if err != nil {
				return RebootPending{Unread: p + " (" + whyUnread(err) + ")"}
			}
			why := "an update asks for a reboot"
			if b, err := ReadFileMax(src, p+".pkgs", 64<<10); err == nil {
				var pkgs []string
				for _, l := range strings.Fields(string(b)) {
					if !slices.Contains(pkgs, l) {
						pkgs = append(pkgs, l)
					}
				}
				if len(pkgs) > 5 {
					pkgs = append(pkgs[:5], "...")
				}
				if len(pkgs) > 0 {
					why += " (" + strings.Join(pkgs, ", ") + ")"
				}
			}
			return RebootPending{Pending: true, Why: why}
		}
		return RebootPending{}
	}
	if kernel == "" {
		return RebootPending{}
	}
	names, err := src.ReadDir("/boot")
	if err != nil {
		if gone(err) {
			return RebootPending{}
		}
		return RebootPending{Unread: "/boot (" + whyUnread(err) + ")"}
	}
	var kernels []string
	running := false
	for _, n := range names {
		v, ok := strings.CutPrefix(n, "vmlinuz-")
		if !ok || strings.Contains(v, "rescue") || strings.HasSuffix(v, ".hmac") || v == "" {
			continue
		}
		running = running || v == kernel
		if kernelFlavor(v) == kernelFlavor(kernel) { // +debug, uek, RHCK, -default, -64kb apart (N-274-3)
			kernels = append(kernels, v)
		}
	}
	if !running {
		return RebootPending{}
	}
	sort.Slice(kernels, func(i, j int) bool { return RPMVerCmp(kernels[i], kernels[j]) < 0 })
	if newest := kernels[len(kernels)-1]; RPMVerCmp(newest, kernel) > 0 {
		return RebootPending{Pending: true, Why: "kernel " + newest + " is installed, " + kernel + " is running"}
	}
	return RebootPending{}
}
