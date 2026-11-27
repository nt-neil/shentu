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

// SudoRule is one rule that runs commands with no password: a NOPASSWD
// tag, or Defaults !authenticate.
type SudoRule struct {
	File, Line string
	Who        string // the user specification's first field: a user, %group, an alias, ALL
	All        bool   // every command (NOPASSWD: ALL, or !authenticate)
	Defaults   bool   // Defaults !authenticate
	CloudInit  bool   // in the file cloud-init writes (90-cloud-init-users, or its header)
}

// OneUser: the rule is for one user by name, not a %group, a +netgroup,
// a User_Alias (upper case), ALL or a list.
func (r SudoRule) OneUser() bool {
	w := r.Who
	return !r.Defaults && w != "" && w != "ALL" && !strings.ContainsAny(w, "%+,:!") && w != strings.ToUpper(w)
}

func (r SudoRule) String() string { return r.File + ": " + r.Line }

// cloudInitSudoers: the file cloud-init writes for the image's default
// user: by its name, or its header ("Created by cloud-init").
func cloudInitSudoers(p string, b []byte) bool {
	if path.Base(p) == "90-cloud-init-users" {
		return true
	}
	head := string(b[:min(len(b), 512)])
	return strings.Contains(head, "# Created by cloud-init")
}

var (
	reNoPass    = regexp.MustCompile(`\bNOPASSWD\s*:`)
	reNoPassAll = regexp.MustCompile(`\bNOPASSWD\s*:\s*(?:[A-Z_]+\s*:\s*)*ALL\b`)
	reNoAuth    = regexp.MustCompile(`(^|[\s,])!\s*authenticate\b`)
)

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
		cloud := cloudInitSudoers(p, b)
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
					s.Rules = append(s.Rules, SudoRule{File: p, Line: ln, All: true, Defaults: true, CloudInit: cloud})
				}
			case f[0] == "User_Alias" || f[0] == "Host_Alias" || f[0] == "Cmnd_Alias" || f[0] == "Cmd_Alias" || f[0] == "Runas_Alias":
			default:
				if reNoPass.MatchString(ln) {
					s.Rules = append(s.Rules, SudoRule{File: p, Line: ln, Who: f[0], All: reNoPassAll.MatchString(ln), CloudInit: cloud})
				}
			}
		}
	}
	read("/etc/sudoers", 0)
	return s
}

// RebootPending is whether the host waits for a reboot to run what an
// update installed.
type RebootPending struct {
	Pending bool
	Why     string // what says so: the packages, or the kernel installed
	Unread  string // what could not be read: pending or not is not known
}

// Reboot tells a pending reboot: on Debian and Ubuntu /run/reboot-required
// (its .pkgs names the packages); elsewhere, a kernel in /boot newer than
// the running one (kernel, Platform.Kernel). A running kernel not in /boot
// (a container, a kernel from outside) is not compared.
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
		kernels = append(kernels, v)
		running = running || v == kernel
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
