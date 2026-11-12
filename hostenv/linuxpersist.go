package hostenv

// Persistence on Linux beyond cron and systemd: authorized_keys files,
// sudo rules, cron files and PAM modules no package installed. Moved from
// tools/persistence.go and tools/system.go (Phase 1c); the parsing rules
// are the tools ones, kept as they were.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"
)

// AuthorizedKeyFile is one authorized_keys file of an account.
type AuthorizedKeyFile struct {
	User     string          `json:"user"` // first account with this home
	Path     string          `json:"path"`
	Lines    int             `json:"lines"` // non-empty, non-comment lines
	Modified time.Time       `json:"modified"`
	Keys     []AuthorizedKey `json:"keys,omitempty"`
	Unread   string          `json:"unread,omitempty"` // why the content could not be read
}

// AuthorizedKey is one key line, without the key itself.
type AuthorizedKey struct {
	Type             string `json:"type"`
	Fingerprint      string `json:"fingerprint"` // SHA256:..., as ssh-keygen -l prints it
	Options          bool   `json:"options,omitempty"`
	CloudInitRefusal bool   `json:"cloud_init_refusal,omitempty"` // root's "Please login as …" line
}

// IsKeyType reports an SSH public key type.
func IsKeyType(t string) bool {
	return strings.HasPrefix(t, "ssh-") || strings.HasPrefix(t, "ecdsa-") || strings.HasPrefix(t, "sk-")
}

// cloudInitCmd is the line cloud-init writes into root's authorized_keys:
// the options force a command that prints "Please login as the user ..."
// and exits 142, so the key cannot open a shell.
var cloudInitCmd = regexp.MustCompile(`^(no-port-forwarding,no-agent-forwarding,no-X11-forwarding,)?command="echo 'Please login as the user \\"[a-z_][a-z0-9_-]*\\" rather than the user \\"root\\".';echo;sleep 10;exit 142" `)

// CloudInitRefusal reports cloud-init's refusal line.
func CloudInitRefusal(line string) bool { return cloudInitCmd.MatchString(strings.TrimSpace(line)) }

// KeyFingerprint parses an authorized_keys line the way sshd does: an
// optional options field (where quoted text may hold spaces), then the key
// type and the base64 key. It returns the SHA256 fingerprint, "" for a line
// sshd would not use.
func KeyFingerprint(line string) string {
	t, fp, _ := keyLine(line)
	_ = t
	return fp
}

func keyLine(line string) (typ, fp string, options bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", "", false
	}
	if !IsKeyType(strings.Fields(line)[0]) {
		options = true
		// The options field, scanned as OpenSSH's sshkey_advance_past_options does.
		quoted := false
		i := 0
		for ; i < len(line) && (quoted || (line[i] != ' ' && line[i] != '\t')); i++ {
			if line[i] == '\\' && i+1 < len(line) && line[i+1] == '"' {
				i++
			} else if line[i] == '"' {
				quoted = !quoted
			}
		}
		line = line[i:]
	}
	f := strings.Fields(line)
	if len(f) < 2 || !IsKeyType(f[0]) {
		return "", "", false
	}
	blob, err := base64.StdEncoding.DecodeString(f[1])
	if err != nil || len(blob) < 16 {
		return "", "", false
	}
	sum := sha256.Sum256(blob)
	return f[0], "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:]), options
}

// ParseAuthorizedKeys returns the keys sshd would use, in file order.
func ParseAuthorizedKeys(b []byte) []AuthorizedKey {
	var out []AuthorizedKey
	for _, l := range strings.Split(string(b), "\n") {
		if t, fp, opt := keyLine(l); fp != "" {
			out = append(out, AuthorizedKey{Type: t, Fingerprint: fp, Options: opt, CloudInitRefusal: CloudInitRefusal(l)})
		}
	}
	return out
}

func countLines(b []byte) int {
	n := 0
	for _, l := range strings.Split(string(b), "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			n++
		}
	}
	return n
}

// SSHKeyFiles reads ~/.ssh/authorized_keys{,2} of every account, login
// shell or not (a key on a nologin account still forwards ports). A home
// shared by several accounts is read once, for the first. The file is read
// without following a symlink in its last element: the account owns it.
func (LinuxCollector) SSHKeyFiles(src Source, accounts []Account) Obs[[]AuthorizedKeyFile] {
	var out []AuthorizedKeyFile
	var unread []string
	reason := Reason("")
	miss := func(p string, err error) {
		if reason == "" {
			reason = Classify(err)
		}
		unread = append(unread, p+" ("+string(Classify(err))+")")
	}
	seen := map[string]bool{}
	for _, a := range accounts {
		if !strings.HasPrefix(a.Home, "/") {
			continue
		}
		for _, name := range []string{"authorized_keys", "authorized_keys2"} {
			p := path.Join(a.Home, ".ssh", name)
			if seen[p] {
				continue
			}
			seen[p] = true
			st, err := Stat(src, p)
			if err != nil {
				if !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, ErrNoStat) {
					miss(p, err)
				}
				if !errors.Is(err, ErrNoStat) {
					continue
				}
			}
			kf := AuthorizedKeyFile{User: a.Name, Path: p, Modified: st.ModTime}
			b, err := ReadFileNoFollow(src, p)
			if errors.Is(err, ErrNoStat) || (errors.Is(err, fs.ErrNotExist) && st.ModTime.IsZero()) {
				continue // no stat and no file: nothing there
			}
			if err != nil && !errors.Is(err, ErrTruncated) {
				kf.Unread = string(Classify(err))
				miss(p, err)
			}
			kf.Lines = countLines(b)
			kf.Keys = ParseAuthorizedKeys(b)
			out = append(out, kf)
		}
	}
	if len(unread) > 0 {
		return Partial(out, reason, "not fully read: "+strings.Join(unread, ", "))
	}
	return OK(out)
}

// SudoRules are the lines of /etc/sudoers and /etc/sudoers.d/* that grant
// with ALL, Defaults excluded, as "file: line".
func (LinuxCollector) SudoRules(src Source) ([]string, Obs[struct{}]) {
	files := []string{"/etc/sudoers"}
	names, derr := src.ReadDir("/etc/sudoers.d")
	for _, n := range names {
		files = append(files, "/etc/sudoers.d/"+n)
	}
	var out, unread []string
	if derr != nil && !errors.Is(derr, fs.ErrNotExist) {
		unread = append(unread, "/etc/sudoers.d")
	}
	for _, f := range files {
		b, err := src.ReadFile(f)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, ErrNotRegular) {
				unread = append(unread, f)
			}
			continue
		}
		for _, l := range strings.Split(string(b), "\n") {
			l = strings.TrimSpace(l)
			if l != "" && !strings.HasPrefix(l, "#") && !strings.HasPrefix(l, "Defaults") && strings.Contains(l, "ALL") {
				out = append(out, f+": "+l)
			}
		}
	}
	if len(unread) > 0 {
		return out, Partial(struct{}{}, ReasonPermission, "unreadable: "+strings.Join(unread, ", "))
	}
	return out, OK(struct{}{})
}

// CronFiles are the regular files of /etc/crontab, /etc/cron.d/*,
// /var/spool/cron/crontabs/* and /var/spool/cron/*, sorted.
func (LinuxCollector) CronFiles(src Source) []string {
	var out []string
	add := func(p string) {
		if st, err := Stat(src, p); err == nil && st.Mode.IsRegular() {
			out = append(out, p)
		}
	}
	add("/etc/crontab")
	for _, d := range []string{"/etc/cron.d", "/var/spool/cron/crontabs", "/var/spool/cron"} {
		names, _ := src.ReadDir(d)
		for _, n := range names {
			add(d + "/" + n)
		}
	}
	sort.Strings(out)
	return out
}

// PreloadEntries are the libraries listed in a preload file.
func PreloadEntries(b []byte) []string {
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out
}

// PAMDirs are where PAM modules live, as patterns ("*" is one component).
var PAMDirs = []string{"/lib/security", "/lib64/security", "/usr/lib/security", "/usr/lib64/security", "/lib/*/security", "/usr/lib/*/security"}

// RpmOwnedFunc reports which of files an rpm package owns; ok is false
// when rpm cannot be asked.
type RpmOwnedFunc func(files []string) (owned map[string]bool, ok bool)

var rpmQalArgv = []string{"/usr/bin/rpm", "-qal"}

func init() {
	registerBig(rpmQalArgv, 128<<20, MaxTimeout)
	registerBig(rpmArgv, 16<<20, MaxTimeout)
	registerBig(dpkgArgv, 16<<20, MaxTimeout)
}

// RpmOwned asks rpm -qal through src, matching rpm's full file list exactly.
func RpmOwned(ctx context.Context, src Source) RpmOwnedFunc {
	return func(files []string) (map[string]bool, bool) {
		res, err := src.Run(ctx, rpmQalArgv)
		if err != nil || res.ExitCode != 0 {
			return nil, false
		}
		all := map[string]bool{}
		for _, l := range strings.Split(string(res.Stdout), "\n") {
			all[l] = true
		}
		owned := map[string]bool{}
		for _, f := range files {
			owned[f] = all[f]
		}
		return owned, true
	}
}

// UnpackagedPAM returns the PAM modules no package installed: dpkg's file
// lists say it, or rpm. It returns nil when there is no package database
// to ask. A module's folder is resolved (merged /usr: /lib64 links to
// /usr/lib64 and rpm lists only the /usr path); the module file is not.
func (LinuxCollector) UnpackagedPAM(src Source, rpmOwned RpmOwnedFunc) []string {
	seen := map[string]bool{}
	var mods []string
	for _, d := range PAMDirs {
		for _, dir := range globDirs(src, d) {
			names, _ := src.ReadDir(dir)
			for _, n := range names {
				if !strings.HasSuffix(n, ".so") {
					continue
				}
				m := dir + "/" + n
				p := m
				if real, err := EvalSymlinks(src, dir); err == nil {
					p = path.Join(real, n)
				}
				if !seen[p] {
					seen[p] = true
					mods = append(mods, p)
				}
			}
		}
	}
	return notPackaged(src, mods, rpmOwned)
}

// globDirs expands "*" components of an absolute directory pattern.
func globDirs(src Source, pattern string) []string {
	dirs := []string{"/"}
	for _, part := range strings.Split(strings.Trim(pattern, "/"), "/") {
		var next []string
		for _, d := range dirs {
			if part != "*" {
				next = append(next, path.Join(d, part))
				continue
			}
			names, _ := src.ReadDir(d)
			for _, n := range names {
				next = append(next, path.Join(d, n))
			}
		}
		dirs = next
	}
	var out []string
	for _, d := range dirs {
		if _, err := src.ReadDir(d); err == nil {
			out = append(out, d)
		}
	}
	return out
}

// EvalSymlinks resolves every link in an absolute path through src, as
// filepath.EvalSymlinks does.
func EvalSymlinks(src Source, p string) (string, error) {
	resolved := "/"
	rest := strings.Split(strings.Trim(path.Clean(p), "/"), "/")
	for hops := 0; len(rest) > 0; {
		part := rest[0]
		rest = rest[1:]
		if part == "" || part == "." {
			continue
		}
		next := path.Join(resolved, part)
		t, err := src.Readlink(next)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) || errors.Is(err, ErrNotRecorded) {
				if _, derr := src.ReadDir(next); derr != nil {
					if _, ferr := Stat(src, next); ferr != nil && !errors.Is(ferr, ErrNoStat) {
						return "", err
					}
				}
			}
			resolved = next // not a link
			continue
		}
		if hops++; hops > 40 {
			return "", errors.New("hostenv: too many links in " + p)
		}
		if !strings.HasPrefix(t, "/") {
			t = path.Join(resolved, t)
		}
		rest = append(strings.Split(strings.Trim(path.Clean(t), "/"), "/"), rest...)
		resolved = "/"
	}
	return resolved, nil
}

func notPackaged(src Source, files []string, rpmOwned RpmOwnedFunc) []string {
	if len(files) == 0 {
		return nil
	}
	var owned map[string]bool
	names, _ := src.ReadDir("/var/lib/dpkg/info")
	var lists []string
	for _, n := range names {
		if strings.HasSuffix(n, ".list") {
			lists = append(lists, "/var/lib/dpkg/info/"+n)
		}
	}
	if len(lists) > 0 {
		owned = map[string]bool{}
		for _, l := range lists {
			b, _ := src.ReadFile(l)
			for _, p := range strings.Split(string(b), "\n") {
				owned[strings.TrimPrefix(p, "/usr")] = true // merged /usr: /lib/... and /usr/lib/... alike
			}
		}
		for _, f := range files {
			if owned[strings.TrimPrefix(f, "/usr")] {
				owned[f] = true
			}
		}
	} else {
		var ok bool
		if owned, ok = rpmOwned(files); !ok {
			return nil
		}
	}
	var out []string
	for _, f := range files {
		if !owned[f] {
			out = append(out, f)
		}
	}
	sort.Strings(out)
	return out
}
