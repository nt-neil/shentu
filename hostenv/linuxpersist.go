package hostenv

// Persistence on Linux beyond cron and systemd: authorized_keys files,
// sudo rules, cron files and PAM modules no package installed. Moved from
// tools/persistence.go and tools/system.go (Phase 1c); the parsing rules
// are the tools ones, kept as they were.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"
)

// AuthorizedKeyFile is one authorized_keys file of an account.
type AuthorizedKeyFile struct {
	User     string          `json:"user"` // first account with this home
	Path     string          `json:"path"`
	Modified time.Time       `json:"modified"`
	Keys     []AuthorizedKey `json:"keys,omitempty"`
	Unparsed []int           `json:"unparsed_lines,omitempty"` // lines that are neither a key nor a comment: sshd ignores them, but a key in a form not read here would hide among them
	Unread   string          `json:"unread,omitempty"`         // why the content could not be read
	// SymlinkTarget is where the file links to; sshd follows the link, so
	// the keys there count. Outside the home it is a warning of its own.
	SymlinkTarget string `json:"symlink_target,omitempty"`
	OutsideHome   bool   `json:"symlink_outside_home,omitempty"`
}

// AuthorizedKey is one key line, without the key itself.
type AuthorizedKey struct {
	Line             int    `json:"line"`
	Type             string `json:"type"`
	Fingerprint      string `json:"fingerprint"` // SHA256:..., as ssh-keygen -l prints it
	Options          bool   `json:"options,omitempty"`
	CloudInitRefusal bool   `json:"cloud_init_refusal,omitempty"` // root's "Please login as …" line
}

// shortKeyTypes are the short names sshd takes for key types (any case).
var shortKeyTypes = map[string]bool{"rsa": true, "dsa": true, "ecdsa": true, "ed25519": true, "ecdsa-sk": true, "ed25519-sk": true,
	"xmss": true, "rsa-cert": true, "dsa-cert": true, "ecdsa-cert": true, "ed25519-cert": true, "ecdsa-sk-cert": true,
	"ed25519-sk-cert": true, "xmss-cert": true}

// IsKeyType reports whether sshd may take t as a key type, by full or
// short name, in any case (the key itself then says which).
func IsKeyType(t string) bool {
	return fullKeyType(strings.ToLower(t)) || shortKeyTypes[strings.ToLower(t)]
}

func fullKeyType(t string) bool {
	return strings.HasPrefix(t, "ssh-") || strings.HasPrefix(t, "ecdsa-") || strings.HasPrefix(t, "sk-")
}

// cloudInitCmd is the line cloud-init writes into root's authorized_keys:
// the options force a command that prints "Please login as the user ..."
// and exits 142, so the key cannot open a shell.
var cloudInitCmd = regexp.MustCompile(`^(no-port-forwarding,no-agent-forwarding,no-X11-forwarding,)?command="echo 'Please login as the user \\"[a-z_][a-z0-9_-]*\\" rather than the user \\"root\\".';echo;sleep 10;exit 142" `)

// CloudInitRefusal reports cloud-init's refusal line.
func CloudInitRefusal(line string) bool { return cloudInitCmd.MatchString(strings.TrimSpace(line)) }

// KeyFingerprint returns the SHA256 fingerprint of an authorized_keys
// line's key, "" when the line holds none.
func KeyFingerprint(line string) string {
	_, fp, _ := ParseKeyLine(line)
	return fp
}

// ParseKeyLine parses an authorized_keys line the way sshd does: an
// optional options field (where quoted text may hold spaces), then the key
// type and the base64 key. sshd takes a type's full name (ssh-ed25519) or
// its short name (ED25519, rsa) in any case; the type that counts is the
// one written in the key itself. keyType and fp (SHA256:..., as ssh-keygen
// -lf shows it) are "" for a line without a key; unparsed is a line that is
// neither a key nor a comment or blank (sshd ignores it; it is reported,
// not dropped). (tools/persistence.go parseKeyLine as of v0.2.5.)
func ParseKeyLine(line string) (keyType, fp string, unparsed bool) {
	keyType, fp, _, unparsed = parseKeyLine(line)
	return keyType, fp, unparsed
}

func parseKeyLine(line string) (keyType, fp string, options, unparsed bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", "", false, false
	}
	if t, fp := keyAt(line); fp != "" {
		return t, fp, false, false
	}
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
	if t, fp := keyAt(strings.TrimSpace(line[i:])); fp != "" {
		return t, fp, true, false
	}
	return "", "", false, true
}

// keyAt reads a key type name and a base64 key at the start of s.
func keyAt(s string) (keyType, fp string) {
	f := strings.Fields(s)
	if len(f) < 2 || !IsKeyType(f[0]) {
		return "", ""
	}
	blob, err := base64.StdEncoding.DecodeString(f[1])
	if err != nil || len(blob) < 16 {
		return "", ""
	}
	// The key starts with its type: a 4-byte big-endian length, then the name.
	n := int(binary.BigEndian.Uint32(blob))
	if n <= 0 || n > 64 || 4+n > len(blob) {
		return "", ""
	}
	keyType = string(blob[4 : 4+n])
	if !fullKeyType(keyType) {
		return "", ""
	}
	sum := sha256.Sum256(blob)
	return keyType, "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

// ParseAuthorizedKeys returns the keys sshd would use, with their line
// numbers, and the lines that are neither a key nor a comment.
func ParseAuthorizedKeys(b []byte) (keys []AuthorizedKey, unparsed []int) {
	for i, l := range strings.Split(string(b), "\n") {
		t, fp, opt, bad := parseKeyLine(l)
		switch {
		case fp != "":
			keys = append(keys, AuthorizedKey{Line: i + 1, Type: t, Fingerprint: fp, Options: opt, CloudInitRefusal: CloudInitRefusal(l)})
		case bad:
			unparsed = append(unparsed, i+1)
		}
	}
	return keys, unparsed
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
			_, lerr := src.Readlink(p)
			_, derr := src.Readlink(path.Dir(p))
			if err != nil && lerr != nil && derr != nil { // a link (the file or ~/.ssh), even dangling, is looked at below
				if !missing(err) && !errors.Is(err, ErrNoStat) {
					miss(p, err)
				}
				if !errors.Is(err, ErrNoStat) {
					continue
				}
			}
			kf := AuthorizedKeyFile{User: a.Name, Path: p, Modified: st.ModTime}
			b, err := readKeyFile(src, p, a.Home, &kf)
			if kf.SymlinkTarget == "" && (errors.Is(err, ErrNoStat) || (errors.Is(err, fs.ErrNotExist) && st.ModTime.IsZero())) {
				continue // no stat and no file: nothing there (a link, even dangling, is kept)
			}
			if err != nil && !errors.Is(err, ErrTruncated) {
				kf.Unread = string(Classify(err))
				miss(p, err)
			}
			kf.Keys, kf.Unparsed = ParseAuthorizedKeys(b)
			out = append(out, kf)
		}
	}
	if len(unread) > 0 {
		return Partial(out, reason, "not fully read: "+strings.Join(unread, ", "))
	}
	return OK(out)
}

// readKeyFile reads an authorized_keys file as sshd does: through a link
// too, as long as the target is a regular file (and at most MaxFileBytes).
// A link is noted in kf, and whether it leaves the home.
func readKeyFile(src Source, p, home string, kf *AuthorizedKeyFile) ([]byte, error) {
	home = strings.TrimSuffix(home, "/")
	_, fileErr := src.Readlink(p)
	_, dirErr := src.Readlink(path.Dir(p)) // ~/.ssh itself may be the link
	if fileErr != nil && dirErr != nil {
		return ReadFileNoFollow(src, p)
	}
	target, err := EvalSymlinks(src, p)
	if err != nil {
		return nil, err
	}
	kf.SymlinkTarget = target
	realHome := home // a home that is, or sits under, a link (/home/a -> /data/a, /home -> /data/home) is not "outside"
	if h, err := EvalSymlinks(src, home); err == nil {
		realHome = h
	}
	kf.OutsideHome = !strings.HasPrefix(target, realHome+"/") && !strings.HasPrefix(target, home+"/")
	if fileErr != nil { // only the folder is a link: the file itself is still read without following
		return ReadFileNoFollow(src, p)
	}
	if st, err := Stat(src, target); err == nil && !st.Mode.IsRegular() {
		return nil, &fs.PathError{Op: "read", Path: target, Err: ErrNotRegular}
	}
	return ReadFileMax(src, target, MaxFileBytes)
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
// The list (a few hundred thousand paths) is streamed and only the files
// asked about are kept, so memory does not grow with it (a 512 MB server).
func RpmOwned(ctx context.Context, src Source) RpmOwnedFunc {
	return func(files []string) (map[string]bool, bool) {
		owned := make(map[string]bool, len(files))
		for _, f := range files {
			owned[f] = false
		}
		res, err := RunLinesUnmasked(ctx, src, rpmQalArgv, func(l string) {
			if _, ok := owned[l]; ok {
				owned[l] = true
			}
		})
		if err != nil || res.ExitCode != 0 {
			return nil, false
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
		if hops++; hops > 255 { // as filepath.EvalSymlinks
			return "", errors.New("EvalSymlinks: too many links") // filepath.EvalSymlinks's words
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

// missing reports a path that is not there, including one under a home
// that is not a folder (sshd's home is /dev/null on Alpine: ENOTDIR).
func missing(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) || strings.HasSuffix(err.Error(), "not a directory")
}
