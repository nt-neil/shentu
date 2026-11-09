package tools

import (
	"crypto/sha256"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Persistence that survives a reboot or a password change: one key planted in many accounts,
// a library preloaded into every program, a PAM module that no package installed.

// SharedKey is one SSH public key found in the authorized_keys of more than one account.
type SharedKey struct {
	Fingerprint string   `json:"fingerprint"` // SHA256:..., as ssh-keygen -lf shows it; the key itself is not output
	Users       []string `json:"users"`
}

// sharedKeys returns the keys that appear in two or more accounts' authorized_keys files.
func sharedKeys(files []KeyFile) []SharedKey {
	users := map[string]map[string]bool{}
	for _, f := range files {
		b, err := os.ReadFile(f.Path)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			if cloudInitRefusal(line) {
				continue // cloud-init puts the default user's key in root's file, only to refuse the login
			}
			if fp := keyFingerprint(line); fp != "" {
				if users[fp] == nil {
					users[fp] = map[string]bool{}
				}
				users[fp][f.User] = true
			}
		}
	}
	var out []SharedKey
	for fp, us := range users {
		if len(us) < 2 {
			continue
		}
		k := SharedKey{Fingerprint: fp}
		for u := range us {
			k.Users = append(k.Users, u)
		}
		sort.Strings(k.Users)
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Fingerprint < out[j].Fingerprint })
	return out
}

// cloudInitRefusal reports the line cloud-init writes into root's authorized_keys: the options force a
// command that prints "Please login as the user ..." and exits 142, so the key cannot open a shell.
var cloudInitCmd = regexp.MustCompile(`^(no-port-forwarding,no-agent-forwarding,no-X11-forwarding,)?command="echo 'Please login as the user \\"[a-z_][a-z0-9_-]*\\" rather than the user \\"root\\".';echo;sleep 10;exit 142" `)

func cloudInitRefusal(line string) bool {
	return cloudInitCmd.MatchString(strings.TrimSpace(line))
}

// keyFingerprint parses an authorized_keys line the way sshd does: an optional options field
// (where quoted text may hold spaces), then the key type and the base64 key. It returns the SHA256 fingerprint.
func keyFingerprint(line string) string {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return ""
	}
	if !isKeyType(strings.Fields(line)[0]) {
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
	if len(f) < 2 || !isKeyType(f[0]) {
		return ""
	}
	blob, err := base64.StdEncoding.DecodeString(f[1])
	if err != nil || len(blob) < 16 {
		return ""
	}
	sum := sha256.Sum256(blob)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

func isKeyType(t string) bool {
	return strings.HasPrefix(t, "ssh-") || strings.HasPrefix(t, "ecdsa-") || strings.HasPrefix(t, "sk-")
}

// preloadEntries returns the libraries listed in ld.so.preload, which every program then loads.
func preloadEntries(path string) []string {
	b, _ := os.ReadFile(path)
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out
}

// sysRoot is "/" except in tests.
var sysRoot = "/"

var pamDirs = []string{"lib/security", "lib64/security", "usr/lib/security", "usr/lib64/security", "lib/*/security", "usr/lib/*/security"}

// unpackagedPAM returns PAM modules that no package installed.
func unpackagedPAM() []string {
	root, err := filepath.EvalSymlinks(sysRoot)
	if err != nil {
		root = sysRoot
	}
	seen := map[string]bool{}
	var mods []string
	for _, d := range pamDirs {
		found, _ := filepath.Glob(filepath.Join(root, d, "*.so"))
		for _, m := range found {
			// merged /usr: /lib64 is a link to /usr/lib64, and rpm lists only the /usr path,
			// so the folder is resolved (the module file itself is not; a package owns the link).
			p := m
			if dir, err := filepath.EvalSymlinks(filepath.Dir(m)); err == nil {
				p = filepath.Join(dir, filepath.Base(m))
			}
			r, err := filepath.Rel(root, p)
			if err != nil || strings.HasPrefix(r, "..") {
				if r, err = filepath.Rel(root, m); err != nil {
					continue
				}
			}
			if r = "/" + r; !seen[r] {
				seen[r] = true
				mods = append(mods, r)
			}
		}
	}
	return notPackaged(mods)
}

// notPackaged returns the files that no package installed: dpkg's file lists say it, or rpm -qf.
// It returns nil when there is no package database to ask.
func notPackaged(files []string) []string {
	if len(files) == 0 {
		return nil
	}
	var owned map[string]bool
	lists, _ := filepath.Glob(filepath.Join(sysRoot, "var/lib/dpkg/info/*.list"))
	if len(lists) > 0 {
		owned = map[string]bool{}
		for _, l := range lists {
			b, _ := os.ReadFile(l)
			for _, p := range strings.Split(string(b), "\n") {
				// merged /usr: dpkg may list /lib/... for a file that is also /usr/lib/...
				owned[strings.TrimPrefix(p, "/usr")] = true
			}
		}
		for i, f := range files {
			if owned[strings.TrimPrefix(f, "/usr")] {
				owned[files[i]] = true
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

// rpmOwned reports which of the files an rpm package owns, matching rpm's full file list
// exactly; ok is false when rpm cannot be asked.
var rpmOwned = func(files []string) (map[string]bool, bool) {
	bin := ""
	for _, b := range []string{"/usr/bin/rpm", "/bin/rpm"} {
		if _, err := os.Stat(b); err == nil {
			bin = b
			break
		}
	}
	if bin == "" {
		return nil, false
	}
	cmd := exec.Command(bin, "-qal")
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	out, err := cmd.Output()
	if err != nil {
		return nil, false
	}
	all := map[string]bool{}
	for _, l := range strings.Split(string(out), "\n") {
		all[l] = true
	}
	owned := map[string]bool{}
	for _, f := range files {
		owned[f] = all[f]
	}
	return owned, true
}
