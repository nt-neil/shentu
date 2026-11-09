package tools

import (
	"crypto/sha256"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
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

// keyFingerprint parses an authorized_keys line the way sshd does: an optional options field
// (where quoted text may hold spaces), then the key type and the base64 key. It returns the SHA256 fingerprint.
func keyFingerprint(line string) string {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return ""
	}
	if !isKeyType(strings.Fields(line)[0]) {
		quoted := false
		i := 0
		for ; i < len(line); i++ {
			c := line[i]
			if c == '\\' && quoted && i+1 < len(line) {
				i++
			} else if c == '"' {
				quoted = !quoted
			} else if (c == ' ' || c == '\t') && !quoted {
				break
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

// unpackagedPAM returns PAM modules that no package installed: dpkg's file lists say it, or rpm -qf.
func unpackagedPAM() []string {
	owned := map[string]bool{}
	lists, _ := filepath.Glob(filepath.Join(sysRoot, "var/lib/dpkg/info/*.list"))
	for _, l := range lists {
		b, _ := os.ReadFile(l)
		for _, p := range strings.Split(string(b), "\n") {
			if strings.HasSuffix(p, ".so") {
				// merged /usr: dpkg may list /lib/... for a file that is also /usr/lib/...
				owned[strings.TrimPrefix(p, "/usr")] = true
			}
		}
	}
	seen := map[string]bool{}
	var out []string
	for _, d := range pamDirs {
		mods, _ := filepath.Glob(filepath.Join(sysRoot, d, "*.so"))
		for _, m := range mods {
			r, err := filepath.Rel(sysRoot, m)
			if err != nil {
				continue
			}
			rel := "/" + r
			if real, err := filepath.EvalSymlinks(m); err == nil {
				if seen[real] {
					continue
				}
				seen[real] = true
			}
			if len(lists) == 0 || !owned[strings.TrimPrefix(rel, "/usr")] {
				out = append(out, rel)
			}
		}
	}
	if len(lists) == 0 && len(out) > 0 {
		// No dpkg: ask rpm, which keeps its file lists in a binary database.
		owned, ok := rpmOwned(out)
		if !ok {
			return nil // no package database to compare with
		}
		var not []string
		for _, p := range out {
			if !owned[p] {
				not = append(not, p)
			}
		}
		out = not
	}
	sort.Strings(out)
	return out
}

// rpmOwned reports which of the files an rpm package owns; ok is false without rpm.
var rpmOwned = func(files []string) (map[string]bool, bool) {
	if _, err := exec.LookPath("rpm"); err != nil {
		return nil, false
	}
	// rpm names each file it does not own: "file /x is not owned by any package".
	out, _ := exec.Command("rpm", append([]string{"-qf", "--queryformat", "%{NAME}\\n"}, files...)...).CombinedOutput()
	owned := map[string]bool{}
	for _, f := range files {
		owned[f] = true
	}
	for _, l := range strings.Split(string(out), "\n") {
		if p, ok := strings.CutSuffix(strings.TrimSpace(l), " is not owned by any package"); ok {
			owned[strings.TrimPrefix(p, "file ")] = false
		}
	}
	return owned, true
}
