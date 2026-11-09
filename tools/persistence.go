package tools

import (
	"crypto/sha256"
	"encoding/base64"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
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

// keyFingerprint finds the key in an authorized_keys line (options may come first) and returns its SHA256 fingerprint.
func keyFingerprint(line string) string {
	if strings.HasPrefix(strings.TrimSpace(line), "#") {
		return ""
	}
	f := strings.Fields(line)
	for i := 0; i+1 < len(f); i++ {
		t := f[i]
		if strings.HasPrefix(t, "ssh-") || strings.HasPrefix(t, "ecdsa-") || strings.HasPrefix(t, "sk-") {
			blob, err := base64.StdEncoding.DecodeString(f[i+1])
			if err != nil || len(blob) < 16 {
				continue
			}
			sum := sha256.Sum256(blob)
			return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
		}
	}
	return ""
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

// unpackagedPAM returns PAM modules that no package installed. With dpkg the package file lists
// say it exactly; with rpm, whose database is binary, a module newer than the database is reported.
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
	var rpmdb time.Time
	if len(lists) == 0 {
		for _, d := range []string{"var/lib/rpm/rpmdb.sqlite", "var/lib/rpm/Packages", "usr/lib/sysimage/rpm/rpmdb.sqlite"} {
			if st, err := os.Stat(filepath.Join(sysRoot, d)); err == nil && st.ModTime().After(rpmdb) {
				rpmdb = st.ModTime()
			}
		}
		if rpmdb.IsZero() {
			return nil // no package database to compare with
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
			if len(lists) > 0 {
				if !owned[strings.TrimPrefix(rel, "/usr")] {
					out = append(out, rel)
				}
			} else if st, err := os.Stat(m); err == nil && st.ModTime().After(rpmdb) {
				out = append(out, rel)
			}
		}
	}
	sort.Strings(out)
	return out
}
