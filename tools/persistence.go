package tools

import (
	"context"
	"sort"

	"github.com/nt-neil/shentu/hostenv"
)

// Persistence that survives a reboot or a password change: one key planted in many accounts,
// a library preloaded into every program, a PAM module that no package installed.
// The reading and parsing live in hostenv (Phase 1c); these are the tools' views of it.

// SharedKey is one SSH public key found in the authorized_keys of more than one account.
type SharedKey struct {
	Fingerprint string   `json:"fingerprint"` // SHA256:..., as ssh-keygen -lf shows it; the key itself is not output
	Users       []string `json:"users"`
}

// sharedKeys returns the keys that appear in two or more accounts' authorized_keys files.
// cloud-init's refusal line (the default user's key in root's file, only to refuse the
// login) does not count.
func sharedKeys(files []KeyFile) []SharedKey {
	src := hostSource()
	users := map[string]map[string]bool{}
	for _, f := range files {
		b, err := hostenv.ReadFileNoFollow(src, f.Path)
		if err != nil {
			continue
		}
		for _, k := range hostenv.ParseAuthorizedKeys(b) {
			if k.CloudInitRefusal {
				continue
			}
			if users[k.Fingerprint] == nil {
				users[k.Fingerprint] = map[string]bool{}
			}
			users[k.Fingerprint][f.User] = true
		}
	}
	var out []SharedKey
	for _, fp := range sortedKeys(users) {
		if len(users[fp]) < 2 {
			continue
		}
		out = append(out, SharedKey{Fingerprint: fp, Users: sortedKeys(users[fp])})
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// keyFingerprint is hostenv.KeyFingerprint: the SHA256 fingerprint of the key sshd
// would use from an authorized_keys line, "" for none.
func keyFingerprint(line string) string { return hostenv.KeyFingerprint(line) }

// preloadEntries returns the libraries listed in ld.so.preload, which every program then loads.
func preloadEntries(path string) []string {
	b, _ := hostSource().ReadFile(path)
	return hostenv.PreloadEntries(b)
}

// sysRoot is "/" except in tests.
var sysRoot = "/"

// unpackagedPAM returns PAM modules that no package installed (nil without a package database).
func unpackagedPAM() []string {
	src := hostSource()
	if sysRoot != "/" {
		live, _ := hostenv.NewLive(nil)
		live.Remap = map[string]string{"/": sysRoot}
		src = live
	}
	return linux.UnpackagedPAM(src, rpmOwned)
}

// rpmOwned reports which of the files an rpm package owns, matching rpm's full file list
// exactly; ok is false when rpm cannot be asked. Replaced in tests.
var rpmOwned = func(files []string) (map[string]bool, bool) {
	return hostenv.RpmOwned(context.Background(), hostSource())(files)
}
