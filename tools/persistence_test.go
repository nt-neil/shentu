package tools

import (
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeKey makes a public key line at run time, so no key sits in the repository.
func fakeKey(t *testing.T) string {
	b := make([]byte, 51)
	rand.Read(b)
	return "ssh-" + "ed25519 " + base64.StdEncoding.EncodeToString(b)
}

func TestSharedKeys(t *testing.T) {
	dir := t.TempDir()
	attacker, own1, own2 := fakeKey(t), fakeKey(t), fakeKey(t)
	files := []KeyFile{}
	for user, body := range map[string]string{
		"root":   own1 + " admin@laptop\n" + attacker + "\n",
		"deploy": `command="/bin/true",no-pty ` + attacker + " x\n" + own2 + " ci\n",
		"ann":    "# " + attacker + "\n" + own2 + " ci\n",
		// cloud-init: the default user's key in root's file, only to refuse root logins.
		"cloud": `no-port-forwarding,no-agent-forwarding,no-X11-forwarding,command="echo 'Please login as the user \"rocky\" rather than the user \"root\".';echo;sleep 10;exit 142" ` + own1 + "\n",
		// The same words elsewhere on the line do not hide a key.
		"mallory": attacker + ` Please login as the user` + "\n",
	} {
		p := filepath.Join(dir, user)
		os.WriteFile(p, []byte(body), 0o600)
		files = append(files, KeyFile{User: user, Path: p})
	}
	got := sharedKeys(files)
	// The attacker key in root, deploy and mallory (the comment line in ann does not count), and own2 in
	// deploy and ann; own1 in cloud-init's refusal line does not count.
	if len(got) != 2 {
		t.Fatalf("got %+v", got)
	}
	for _, k := range got {
		if !strings.HasPrefix(k.Fingerprint, "SHA256:") || len(k.Users) < 2 || strings.Contains(strings.Join(k.Users, ","), "cloud") {
			t.Errorf("bad shared key %+v", k)
		}
		if strings.Contains(k.Fingerprint, strings.Fields(attacker)[1]) {
			t.Error("the key itself is in the output")
		}
	}
	if fp := keyFingerprint(attacker); fp == "" || fp != keyFingerprint(`from="10.0.0.1" `+attacker+" c") {
		t.Error("options before the key change its fingerprint")
	}
	// A decoy key inside a quoted option must not be taken for the key.
	decoy := `command="echo ` + own1 + `",no-pty ` + attacker + " c"
	if keyFingerprint(decoy) != keyFingerprint(attacker) {
		t.Error("a key inside a quoted option was fingerprinted")
	}
	if keyFingerprint(`environment="A=\"x y\"" `+attacker) != keyFingerprint(attacker) {
		t.Error("escaped quotes in options")
	}
	// As in OpenSSH: \" never closes a quote, so this line has no key sshd would use either.
	if fp := keyFingerprint(`environment="A=\\" ` + attacker); fp != "" {
		t.Errorf("unterminated quote: got %s", fp)
	}
	// An escaped quote outside quotes does not open a quoted part.
	if keyFingerprint(`from=\"x `+attacker) != keyFingerprint(attacker) {
		t.Error("an escaped quote outside quotes")
	}
}

func TestPreloadEntries(t *testing.T) {
	p := filepath.Join(t.TempDir(), "ld.so.preload")
	if len(preloadEntries(p)) != 0 {
		t.Error("missing file")
	}
	os.WriteFile(p, []byte("# empty\n\n"), 0o644)
	if len(preloadEntries(p)) != 0 {
		t.Error("comment only")
	}
	os.WriteFile(p, []byte("/usr/lib/libprocesshider.so\n"), 0o644)
	if got := preloadEntries(p); len(got) != 1 || got[0] != "/usr/lib/libprocesshider.so" {
		t.Errorf("got %v", got)
	}
}

func TestUnpackagedPAM(t *testing.T) {
	root := t.TempDir()
	sysRoot = root
	t.Cleanup(func() { sysRoot = "/" })
	w := func(p, body string) {
		os.MkdirAll(filepath.Dir(filepath.Join(root, p)), 0o755)
		os.WriteFile(filepath.Join(root, p), []byte(body), 0o644)
	}
	// dpkg: the package lists name the modules exactly.
	w("usr/lib/x86_64-linux-gnu/security/pam_unix.so", "")
	w("usr/lib/x86_64-linux-gnu/security/pam_sshd.so", "")
	w("var/lib/dpkg/info/libpam-modules.list", "/lib/x86_64-linux-gnu/security/pam_unix.so\n")
	if got := unpackagedPAM(); len(got) != 1 || got[0] != "/usr/lib/x86_64-linux-gnu/security/pam_sshd.so" {
		t.Errorf("dpkg: got %v", got)
	}
	// rpm: rpm -qf says which modules it owns.
	os.RemoveAll(filepath.Join(root, "var/lib/dpkg"))
	os.RemoveAll(filepath.Join(root, "usr"))
	w("lib64/security/pam_unix.so", "")
	w("lib64/security/pam_x.so", "")
	saved := rpmOwned
	t.Cleanup(func() { rpmOwned = saved })
	rpmOwned = func(files []string) (map[string]bool, bool) {
		return map[string]bool{"/lib64/security/pam_unix.so": true}, true
	}
	if got := unpackagedPAM(); len(got) != 1 || got[0] != "/lib64/security/pam_x.so" {
		t.Errorf("rpm: got %v", got)
	}
	// merged /usr, as on Rocky 9: /lib64 links to /usr/lib64 and rpm lists only /usr/lib64/....
	os.RemoveAll(filepath.Join(root, "lib64"))
	w("usr/lib64/security/pam_unix.so", "")
	w("usr/lib64/security/pam_x.so", "")
	os.Symlink("usr/lib64", filepath.Join(root, "lib64"))
	rpmOwned = func(files []string) (map[string]bool, bool) {
		owned := map[string]bool{}
		for _, f := range files {
			owned[f] = f == "/usr/lib64/security/pam_unix.so"
		}
		return owned, true
	}
	if got := unpackagedPAM(); len(got) != 1 || got[0] != "/usr/lib64/security/pam_x.so" {
		t.Errorf("rpm, merged /usr: got %v", got)
	}
	rpmOwned = func([]string) (map[string]bool, bool) { return nil, false }
	if got := unpackagedPAM(); got != nil {
		t.Errorf("no package database: got %v", got)
	}
}

// On the real root the module paths must still match the package lists exactly.
func TestUnpackagedPAMRealRoot(t *testing.T) {
	_, dpkg := os.Stat("/var/lib/dpkg/info")
	_, rpm := os.Stat("/usr/bin/rpm")
	if dpkg != nil && rpm != nil {
		t.Skip("no dpkg or rpm here")
	}
	if got := unpackagedPAM(); len(got) > 0 {
		t.Errorf("stock PAM modules reported as unpackaged: %v", got)
	}
}
