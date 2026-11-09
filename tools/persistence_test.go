package tools

import (
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
	} {
		p := filepath.Join(dir, user)
		os.WriteFile(p, []byte(body), 0o600)
		files = append(files, KeyFile{User: user, Path: p})
	}
	got := sharedKeys(files)
	// The attacker key in root and deploy (the comment line in ann does not count), and own2 in deploy and ann.
	if len(got) != 2 {
		t.Fatalf("got %+v", got)
	}
	for _, k := range got {
		if !strings.HasPrefix(k.Fingerprint, "SHA256:") || len(k.Users) != 2 {
			t.Errorf("bad shared key %+v", k)
		}
		if strings.Contains(k.Fingerprint, strings.Fields(attacker)[1]) {
			t.Error("the key itself is in the output")
		}
	}
	if fp := keyFingerprint(attacker); fp != keyFingerprint(`from="10.0.0.1" `+attacker+" c") {
		t.Error("options before the key change its fingerprint")
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
	// rpm: a module newer than the package database.
	os.RemoveAll(filepath.Join(root, "var/lib/dpkg"))
	os.RemoveAll(filepath.Join(root, "usr"))
	w("lib64/security/pam_unix.so", "")
	w("var/lib/rpm/rpmdb.sqlite", "")
	old := time.Now().Add(-time.Hour)
	os.Chtimes(filepath.Join(root, "lib64/security/pam_unix.so"), old, old)
	w("lib64/security/pam_x.so", "")
	os.Chtimes(filepath.Join(root, "var/lib/rpm/rpmdb.sqlite"), old.Add(time.Minute), old.Add(time.Minute))
	if got := unpackagedPAM(); len(got) != 1 || got[0] != "/lib64/security/pam_x.so" {
		t.Errorf("rpm: got %v", got)
	}
}
