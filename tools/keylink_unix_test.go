//go:build unix

package tools

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nt-neil/shentu/hostenv"
)

// N4: an authorized_keys that links out of its home is read as sshd reads
// it, flagged, and its keys count for keys shared between accounts.
func TestKeysThroughSymlink(t *testing.T) {
	root := t.TempDir()
	w := func(p, body string) {
		os.MkdirAll(filepath.Dir(filepath.Join(root, p)), 0o755)
		os.WriteFile(filepath.Join(root, p), []byte(body), 0o600)
	}
	shared, own := fakeKey(t), fakeKey(t)
	w("etc/passwd", "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\nbob:x:1001:1001::/home/bob:/bin/bash\n")
	w("etc/group", "sudo:x:27:\n")
	w("srv/shared/keys", shared+"\n")
	w("home/alice/notes/keys", own+"\n")
	w("home/bob/.ssh/authorized_keys", shared+"\n")
	os.MkdirAll(filepath.Join(root, "home/alice/.ssh"), 0o700)
	os.Symlink("/srv/shared/keys", filepath.Join(root, "home/alice/.ssh/authorized_keys")) // out of the home
	os.Symlink("../notes/keys", filepath.Join(root, "home/alice/.ssh/authorized_keys2"))   // inside it
	remap := map[string]string{}
	for _, d := range []string{"/etc", "/home", "/srv", "/root"} {
		remap[d] = filepath.Join(root, d)
	}
	withHost(t, &hostenv.Live{Remap: remap})
	a := AccountsAudit()
	got := map[string]KeyFile{}
	for _, kf := range a.KeyFiles {
		got[kf.Path] = kf
	}
	if k := got["/home/alice/.ssh/authorized_keys"]; k.Keys != 1 || k.SymlinkOutsideHome != "/srv/shared/keys" {
		t.Errorf("link out of the home: %+v", k)
	}
	if k := got["/home/alice/.ssh/authorized_keys2"]; k.Keys != 1 || k.SymlinkOutsideHome != "" {
		t.Errorf("link inside the home: %+v", k)
	}
	if len(a.SharedKeys) != 1 || len(a.SharedKeys[0].Users) != 2 {
		t.Errorf("shared keys: %+v", a.SharedKeys)
	}
}
