//go:build unix

package hostenv

import (
	"os"
	"path/filepath"
	"testing"
)

// A home under a linked parent (/home -> /data/home) is not "outside" for
// a key file linked inside it; a link out of the home still is.
func TestKeyFileHomeUnderLinkedParent(t *testing.T) {
	tmp, _ := filepath.EvalSymlinks(t.TempDir())
	real := filepath.Join(tmp, "data", "home", "a")
	os.MkdirAll(filepath.Join(real, ".ssh"), 0o700)
	os.MkdirAll(filepath.Join(real, "keys"), 0o700)
	os.WriteFile(filepath.Join(real, "keys", "ak"), []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKkey a@b\n"), 0o600)
	os.Symlink(filepath.Join(tmp, "data", "home"), filepath.Join(tmp, "home"))
	home := filepath.Join(tmp, "home", "a")
	p := filepath.Join(home, ".ssh", "authorized_keys")
	os.Symlink("../keys/ak", filepath.Join(real, ".ssh", "authorized_keys"))
	var kf AuthorizedKeyFile
	if _, err := readKeyFile(&Live{}, p, home, &kf); err != nil || kf.SymlinkTarget == "" || kf.OutsideHome {
		t.Errorf("link inside a home under a linked parent: err %v, %+v", err, kf)
	}
	os.MkdirAll(filepath.Join(tmp, "elsewhere"), 0o700)
	os.WriteFile(filepath.Join(tmp, "elsewhere", "ak"), []byte("x\n"), 0o600)
	os.Remove(filepath.Join(real, ".ssh", "authorized_keys"))
	os.Symlink(filepath.Join(tmp, "elsewhere", "ak"), filepath.Join(real, ".ssh", "authorized_keys"))
	kf = AuthorizedKeyFile{}
	if readKeyFile(&Live{}, p, home, &kf); !kf.OutsideHome {
		t.Errorf("link out of the home: %+v", kf)
	}
}
