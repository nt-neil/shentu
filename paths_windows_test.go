//go:build windows

package main

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// aceSIDs returns the trustees of a DACL's allow entries and whether the
// DACL is protected from inheritance.
func aceSIDs(t *testing.T, path string) (sids []string, protected bool) {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	s := sd.String()
	dacl := s[strings.Index(s, "D:"):]
	for _, m := range regexp.MustCompile(`\(A;[^;]*;[^;]*;;;([^)]+)\)`).FindAllStringSubmatch(dacl, -1) {
		sids = append(sids, m[1])
	}
	sort.Strings(sids)
	return sids, strings.HasPrefix(dacl, "D:P")
}

func TestSecureDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "Shentu", "state")
	if err := secureDir(dir); err != nil {
		t.Fatal(err) // CI runs elevated, as the service does
	}
	sids, protected := aceSIDs(t, dir)
	if !protected || strings.Join(sids, ",") != "BA,SY" {
		t.Errorf("state dir DACL: protected %v, trustees %v; want protected, BA and SY only", protected, sids)
	}
	f := filepath.Join(dir, "state.json")
	if err := os.WriteFile(f, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if sids, _ := aceSIDs(t, f); strings.Join(sids, ",") != "BA,SY" {
		t.Errorf("a file inside inherits only BA and SY: %v", sids)
	}
}

func TestTrustConfig(t *testing.T) {
	plain := t.TempDir() // the runner user's own ACL: not trusted
	if _, err := trustConfig(filepath.Join(plain, "shentu.toml")); err == nil {
		t.Error("a folder under a user profile must be refused")
	}

	dir := filepath.Join(t.TempDir(), "Shentu")
	if err := secureDir(dir); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "shentu.toml")
	if err := os.WriteFile(cfg, []byte("language = \"English\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if load, err := trustConfig(cfg); err != nil || !load {
		t.Errorf("secured folder refused: %v", err)
	}
	if _, err := loadConfig(cfg); err != nil {
		t.Errorf("loadConfig of a secured config: %v", err)
	}

	// BUILTIN\Users may add files: a planted env file could follow.
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x2;;;BU)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, _ := sd.DACL()
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := trustConfig(cfg); err == nil || !strings.Contains(err.Error(), "S-1-5-32-545") {
		t.Errorf("Users with write access must be refused: %v", err)
	}
	if _, err := loadConfig(cfg); err == nil {
		t.Error("loadConfig must refuse it too")
	}
}

func TestSecureDirRefusesSquatted(t *testing.T) {
	squat := filepath.Join(t.TempDir(), "Shentu") // created by the runner user, as a squatter would
	if err := os.Mkdir(squat, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := secureDir(squat); err == nil {
		t.Error("a folder someone else created first must be refused, not taken over")
	}
	again := filepath.Join(t.TempDir(), "Shentu")
	if err := secureDir(again); err != nil {
		t.Fatal(err)
	}
	if err := secureDir(again); err != nil {
		t.Errorf("a folder secureDir made is trusted the next time: %v", err)
	}
}

func TestTrustConfigMissingAndLinks(t *testing.T) {
	// A missing folder is created on the spot with the trusted ACL.
	cfg := filepath.Join(t.TempDir(), "Shentu", "shentu.toml")
	if load, err := trustConfig(cfg); err != nil || !load {
		t.Fatalf("missing folder: load %v, %v", load, err)
	}
	if sids, protected := aceSIDs(t, filepath.Dir(cfg)); !protected || strings.Join(sids, ",") != "BA,SY" {
		t.Errorf("created folder: %v %v", protected, sids)
	}
	// A link inside (a skill pointing out of the folder) is refused.
	skills := filepath.Join(filepath.Dir(cfg), "skills")
	if err := os.Mkdir(skills, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(os.TempDir(), filepath.Join(skills, "elsewhere")); err != nil {
		t.Fatal(err)
	}
	if _, err := trustConfig(cfg); err == nil || !strings.Contains(err.Error(), "link") {
		t.Errorf("a link in the config folder must be refused: %v", err)
	}
}
