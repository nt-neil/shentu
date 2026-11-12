//go:build windows

package main

import (
	"context"
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
	if err := secureDir(dir, false); err != nil {
		t.Fatal(err) // CI runs elevated, as the service does
	}
	sids, protected := aceSIDs(t, dir)
	if !protected || strings.Join(sids, ",") != "BA,OW,SY" {
		t.Errorf("state dir DACL: protected %v, trustees %v; want protected, BA, SY and OWNER RIGHTS (read) only", protected, sids)
	}
	f := filepath.Join(dir, "state.json")
	if err := os.WriteFile(f, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if sids, _ := aceSIDs(t, f); strings.Join(sids, ",") != "BA,OW,SY" {
		t.Errorf("a file inside inherits only BA and SY: %v", sids)
	}
}

func TestTrustConfig(t *testing.T) {
	plain := t.TempDir() // the runner user's own ACL: not trusted
	if _, err := trustConfig(filepath.Join(plain, "shentu.toml")); err == nil {
		t.Error("a folder under a user profile must be refused")
	}

	dir := filepath.Join(t.TempDir(), "Shentu")
	if err := secureDir(dir, false); err != nil {
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
	if err := secureDir(squat, false); err == nil {
		t.Error("a folder someone else created first must be refused, not taken over")
	}
	again := filepath.Join(t.TempDir(), "Shentu")
	if err := secureDir(again, false); err != nil {
		t.Fatal(err)
	}
	if err := secureDir(again, false); err != nil {
		t.Errorf("a folder secureDir made is trusted the next time: %v", err)
	}
}

func TestTrustConfigMissingAndLinks(t *testing.T) {
	// A missing folder is created on the spot with the trusted ACL.
	cfg := filepath.Join(t.TempDir(), "Shentu", "shentu.toml")
	if load, err := trustConfig(cfg); err != nil || !load {
		t.Fatalf("missing folder: load %v, %v", load, err)
	}
	if sids, protected := aceSIDs(t, filepath.Dir(cfg)); !protected || strings.Join(sids, ",") != "BA,OW,SY" {
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

func TestSkillsNeedTrustedFolder(t *testing.T) {
	skill := "---\nname: planted-skill\ndescription: test\n---\nbody\n"
	write := func(dir string) {
		p := filepath.Join(dir, "skills", "planted", "SKILL.md")
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(skill), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	plain := t.TempDir()
	write(plain)
	if _, ok := loadSkills(filepath.Join(plain, "skills"))["planted-skill"]; ok {
		t.Error("a skill in an untrusted folder must not load")
	}
	secured := filepath.Join(t.TempDir(), "Shentu")
	if err := secureDir(secured, false); err != nil {
		t.Fatal(err)
	}
	write(secured)
	if _, ok := loadSkills(filepath.Join(secured, "skills"))["planted-skill"]; !ok {
		t.Error("a skill in the trusted folder loads")
	}
}

// N13: chat and bot refuse a state directory Shentu did not make.
func TestStateReadyRefusesForeignState(t *testing.T) {
	squat := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(squat, 0o755); err != nil {
		t.Fatal(err)
	}
	err := stateReady(squat)
	if err == nil || !strings.Contains(err.Error(), "service install") {
		t.Errorf("want a refusal pointing to service install: %v", err)
	}
}

// S3: an access entry of a type the check does not read is not trusted;
// a deny entry is fine.
func TestCheckTrustedACETypes(t *testing.T) {
	set := func(dir, sddl string) {
		t.Helper()
		sd, err := windows.SecurityDescriptorFromString(sddl)
		if err != nil {
			t.Fatal(err)
		}
		dacl, _, _ := sd.DACL()
		if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
			t.Fatal(err)
		}
	}
	dir := filepath.Join(t.TempDir(), "Shentu")
	if err := secureDir(dir, false); err != nil {
		t.Fatal(err)
	}
	set(dir, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(D;;FA;;;BG)")
	if err := checkTrusted(dir); err != nil {
		t.Errorf("a deny entry must not make it untrusted: %v", err)
	}
	// A callback (conditional) allow entry: type 9.
	set(dir, `D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(XA;;FA;;;BU;(Member_of {SID(BA)}))`)
	if err := checkTrusted(dir); err == nil || !strings.Contains(err.Error(), "type") {
		t.Errorf("a callback entry must be untrusted: %v", err)
	}
}

// S6: setup and its wizard say they do not run on Windows.
func TestSetupNotOnWindows(t *testing.T) {
	if err := setup(context.Background(), nil); err != errSetupWindows {
		t.Errorf("setup: %v", err)
	}
	if err := wizard(context.Background(), nil, true); err != errSetupWindows {
		t.Errorf("wizard: %v", err)
	}
}

// S1: an ordinary run only checks an existing state folder; install
// sets its owner and DACL again.
func TestSecureDirRepairOnlyAtInstall(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "Shentu")
	if err := secureDir(dir, false); err != nil {
		t.Fatal(err)
	}
	// An administrator adds read access for Users: still trusted (no write).
	sd, _ := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FR;;;OW)(A;OICI;FR;;;BU)")
	dacl, _, _ := sd.DACL()
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	if err := secureDir(dir, false); err != nil {
		t.Fatal(err)
	}
	if sids, _ := aceSIDs(t, dir); strings.Join(sids, ",") != "BA,BU,OW,SY" {
		t.Errorf("a check must not rewrite the DACL: %v", sids)
	}
	if err := secureDir(dir, true); err != nil {
		t.Fatal(err)
	}
	if sids, _ := aceSIDs(t, dir); strings.Join(sids, ",") != "BA,OW,SY" {
		t.Errorf("install sets the DACL again: %v", sids)
	}
}

// Round 2: a state directory outside %ProgramData%\Shentu needs folders
// above it that no ordinary user may delete, move or re-permission.
func TestStateDirParentsChecked(t *testing.T) {
	ok := filepath.Join(t.TempDir(), "state") // the runner admin's own temp: admins only
	if err := ensureStateDir(ok); err != nil {
		t.Errorf("an admin-only parent: %v", err)
	}
	loose := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(loose, 0o755); err != nil {
		t.Fatal(err)
	}
	sd, _ := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;BU)")
	dacl, _, _ := sd.DACL()
	if err := windows.SetNamedSecurityInfo(loose, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	if err := ensureStateDir(filepath.Join(loose, "state")); err == nil || !strings.Contains(err.Error(), "folder above") {
		t.Errorf("Users may delete the parent's children: %v", err)
	}
}
