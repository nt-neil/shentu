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
