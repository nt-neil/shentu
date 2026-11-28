//go:build windows

package tools

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// stateSDDLForTest is the root package's stateSDDL (paths_windows.go): what
// secureDir puts on the state directory.
const stateSDDLForTest = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FR;;;OW)"

// S-278-3: in a state directory as secureDir makes it, loginindex.json
// written by save (CreateTemp, then Rename) keeps only the directory's
// inherited trustees: BA, OWNER RIGHTS, SYSTEM.
func TestLoginIndexSaveACL(t *testing.T) {
	// S-301-1: the same SDDL as the root package's stateSDDL.
	src, err := os.ReadFile(filepath.Join("..", "paths_windows.go"))
	if err != nil {
		t.Fatal(err)
	}
	if m := regexp.MustCompile(`const stateSDDL = "([^"]+)"`).FindSubmatch(src); m == nil || string(m[1]) != stateSDDLForTest {
		t.Fatalf("stateSDDLForTest is not paths_windows.go's stateSDDL: %q", m)
	}
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString(stateSDDLForTest)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err) // CI runs elevated, as the service does
	}
	x := &loginIndex{Version: loginIndexVersion, From: time.Now(), Addrs: map[string]*loginIndexAddr{}}
	// Twice: the second Rename replaces the file the first one made.
	for i := 1; i <= 2; i++ {
		if err := x.save(dir); err != nil {
			t.Fatal(err)
		}
		got, err := windows.GetNamedSecurityInfo(filepath.Join(dir, LoginIndexFile), windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		s := got.String()
		var sids []string
		for _, m := range regexp.MustCompile(`\(A;[^;]*;[^;]*;;;([^)]+)\)`).FindAllStringSubmatch(s[strings.Index(s, "D:"):], -1) {
			sids = append(sids, m[1])
		}
		sort.Strings(sids)
		if strings.Join(sids, ",") != "BA,OW,SY" {
			t.Errorf("save %d: loginindex.json's trustees %v (%s), want BA, OW and SY only", i, sids, s)
		}
	}
}
