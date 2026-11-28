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
		t.Errorf("loginindex.json's trustees %v (%s), want BA, OW and SY only", sids, s)
	}
}
