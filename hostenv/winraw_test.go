package hostenv

import (
	"strings"
	"testing"
)

func winKeyBegin() string { return "-----BEGIN " + "RSA PRIVATE KEY-----" } // built at run time

// Inventory item 5: Windows checks read a service's command line, a
// registry string and a task's XML as written; what they output is masked.

// A key BEGIN in a service's path masked the rest of it away: an unquoted
// path with spaces after it read as one without.
func TestServiceBinaryPathAsWritten(t *testing.T) {
	raw := `C:\Svc` + winKeyBegin() + `\Evil Dir\evil.exe`
	svcs := []WinService{{Name: "evil", BinaryPath: MaskSecrets(raw), rawBinary: raw, StartType: "auto"}}
	o := winPersistence(newFakeWin(), svcs, nil)
	found := false
	for _, it := range o.Value {
		if it.Location == "service:evil" {
			found = true
			if !strings.Contains(it.Detail, "unquoted path with spaces") {
				t.Errorf("not read as written: %+v", it)
			}
			if strings.Contains(it.Command, "Evil Dir") {
				t.Errorf("output not masked: %q", it.Command)
			}
		}
	}
	if !found {
		t.Fatalf("no service item: %+v", o.Value)
	}
	if s := winServices(svcs, nil); len(s.Value) != 1 || strings.Contains(s.Value[0].Exe, "Evil Dir") {
		t.Errorf("service exe not masked: %+v", s.Value)
	}
}

// A key BEGIN in a profile's path masked it: the startup folder under that
// home was not read. Its items are output masked.
func TestRegistryHomeAsWritten(t *testing.T) {
	home := `C:\Users\x` + winKeyBegin()
	sid := "S-1-5-21-1-2-3-1001"
	w := newFakeWin()
	w.subkeys[KeyProfileList] = []string{sid}
	w.reg[KeyProfileList+`\`+sid] = map[string]RegValue{"ProfileImagePath": {Type: "EXPAND_SZ", String: MaskSecrets(home), Raw: home}}
	w.dirList[home+`\`+winStartupPerUser] = []string{"evil.lnk"}
	o := winPersistence(w, nil, nil)
	found := false
	for _, it := range o.Value {
		if it.Kind == "startup_folder" { // the masked location may lose the name after the marker
			found = true
			if strings.Contains(it.Location, winKeyBegin()) {
				t.Errorf("output not masked: %q", it.Location)
			}
		}
	}
	if !found {
		t.Errorf("the startup folder under the home not read: %+v", o.Value)
	}
}

// A key BEGIN in a task's description masked the rest of its XML, and the
// task read as unparsable. Read as written it parses; what leaves is masked.
func TestTaskXMLAsWritten(t *testing.T) {
	x := `<?xml version="1.0" encoding="UTF-16"?><Task><RegistrationInfo><Description>note ` + winKeyBegin() +
		`</Description></RegistrationInfo><Principals><Principal><UserId>svc password=hunter2x9</UserId></Principal></Principals>` +
		`<Actions><Exec><Command>C:\Users\Public\x.exe</Command><Arguments>--token=abcdef123</Arguments></Exec></Actions></Task>`
	if _, err := ParseTaskXML(`\evil`, []byte(MaskSecrets(x))); err == nil {
		t.Fatal("masked first, the XML still parses: the test does not show the case")
	}
	tk, err := ParseTaskXML(`\evil`, []byte(x))
	if err != nil || len(tk.Actions) != 1 || !strings.HasPrefix(tk.Actions[0], `C:\Users\Public\x.exe`) {
		t.Fatalf("task: %+v %v", tk, err)
	}
	if strings.Contains(tk.Actions[0], "abcdef123") || strings.Contains(tk.RunAs, "hunter2x9") {
		t.Errorf("output not masked: %+v", tk)
	}
}
