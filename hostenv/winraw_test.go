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

// S-294-1: log_search's text of an event is masked field by field: an
// unclosed key BEGIN in a field a client sent hides no field after it (a
// failed logon's source address). WorkstationName, the client's own, is
// dropped as the other typed names are.
func TestParseEventTextFieldByField(t *testing.T) {
	x := `<Event><System><EventID>4625</EventID><Channel>Security</Channel><TimeCreated SystemTime="2026-11-28T01:00:00Z"/></System><EventData>` +
		`<Data Name="WorkstationName">WS ` + winKeyBegin() + `</Data><Data Name="LogonProcessName">NtLmSsp ` + winKeyBegin() + `</Data>` +
		`<Data Name="Password">hunter2x9</Data><Data Name="IpAddress">203.0.113.9</Data><Data Name="IpPort">51000</Data></EventData></Event>`
	got, err := ParseEventText(x)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "IpAddress=203.0.113.9") || !strings.Contains(got, "IpPort=51000") {
		t.Errorf("fields after a key BEGIN hidden: %q", got)
	}
	if strings.Contains(got, "WorkstationName") || strings.Contains(got, "hunter2x9") || strings.Contains(got, winKeyBegin()) {
		t.Errorf("a typed name or a secret shown: %q", got)
	}
}

// S-294-2: a secret named in one field and given in the next is masked by
// the joined line's pass; that pass leaves out the rules that run across
// fields, so a key BEGIN and END in two fields hide none between them.
func TestParseEventTextAcrossFields(t *testing.T) {
	ev := func(data string) string {
		return `<Event><System><EventID>7045</EventID><Channel>System</Channel></System><EventData>` + data + `</EventData></Event>`
	}
	tok := "tok" + "en0123456789abcdef"
	got, _ := ParseEventText(ev(`<Data Name="param1">--password</Data><Data Name="param2">hunter2x9</Data>`))
	if strings.Contains(got, "hunter2x9") {
		t.Errorf("--password then its value: %q", got)
	}
	got, _ = ParseEventText(ev(`<Data Name="Header">Bearer</Data><Data Name="Value">` + tok + `</Data>`))
	if strings.Contains(got, tok) {
		t.Errorf("Bearer then its token: %q", got)
	}
	got, _ = ParseEventText(ev(`<Data Name="a">x ` + winKeyBegin() + `</Data><Data Name="IpAddress">203.0.113.9</Data><Data Name="b">-----END ` + `RSA PRIVATE KEY-----</Data>`))
	if !strings.Contains(got, "IpAddress=203.0.113.9") {
		t.Errorf("a key's BEGIN and END in two fields hid the one between: %q", got)
	}
	// The security review of 42e9b2d6: curl's -u ending a field, the
	// user:password in the next; --password ending one, a quoted value with
	// spaces in the next.
	got, _ = ParseEventText(ev(`<Data Name="a">x ` + "cu" + "rl" + ` -s -u</Data><Data Name="b">bob:hunter2x9</Data><Data Name="IpAddress">203.0.113.9</Data>`))
	if strings.Contains(got, "hunter2x9") || !strings.Contains(got, "b=bob:[REDACTED]") || !strings.Contains(got, "IpAddress=203.0.113.9") {
		t.Errorf("curl -u then user:password: %q", got)
	}
	got, _ = ParseEventText(ev(`<Data Name="a">tool --password</Data><Data Name="b">"hunter2x9 more"</Data><Data Name="IpAddress">203.0.113.9</Data>`))
	if strings.Contains(got, "hunter2x9") || strings.Contains(got, "more") || !strings.Contains(got, "IpAddress=203.0.113.9") {
		t.Errorf("--password then a quoted value: %q", got)
	}
	// A quoted user:password left open in one field (masked there to its
	// end) would take every field after it in a pass over the line.
	dl := "cu" + "rl"
	got, _ = ParseEventText(ev(`<Data Name="a">x ` + dl + ` -u 'bob:hunter2x9</Data><Data Name="IpAddress">203.0.113.9</Data>`))
	if !strings.Contains(got, "IpAddress=203.0.113.9") || strings.Contains(got, "hunter2x9") {
		t.Errorf("an open quoted user:password hid the fields after it: %q", got)
	}
	// A program at a value's start (the field's name and = before it).
	got, _ = ParseEventText(ev(`<Data Name="CommandLine">mysql -u root -phunter2x9 db</Data>`))
	if strings.Contains(got, "hunter2x9") {
		t.Errorf("a program at a value's start: %q", got)
	}
	n := 0
	for _, r := range secretRules {
		if acrossFieldsRule(r.re.String()) {
			n++
		}
	}
	if n != 9 {
		t.Errorf("%d rules left out of the joined pass, want 9 (two private key, four of a command's own password, three JSON argv)", n)
	}
	// N-296-1: a quote opened in one field and closed in a later one hides
	// none between.
	for _, c := range [][2]string{
		{`--password "x`, `y"`},
		{`--password 'x`, `y'`},
		{`"mysql" "-p`, `"`},
		{`x mysql -p"x`, `y"`},
		{`x ` + dl + ` -u bob:"x`, `y"`},
	} {
		got, _ := ParseEventText(ev(`<Data Name="a">` + c[0] + `</Data><Data Name="IpAddress">203.0.113.9</Data><Data Name="b">` + c[1] + `</Data>`))
		if !strings.Contains(got, "IpAddress=203.0.113.9") {
			t.Errorf("%q ... %q hid the field between: %q", c[0], c[1], got)
		}
	}
}
