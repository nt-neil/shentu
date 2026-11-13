package hostenv

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// A path below a Windows profile is masked to the end of its field, as
// /Users and /home are (f116214); the profile name becomes a placeholder;
// the Startup folder and the temp folder's name stay for the collector.
func TestMaskWinHome(t *testing.T) {
	leak := []string{"alice", "Acme", "Inc (2026)", "q3:plan", "secret project", "x.exe", "Bob's", "a;b", "Clients"}
	for _, in := range []string{
		`C:\Users\alice\Clients\Acme, Inc (2026)\q3:plan`,
		`run C:\Users\alice\Documents\secret project\x.exe -flag`,
		`C:\Users\alice\Bob's files\plan.txt`,
		`C:\Users\alice\a;b\plan.txt`,
		`C:/Users/alice/Clients/plan.txt`,
		`%SystemDrive%\Users\alice\Clients\plan.txt`,
	} {
		out := maskWinHome(in)
		for _, l := range leak {
			if strings.Contains(out, l) {
				t.Errorf("%s -> %s leaks %q", in, out, l)
			}
		}
	}
	// Same path, same placeholder; the name is a placeholder too.
	a, b := maskWinHome(`C:\Users\bob\Docs\plan.txt`), maskWinHome(`C:\Users\bob\Docs\plan.txt`)
	if a != b || strings.Contains(a, "bob") || strings.Count(a, "redacted-") != 2 {
		t.Errorf("not consistent or name kept: %s / %s", a, b)
	}
	// Shared profiles name no one.
	if out := maskWinHome(`C:\Users\Public\Documents\x`); !strings.HasPrefix(out, `C:\Users\Public\redacted-`) || !WinInTempDir(out) {
		t.Errorf("Public: %s", out)
	}
	// Kept: Startup and one entry; the temp folder by name.
	st := maskWinHome(`C:\Users\bob\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\My App.lnk`)
	if !strings.HasSuffix(st, `\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\My App.lnk`) || strings.Contains(st, "bob") {
		t.Errorf("Startup: %s", st)
	}
	if out := maskWinHome(`C:\Users\bob\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\a.lnk -arg C:\Users\eve\secret`); strings.Contains(out, "secret") || strings.Contains(out, "a.lnk") {
		t.Errorf("Startup with a tail: %s", out)
	}
	if out := maskWinHome(`C:\Users\bob\AppData\Local\Temp\dropper.exe`); !strings.Contains(out, `\AppData\Local\Temp\redacted-`) || !WinInTempDir(out) || strings.Contains(out, "dropper") {
		t.Errorf("Temp: %s", out)
	}
	// Masking twice changes nothing: the placeholders are kept.
	if once := maskWinHome(`C:\Users\bob\Docs\x`); maskWinHome(once) != once {
		t.Errorf("not idempotent: %s -> %s", once, maskWinHome(once))
	}
}

// Final review (N-W): JSON is masked string by string after decoding, so
// a quoted command line keeps its escapes (the blob still parses) and a
// value's next line is not swallowed; ProfileList roots elsewhere count.
func TestMaskWinProfilePathsJSON(t *testing.T) {
	procs := []WinProcess{
		{PID: 1, Name: "OneDrive.exe", Exe: `C:\Users\alice\AppData\Local\Microsoft\OneDrive\OneDrive.exe`,
			Cmdline: `"C:\Users\alice\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background`},
		{PID: 2, Name: "ms-teams.exe", Exe: `D:\Profiles\bob\AppData\Local\Teams\ms-teams.exe`,
			Cmdline: `"D:\Profiles\bob\AppData\Local\Teams\ms-teams.exe" --process-start-args "--profile=C:\Users\alice\x"`},
	}
	pb, _ := json.Marshal(procs)
	task, _ := json.Marshal([]WinTask{{Path: `\t`, Actions: []string{"C:\\Users\\alice\\run.cmd\nC:\\Windows\\System32\\cmd.exe"}}})
	prof, _ := json.Marshal(map[string]RegValue{"ProfileImagePath": {Type: "EXPAND_SZ", String: `D:\Profiles\bob`}})
	entries := []*entry{
		{Op: "winproc", data: pb},
		{Op: "wintask", data: task},
		{Op: "reg", Path: KeyProfileList + `\S-1-5-21-1-2-3-1001`, data: prof},
		{Op: "dir", Path: `D:\Profiles\bob\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`, Names: []string{"a.lnk"}},
	}
	maskWinProfilePaths(entries)

	var got []WinProcess
	if err := json.Unmarshal(entries[0].data, &got); err != nil {
		t.Fatalf("masked blob does not parse: %v\n%s", err, entries[0].data)
	}
	for _, p := range got {
		for _, s := range []string{p.Exe, p.Cmdline} {
			if strings.Contains(s, "alice") || strings.Contains(s, "bob") || strings.Contains(s, "OneDrive.exe") || strings.Contains(s, "Teams") {
				t.Errorf("leak: %s", s)
			}
		}
		if !strings.HasPrefix(p.Cmdline, `"`) || !strings.Contains(p.Cmdline, `" `) {
			t.Errorf("the quotes of a command line must stay: %s", p.Cmdline)
		}
	}
	var tasks []WinTask
	if err := json.Unmarshal(entries[1].data, &tasks); err != nil {
		t.Fatal(err)
	}
	if lines := strings.Split(tasks[0].Actions[0], "\n"); len(lines) != 2 || lines[1] != `C:\Windows\System32\cmd.exe` || strings.Contains(lines[0], "run.cmd") {
		t.Errorf("multi-line value: %q", tasks[0].Actions[0])
	}
	var v map[string]RegValue
	json.Unmarshal(entries[2].data, &v)
	home := v["ProfileImagePath"].String
	if !strings.HasPrefix(home, `D:\Profiles\redacted-`) {
		t.Errorf("ProfileList root: %s", home)
	}
	// A replay builds the Startup path from the masked profile: it must be the key recorded.
	if want := home + `\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`; entries[3].Path != want {
		t.Errorf("Startup key %s, replay asks %s", entries[3].Path, want)
	}
}

// File contents are masked as text: an escaped path (a JSON or .reg file,
// C:\\Users\\bob\\...) is masked too, and the escape of the quote that
// ends it stays (security review of 9c256b2).
func TestMaskWinProfilePathsText(t *testing.T) {
	data := `{"path": "C:\\Users\\bob\\Clients\\plan.txt", "q": "\"C:\\Users\\bob\\x.exe\" -a"}` + "\n" + `C:\Users\bob\notes.txt`
	e := &entry{Op: "file", Path: `C:\conf\app.json`, data: []byte(data)}
	maskWinProfilePaths([]*entry{e})
	out := string(e.data)
	for _, l := range []string{"bob", "Clients", "plan.txt", "x.exe", "notes.txt"} {
		if strings.Contains(out, l) {
			t.Errorf("leaks %q: %s", l, out)
		}
	}
	var v map[string]string
	if err := json.Unmarshal([]byte(strings.SplitN(out, "\n", 2)[0]), &v); err != nil {
		t.Errorf("the JSON in the file must still parse: %v\n%s", err, out)
	}
	if !strings.HasPrefix(v["q"], `"`) || !strings.Contains(v["q"], `" -a`) {
		t.Errorf("quoted command: %q", v["q"])
	}
}

// Final review: when the masked JSON cannot be encoded again, nothing of
// the recorded data is kept (fail closed).
func TestMaskWinProfilePathsFailClosed(t *testing.T) {
	old := winMarshal
	t.Cleanup(func() { winMarshal = old })
	winMarshal = func(any) ([]byte, error) { return nil, errors.New("boom") }
	e := &entry{Op: "winproc", data: []byte(`[{"exe":"C:\\Users\\alice\\x.exe"}]`)}
	maskWinProfilePaths([]*entry{e})
	if e.data != nil {
		t.Errorf("data kept after a failed encode: %s", e.data)
	}
}
