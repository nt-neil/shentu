package hostenv

import (
	"context"
	"encoding/hex"
	"io/fs"
	"reflect"
	"strings"
	"testing"
	"time"
)

// A launchd job, written by plutil -convert binary1 from the XML below.
const testBplistHex = "62706c6973743030d6010203040506070a0d0e0f105f101050726f6772616d417267756d656e7473594b656570416c697665554c6162656c5952756e41744c6f6164544e696365544e616d65a208095f10142f7573722f6c6f63616c2f62696e2f6167656e74562d2d73796e63d10b0c5e5375636365737366756c45786974085f1011636f6d2e6578616d706c652e6167656e740913fffffffffffffffb6700630061006600e9002065e5672c081528323842474c4f666d707f8094959e00000000000001010000000000000011000000000000000000000000000000ad"

const testPlistXML = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key><string>com.example.agent</string>
	<key>ProgramArguments</key><array><string>/usr/local/bin/agent</string><string>--sync</string></array>
	<key>RunAtLoad</key><true/>
	<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
	<key>Nice</key><integer>-5</integer>
	<key>Name</key><string>caf&#233; 日本</string>
</dict>
</plist>`

func TestParsePlist(t *testing.T) {
	want := map[string]any{
		"Label":            "com.example.agent",
		"ProgramArguments": []any{"/usr/local/bin/agent", "--sync"},
		"RunAtLoad":        true,
		"KeepAlive":        map[string]any{"SuccessfulExit": false},
		"Nice":             int64(-5),
		"Name":             "café 日本",
	}
	bin, _ := hex.DecodeString(testBplistHex)
	for name, b := range map[string][]byte{"xml": []byte(testPlistXML), "binary": bin} {
		got, err := ParsePlist(b)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("%s: %#v, %v", name, got, err)
		}
	}
	// Damaged input fails, never panics.
	for i := 8; i < len(bin); i += 3 {
		ParsePlist(bin[:i])
		bad := append([]byte(nil), bin...)
		bad[i] ^= 0xff
		ParsePlist(bad)
	}
	// Each array holds the previous one twice: 2^60 elements if expanded.
	if v, err := ParsePlist(nestedBplist(60)); err != nil || v == nil {
		t.Errorf("shared objects: %v", err)
	}
	if _, err := ParsePlist([]byte("<plist><dict><key>a</key>")); err == nil {
		t.Error("truncated XML parsed")
	}
}

func TestDarwinAllowlist(t *testing.T) {
	for _, argv := range (DarwinCollector{}).Allowlist() {
		if err := checkArgv(argv); err != nil {
			t.Error(err)
		}
		// They print the serial number and hardware UUID.
		if b := baseName(argv[0]); b == "system_profiler" || b == "ioreg" || b == "sudo" {
			t.Errorf("%v must not be allowlisted", argv)
		}
	}
}

func TestMaskMacIdentity(t *testing.T) {
	m := &Masker{Users: []string{"alice"}}
	m.init()
	in := "home /Users/alice/Library; host Alices-MacBook-Pro.local and alices-macbook-pro.local; " +
		"hw 1A2B3C4D-0000-4E5F-8A9B-0C1D2E3F4A5B / 1a2b3c4d-0000-4e5f-8a9b-0c1d2e3f4a5b; " +
		"id alice.chen@icloud.com bob@shop.app; Ciphers aes256-gcm@openssh.com com.example.db@2.plist; url http://alices-mbp.local/x; files /etc/rc.local /usr/local/bin x.local/y"
	got := m.text(in, true, true)
	want := "home /Users/user1/redacted1; host localhost1.local and localhost1.local; " +
		"hw 00000000-0000-0000-0000-000000000001 / 00000000-0000-0000-0000-000000000001; " +
		"id user1@example.com user2@example.com; Ciphers aes256-gcm@openssh.com com.example.db@2.plist; url http://localhost2.local/x; files /etc/rc.local /usr/local/bin x.local/y"
	if got != want {
		t.Errorf("masked:\n%s\nwant:\n%s", got, want)
	}
	// Kept places stay; anything else below a home is masked to the end of
	// the field, the paths after it too.
	home := m.text("/Users/alice/.ssh/authorized_keys /Users/alice/Library/LaunchAgents/a.plist /Users/alice/Library/Caches --x", true, true)
	if want := "/Users/user1/.ssh/authorized_keys /Users/user1/Library/LaunchAgents/a.plist /Users/user1/redacted2"; home != want {
		t.Errorf("home paths: %s", home)
	}
	if again := m.text(got, true, true); again != got {
		t.Errorf("masking twice changed it: %s", again)
	}
}

func TestMaskLsofFields(t *testing.T) {
	m := &Masker{}
	e := &entry{Op: "cmd", Argv: lsofListenArgv, data: []byte("p1\nn172.16.5.9:51655->203.0.113.9:443\nn*:5353\n")}
	m.apply([]*entry{e})
	if got := string(e.data); got != "p1\nn10.0.0.1:51655->198.51.100.1:443\nn*:5353\n" {
		t.Errorf("lsof masked: %q", got)
	}
}

func TestDropArgs(t *testing.T) {
	comm := &entry{Op: "cmd", Argv: macPsArgv, data: []byte("  10     1   501 alice    01:00 /Applications/Google Chrome.app/Contents/MacOS/Google Chrome\n")}
	args := &entry{Op: "cmd", Argv: macPsArgsArgv, data: []byte("  10 /Applications/Google Chrome.app/Contents/MacOS/Google Chrome --profile=/Users/alice/x --token abc\n")}
	proc := &entry{Op: "file", Path: "/proc/7/cmdline", data: []byte("/usr/bin/python3\x00/home/alice/secret.py\x00")}
	(&Masker{DropArgs: true}).apply([]*entry{comm, args, proc})
	if got := string(args.data); got != "   10 /Applications/Google Chrome.app/Contents/MacOS/Google Chrome\n" {
		t.Errorf("ps args: %q", got)
	}
	if got := string(proc.data); got != "/usr/bin/python3" {
		t.Errorf("cmdline: %q", got)
	}
}

func TestParseEtime(t *testing.T) {
	for s, want := range map[string]time.Duration{
		"00:05": 5 * time.Second, "01:02:03": time.Hour + 2*time.Minute + 3*time.Second,
		"3-00:00:01": 72*time.Hour + time.Second,
	} {
		if got, ok := parseEtime(s); !ok || got != want {
			t.Errorf("parseEtime(%q) = %v %v", s, got, ok)
		}
	}
	for _, s := range []string{"", "5", "a:b", "x-01:00"} {
		if _, ok := parseEtime(s); ok {
			t.Errorf("parseEtime(%q) accepted", s)
		}
	}
}

// fakeMac answers commands from a map; files from memHost-like contents.
type fakeMac struct {
	cmds  map[string]string
	files map[string]string
}

func (f fakeMac) Info() SourceInfo { return SourceInfo{GOOS: "darwin", GOARCH: "arm64"} }
func (f fakeMac) ReadFile(p string) ([]byte, error) {
	if s, ok := f.files[p]; ok {
		return []byte(s), nil
	}
	return nil, &notExist{p}
}
func (f fakeMac) ReadDir(string) ([]string, error) { return nil, &notExist{} }
func (f fakeMac) Readlink(string) (string, error)  { return "", &notExist{} }
func (f fakeMac) Run(_ context.Context, argv []string) (CmdResult, error) {
	if s, ok := f.cmds[strings.Join(argv, " ")]; ok {
		return CmdResult{Stdout: []byte(s)}, nil
	}
	return CmdResult{}, &notExist{argv[0]}
}

type notExist struct{ p string }

func (e *notExist) Error() string { return e.p + ": no such file" }
func (e *notExist) Unwrap() error { return fs.ErrNotExist }

func TestDarwinListeners(t *testing.T) {
	head := "Active Internet connections (including servers)\nProto Recv-Q Send-Q  Local Address          Foreign Address        (state)          rxbytes      txbytes  rhiwat  shiwat          process:pid    state  options           gencnt    flags   flags1 usecnt rtncnt fltrs\n"
	tcp := head +
		"tcp4       0      0  *.22                   *.*                    LISTEN                 0            0  131072  131072          launchd:1      00100 00000006 0000000001 00000001 00000800      1      0 000000\n" +
		"tcp6       0      0  ::1.7777               *.*                    LISTEN                 0            0  131072  131072        exampledb:812    00100 00000006 0000000002 00000001 00000800      1      0 000000\n" +
		"tcp4       0      0  172.16.5.9.53959     203.0.113.80.443    ESTABLISHED         3476         6659  131072  131412 Browser Helper (:870    00102 00000008 0000000003 00000080 04000900      2      0 000000\n"
	udp := head +
		"udp4       0      0  *.5353                 *.*                                           0            0  786896    9216 ExampleBrowser H:873    00180 00000020 0000000004 00008000 00000800      1      0 000000\n" +
		"udp4       0      0  172.16.5.9.52663     203.0.113.81.443                       14952         5623 1048576   29040 ExampleBrowser H:873    00102 00000000 0000000005 00000000 04200900      1      0 000002\n"
	src := fakeMac{cmds: map[string]string{
		strings.Join(netstatTCPArgv, " "): tcp,
		strings.Join(netstatUDPArgv, " "): udp,
	}}
	got := DarwinCollector{}.Listeners(context.Background(), src)
	want := []Listener{
		{Proto: "tcp", Addr: "0.0.0.0", Port: 22, PID: 1, Process: "launchd"},
		{Proto: "udp", Addr: "0.0.0.0", Port: 5353, PID: 873, Process: "ExampleBrowser H"},
		{Proto: "tcp6", Addr: "::1", Port: 7777, PID: 812, Process: "exampledb"},
	}
	if got.Status != StatusOK || !reflect.DeepEqual(got.Value, want) {
		t.Errorf("netstat: %+v", got)
	}

	// netstat hidden from programs: header only. lsof gives this user's.
	src.cmds[strings.Join(netstatTCPArgv, " ")] = head
	src.cmds[strings.Join(netstatUDPArgv, " ")] = head
	src.cmds[strings.Join(lsofListenArgv, " ")] = "p648\ncrapportd\nf11\ntIPv4\nPTCP\nn*:49154\nf23\ntIPv6\nPUDP\nn*:3722\n" +
		"p658\ncidentityservicesd\nf7\ntIPv4\nPUDP\nn*:*\nf8\ntIPv4\nPUDP\nn10.0.0.2:5000->10.0.0.9:53\n"
	got = DarwinCollector{}.Listeners(context.Background(), src)
	want = []Listener{
		{Proto: "udp6", Addr: "::", Port: 3722, PID: 648, Process: "rapportd"},
		{Proto: "tcp", Addr: "0.0.0.0", Port: 49154, PID: 648, Process: "rapportd"},
	}
	if got.Status != StatusPartial || !reflect.DeepEqual(got.Value, want) {
		t.Errorf("lsof fallback: %+v", got)
	}

	// Neither: unknown, never "nothing listens".
	delete(src.cmds, strings.Join(lsofListenArgv, " "))
	if got = (DarwinCollector{}).Listeners(context.Background(), src); got.Known() {
		t.Errorf("hidden netstat without lsof: %+v", got)
	}
}

// nestedBplist builds a binary plist whose object i is an array of two
// references to object i-1 (object 0 is an empty string).
func nestedBplist(n int) []byte {
	b := []byte("bplist00")
	var offs []int
	offs = append(offs, len(b))
	b = append(b, 0x50) // ""
	for i := 1; i <= n; i++ {
		offs = append(offs, len(b))
		b = append(b, 0xa2, byte(i-1), byte(i-1))
	}
	table := len(b)
	for _, o := range offs {
		b = append(b, byte(o>>8), byte(o))
	}
	t := make([]byte, 32)
	t[6], t[7] = 2, 1
	put := func(at int, v int) {
		for k := 0; k < 8; k++ {
			t[at+7-k] = byte(v >> (8 * k))
		}
	}
	put(8, len(offs))
	put(16, n)
	put(24, table)
	return append(b, t...)
}

func TestDarwinProtections(t *testing.T) {
	src := fakeMac{cmds: map[string]string{
		strings.Join(csrutilArgv, " "):  "System Integrity Protection status: enabled (Custom Configuration).\n\nConfiguration:\n\tKernel Integrity Protections: disabled\n",
		strings.Join(spctlArgv, " "):    "assessments enabled\n",
		strings.Join(fdesetupArgv, " "): "FileVault is Off.\n",
	}}
	got := DarwinCollector{}.Protections(context.Background(), src)
	if got.Status != StatusOK || got.Value.Integrity != "off" || got.Value.AppVerification != "on" ||
		got.Value.DiskEncryption != "off" || !strings.Contains(got.Value.Extra["sip"], "Kernel Integrity Protections: disabled") {
		t.Errorf("custom SIP: %+v", got)
	}
}
