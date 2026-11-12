package hostenv

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"unicode/utf16"
)

// fakeWin is an in-memory WinSource.
type fakeWin struct {
	*fakeHost
	reg     map[string]map[string]RegValue
	subkeys map[string][]string
	denied  map[string]bool // registry keys, "svc", "proc", "sock", "users", group SIDs, "tasks", channels
	svcs    []WinService
	procs   []WinProcess
	sockets []WinSocket
	users   []WinUser
	groups  map[string][]string
	tasks   []WinTask
	events  map[string][]WinEvent // by channel
	dirList map[string][]string   // Windows directory listings
}

func newFakeWin() *fakeWin {
	h := newFake(true)
	h.info.GOOS, h.info.GOARCH = "windows", "amd64"
	return &fakeWin{fakeHost: h, reg: map[string]map[string]RegValue{}, subkeys: map[string][]string{},
		denied: map[string]bool{}, groups: map[string][]string{}, events: map[string][]WinEvent{}, dirList: map[string][]string{}}
}

func dword(n uint64) RegValue { return RegValue{Type: "DWORD", Int: n} }
func sz(s string) RegValue    { return RegValue{Type: "SZ", String: s} }

func denied(op, what string) error {
	return &fs.PathError{Op: op, Path: what, Err: fs.ErrPermission}
}

func (w *fakeWin) RegValues(key string) (map[string]RegValue, error) {
	if w.denied[key] {
		return nil, denied("RegOpenKeyEx", key)
	}
	if v, ok := w.reg[key]; ok {
		return v, nil
	}
	if _, ok := w.subkeys[key]; ok {
		return map[string]RegValue{}, nil
	}
	return nil, &fs.PathError{Op: "RegOpenKeyEx", Path: key, Err: fs.ErrNotExist}
}

func (w *fakeWin) RegSubkeys(key string) ([]string, error) {
	if w.denied[key] {
		return nil, denied("RegOpenKeyEx", key)
	}
	if s, ok := w.subkeys[key]; ok {
		return s, nil
	}
	if _, ok := w.reg[key]; ok {
		return nil, nil
	}
	return nil, &fs.PathError{Op: "RegOpenKeyEx", Path: key, Err: fs.ErrNotExist}
}

func pick[T any](w *fakeWin, k string, v T) (T, error) {
	if w.denied[k] {
		var zero T
		return zero, denied(k, k)
	}
	return v, nil
}

func (w *fakeWin) Services() ([]WinService, error)  { return pick(w, "svc", w.svcs) }
func (w *fakeWin) Processes() ([]WinProcess, error) { return pick(w, "proc", w.procs) }
func (w *fakeWin) Sockets() ([]WinSocket, error)    { return pick(w, "sock", w.sockets) }
func (w *fakeWin) Users() ([]WinUser, error)        { return pick(w, "users", w.users) }
func (w *fakeWin) Tasks() ([]WinTask, error)        { return pick(w, "tasks", w.tasks) }
func (w *fakeWin) GroupMembers(sid string) ([]string, error) {
	return pick(w, sid, w.groups[sid])
}
func (w *fakeWin) Events(ch, _ string, max int) ([]WinEvent, error) {
	ev, err := pick(w, ch, w.events[ch])
	if len(ev) > max {
		ev = ev[:max]
	}
	return ev, err
}

const (
	sidBase = "S-1-5-21-111-222-333"
	userHKU = `HKU\` + sidBase + `-1001`
)

// A deliberately weak Windows Server 2022: RDP without NLA, SMB1, WinRM
// over HTTP with Basic, the public firewall profile off, Defender's
// real-time protection off with a broad exclusion, a webshell, a miner in
// Temp, a Run key, a task and a service with an unquoted path, a cleared
// log and a brute-force source.
func weakServer() *fakeWin {
	w := newFakeWin()
	w.reg[KeyCurrentVersion] = map[string]RegValue{"ProductName": sz("Windows Server 2022 Datacenter"), "DisplayVersion": sz("21H2"),
		"CurrentBuild": sz("20348"), "UBR": dword(2762), "InstallationType": sz("Server")}
	w.reg[KeyTerminalServer] = map[string]RegValue{"fDenyTSConnections": dword(0)}
	w.reg[KeyRDPTcp] = map[string]RegValue{"UserAuthentication": dword(0), "PortNumber": dword(3390), "SecurityLayer": dword(0)}
	w.reg[KeyLanmanServer] = map[string]RegValue{"SMB1": dword(1)}
	w.reg[KeyWinRMService] = map[string]RegValue{"AllowUnencryptedTraffic": dword(0)}
	w.reg[KeyWinRMPolicy] = map[string]RegValue{"AllowUnencryptedTraffic": dword(1), "AllowBasic": dword(1)}
	for _, p := range []string{"DomainProfile", "StandardProfile"} {
		w.reg[KeyFirewallPolicy+`\`+p] = map[string]RegValue{"EnableFirewall": dword(1)}
	}
	w.reg[KeyFirewallPolicy+`\PublicProfile`] = map[string]RegValue{"EnableFirewall": dword(0)}

	// Defender: installed, real-time monitoring off, signatures 12 days old.
	sig := make([]byte, 8)
	binary.LittleEndian.PutUint64(sig, toFiletime(w.info.RecordedAt.AddDate(0, 0, -12).Unix()))
	w.reg[KeyDefender] = map[string]RegValue{"ProductStatus": dword(0)}
	w.reg[KeyDefender+`\Real-Time Protection`] = map[string]RegValue{"DisableRealtimeMonitoring": dword(1)}
	w.reg[KeyDefender+`\Signature Updates`] = map[string]RegValue{"SignaturesLastUpdated": {Type: "BINARY", Bytes: sig}}
	w.reg[KeyDefender+`\Exclusions\Paths`] = map[string]RegValue{`C:\`: dword(0), `D:\data`: dword(0)}
	w.reg[KeyDefender+`\Exclusions\Extensions`] = map[string]RegValue{"ps1": dword(0)}

	// Software and patches.
	w.subkeys[KeyUninstall] = []string{"{A}", "{B}", "KB-update"}
	w.reg[KeyUninstall+`\{A}`] = map[string]RegValue{"DisplayName": sz("7-Zip 19.00 (x64)"), "DisplayVersion": sz("19.00")}
	w.reg[KeyUninstall+`\{B}`] = map[string]RegValue{"DisplayName": sz("Contoso Agent"), "DisplayVersion": sz("1.2.3.4")}
	w.reg[KeyUninstall+`\KB-update`] = map[string]RegValue{"DisplayName": sz("Update for X"), "ParentKeyName": sz("X")}
	w.subkeys[KeyCBSPackages] = []string{
		"Package_for_KB5034439~31bf3856ad364e35~amd64~~20348.2227.1.3",
		"Package_1_for_KB5034439~31bf3856ad364e35~amd64~~20348.2227.1.3",
		"Package_for_KB5099999~31bf3856ad364e35~amd64~~20348.9.1.0",
		"Microsoft-Windows-Foo-Package~31bf3856ad364e35~amd64~~10.0.20348.1",
	}
	w.reg[KeyCBSPackages+`\Package_for_KB5034439~31bf3856ad364e35~amd64~~20348.2227.1.3`] = map[string]RegValue{
		"CurrentState": dword(0x70), "InstallTimeHigh": dword(31076243), "InstallTimeLow": dword(0)}
	w.reg[KeyCBSPackages+`\Package_1_for_KB5034439~31bf3856ad364e35~amd64~~20348.2227.1.3`] = map[string]RegValue{"CurrentState": dword(0x70)}
	w.reg[KeyCBSPackages+`\Package_for_KB5099999~31bf3856ad364e35~amd64~~20348.9.1.0`] = map[string]RegValue{"CurrentState": dword(0x20)} // pending

	// Accounts.
	w.users = []WinUser{{Name: "Administrator", SID: sidBase + "-500"}, {Name: "Guest", SID: sidBase + "-501", Disabled: true},
		{Name: "backdoor", SID: sidBase + "-1001", Home: `C:\Users\backdoor`}}
	w.groups[SIDAdministrators] = []string{sidBase + "-500", sidBase + "-1001", "S-1-5-21-9-9-9-512"}

	// Processes, sockets, services.
	w.procs = []WinProcess{
		{PID: 0, Name: "[System Process]"}, {PID: 4, Name: "System"},
		{PID: 900, PPID: 600, Name: "w3wp.exe", Exe: `C:\Windows\System32\inetsrv\w3wp.exe`, User: `IIS APPPOOL\DefaultAppPool`},
		{PID: 901, PPID: 900, Name: "cmd.exe", Exe: `C:\Windows\System32\cmd.exe`, User: `IIS APPPOOL\DefaultAppPool`, Cmdline: `cmd /c whoami`},
		{PID: 1200, PPID: 1, Name: "xmrig.exe", Exe: `C:\Users\backdoor\AppData\Local\Temp\xmrig.exe`, User: `HOST\backdoor`, SID: sidBase + "-1001",
			Cmdline: "xmrig.exe -o stratum+tcp://pool:3333 --password=hunter22"},
		{PID: 1300, PPID: 1, Name: "mysqld.exe", Exe: `C:\mysql\bin\mysqld.exe`},
	}
	w.sockets = []WinSocket{
		{Proto: "tcp", Addr: "0.0.0.0", Port: 5985, State: "LISTEN", OwnerPID: 4},
		{Proto: "tcp", Addr: "0.0.0.0", Port: 3306, State: "LISTEN", OwnerPID: 1300},
		{Proto: "udp", Addr: "0.0.0.0", Port: 500, OwnerPID: 1100},
	}
	w.svcs = []WinService{
		{Name: "MpsSvc", State: "running", StartType: "auto", BinaryPath: `C:\Windows\system32\svchost.exe -k LocalServiceNoNetworkFirewall -p`, Account: `NT Authority\LocalService`},
		{Name: "WinDefend", State: "running", StartType: "auto", BinaryPath: `"C:\ProgramData\Microsoft\Windows Defender\platform\4.18\MsMpEng.exe"`, Account: "LocalSystem"},
		{Name: "Updater", State: "running", StartType: "auto", BinaryPath: `C:\Program Files\Contoso Agent\agent.exe -run`, Account: "LocalSystem"},
		{Name: "Spooler", State: "stopped", StartType: "manual", BinaryPath: `C:\Windows\System32\spoolsv.exe`},
	}

	// Persistence.
	w.subkeys[`HKU`] = []string{".DEFAULT", sidBase + "-1001", sidBase + "-1001_Classes", "S-1-5-18"}
	w.reg[`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`] = map[string]RegValue{"SecurityHealth": {Type: "EXPAND_SZ", String: `%windir%\system32\SecurityHealthSystray.exe`}}
	w.reg[userHKU+`\Software\Microsoft\Windows\CurrentVersion\Run`] = map[string]RegValue{"upd": sz(`C:\Users\Public\upd.exe`)}
	w.reg[KeyWinlogon] = map[string]RegValue{"Shell": sz("explorer.exe"), "Userinit": sz(`C:\Windows\system32\userinit.exe,`)}
	w.subkeys[KeyIFEO] = []string{"sethc.exe", "notepad.exe"}
	w.reg[KeyIFEO+`\sethc.exe`] = map[string]RegValue{"Debugger": sz(`C:\Windows\System32\cmd.exe`)}
	w.tasks = []WinTask{{Path: `\Updater`, Enabled: true, RunAs: "S-1-5-18", Triggers: []string{"BootTrigger"}, Actions: []string{`C:\ProgramData\u.exe -q`}}}
	w.subkeys[KeyProfileList] = []string{"S-1-5-18", sidBase + "-1001"}
	w.reg[KeyProfileList+`\`+sidBase+"-1001"] = map[string]RegValue{"ProfileImagePath": sz(`C:\Users\backdoor`)}
	w.dirs(winStartupAll, "desktop.ini")
	w.dirs(`C:\Users\backdoor\`+winStartupPerUser, "desktop.ini", "run.lnk")

	// Event Log.
	for i := 0; i < 25; i++ {
		w.events["Security"] = append(w.events["Security"], WinEvent{Channel: "Security", ID: 4625, Time: "2026-11-12T02:00:00Z", Data: map[string]string{"IpAddress": "203.0.113.9"}})
	}
	w.events["Security"] = append(w.events["Security"],
		WinEvent{Channel: "Security", ID: 4625, Time: "2026-11-12T02:01:00Z", Data: map[string]string{"IpAddress": "-"}},
		WinEvent{Channel: "Security", ID: 1102, Time: "2026-11-12T02:30:00Z", Data: map[string]string{"SubjectUserName": "backdoor"}},
		WinEvent{Channel: "Security", ID: 4720, Time: "2026-11-12T02:10:00Z", Data: map[string]string{"TargetUserName": "backdoor"}})
	w.events["System"] = []WinEvent{{Channel: "System", ID: 7045, Time: "2026-11-12T02:20:00Z", Data: map[string]string{"ServiceName": "Updater"}}}
	return w
}

// dirs registers a Windows directory listing.
func (w *fakeWin) dirs(dir string, names ...string) { w.dirList[dir] = names }

func (w *fakeWin) ReadDir(p string) ([]string, error) {
	if n, ok := w.dirList[p]; ok && !w.denied[p] {
		return n, nil
	}
	return w.fakeHost.ReadDir(p)
}

func toFiletime(unix int64) uint64 { return uint64(unix)*10000000 + 116444736000000000 }

func TestWindowsCollectorWeakServer(t *testing.T) {
	f := WindowsCollector{}.Collect(context.Background(), weakServer())
	p := f.Platform.Value
	if f.Platform.Status != StatusOK || p.Family != "windows-server" || p.Build != "20348.2762" || p.ServerCore {
		t.Errorf("platform %+v", f.Platform)
	}
	if r := f.RemoteAccess.RDP; r.Status != StatusOK || !r.Value.Enabled || r.Value.NLA || r.Value.Port != 3390 || r.Value.SecurityLayer != "rdp" {
		t.Errorf("rdp %+v", r)
	}
	if s := f.RemoteAccess.SMB; !s.Value.SMB1Enabled || s.Value.SigningRequired {
		t.Errorf("smb %+v", s)
	}
	if w := f.RemoteAccess.WinRM.Value; !w.Running || !w.HTTPListener || !w.AllowUnencrypted || !w.BasicAuth {
		t.Errorf("winrm: policy must override the service setting: %+v", w)
	}
	if f.RemoteAccess.SSH.Status != StatusNotApplicable {
		t.Errorf("no sshd service and no config: %+v", f.RemoteAccess.SSH)
	}
	if fw := f.Firewall; fw.Status != StatusOK || fw.Value.Profiles["Public"] || !fw.Value.Profiles["Domain"] || !fw.Value.Enabled {
		t.Errorf("firewall %+v", fw)
	}
	am := f.Antimalware
	if am.Status != StatusOK || am.Value.RealTime || am.Value.SignatureAgeDays != 12 || len(am.Value.Exclusions) != 3 {
		t.Errorf("defender %+v", am)
	}
	if pk := f.Packages; pk.Status != StatusOK || len(pk.Value.Items) != 2 || pk.Value.Items[0].Name != "7-Zip 19.00 (x64)" || pk.Value.Items[1].Version != "1.2.3.4" {
		t.Errorf("packages %+v", pk)
	}
	if pt := f.Patches; pt.Status != StatusOK || len(pt.Value) != 1 || pt.Value[0].ID != "KB5034439" || pt.Value[0].InstalledOn == "" {
		t.Errorf("patches: only installed KBs, once each: %+v", pt)
	}
	if ac := f.Accounts; ac.Status != StatusOK || len(ac.Value) != 3 || !ac.Value[0].IsAdmin || !ac.Value[2].IsAdmin || ac.Value[1].CanLogin {
		t.Errorf("accounts %+v", ac)
	}
	pr := f.Processes
	if pr.Status != StatusOK || len(pr.Value) != 6 {
		t.Fatalf("processes %+v", pr)
	}
	for _, q := range pr.Value {
		if q.PID == 1200 && (!q.InTemp || strings.Contains(q.Cmdline, "hunter22")) {
			t.Errorf("miner in Temp, password masked: %+v", q)
		}
	}
	if l := f.Listeners; len(l.Value) != 3 || l.Value[0].Process != "mysqld.exe" {
		t.Errorf("listeners %+v", l)
	}
	kinds := map[string][]string{}
	for _, it := range f.Persistence.Value {
		kinds[it.Kind] = append(kinds[it.Kind], it.Location+" "+it.Detail)
	}
	if f.Persistence.Status != StatusPartial || f.Persistence.Reason != ReasonNotCollected {
		t.Errorf("persistence must admit WMI subscriptions were not read: %+v", f.Persistence)
	}
	if len(kinds["run_key"]) != 5 || len(kinds["service"]) != 3 || len(kinds["schtask"]) != 1 || len(kinds["startup_folder"]) != 1 {
		t.Errorf("persistence kinds %v", kinds)
	}
	if !strings.Contains(strings.Join(kinds["service"], "|"), "service:Updater auto as LocalSystem; unquoted path with spaces") {
		t.Errorf("unquoted service path not flagged: %v", kinds["service"])
	}
	ae := f.AuthEvents
	if ae.Status != StatusOK || ae.Value.FailedBySrc["203.0.113.9"] != 25 || ae.Value.FailedBySrc["local"] != 1 || len(ae.Value.Notable) != 3 {
		t.Errorf("auth events %+v", ae)
	}
	if ae.Value.Notable[2].Kind != "log_cleared" {
		t.Errorf("notable must be time-ordered: %+v", ae.Value.Notable)
	}
}

func TestWindowsDefaultsAndDenied(t *testing.T) {
	w := newFakeWin()
	w.info.Elevated = false
	w.reg[KeyTerminalServer] = map[string]RegValue{} // values absent: Windows defaults
	w.reg[KeyLanmanServer] = map[string]RegValue{}
	w.denied[KeyFirewallPolicy+`\PublicProfile`] = true
	w.reg[KeyFirewallPolicy+`\DomainProfile`] = map[string]RegValue{"EnableFirewall": dword(1)}
	w.denied[KeyDefender] = true
	w.denied[KeyWinRMPolicy] = true
	w.denied["Security"] = true
	w.denied[SIDAdministrators] = true
	w.users = []WinUser{{Name: "Administrator", SID: sidBase + "-500"}}
	w.procs = []WinProcess{{PID: 4, Name: "System"}, {PID: 700, Name: "lsass.exe", ExeErr: "permission"}}
	f := WindowsCollector{}.Collect(context.Background(), w)
	if r := f.RemoteAccess.RDP.Value; r.Enabled || !r.NLA || r.Port != 3389 {
		t.Errorf("rdp defaults %+v", r)
	}
	if f.Firewall.Status != StatusPartial || f.Firewall.Reason != ReasonPermission {
		t.Errorf("firewall %+v", f.Firewall)
	}
	if f.Antimalware.Status != StatusUnknown || f.Antimalware.Reason != ReasonPermission {
		t.Errorf("defender %+v", f.Antimalware)
	}
	if f.RemoteAccess.WinRM.Status != StatusUnknown {
		t.Errorf("unreadable WinRM policy must be unknown: %+v", f.RemoteAccess.WinRM)
	}
	if f.Platform.Status != StatusPartial {
		t.Errorf("platform without CurrentVersion %+v", f.Platform)
	}
	if f.AuthEvents.Status != StatusUnknown || f.AuthEvents.Reason != ReasonPermission {
		t.Errorf("Security log denied must be unknown, not zero failures: %+v", f.AuthEvents)
	}
	if f.Accounts.Status != StatusPartial {
		t.Errorf("admin membership unreadable must be partial: %+v", f.Accounts)
	}
	if f.Processes.Status != StatusPartial || f.Processes.Reason != ReasonPermission {
		t.Errorf("hidden image path must be partial: %+v", f.Processes)
	}
	if f.Packages.Status != StatusUnknown || f.Patches.Status != StatusUnknown {
		t.Errorf("no Uninstall/CBS key: %+v %+v", f.Packages, f.Patches)
	}
}

func TestWindowsSourceFailuresAreUnknown(t *testing.T) {
	w := weakServer()
	for _, k := range []string{"svc", "proc", "sock", "users"} {
		w.denied[k] = true
	}
	f := WindowsCollector{}.Collect(context.Background(), w)
	for name, s := range map[string]Status{"services": f.Services.Status, "processes": f.Processes.Status,
		"listeners": f.Listeners.Status, "accounts": f.Accounts.Status} {
		if s != StatusUnknown {
			t.Errorf("%s: %s", name, s)
		}
	}
	if f.Firewall.Status != StatusPartial || f.RemoteAccess.WinRM.Status != StatusPartial || f.Antimalware.Status != StatusPartial {
		t.Errorf("service/socket state unknown must make dependants partial: %+v %+v %+v", f.Firewall, f.RemoteAccess.WinRM, f.Antimalware)
	}
}

func TestWindowsCollectorNeedsWinSource(t *testing.T) {
	f := WindowsCollector{}.Collect(context.Background(), newFake(true))
	if f.Platform.Reason != ReasonUnsupported {
		t.Errorf("%+v", f.Platform)
	}
	if ForOS("windows").Name() != "windows" {
		t.Error("ForOS(windows) must return the Windows collector")
	}
}

func TestDefenderExclusionsHidden(t *testing.T) {
	w := weakServer()
	w.denied[KeyDefender+`\Exclusions\Paths`] = true
	am := (WindowsCollector{}).Collect(context.Background(), w).Antimalware
	if am.Status != StatusPartial || am.Reason != ReasonPermission {
		t.Errorf("hidden exclusions: %+v", am)
	}
	w = weakServer()
	w.info.Elevated = false
	for _, k := range []string{"Paths", "Extensions"} {
		delete(w.reg, KeyDefender+`\Exclusions\`+k)
	}
	if am := (WindowsCollector{}).Collect(context.Background(), w).Antimalware; am.Status != StatusPartial {
		t.Errorf("empty list without elevation: %+v", am)
	}
	w = weakServer()
	w.reg[KeyDefenderPolicy+`\Real-Time Protection`] = map[string]RegValue{"DisableRealtimeMonitoring": dword(0)}
	if am := (WindowsCollector{}).Collect(context.Background(), w).Antimalware; !am.Value.RealTime {
		t.Errorf("policy must win over the local setting: %+v", am)
	}
	w.svcs[1].State = "stopped"
	if am := (WindowsCollector{}).Collect(context.Background(), w).Antimalware; am.Value.RealTime {
		t.Errorf("stopped WinDefend cannot protect: %+v", am)
	}
	delete(w.reg, KeyDefender)
	if am := (WindowsCollector{}).Collect(context.Background(), w).Antimalware; am.Status != StatusUnknown || am.Reason != ReasonNotInstalled {
		t.Errorf("no Defender: %+v", am)
	}
}

func TestWindowsSSH(t *testing.T) {
	w := weakServer()
	w.svcs = append(w.svcs, WinService{Name: "sshd", State: "running", StartType: "auto"})
	w.files[winSSHDConfig] = "PasswordAuthentication yes\nPermitRootLogin=no\nMatch Group administrators\n  PasswordAuthentication no\n"
	s := WindowsCollector{}.Collect(context.Background(), w).RemoteAccess.SSH
	if s.Status != StatusOK || s.Value.Settings["passwordauthentication"] != "yes" || s.Value.Settings["permitrootlogin"] != "no" {
		t.Errorf("sshd_config up to the first Match: %+v", s)
	}
	w.denied[winSSHDConfig] = true
	if s := (WindowsCollector{}).Collect(context.Background(), w).RemoteAccess.SSH; s.Status != StatusPartial || s.Value.Settings["passwordauthentication"] != "unknown" {
		t.Errorf("unreadable sshd_config: %+v", s)
	}
}

func TestParseSocketTable(t *testing.T) {
	b := make([]byte, 4+2*tcp4RowSize)
	binary.LittleEndian.PutUint32(b, 2)
	row := func(i int, state uint32, ip [4]byte, port uint16, pid uint32) {
		r := b[4+i*tcp4RowSize:]
		binary.LittleEndian.PutUint32(r, state)
		copy(r[4:], ip[:])
		binary.BigEndian.PutUint16(r[8:], port)
		binary.LittleEndian.PutUint32(r[20:], pid)
	}
	row(0, 2, [4]byte{0, 0, 0, 0}, 3389, 1044)
	row(1, 2, [4]byte{127, 0, 0, 1}, 5985, 4)
	got, err := ParseSocketTable("tcp", b)
	want := []WinSocket{{Proto: "tcp", Addr: "0.0.0.0", Port: 3389, State: "LISTEN", OwnerPID: 1044},
		{Proto: "tcp", Addr: "127.0.0.1", Port: 5985, State: "LISTEN", OwnerPID: 4}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Errorf("tcp: %v %+v", err, got)
	}
	u6 := make([]byte, 4+udp6RowSize)
	binary.LittleEndian.PutUint32(u6, 1)
	u6[4+15] = 1 // ::1
	binary.BigEndian.PutUint16(u6[4+20:], 53)
	binary.LittleEndian.PutUint32(u6[4+24:], 77)
	if got, err := ParseSocketTable("udp6", u6); err != nil || got[0] != (WinSocket{Proto: "udp6", Addr: "::1", Port: 53, OwnerPID: 77}) {
		t.Errorf("udp6: %v %+v", err, got)
	}
	if _, err := ParseSocketTable("tcp", b[:30]); err == nil {
		t.Error("a short table must fail, not read past the end")
	}
}

func TestParseEventXML(t *testing.T) {
	failed := `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing"/>` +
		`<EventID>4625</EventID><TimeCreated SystemTime="2026-11-12T02:00:00.1234567Z"/><Channel>Security</Channel></System>` +
		`<EventData><Data Name="TargetUserName">administrator</Data><Data Name="IpAddress">203.0.113.9</Data><Data Name="LogonType">3</Data></EventData></Event>`
	e, err := ParseEventXML(failed)
	if err != nil || e.ID != 4625 || e.Channel != "Security" || e.Data["IpAddress"] != "203.0.113.9" || e.Time != "2026-11-12T02:00:00.1234567Z" {
		t.Errorf("4625: %v %+v", err, e)
	}
	cleared := `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>1102</EventID><Channel>Security</Channel>` +
		`<TimeCreated SystemTime="2026-11-12T03:00:00Z"/></System><UserData><LogFileCleared xmlns="http://manifests.microsoft.com/win/2004/08/windows/eventlog">` +
		`<SubjectUserSid>S-1-5-21-1-2-3-500</SubjectUserSid><SubjectUserName>Administrator</SubjectUserName></LogFileCleared></UserData></Event>`
	if e, err := ParseEventXML(cleared); err != nil || e.ID != 1102 || e.Data["SubjectUserName"] != "Administrator" {
		t.Errorf("1102 UserData: %v %+v", err, e)
	}
}

func utf16File(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := []byte{0xFF, 0xFE}
	for _, c := range u {
		b = binary.LittleEndian.AppendUint16(b, c)
	}
	return b
}

func TestParseTaskXML(t *testing.T) {
	x := `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers><BootTrigger><Enabled>true</Enabled></BootTrigger><TimeTrigger><Enabled>false</Enabled></TimeTrigger><LogonTrigger/></Triggers>
  <Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings><Enabled>true</Enabled></Settings>
  <Actions Context="Author"><Exec><Command>C:\ProgramData\u.exe</Command><Arguments>-k token=abcdef123456</Arguments></Exec></Actions>
</Task>`
	tk, err := ParseTaskXML(`\Updater`, utf16File(x))
	if err != nil || !tk.Enabled || tk.RunAs != "S-1-5-18 (highest)" || !reflect.DeepEqual(tk.Triggers, []string{"BootTrigger", "LogonTrigger"}) {
		t.Fatalf("%v %+v", err, tk)
	}
	if len(tk.Actions) != 1 || strings.Contains(tk.Actions[0], "abcdef123456") || !strings.HasPrefix(tk.Actions[0], `C:\ProgramData\u.exe -k token=`) {
		t.Errorf("actions must be masked: %+v", tk.Actions)
	}
}

func TestWindowsHelpers(t *testing.T) {
	for in, want := range map[string]string{
		"Package_for_KB5034439~31bf3856ad364e35~amd64~~20348.2227.1.3":  "KB5034439",
		"Package_12_for_KB890830~31bf3856ad364e35~amd64~~5.120.0.0":     "KB890830",
		"Package_for_RollupFix~31bf3856ad364e35~amd64~~20348.2762.1.10": "",
		"Microsoft-Windows-KB-Package":                                  "",
	} {
		if got := CBSPackageKB(in); got != want {
			t.Errorf("CBSPackageKB(%q) = %q", in, got)
		}
	}
	for in, want := range map[string]string{
		`"C:\Program Files\A\a.exe" -x`:          `C:\Program Files\A\a.exe`,
		`C:\Program Files\A\a.exe -x`:            `C:\Program Files\A\a.exe`,
		`C:\Windows\system32\svchost.exe -k net`: `C:\Windows\system32\svchost.exe`,
		`\SystemRoot\System32\drivers\x.sys`:     `\SystemRoot\System32\drivers\x.sys`,
	} {
		if got := ServiceImage(in); got != want {
			t.Errorf("ServiceImage(%q) = %q", in, got)
		}
	}
	if !UnquotedServicePath(`C:\Program Files\A\a.exe -x`) || UnquotedServicePath(`"C:\Program Files\A\a.exe"`) || UnquotedServicePath(`C:\Windows\a.exe -k x y`) {
		t.Error("UnquotedServicePath")
	}
	for in, want := range map[string]bool{
		`C:\Windows\Temp\a.exe`: true, `c:\users\bob\appdata\local\temp\x\y.exe`: true, `C:\Users\Public\a.exe`: true,
		`C:\ProgramData\a.exe`: true, `C:\ProgramData\Microsoft\Windows Defender\MsMpEng.exe`: false,
		`C:\Windows\System32\cmd.exe`: false, `\\?\C:\$Recycle.Bin\S-1\a.exe`: true,
	} {
		if WinInTempDir(in) != want {
			t.Errorf("WinInTempDir(%q) != %v", in, want)
		}
	}
	if WindowsServerName("26100.1742") != "Windows Server 2025" || WindowsServerName("17763") != "Windows Server 2019" {
		t.Error("WindowsServerName")
	}
}

// A recorded Windows host replays to the same facts, and the fixture is
// masked: human account names and the machine SID never reach disk, while
// version numbers that look like IPs survive.
func TestWindowsRecordReplay(t *testing.T) {
	w := weakServer()
	rec := NewRecorder(w)
	want := WindowsCollector{}.Collect(context.Background(), rec)
	dir := filepath.Join(t.TempDir(), "fx")
	if err := rec.Save(dir, nil); err != nil {
		t.Fatal(err)
	}
	rp, err := LoadReplay(dir)
	if err != nil {
		t.Fatal(err)
	}
	got := Collect(context.Background(), rp)
	gb, _ := json.Marshal(got)
	wb, _ := json.Marshal(want)
	if string(gb) != string(wb) {
		t.Errorf("unmasked replay differs:\n got %s\nwant %s", gb, wb)
	}

	masked := filepath.Join(t.TempDir(), "fx")
	if err := rec.Save(masked, &Masker{}); err != nil {
		t.Fatal(err)
	}
	var all strings.Builder
	filepath.Walk(masked, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			b, _ := os.ReadFile(p)
			all.Write(b)
		}
		return nil
	})
	s := all.String()
	for _, leak := range []string{"backdoor", "111-222-333", "hunter22"} {
		if strings.Contains(s, leak) {
			t.Errorf("fixture leaks %q", leak)
		}
	}
	if !strings.Contains(s, "1.2.3.4") {
		t.Error("a package version was masked as an IP address")
	}
	rp, err = LoadReplay(masked)
	if err != nil {
		t.Fatal(err)
	}
	if f := Collect(context.Background(), rp); f.Accounts.Status != StatusOK || len(f.Accounts.Value) != 3 || !f.Accounts.Value[0].IsAdmin {
		t.Errorf("masked replay lost admin membership: %+v", f.Accounts)
	}
}
