package hostenv

import (
	"context"
	"io/fs"
	"testing"
)

// fakeWin is an in-memory WinSource.
type fakeWin struct {
	*fakeHost
	reg     map[string]map[string]RegValue
	denied  map[string]bool
	wmi     map[string][]map[string]any
	sockets []WinSocket
}

func newFakeWin() *fakeWin {
	h := newFake(true)
	h.info.GOOS, h.info.GOARCH = "windows", "amd64"
	return &fakeWin{fakeHost: h, reg: map[string]map[string]RegValue{}, denied: map[string]bool{}, wmi: map[string][]map[string]any{}}
}

func dword(n uint64) RegValue { return RegValue{Type: "DWORD", Int: n} }
func sz(s string) RegValue    { return RegValue{Type: "SZ", String: s} }

func (w *fakeWin) RegValues(key string) (map[string]RegValue, error) {
	if w.denied[key] {
		return nil, &fs.PathError{Op: "RegOpenKeyEx", Path: key, Err: fs.ErrPermission}
	}
	if v, ok := w.reg[key]; ok {
		return v, nil
	}
	return nil, &fs.PathError{Op: "RegOpenKeyEx", Path: key, Err: fs.ErrNotExist}
}
func (w *fakeWin) RegSubkeys(string) ([]string, error)            { return nil, nil }
func (w *fakeWin) Services() ([]WinService, error)                { return nil, nil }
func (w *fakeWin) Processes() ([]WinProcess, error)               { return nil, nil }
func (w *fakeWin) Sockets() ([]WinSocket, error)                  { return w.sockets, nil }
func (w *fakeWin) Users() ([]WinUser, error)                      { return nil, nil }
func (w *fakeWin) GroupMembers(string) ([]string, error)          { return nil, nil }
func (w *fakeWin) Events(string, string, int) ([]WinEvent, error) { return nil, nil }
func (w *fakeWin) WMI(ns, q string) ([]map[string]any, error) {
	if w.denied[ns] {
		return nil, &fs.PathError{Op: "WMI", Path: ns, Err: fs.ErrPermission}
	}
	return w.wmi[q], nil
}

const (
	qDefStatus = "SELECT RealTimeProtectionEnabled, AntivirusSignatureAge, AMRunningMode FROM MSFT_MpComputerStatus"
	qDefPrefs  = "SELECT ExclusionPath, ExclusionExtension, ExclusionProcess FROM MSFT_MpPreference"
)

// A deliberately weak Windows Server 2022: RDP without NLA, SMB1, WinRM
// over HTTP with Basic, the public firewall profile off, Defender off.
func weakServer() *fakeWin {
	w := newFakeWin()
	w.reg[KeyCurrentVersion] = map[string]RegValue{"ProductName": sz("Windows Server 2022 Datacenter"), "DisplayVersion": sz("21H2"),
		"CurrentBuild": sz("20348"), "UBR": dword(2762), "InstallationType": sz("Server")}
	w.reg[KeyTerminalServer] = map[string]RegValue{"fDenyTSConnections": dword(0)}
	w.reg[KeyRDPTcp] = map[string]RegValue{"UserAuthentication": dword(0), "PortNumber": dword(3390), "SecurityLayer": dword(0)}
	w.reg[KeyLanmanServer] = map[string]RegValue{"SMB1": dword(1)}
	w.reg[KeyWinRMService] = map[string]RegValue{"AllowUnencryptedTraffic": dword(0)}
	w.reg[KeyWinRMPolicy] = map[string]RegValue{"AllowUnencryptedTraffic": dword(1), "AllowBasic": dword(1)}
	w.sockets = []WinSocket{{Proto: "tcp", Addr: "0.0.0.0", Port: 5985, State: "LISTEN", OwnerPID: 4}}
	for _, p := range []string{"DomainProfile", "StandardProfile"} {
		w.reg[KeyFirewallPolicy+`\`+p] = map[string]RegValue{"EnableFirewall": dword(1)}
	}
	w.reg[KeyFirewallPolicy+`\PublicProfile`] = map[string]RegValue{"EnableFirewall": dword(0)}
	w.wmi[qDefStatus] = []map[string]any{{"RealTimeProtectionEnabled": false, "AntivirusSignatureAge": uint32(12), "AMRunningMode": "Normal"}}
	w.wmi[qDefPrefs] = []map[string]any{{"ExclusionPath": []any{`C:\`, `D:\data`}, "ExclusionExtension": []any{"ps1"}}}
	return w
}

func TestWindowsCollectorDraft(t *testing.T) {
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
	if fw := f.Firewall; fw.Status != StatusOK || fw.Value.Profiles["Public"] || !fw.Value.Profiles["Domain"] || !fw.Value.Enabled {
		t.Errorf("firewall %+v", fw)
	}
	if am := f.Antimalware; am.Status != StatusOK || am.Value.RealTime || am.Value.SignatureAgeDays != 12 || len(am.Value.Exclusions) != 3 {
		t.Errorf("defender %+v", am)
	}
	// Not gathered yet: honest not_collected, not empty lists.
	if f.Processes.Reason != ReasonNotCollected || f.Packages.Reason != ReasonNotCollected {
		t.Errorf("uncollected facts: %+v %+v", f.Processes, f.Packages)
	}
}

func TestWindowsDefaultsAndDenied(t *testing.T) {
	w := newFakeWin()
	w.reg[KeyTerminalServer] = map[string]RegValue{} // values absent: Windows defaults
	w.reg[KeyLanmanServer] = map[string]RegValue{}
	w.denied[KeyFirewallPolicy+`\PublicProfile`] = true
	w.reg[KeyFirewallPolicy+`\DomainProfile`] = map[string]RegValue{"EnableFirewall": dword(1)}
	w.denied[NamespaceDefender] = true
	w.denied[KeyWinRMPolicy] = true
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
}

func TestWindowsCollectorNeedsWinSource(t *testing.T) {
	f := WindowsCollector{}.Collect(context.Background(), newFake(true))
	if f.Platform.Reason != ReasonUnsupported {
		t.Errorf("%+v", f.Platform)
	}
	if ForOS("windows").Name() != "unsupported-windows" {
		t.Error("the Windows draft must not be wired into ForOS before Phase 2")
	}
}

func TestDefenderExclusionsHidden(t *testing.T) {
	w := weakServer()
	w.info.Elevated = false
	w.wmi[qDefPrefs] = []map[string]any{{"ExclusionPath": []any{"N/A: Must be an administrator to view exclusions"}}}
	if am := (WindowsCollector{}).Collect(context.Background(), w).Antimalware; am.Status != StatusPartial || am.Reason != ReasonPermission || am.Value.Exclusions != nil {
		t.Errorf("N/A placeholder: %+v", am)
	}
	w.wmi[qDefPrefs] = []map[string]any{{}}
	if am := (WindowsCollector{}).Collect(context.Background(), w).Antimalware; am.Status != StatusPartial {
		t.Errorf("empty list without elevation: %+v", am)
	}
}
