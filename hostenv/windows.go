package hostenv

// Draft of the Windows collector (Phase 2). The file name has no _windows
// suffix on purpose: the collector and its mappings are pure and are tested
// on every OS against a fake WinSource. Only the WinSource implementation
// (x/sys/windows registry and svc/mgr, WMI, wevtapi, iphlpapi, netapi32)
// will carry a windows build tag. No PowerShell, no commands.
//
// Not wired into ForOS yet: until Phase 2 lands, Windows hosts get the
// Unsupported collector, so every fact says "unsupported_platform".

import (
	"context"
	"strconv"
	"strings"
)

// RegValue is one registry value, decoded.
type RegValue struct {
	Type    string   `json:"type"` // SZ, EXPAND_SZ, MULTI_SZ, DWORD, QWORD, BINARY
	String  string   `json:"string,omitempty"`
	Strings []string `json:"strings,omitempty"`
	Int     uint64   `json:"int,omitempty"`
}

// WinService is one SCM entry (svc/mgr Config + Query).
type WinService struct {
	Name, DisplayName, BinaryPath, StartType, State, Account string
}

// WinProcess is one Toolhelp32 entry, with the image path and command
// line when they could be read.
type WinProcess struct {
	PID, PPID       int
	Name, Exe, User string
	Cmdline         string
	ExeErr          error // why Exe is empty: permission, or the process exited
}

// WinSocket is one row of GetExtendedTcpTable / GetExtendedUdpTable.
type WinSocket struct {
	Proto    string // tcp, tcp6, udp, udp6
	Addr     string
	Port     int
	State    string // LISTEN, ESTABLISHED, …; empty for UDP
	OwnerPID int
}

// WinUser is one NetUserEnum entry.
type WinUser struct {
	Name, SID          string
	Disabled, NoExpire bool
	LastLogon          string
}

// WinEvent is one rendered Event Log record.
type WinEvent struct {
	Channel string
	ID      int
	Time    string
	Data    map[string]string // EventData Name -> value
}

// WinSource is everything the Windows collector reads. Every method is
// read-only. Errors carry fs.ErrPermission / fs.ErrNotExist (or wrap them)
// so Classify maps them to reasons as on Linux.
//
// Keys are full paths with the hive spelled out: `HKLM\SYSTEM\...`.
type WinSource interface {
	Source // Info, plus ReadFile/ReadDir for applicationHost.config and Tasks XML

	RegValues(key string) (map[string]RegValue, error)
	RegSubkeys(key string) ([]string, error)
	Services() ([]WinService, error)
	Processes() ([]WinProcess, error)
	Sockets() ([]WinSocket, error)
	Users() ([]WinUser, error)
	GroupMembers(sid string) ([]string, error) // member SIDs of a local group
	WMI(namespace, query string) ([]map[string]any, error)
	Events(channel, xpath string, max int) ([]WinEvent, error)
}

// Registry keys the collector reads.
const (
	KeyCurrentVersion = `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`
	KeyTerminalServer = `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server`
	KeyRDPTcp         = `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp`
	KeyLanmanServer   = `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`
	KeyWinRMService   = `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Service`
	KeyWinRMPolicy    = `HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service`
	KeyFirewallPolicy = `HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy`
	SIDAdministrators = "S-1-5-32-544"
	NamespaceDefender = `root\Microsoft\Windows\Defender`
)

// WindowsCollector reads a WinSource. Facts it does not gather yet stay
// not_collected.
type WindowsCollector struct{}

func (WindowsCollector) Name() string          { return "windows" }
func (WindowsCollector) Allowlist() [][]string { return nil } // registry and APIs only

func (c WindowsCollector) Collect(ctx context.Context, src Source) *Facts {
	info := src.Info()
	f := NewFacts(c.Name(), CollectorVersion, info.RecordedAt)
	f.Privilege = OK(Privilege{Elevated: info.Elevated})
	ws, ok := src.(WinSource)
	if !ok {
		f.Platform = Unknown[Platform](ReasonUnsupported, "source cannot read Windows APIs")
		return f
	}
	f.Platform = winPlatform(ws, info)
	f.RemoteAccess.SSH = NotApplicable[SSHConfig]() // OpenSSH Server: Phase 2, reusing ParseSSHDConfig
	f.RemoteAccess.RDP = winRDP(ws)
	f.RemoteAccess.SMB = winSMB(ws)
	f.RemoteAccess.WinRM = winWinRM(ws)
	f.Firewall = winFirewall(ws)
	f.Antimalware = winDefender(ws)
	return f
}

func regString(v map[string]RegValue, name string) string { return v[name].String }

func regInt(v map[string]RegValue, name string, def uint64) uint64 {
	r, ok := v[name]
	if !ok {
		return def
	}
	if r.Type == "DWORD" || r.Type == "QWORD" {
		return r.Int
	}
	if n, err := strconv.ParseUint(r.String, 10, 64); err == nil {
		return n
	}
	return def
}

func winPlatform(ws WinSource, info SourceInfo) Obs[Platform] {
	p := Platform{OS: "windows", Distro: "windows", Arch: info.GOARCH}
	v, err := ws.RegValues(KeyCurrentVersion)
	if err != nil {
		return Obs[Platform]{Status: StatusPartial, Reason: Classify(err), Detail: "CurrentVersion: " + err.Error(), Value: p}
	}
	p.PrettyName = regString(v, "ProductName")
	p.Version = regString(v, "DisplayVersion")
	if p.Version == "" {
		p.Version = regString(v, "ReleaseId")
	}
	p.Build = regString(v, "CurrentBuild")
	if ubr := regInt(v, "UBR", 0); p.Build != "" && ubr > 0 {
		p.Build += "." + strconv.FormatUint(ubr, 10)
	}
	p.Kernel = p.Build
	typ := regString(v, "InstallationType") // Server, Server Core, Client
	p.ServerCore = typ == "Server Core"
	p.Family = "windows-client"
	if strings.HasPrefix(typ, "Server") {
		p.Family = "windows-server"
	}
	return OK(p)
}

// winRDP follows Windows defaults when a value is missing: RDP off
// (fDenyTSConnections=1), NLA on, port 3389.
func winRDP(ws WinSource) Obs[RDPConfig] {
	ts, err := ws.RegValues(KeyTerminalServer)
	if err != nil {
		return unknownFrom[RDPConfig](KeyTerminalServer, err)
	}
	cfg := RDPConfig{Enabled: regInt(ts, "fDenyTSConnections", 1) == 0, NLA: true, Port: 3389}
	tcp, err := ws.RegValues(KeyRDPTcp)
	if err != nil {
		if cfg.Enabled {
			return Partial(cfg, Classify(err), "RDP-Tcp unreadable: NLA and port assumed default")
		}
		return OK(cfg)
	}
	cfg.NLA = regInt(tcp, "UserAuthentication", 1) == 1
	cfg.Port = int(regInt(tcp, "PortNumber", 3389))
	cfg.SecurityLayer = map[uint64]string{0: "rdp", 1: "negotiate", 2: "tls"}[regInt(tcp, "SecurityLayer", 2)]
	return OK(cfg)
}

// winSMB reads the server side only. SMB1 defaults to off on 2019+ when the
// value is absent; signing defaults to not required on the server role
// before 2025.
func winSMB(ws WinSource) Obs[SMBConfig] {
	v, err := ws.RegValues(KeyLanmanServer)
	if err != nil {
		return unknownFrom[SMBConfig](KeyLanmanServer, err)
	}
	return OK(SMBConfig{
		SMB1Enabled:     regInt(v, "SMB1", 0) == 1,
		SigningRequired: regInt(v, "RequireSecuritySignature", 0) == 1,
	})
}

// winWinRM: a Group Policy value wins over the service's own setting.
// The listener comes from the socket table (5985 = HTTP).
func winWinRM(ws WinSource) Obs[WinRMConfig] {
	svc, err := ws.RegValues(KeyWinRMService)
	if err != nil && !isNotExist(err) {
		return unknownFrom[WinRMConfig](KeyWinRMService, err)
	}
	pol, perr := ws.RegValues(KeyWinRMPolicy)
	if perr != nil && !isNotExist(perr) {
		return unknownFrom[WinRMConfig](KeyWinRMPolicy, perr) // a policy we cannot read may override everything
	}
	pick := func(name string) bool {
		if _, ok := pol[name]; ok {
			return regInt(pol, name, 0) == 1
		}
		return regInt(svc, name, 0) == 1
	}
	cfg := WinRMConfig{AllowUnencrypted: pick("AllowUnencryptedTraffic"), BasicAuth: pick("AllowBasic")}
	socks, serr := ws.Sockets()
	if serr != nil {
		return Partial(cfg, Classify(serr), "socket table unreadable: listener unknown")
	}
	for _, s := range socks {
		if strings.HasPrefix(s.Proto, "tcp") && s.State == "LISTEN" && (s.Port == 5985 || s.Port == 5986) {
			cfg.Running = true
			cfg.HTTPListener = cfg.HTTPListener || s.Port == 5985
		}
	}
	return OK(cfg)
}

func isNotExist(err error) bool { return Classify(err) == ReasonNotInstalled }

// winFirewall reads the local profile switches. A Group Policy setting can
// override them; Phase 2 reads the effective state through INetFwPolicy2 and
// keeps this as the fallback.
func winFirewall(ws WinSource) Obs[Firewall] {
	fw := Firewall{Backend: "windows", Profiles: map[string]bool{}}
	var firstErr error
	for _, p := range []struct{ key, name string }{
		{"DomainProfile", "Domain"}, {"StandardProfile", "Private"}, {"PublicProfile", "Public"},
	} {
		v, err := ws.RegValues(KeyFirewallPolicy + `\` + p.key)
		if err != nil && !isNotExist(err) { // an absent key means the Windows default: on
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		on := regInt(v, "EnableFirewall", 1) == 1
		fw.Profiles[p.name] = on
		fw.Enabled = fw.Enabled || on
	}
	switch {
	case len(fw.Profiles) == 0:
		return unknownFrom[Firewall](KeyFirewallPolicy, firstErr)
	case firstErr != nil:
		return Partial(fw, Classify(firstErr), "some firewall profiles unreadable")
	}
	return OK(fw)
}

func winDefender(ws WinSource) Obs[Antimalware] {
	rows, err := ws.WMI(NamespaceDefender, "SELECT RealTimeProtectionEnabled, AntivirusSignatureAge, AMRunningMode FROM MSFT_MpComputerStatus")
	if err != nil {
		return unknownFrom[Antimalware]("MSFT_MpComputerStatus", err)
	}
	if len(rows) == 0 {
		return Unknown[Antimalware](ReasonNotInstalled, "Defender reports no status (another antivirus may be active)")
	}
	r := rows[0]
	am := Antimalware{Product: "Microsoft Defender", RealTime: asBool(r["RealTimeProtectionEnabled"]), SignatureAgeDays: asInt(r["AntivirusSignatureAge"])}
	if mode, _ := r["AMRunningMode"].(string); mode != "" && mode != "Normal" {
		am.Product += " (" + mode + ")" // Passive / EDR Block: another product is primary
	}
	prefs, err := ws.WMI(NamespaceDefender, "SELECT ExclusionPath FROM MSFT_MpPreference")
	if err != nil {
		return Partial(am, Classify(err), "exclusions unreadable")
	}
	if len(prefs) > 0 {
		am.Exclusions = asStrings(prefs[0]["ExclusionPath"])
	}
	return OK(am)
}

func asBool(v any) bool {
	b, _ := v.(bool)
	return b
}

func asInt(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case int32:
		return int(n)
	case int64:
		return int(n)
	case uint32:
		return int(n)
	case float64:
		return int(n)
	}
	return 0
}

func asStrings(v any) []string {
	switch s := v.(type) {
	case []string:
		return s
	case []any:
		var out []string
		for _, x := range s {
			if str, ok := x.(string); ok {
				out = append(out, str)
			}
		}
		return out
	}
	return nil
}
