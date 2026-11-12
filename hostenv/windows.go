package hostenv

// The Windows collector. The file name has no _windows suffix on purpose:
// the collector and its mappings are pure and are tested on every OS
// against a fake WinSource and replayed fixtures. Only the live WinSource
// (live_windows.go: x/sys/windows, registry, SCM, Toolhelp32, iphlpapi,
// netapi32, wevtapi, and a minimal COM client for the two things only WMI
// knows: event subscriptions and Defender's runtime status) carries a
// windows build tag. No PowerShell, no commands.

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"time"
)

// RegValue is one registry value, decoded. Strings are secret-masked;
// binary values are capped at MaxRegBinary bytes.
type RegValue struct {
	Type    string   `json:"type"` // SZ, EXPAND_SZ, MULTI_SZ, DWORD, QWORD, BINARY
	String  string   `json:"string,omitempty"`
	Strings []string `json:"strings,omitempty"`
	Int     uint64   `json:"int,omitempty"`
	Bytes   []byte   `json:"bytes,omitempty"`
}

// MaxRegBinary caps a REG_BINARY value; the collector only needs FILETIMEs.
const MaxRegBinary = 4096

// regBinaryKept names the REG_BINARY values whose data a source returns
// (the Defender signature FILETIMEs). Every other binary value comes back
// as its type alone, so opaque blobs never reach a fixture.
var regBinaryKept = []string{"SignaturesLastUpdated", "AVSignatureApplied"}

// secretValueNames mark registry values whose data is a credential:
// Winlogon DefaultPassword / AltDefaultPassword (auto-logon), service and
// application secrets. Their data never leaves the source.
var secretValueNames = []string{"password", "passwd", "pwd", "secret", "token", "apikey", "api_key", "credential", "privatekey"}

// RedactRegValues blanks the data of every value whose name marks it as a
// credential, keeping the type so a check can still see the value is set.
func RedactRegValues(v map[string]RegValue) map[string]RegValue {
	for name, r := range v {
		n := strings.ToLower(name)
		for _, s := range secretValueNames {
			if strings.Contains(n, s) {
				v[name] = RegValue{Type: r.Type, String: "[REDACTED]"}
				break
			}
		}
	}
	return v
}

// WinFirewallPolicy is what INetFwPolicy2 reports. Profiles are keyed
// Domain, Private and Public; Active lists the profiles in force now.
type WinFirewallPolicy struct {
	Active   []string                      `json:"active"`
	Profiles map[string]WinFirewallProfile `json:"profiles"`
}

type WinFirewallProfile struct {
	Enabled         bool `json:"enabled"`
	BlockAllInbound bool `json:"block_all_inbound"`
	InboundAllowed  bool `json:"inbound_allowed"` // DefaultInboundAction is NET_FW_ACTION_ALLOW
}

// WinService is one SCM entry (EnumServicesStatusEx + QueryServiceConfig).
type WinService struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name,omitempty"`
	BinaryPath  string `json:"binary_path,omitempty"`
	StartType   string `json:"start_type,omitempty"` // boot, system, auto, manual, disabled
	State       string `json:"state,omitempty"`      // running, stopped, …
	Account     string `json:"account,omitempty"`
	PID         int    `json:"pid,omitempty"`
	ConfigErr   string `json:"config_err,omitempty"` // why the config could not be read (errCode)
}

// WinProcess is one Toolhelp32 entry, with the image path, owner and
// command line when they could be read.
type WinProcess struct {
	PID        int    `json:"pid"`
	PPID       int    `json:"ppid"`
	Name       string `json:"name"`
	Exe        string `json:"exe,omitempty"`
	ExeErr     string `json:"exe_err,omitempty"` // errCode of the failed image-path read
	ExeMissing bool   `json:"exe_missing,omitempty"`
	User       string `json:"user,omitempty"` // DOMAIN\name
	SID        string `json:"sid,omitempty"`
	Cmdline    string `json:"cmdline,omitempty"` // masked and capped by the source
}

// WinSocket is one row of GetExtendedTcpTable / GetExtendedUdpTable.
type WinSocket struct {
	Proto    string `json:"proto"` // tcp, tcp6, udp, udp6
	Addr     string `json:"addr"`
	Port     int    `json:"port"`
	State    string `json:"state,omitempty"` // LISTEN for TCP; empty for UDP
	OwnerPID int    `json:"owner_pid"`
}

// WinUser is one NetUserEnum entry.
type WinUser struct {
	Name     string `json:"name"`
	SID      string `json:"sid,omitempty"`
	Home     string `json:"home,omitempty"`
	Disabled bool   `json:"disabled,omitempty"`
	NoExpire bool   `json:"no_expire,omitempty"`
}

// WinTask is one scheduled task from C:\Windows\System32\Tasks.
type WinTask struct {
	Path     string   `json:"path"` // \Microsoft\Windows\…\Name
	Enabled  bool     `json:"enabled"`
	RunAs    string   `json:"run_as,omitempty"`
	Triggers []string `json:"triggers,omitempty"`
	Actions  []string `json:"actions,omitempty"` // command plus arguments, masked
	Err      string   `json:"err,omitempty"`     // errCode when the task file could not be read
}

// WinEvent is one rendered Event Log record.
type WinEvent struct {
	Channel string            `json:"channel"`
	ID      int               `json:"id"`
	Time    string            `json:"time"`
	Data    map[string]string `json:"data,omitempty"` // EventData/UserData Name -> value
}

// WinSource is everything the Windows collector reads. Every method is
// read-only. Errors carry fs.ErrPermission / fs.ErrNotExist (or wrap them)
// so Classify maps them to reasons as on Linux.
//
// Keys are full paths with the hive spelled out: `HKLM\SYSTEM\...`, `HKU\<SID>\...`.
type WinSource interface {
	Source // Info, plus ReadFile/ReadDir for sshd_config and startup folders

	RegValues(key string) (map[string]RegValue, error)
	RegSubkeys(key string) ([]string, error)
	Services() ([]WinService, error)
	Processes() ([]WinProcess, error)
	Sockets() ([]WinSocket, error) // TCP listeners and bound UDP sockets
	Users() ([]WinUser, error)
	GroupMembers(sid string) ([]string, error) // member SIDs of a local group
	Tasks() ([]WinTask, error)
	Events(channel, xpath string, max int) ([]WinEvent, error)
	// WMI runs one WQL query and returns the named properties of each row:
	// string, bool, int64, uint64, float64, nil or []any of those.
	WMI(namespace, query string, props []string) ([]map[string]any, error)
	// FirewallPolicy reads INetFwPolicy2: the firewall state in force, with
	// group policy already merged in.
	FirewallPolicy() (WinFirewallPolicy, error)
}

// WMI namespaces and queries the collector runs.
const (
	NamespaceSubscription = `root\subscription`
	NamespaceDefaultWMI   = `root\default`
	NamespaceDefender     = `root\Microsoft\Windows\Defender`
)

type wmiQuery struct {
	query string
	props []string
}

var (
	qMpStatus = wmiQuery{"SELECT * FROM MSFT_MpComputerStatus",
		[]string{"AMRunningMode", "AMServiceEnabled", "AntivirusEnabled", "RealTimeProtectionEnabled", "AntivirusSignatureAge"}}
	qWMIFilters  = wmiQuery{"SELECT * FROM __EventFilter", []string{"Name", "Query", "EventNamespace"}}
	qWMICmdLine  = wmiQuery{"SELECT * FROM CommandLineEventConsumer", []string{"Name", "CommandLineTemplate", "ExecutablePath"}}
	qWMIScript   = wmiQuery{"SELECT * FROM ActiveScriptEventConsumer", []string{"Name", "ScriptingEngine", "ScriptFileName", "ScriptText"}}
	qWMIBindings = wmiQuery{"SELECT * FROM __FilterToConsumerBinding", []string{"Filter", "Consumer"}}
)

// Registry keys the collector reads.
const (
	KeyCurrentVersion = `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`
	KeyTerminalServer = `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server`
	KeyRDPTcp         = `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp`
	KeyLanmanServer   = `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`
	KeyWinRMService   = `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Service`
	KeyWinRMPolicy    = `HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service`
	KeyFirewallPolicy = `HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy`
	KeyFirewallGPO    = `HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall`
	KeyDefender       = `HKLM\SOFTWARE\Microsoft\Windows Defender`
	KeyDefenderPolicy = `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender`
	KeyUninstall      = `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`
	KeyUninstall32    = `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`
	KeyCBSPackages    = `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages`
	KeyProfileList    = `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`
	KeyWinlogon       = `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`
	KeyWindowsNT      = `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows`
	KeyIFEO           = `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`
	SIDAdministrators = "S-1-5-32-544"

	winSSHDConfig     = `C:\ProgramData\ssh\sshd_config`
	winStartupAll     = `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp`
	winStartupPerUser = `AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`
)

// Event Log queries: the last AuthWindowHours, at most MaxEvents each.
const (
	AuthWindowHours = 24
	MaxEvents       = 5000
)

// WindowsCollector reads a WinSource.
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
	procs, procErr := ws.Processes()
	svcs, svcErr := ws.Services()
	socks, sockErr := ws.Sockets()
	f.Processes = winProcesses(procs, procErr)
	f.Services = winServices(svcs, svcErr)
	f.Listeners = winListeners(socks, sockErr, procs)
	f.Accounts = winAccounts(ws)
	f.Packages = winPackages(ws)
	f.Patches = winPatches(ws)
	f.Persistence = winPersistence(ws, svcs, svcErr)
	f.RemoteAccess.SSH = winSSH(ws, svcs, svcErr)
	f.RemoteAccess.RDP = winRDP(ws)
	f.RemoteAccess.SMB = winSMB(ws)
	f.RemoteAccess.WinRM = winWinRM(ws, socks, sockErr)
	f.Firewall = winFirewall(ws, svcs, svcErr)
	f.Antimalware = winDefender(ws, svcs, svcErr)
	f.AuthEvents = winAuthEvents(ws)
	f.Web = winWeb(ws, svcs, svcErr)
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
		// ProductName still says "Windows Server 2019" on 2022 and 2025
		// images that were upgraded in place; the build is authoritative.
		if name := WindowsServerName(p.Build); name != "" && !strings.Contains(p.PrettyName, name) {
			p.PrettyName = strings.TrimSpace(p.PrettyName + " (" + name + " by build)")
		}
	}
	return OK(p)
}

// WindowsServerName maps a server build number to its marketing name.
func WindowsServerName(build string) string {
	n, _ := strconv.Atoi(strings.SplitN(build, ".", 2)[0])
	switch {
	case n >= 26100:
		return "Windows Server 2025"
	case n >= 20348:
		return "Windows Server 2022"
	case n >= 17763:
		return "Windows Server 2019"
	case n >= 14393:
		return "Windows Server 2016"
	}
	return ""
}

// winProcesses: Idle (0), System (4) and the kernel's pseudo-processes have
// no image path by design; any other unreadable path makes the list partial.
func winProcesses(procs []WinProcess, err error) Obs[[]Process] {
	if err != nil {
		return unknownFrom[[]Process]("process snapshot", err)
	}
	out := make([]Process, 0, len(procs))
	hidden := 0
	var why Reason
	for _, p := range procs {
		q := Process{PID: p.PID, PPID: p.PPID, Name: p.Name, Exe: p.Exe, ExeKnown: p.Exe != "",
			Cmdline: capCmdline(p.Cmdline), User: p.User, UID: p.SID}
		if q.ExeKnown {
			q.ExeExists = !p.ExeMissing
			q.InTemp = WinInTempDir(p.Exe)
		} else if !winKernelProcess(p) {
			hidden++
			if why == "" {
				why = Classify(codeErr(p.ExeErr, p.Name))
			}
		}
		out = append(out, q)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PID < out[j].PID })
	if hidden > 0 {
		if why == "" || why == ReasonCommandFailed {
			why = ReasonPermission
		}
		return Partial(out, why, fmt.Sprintf("%d processes hide their image path", hidden))
	}
	return OK(out)
}

func winKernelProcess(p WinProcess) bool {
	switch p.PID {
	case 0, 4:
		return true
	}
	switch strings.ToLower(p.Name) {
	case "registry", "memory compression", "secure system", "vmmem", "vmmemwsl":
		return true
	}
	return false
}

func capCmdline(s string) string {
	s = MaskSecrets(s)
	if len(s) > MaxCmdline {
		s = s[:MaxCmdline] + "…"
	}
	return s
}

// WinInTempDir reports an executable under a folder any user can write to:
// the Windows and per-user temp folders, C:\Users\Public, the root of
// C:\ProgramData, the recycle bin and C:\PerfLogs.
func WinInTempDir(exe string) bool {
	p := strings.ToLower(strings.ReplaceAll(exe, "/", `\`))
	p = strings.TrimPrefix(p, `\\?\`)
	if len(p) >= 2 && p[1] == ':' {
		p = p[2:]
	}
	for _, d := range []string{`\windows\temp\`, `\users\public\`, `\$recycle.bin\`, `\perflogs\`} {
		if strings.HasPrefix(p, d) {
			return true
		}
	}
	if strings.Contains(p, `\appdata\local\temp\`) {
		return true
	}
	if rest, ok := strings.CutPrefix(p, `\programdata\`); ok && !strings.Contains(rest, `\`) {
		return true
	}
	return false
}

func winServices(svcs []WinService, err error) Obs[[]Service] {
	if err != nil {
		return unknownFrom[[]Service]("service control manager", err)
	}
	out := make([]Service, 0, len(svcs))
	unread := 0
	for _, s := range svcs {
		if s.ConfigErr != "" {
			unread++
		}
		out = append(out, Service{Name: s.Name, Exe: ServiceImage(s.BinaryPath), StartMode: s.StartType, State: s.State, RunAs: s.Account})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	if unread > 0 {
		return Partial(out, ReasonPermission, fmt.Sprintf("%d service configurations unreadable", unread))
	}
	return OK(out)
}

// ServiceImage extracts the executable from a service command line. An
// unquoted path with spaces is resolved the way the SCM tries it, shortest
// first, stopping at the first segment ending in .exe.
func ServiceImage(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	if strings.HasPrefix(cmd, `"`) {
		if end := strings.Index(cmd[1:], `"`); end >= 0 {
			return cmd[1 : end+1]
		}
		return strings.Trim(cmd, `"`)
	}
	lower := strings.ToLower(cmd)
	if i := strings.Index(lower, ".exe"); i >= 0 {
		return cmd[:i+4]
	}
	if i := strings.IndexByte(cmd, ' '); i >= 0 {
		return cmd[:i]
	}
	return cmd
}

// UnquotedServicePath reports the classic privilege-escalation shape: the
// image path has a space before .exe and no quotes.
func UnquotedServicePath(cmd string) bool {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" || strings.HasPrefix(cmd, `"`) {
		return false
	}
	return strings.Contains(ServiceImage(cmd), " ")
}

func winListeners(socks []WinSocket, err error, procs []WinProcess) Obs[[]Listener] {
	if err != nil {
		return unknownFrom[[]Listener]("socket tables", err)
	}
	names := map[int]string{}
	for _, p := range procs {
		names[p.PID] = p.Name
	}
	out := make([]Listener, 0, len(socks))
	for _, s := range socks {
		if strings.HasPrefix(s.Proto, "tcp") && s.State != "LISTEN" {
			continue
		}
		out = append(out, Listener{Proto: s.Proto, Addr: s.Addr, Port: s.Port, PID: s.OwnerPID, Process: names[s.OwnerPID]})
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Proto != b.Proto {
			return a.Proto < b.Proto
		}
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		return a.Addr < b.Addr
	})
	return OK(out)
}

func winAccounts(ws WinSource) Obs[[]Account] {
	users, err := ws.Users()
	if err != nil {
		return unknownFrom[[]Account]("NetUserEnum", err)
	}
	admins := map[string]bool{}
	members, merr := ws.GroupMembers(SIDAdministrators)
	for _, m := range members {
		admins[m] = true
	}
	out := make([]Account, 0, len(users))
	for _, u := range users {
		out = append(out, Account{Name: u.Name, UID: u.SID, Home: u.Home, CanLogin: !u.Disabled, IsAdmin: admins[u.SID], Disabled: u.Disabled})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	if merr != nil {
		return Partial(out, Classify(merr), "Administrators membership unreadable: is_admin unknown")
	}
	return OK(out)
}

// userHives are the loaded per-user hives (HKU\S-1-5-21-…), without the
// _Classes companions.
func userHives(ws WinSource) ([]string, error) {
	names, err := ws.RegSubkeys(`HKU`)
	var out []string
	for _, n := range names {
		if strings.HasPrefix(n, "S-1-5-21-") && !strings.HasSuffix(n, "_Classes") {
			out = append(out, `HKU\`+n)
		}
	}
	return out, err
}

// winPackages reads the Uninstall keys: 64-bit, 32-bit and each loaded
// user hive. Updates (ParentKeyName) and entries without a DisplayName are
// not programs and are skipped.
func winPackages(ws WinSource) Obs[PackageSet] {
	set := PackageSet{Manager: "msi-registry"}
	roots := []struct{ key, arch string }{{KeyUninstall, "x64"}, {KeyUninstall32, "x86"}}
	hives, herr := userHives(ws)
	for _, h := range hives {
		roots = append(roots, struct{ key, arch string }{h + `\Software\Microsoft\Windows\CurrentVersion\Uninstall`, ""})
	}
	var unread []string
	if herr != nil {
		unread = append(unread, `HKU (`+string(Classify(herr))+`)`)
	}
	seen := map[string]bool{}
	readOne := false
	for _, r := range roots {
		subs, err := ws.RegSubkeys(r.key)
		if err != nil {
			if !isNotExist(err) {
				unread = append(unread, r.key+" ("+string(Classify(err))+")")
			}
			continue
		}
		readOne = true
		for _, s := range subs {
			v, err := ws.RegValues(r.key + `\` + s)
			if err != nil {
				if !isNotExist(err) {
					unread = append(unread, r.key+`\`+s+" ("+string(Classify(err))+")")
				}
				continue
			}
			name := strings.TrimSpace(regString(v, "DisplayName"))
			if name == "" || regString(v, "ParentKeyName") != "" {
				continue
			}
			p := Package{Name: name, Version: strings.TrimSpace(regString(v, "DisplayVersion")), Arch: r.arch}
			k := p.Name + "\x00" + p.Version + "\x00" + p.Arch
			if !seen[k] {
				seen[k] = true
				set.Items = append(set.Items, p)
			}
		}
	}
	sort.Slice(set.Items, func(i, j int) bool {
		a, b := set.Items[i], set.Items[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Version+a.Arch < b.Version+b.Arch
	})
	if !readOne {
		return Unknown[PackageSet](ReasonPermission, "no Uninstall key readable: "+strings.Join(unread, "; "))
	}
	if len(unread) > 0 {
		return Partial(set, ReasonPermission, "unreadable: "+strings.Join(unread, "; "))
	}
	return OK(set)
}

// cbsInstalled is CBS CurrentState "Installed" (0x70). 0x50 is "Staged",
// 0x20 "Install Pending"; neither protects the host yet.
const cbsInstalled = 0x70

// winPatches reads Component Based Servicing packages: one entry per KB
// that has a package in the Installed state. The build and UBR in platform
// stay the main signal, as cumulative updates do not always name their KB.
func winPatches(ws WinSource) Obs[[]Patch] {
	subs, err := ws.RegSubkeys(KeyCBSPackages)
	if err != nil {
		return unknownFrom[[]Patch](KeyCBSPackages, err)
	}
	byKB := map[string]string{}
	unread := 0
	var firstErr error
	for _, s := range subs {
		kb := CBSPackageKB(s)
		if kb == "" {
			continue
		}
		v, err := ws.RegValues(KeyCBSPackages + `\` + s)
		if err != nil {
			unread++
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if regInt(v, "CurrentState", 0) != cbsInstalled {
			continue
		}
		when := filetimeDate(regInt(v, "InstallTimeHigh", 0), regInt(v, "InstallTimeLow", 0))
		if old, ok := byKB[kb]; !ok || (when != "" && (old == "" || when < old)) {
			byKB[kb] = when
		}
	}
	out := make([]Patch, 0, len(byKB))
	for kb, when := range byKB {
		out = append(out, Patch{ID: kb, InstalledOn: when})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	if unread > 0 {
		return Partial(out, Classify(firstErr), fmt.Sprintf("%d servicing packages unreadable", unread))
	}
	return OK(out)
}

// CBSPackageKB pulls "KB5034439" out of a CBS package key such as
// "Package_for_KB5034439~31bf3856ad364e35~amd64~~20348.2227.1.3" or
// "Package_1_for_KB5034439~…".
func CBSPackageKB(name string) string {
	i := strings.Index(name, "_KB")
	if i < 0 || !strings.HasPrefix(name, "Package_") {
		return ""
	}
	j := i + 3
	for j < len(name) && name[j] >= '0' && name[j] <= '9' {
		j++
	}
	if j == i+3 {
		return ""
	}
	return name[i+1 : j]
}

// filetimeDate turns a FILETIME split in two DWORDs into YYYY-MM-DD.
func filetimeDate(high, low uint64) string {
	t, ok := filetime(high<<32 | low)
	if !ok {
		return ""
	}
	return t.Format("2006-01-02")
}

func filetime(ft uint64) (time.Time, bool) {
	const epochDiff = 116444736000000000 // 1601-01-01 to 1970-01-01 in 100ns
	if ft <= epochDiff {
		return time.Time{}, false
	}
	return time.Unix(0, 0).Add(time.Duration(ft-epochDiff) * 100).UTC(), true
}

// winPersistence gathers autostart locations, WMI event subscriptions
// included.
func winPersistence(ws WinSource, svcs []WinService, svcErr error) Obs[[]PersistenceItem] {
	var out []PersistenceItem
	var unread []string
	perKind := map[string]int{}
	dropped := 0
	add := func(it PersistenceItem) {
		if perKind[it.Kind] >= MaxPersistenceItems {
			dropped++
			return
		}
		perKind[it.Kind]++
		it.Command = capCmdline(it.Command)
		out = append(out, it)
	}
	note := func(what string, err error) {
		if err != nil && !isNotExist(err) {
			unread = append(unread, what+" ("+string(Classify(err))+")")
		}
	}
	values := func(key string) map[string]RegValue {
		v, err := ws.RegValues(key)
		note(key, err)
		return v
	}

	// Run keys, machine-wide and per loaded user hive.
	hives := []string{`HKLM\SOFTWARE`, `HKLM\SOFTWARE\WOW6432Node`}
	users, herr := userHives(ws)
	note("HKU", herr)
	for _, u := range users {
		hives = append(hives, u+`\Software`)
	}
	for _, h := range hives {
		for _, sub := range []string{`Microsoft\Windows\CurrentVersion\Run`, `Microsoft\Windows\CurrentVersion\RunOnce`,
			`Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`} {
			key := h + `\` + sub
			v := values(key)
			for _, name := range sortedNames(v) {
				add(PersistenceItem{Kind: "run_key", Location: key + `\` + name, Command: regText(v[name])})
			}
		}
	}

	// Winlogon shell and userinit, AppInit_DLLs, IFEO debuggers.
	wl := values(KeyWinlogon)
	for _, name := range []string{"Shell", "Userinit"} {
		if r, ok := wl[name]; ok {
			add(PersistenceItem{Kind: "run_key", Location: KeyWinlogon + `\` + name, Command: regText(r), Detail: "winlogon"})
		}
	}
	if v := values(KeyWindowsNT); strings.TrimSpace(regString(v, "AppInit_DLLs")) != "" {
		detail := "appinit_dlls"
		if regInt(v, "LoadAppInit_DLLs", 0) == 0 {
			detail += " (LoadAppInit_DLLs=0)"
		}
		add(PersistenceItem{Kind: "run_key", Location: KeyWindowsNT + `\AppInit_DLLs`, Command: regString(v, "AppInit_DLLs"), Detail: detail})
	}
	ifeo, err := ws.RegSubkeys(KeyIFEO)
	note(KeyIFEO, err)
	for _, exe := range ifeo {
		if v := values(KeyIFEO + `\` + exe); regString(v, "Debugger") != "" {
			add(PersistenceItem{Kind: "run_key", Location: KeyIFEO + `\` + exe + `\Debugger`, Command: regString(v, "Debugger"), Detail: "ifeo"})
		}
	}

	// Services that start without anyone logging in.
	if svcErr != nil {
		note("services", svcErr)
	}
	for _, s := range svcs {
		if s.StartType != "auto" && s.StartType != "boot" && s.StartType != "system" {
			continue
		}
		detail := s.StartType
		if s.Account != "" {
			detail += " as " + s.Account
		}
		if UnquotedServicePath(s.BinaryPath) {
			detail += "; unquoted path with spaces"
		}
		add(PersistenceItem{Kind: "service", Location: "service:" + s.Name, Command: s.BinaryPath, Detail: detail})
	}

	// Scheduled tasks.
	tasks, terr := ws.Tasks()
	note(`C:\Windows\System32\Tasks`, terr)
	for _, t := range tasks {
		if t.Err != "" {
			note(`task `+t.Path, codeErr(t.Err, t.Path))
			continue
		}
		detail := "disabled"
		if t.Enabled {
			detail = "enabled"
		}
		if t.RunAs != "" {
			detail += " as " + t.RunAs
		}
		if len(t.Triggers) > 0 {
			detail += "; triggers " + strings.Join(t.Triggers, ",")
		}
		add(PersistenceItem{Kind: "schtask", Location: "task:" + t.Path, Command: strings.Join(t.Actions, " ; "), Detail: detail})
	}

	// Startup folders: all users, then each profile.
	startup := []string{winStartupAll}
	profiles, perr := ws.RegSubkeys(KeyProfileList)
	note(KeyProfileList, perr)
	for _, sid := range profiles {
		if !strings.HasPrefix(sid, "S-1-5-21-") {
			continue
		}
		if home := regString(values(KeyProfileList+`\`+sid), "ProfileImagePath"); home != "" {
			startup = append(startup, home+`\`+winStartupPerUser)
		}
	}
	for _, dir := range startup {
		names, err := ws.ReadDir(dir)
		note(dir, err)
		for _, n := range names {
			if strings.EqualFold(n, "desktop.ini") {
				continue
			}
			add(PersistenceItem{Kind: "startup_folder", Location: dir + `\` + n})
		}
	}

	// WMI event subscriptions: consumers that run a command or a script.
	for _, ns := range []string{NamespaceSubscription, NamespaceDefaultWMI} {
		items, err := wmiSubscriptions(ws, ns)
		note("WMI "+ns, err)
		for _, it := range items {
			add(it)
		}
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Location < out[j].Location
	})
	switch {
	case dropped > 0:
		return Partial(out, ReasonTruncated, fmt.Sprintf("%d items over the per-kind cap of %d", dropped, MaxPersistenceItems))
	case len(unread) > 0:
		return Partial(out, ReasonPermission, "unreadable: "+strings.Join(unread, "; "))
	}
	return OK(out)
}

func sortedNames(v map[string]RegValue) []string {
	names := make([]string, 0, len(v))
	for n := range v {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

func regText(r RegValue) string {
	if len(r.Strings) > 0 {
		return strings.Join(r.Strings, " ")
	}
	if r.String != "" {
		return r.String
	}
	if r.Type == "DWORD" || r.Type == "QWORD" {
		return strconv.FormatUint(r.Int, 10)
	}
	return ""
}

// winIISConfig is applicationHost.config under the system root.
const winIISConfig = `\System32\inetsrv\config\applicationHost.config`

// winWeb reports IIS: its web roots are the physical paths of every
// virtual directory in applicationHost.config. No config and no W3SVC
// service means no IIS, which is an empty, known web fact (as on Linux
// without nginx or Apache).
func winWeb(ws WinSource, svcs []WinService, svcErr error) Obs[Web] {
	root := `C:\Windows`
	if v, err := ws.RegValues(KeyCurrentVersion); err == nil {
		if r := strings.TrimRight(regString(v, "SystemRoot"), `\`); r != "" {
			root = r
		}
	}
	path := root + winIISConfig
	b, err := ws.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if _, ok := findService(svcs, "W3SVC"); ok {
			return Partial(Web{Server: "iis", ConfigUnreadable: []string{path + " (missing)"}}, ReasonNotInstalled,
				"W3SVC is installed but applicationHost.config is missing")
		}
		if svcErr != nil {
			return Partial(Web{}, Classify(svcErr), "IIS presence unknown: services unreadable")
		}
		return OK(Web{})
	case err != nil:
		return Partial(Web{Server: "iis", ConfigUnreadable: []string{path + " (" + string(Classify(err)) + ")"}}, Classify(err),
			"applicationHost.config unreadable; its web roots are missing")
	}
	roots, perr := ParseIISConfig(b, root)
	w := Web{Server: "iis"}
	if perr != nil {
		w.ConfigUnreadable = []string{path + " (malformed)"}
		return Partial(w, ReasonParse, "applicationHost.config could not be parsed")
	}
	seen := map[string]bool{}
	for _, r := range roots {
		if k := strings.ToLower(r); !seen[k] {
			seen[k] = true
			w.WebRoots = append(w.WebRoots, r)
		}
	}
	sort.Strings(w.WebRoots)
	return OK(w)
}

func findService(svcs []WinService, name string) (WinService, bool) {
	for _, s := range svcs {
		if strings.EqualFold(s.Name, name) {
			return s, true
		}
	}
	return WinService{}, false
}

// winSSH reads the OpenSSH Server config with the shared parser, up to the
// first Match (the stock file ends with "Match Group administrators").
func winSSH(ws WinSource, svcs []WinService, svcErr error) Obs[SSHConfig] {
	b, err := ws.ReadFile(winSSHDConfig)
	if errors.Is(err, fs.ErrNotExist) {
		if _, ok := findService(svcs, "sshd"); !ok && svcErr == nil {
			return NotApplicable[SSHConfig]()
		}
		return Unknown[SSHConfig](ReasonNotInstalled, "sshd service present but "+winSSHDConfig+" missing")
	}
	cfg := SSHConfig{ConfigPath: winSSHDConfig, Settings: SSHDDefaults()}
	if err != nil {
		for k := range cfg.Settings {
			cfg.Settings[k] = "unknown"
		}
		cfg.Unread = []string{winSSHDConfig}
		return Partial(cfg, Classify(err), "sshd_config unreadable; settings are \"unknown\"")
	}
	sum := sha256.Sum256(b)
	cfg.Hash = hex.EncodeToString(sum[:])[:16]
	dirs, _ := ParseSSHDConfig(b)
	got := map[string]bool{}
	include := false
	for _, d := range dirs {
		if d.Key == "include" {
			include = true
			continue
		}
		if _, want := cfg.Settings[d.Key]; want && !got[d.Key] {
			cfg.Settings[d.Key], got[d.Key] = d.Value, true
		}
	}
	if include {
		return Partial(cfg, ReasonNotCollected, "Include is not followed on Windows yet")
	}
	return OK(cfg)
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
func winWinRM(ws WinSource, socks []WinSocket, serr error) Obs[WinRMConfig] {
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

// winFirewall reads each profile's switch; a Group Policy value wins over
// the local one. A stopped firewall service (MpsSvc) filters nothing,
// whatever the switches say.
func winFirewall(ws WinSource, svcs []WinService, svcErr error) Obs[Firewall] {
	fw := Firewall{Backend: "windows", Profiles: map[string]bool{}, Extra: map[string]string{}}
	var firstErr error
	if pol, err := ws.FirewallPolicy(); err == nil && len(pol.Profiles) > 0 {
		winFirewallPolicy(&fw, pol)
	} else {
		firstErr = winFirewallRegistry(ws, &fw)
	}
	if s, ok := findService(svcs, "MpsSvc"); ok {
		fw.Extra["service"] = s.State
		if s.State != "running" {
			for k := range fw.Profiles {
				fw.Profiles[k] = false
			}
			if fw.DefaultInbound != "" {
				fw.DefaultInbound = "allow"
			}
		}
	}
	if len(fw.Extra) == 0 {
		fw.Extra = nil
	}
	for _, on := range fw.Profiles {
		fw.Enabled = fw.Enabled || on
	}
	switch {
	case len(fw.Profiles) == 0:
		return unknownFrom[Firewall](KeyFirewallPolicy, firstErr)
	case firstErr != nil:
		return Partial(fw, Classify(firstErr), "some firewall profiles unreadable")
	case svcErr != nil:
		return Partial(fw, Classify(svcErr), "firewall service state unknown")
	}
	return OK(fw)
}

// winFirewallPolicy fills fw from INetFwPolicy2. Inbound traffic counts
// as allowed by default when any active profile is off, or lets
// unmatched inbound connections through.
func winFirewallPolicy(fw *Firewall, pol WinFirewallPolicy) {
	for name, p := range pol.Profiles {
		fw.Profiles[name] = p.Enabled
	}
	if len(pol.Active) == 0 {
		return
	}
	fw.Extra["active_profiles"] = strings.Join(pol.Active, ",")
	fw.DefaultInbound = "block"
	for _, n := range pol.Active {
		if p := pol.Profiles[n]; !p.Enabled || (!p.BlockAllInbound && p.InboundAllowed) {
			fw.DefaultInbound = "allow"
		}
	}
}

// winFirewallRegistry fills fw.Profiles from the registry, group policy
// first, when INetFwPolicy2 cannot be read. It returns the first read
// error other than an absent key.
func winFirewallRegistry(ws WinSource, fw *Firewall) error {
	var firstErr error
	for _, p := range []struct{ local, gpo, name string }{
		{"DomainProfile", "DomainProfile", "Domain"}, {"StandardProfile", "PrivateProfile", "Private"}, {"PublicProfile", "PublicProfile", "Public"},
	} {
		pol, perr := ws.RegValues(KeyFirewallGPO + `\` + p.gpo)
		if perr != nil && !isNotExist(perr) {
			if firstErr == nil {
				firstErr = perr
			}
			continue
		}
		if _, ok := pol["EnableFirewall"]; ok {
			fw.Profiles[p.name] = regInt(pol, "EnableFirewall", 1) == 1
			continue
		}
		v, err := ws.RegValues(KeyFirewallPolicy + `\` + p.local)
		if err != nil && !isNotExist(err) { // an absent key means the Windows default: on
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		fw.Profiles[p.name] = regInt(v, "EnableFirewall", 1) == 1
	}
	return firstErr
}

// winDefender reads Defender's state from the registry and the WinDefend
// service, never from WMI. Policy values win over local ones. Real-time
// protection counts as on only when the service runs, nothing disables it
// and Defender is not in passive mode.
func winDefender(ws WinSource, svcs []WinService, svcErr error) Obs[Antimalware] {
	base, err := ws.RegValues(KeyDefender)
	if err != nil {
		if isNotExist(err) {
			return Unknown[Antimalware](ReasonNotInstalled, "Microsoft Defender is not installed (another antivirus may be active)")
		}
		return unknownFrom[Antimalware](KeyDefender, err)
	}
	am := Antimalware{Product: "Microsoft Defender"}
	var gaps []string
	var why Reason
	gap := func(r Reason, s string) {
		gaps = append(gaps, s)
		if why == "" {
			why = r
		}
	}
	read := func(key string) map[string]RegValue {
		v, err := ws.RegValues(key)
		if err != nil && !isNotExist(err) {
			gap(Classify(err), key+" unreadable")
		}
		return v
	}
	pol := read(KeyDefenderPolicy)
	polRT := read(KeyDefenderPolicy + `\Real-Time Protection`)
	rt := read(KeyDefender + `\Real-Time Protection`)
	disabled := func(local, policy map[string]RegValue, name string) bool {
		if _, ok := policy[name]; ok {
			return regInt(policy, name, 0) == 1
		}
		return regInt(local, name, 0) == 1
	}
	off := disabled(base, pol, "DisableAntiSpyware") || disabled(base, pol, "DisableAntiVirus")
	rtOff := disabled(rt, polRT, "DisableRealtimeMonitoring")
	passive := regInt(base, "PassiveMode", 0) == 1
	if passive {
		am.Product += " (Passive)" // another product is primary
	}
	running := false
	if s, ok := findService(svcs, "WinDefend"); ok {
		running = s.State == "running"
		if !running {
			am.Product += " (service " + s.State + ")"
		}
	} else if svcErr != nil {
		gap(Classify(svcErr), "WinDefend service state unknown")
		running = true // judged on the settings alone, and marked partial
	} else {
		am.Product += " (no WinDefend service)"
	}
	am.RealTime = running && !off && !rtOff && !passive
	sigKnown := false
	// Defender's own view wins over what the settings imply: tamper
	// protection or a third-party product can override both.
	if st, err := ws.WMI(NamespaceDefender, qMpStatus.query, qMpStatus.props); err == nil && len(st) > 0 {
		r := st[0]
		am.Product = "Microsoft Defender"
		if mode, _ := r["AMRunningMode"].(string); mode != "" && mode != "Normal" {
			am.Product += " (" + mode + ")"
		}
		am.RealTime = asBool(r["RealTimeProtectionEnabled"]) && asBool(r["AMServiceEnabled"]) && asBool(r["AntivirusEnabled"])
		if age, ok := r["AntivirusSignatureAge"]; ok && age != nil {
			am.SignatureAgeDays, sigKnown = asInt(age), true
		}
	} else if err != nil && !isNotExist(err) {
		gap(Classify(err), "runtime status unreadable (MSFT_MpComputerStatus); judged on settings")
	}

	if !sigKnown {
		sig := read(KeyDefender + `\Signature Updates`)
		if t, ok := regFiletime(sig, "SignaturesLastUpdated", "AVSignatureApplied"); ok {
			am.SignatureAgeDays = max(int(ws.Info().RecordedAt.Sub(t).Hours()/24), 0)
		} else {
			gap(ReasonNotInstalled, "signature date unknown")
		}
	}

	for _, root := range []string{KeyDefender + `\Exclusions`, KeyDefenderPolicy + `\Exclusions`} {
		for _, kind := range []string{"Paths", "Extensions", "Processes"} {
			v, err := ws.RegValues(root + `\` + kind)
			if err != nil {
				if !isNotExist(err) {
					gap(Classify(err), "exclusions hidden ("+root+`\`+kind+")")
				}
				continue
			}
			am.Exclusions = append(am.Exclusions, sortedNames(v)...)
		}
	}
	if len(am.Exclusions) == 0 && !ws.Info().Elevated {
		gap(ReasonPermission, "exclusions cannot be confirmed empty without elevation")
	}
	if len(gaps) > 0 {
		return Partial(am, why, strings.Join(gaps, "; "))
	}
	return OK(am)
}

// regFiletime reads the first of names that holds an 8-byte FILETIME.
func regFiletime(v map[string]RegValue, names ...string) (time.Time, bool) {
	for _, n := range names {
		r, ok := v[n]
		if !ok {
			continue
		}
		var ft uint64
		switch {
		case len(r.Bytes) == 8:
			ft = binary.LittleEndian.Uint64(r.Bytes)
		case r.Type == "QWORD":
			ft = r.Int
		default:
			continue
		}
		if t, ok := filetime(ft); ok {
			return t, true
		}
	}
	return time.Time{}, false
}

// Event Log queries.
var (
	securityXPath = fmt.Sprintf("*[System[(EventID=4625 or EventID=1102 or EventID=4720 or EventID=4732) and TimeCreated[timediff(@SystemTime) <= %d]]]", AuthWindowHours*3600*1000)
	systemXPath   = fmt.Sprintf("*[System[(EventID=104 or EventID=7045) and TimeCreated[timediff(@SystemTime) <= %d]]]", AuthWindowHours*3600*1000)
)

// winAuthEvents counts failed logons (4625) by source address and lists
// what an intruder leaves behind: cleared logs (1102, 104), new accounts
// (4720), local group additions (4732) and new services (7045). The
// Security log needs elevation; without it the fact is unknown.
func winAuthEvents(ws WinSource) Obs[AuthEvents] {
	ae := AuthEvents{WindowHours: AuthWindowHours, FailedBySrc: map[string]int{}}
	sec, err := ws.Events("Security", securityXPath, MaxEvents)
	if err != nil {
		return unknownFrom[AuthEvents]("Security event log", err)
	}
	sys, serr := ws.Events("System", systemXPath, MaxEvents)
	for _, e := range append(sec, sys...) {
		d := e.Data
		switch {
		case e.Channel == "Security" && e.ID == 4625:
			src := d["IpAddress"]
			if src == "" || src == "-" {
				src = "local"
			}
			ae.FailedBySrc[src]++
		case e.ID == 1102 || (e.Channel == "System" && e.ID == 104):
			ae.Notable = append(ae.Notable, AuthEvent{Kind: "log_cleared", When: e.Time, Who: d["SubjectUserName"]})
		case e.ID == 4720:
			ae.Notable = append(ae.Notable, AuthEvent{Kind: "account_created", When: e.Time, Who: d["TargetUserName"]})
		case e.ID == 4732:
			ae.Notable = append(ae.Notable, AuthEvent{Kind: "group_member_added", When: e.Time, Who: d["TargetUserName"] + " <- " + d["MemberSid"]})
		case e.ID == 7045:
			ae.Notable = append(ae.Notable, AuthEvent{Kind: "service_installed", When: e.Time, Who: d["ServiceName"]})
		}
	}
	sort.SliceStable(ae.Notable, func(i, j int) bool { return ae.Notable[i].When < ae.Notable[j].When })
	switch {
	case len(sec) >= MaxEvents:
		return Partial(ae, ReasonTruncated, fmt.Sprintf("Security log: more than %d matching events", MaxEvents))
	case serr != nil:
		return Partial(ae, Classify(serr), "System event log unreadable")
	}
	return OK(ae)
}

// wmiSubscriptions lists the command-line and script consumers in one
// namespace, each with the filters bound to it. Built-in subscriptions
// (the SCM event log consumer) use other consumer classes and are not
// listed. A namespace that does not exist is not an error.
func wmiSubscriptions(ws WinSource, ns string) ([]PersistenceItem, error) {
	get := func(q wmiQuery) ([]map[string]any, error) {
		rows, err := ws.WMI(ns, q.query, q.props)
		if isNotExist(err) {
			return nil, nil
		}
		return rows, err
	}
	filters, err := get(qWMIFilters)
	if err != nil {
		return nil, err
	}
	bindings, err := get(qWMIBindings)
	if err != nil {
		return nil, err
	}
	filterQuery := map[string]string{}
	for _, f := range filters {
		filterQuery[asString(f["Name"])] = asString(f["Query"])
	}
	// Binding paths look like __EventFilter.Name="x" and
	// CommandLineEventConsumer.Name="y"; key both by class and name.
	boundTo := map[string][]string{}
	for _, b := range bindings {
		fc, fname := wmiRef(asString(b["Filter"]))
		cc, cname := wmiRef(asString(b["Consumer"]))
		if fc != "" && cc != "" {
			desc := fname
			if q := filterQuery[fname]; q != "" {
				desc += " [" + q + "]"
			}
			boundTo[cc+"."+cname] = append(boundTo[cc+"."+cname], desc)
		}
	}
	var out []PersistenceItem
	for _, c := range []struct {
		q     wmiQuery
		class string
		cmd   func(map[string]any) string
	}{
		{qWMICmdLine, "CommandLineEventConsumer", func(r map[string]any) string {
			if t := asString(r["CommandLineTemplate"]); t != "" {
				return t
			}
			return asString(r["ExecutablePath"])
		}},
		{qWMIScript, "ActiveScriptEventConsumer", func(r map[string]any) string {
			if f := asString(r["ScriptFileName"]); f != "" {
				return asString(r["ScriptingEngine"]) + " " + f
			}
			return asString(r["ScriptingEngine"]) + ": " + asString(r["ScriptText"])
		}},
	} {
		rows, err := get(c.q)
		if err != nil {
			return out, err
		}
		for _, r := range rows {
			name := asString(r["Name"])
			detail := "unbound"
			if f := boundTo[c.class+"."+name]; len(f) > 0 {
				sort.Strings(f)
				detail = "bound to " + strings.Join(f, ", ")
			}
			out = append(out, PersistenceItem{Kind: "wmi_subscription", Location: ns + ":" + c.class + "." + name, Command: c.cmd(r), Detail: detail})
		}
	}
	return out, nil
}

// wmiRef splits a WMI object path such as
// `\\HOST\root\subscription:CommandLineEventConsumer.Name="evil"` into
// its class and Name key.
func wmiRef(path string) (class, name string) {
	// The namespace part (\\HOST\root\subscription) cannot hold a colon,
	// so the first one ends it; a colon inside the quoted name stays.
	if strings.HasPrefix(path, `\\`) {
		i := strings.IndexByte(path, ':')
		if i < 0 {
			return "", ""
		}
		path = path[i+1:]
	}
	class, key, ok := strings.Cut(path, ".")
	if !ok {
		return "", ""
	}
	_, val, ok := strings.Cut(key, "=")
	if !ok || len(val) < 2 || val[0] != '"' {
		return "", ""
	}
	// One left-to-right scan: \X is X (covers \\ and \"), and the first
	// unescaped quote ends the value.
	var b strings.Builder
	for i := 1; i < len(val); i++ {
		switch c := val[i]; {
		case c == '\\' && i+1 < len(val):
			i++
			b.WriteByte(val[i])
		case c == '"':
			return class, b.String()
		default:
			b.WriteByte(c)
		}
	}
	return "", "" // unterminated
}

func asString(v any) string {
	s, _ := v.(string)
	return s
}

func asBool(v any) bool {
	b, _ := v.(bool)
	return b
}

// asInt accepts what a live query (int64, uint64) or a JSON replay
// (float64) yields, and WMI's string-encoded 64-bit integers.
func asInt(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case uint64:
		return int(n)
	case float64:
		return int(n)
	case string:
		i, _ := strconv.Atoi(n)
		return i
	}
	return 0
}
