package hostenv

import "time"

// SchemaVersion names the facts format. Adding fields keeps "hostfacts/1";
// renaming, removing or changing the meaning of one bumps the major number.
const SchemaVersion = "hostfacts/1"

// Status says how much an observation can be trusted.
type Status string

const (
	StatusOK            Status = "ok"             // complete
	StatusPartial       Status = "partial"        // some entries hidden (Reason says why)
	StatusUnknown       Status = "unknown"        // could not be determined: checks must say so, not pass
	StatusNotApplicable Status = "not_applicable" // the platform has no such thing (RDP on Linux)
	StatusError         Status = "error"          // the collector itself failed
)

// Reason explains a non-ok Status.
type Reason string

const (
	ReasonPermission    Reason = "permission_denied"
	ReasonNotInstalled  Reason = "not_installed"
	ReasonTimeout       Reason = "timeout"
	ReasonTruncated     Reason = "output_truncated"
	ReasonNotCollected  Reason = "not_collected" // this collector does not gather it yet
	ReasonUnsupported   Reason = "unsupported_platform"
	ReasonNotRecorded   Reason = "not_recorded" // replay asked for something the fixture lacks
	ReasonCommandFailed Reason = "command_failed"
	ReasonParse         Reason = "parse_error"
	ReasonSymlink       Reason = "symlink_not_followed"
	ReasonNotRegular    Reason = "not_regular_file"
)

// Obs wraps every fact so that "unknown" can never be mistaken for "empty".
type Obs[T any] struct {
	Status Status `json:"status"`
	Reason Reason `json:"reason,omitempty"`
	Detail string `json:"detail,omitempty"`
	Value  T      `json:"value"`
}

func OK[T any](v T) Obs[T] { return Obs[T]{Status: StatusOK, Value: v} }

// Partial is a usable value with entries missing for reason r.
func Partial[T any](v T, r Reason, detail string) Obs[T] {
	return Obs[T]{Status: StatusPartial, Reason: r, Detail: detail, Value: v}
}

func Unknown[T any](r Reason, detail string) Obs[T] {
	return Obs[T]{Status: StatusUnknown, Reason: r, Detail: detail}
}

func NotApplicable[T any]() Obs[T] { return Obs[T]{Status: StatusNotApplicable} }

// Known reports whether the value can be relied on (fully or partly).
func (o Obs[T]) Known() bool { return o.Status == StatusOK || o.Status == StatusPartial }

// Facts is one snapshot of a host.
type Facts struct {
	Schema      string        `json:"schema"`
	CollectedAt time.Time     `json:"collected_at"`
	Collector   CollectorInfo `json:"collector"`

	Platform     Obs[Platform]          `json:"platform"`
	Privilege    Obs[Privilege]         `json:"privilege"`
	Resources    Obs[Resources]         `json:"resources"`
	Packages     Obs[PackageSet]        `json:"packages"`
	Patches      Obs[[]Patch]           `json:"patches"`
	Services     Obs[[]Service]         `json:"services"`
	Processes    Obs[[]Process]         `json:"processes"`
	Accounts     Obs[[]Account]         `json:"accounts"`
	Listeners    Obs[[]Listener]        `json:"listeners"`
	Persistence  Obs[[]PersistenceItem] `json:"persistence"`
	Firewall     Obs[Firewall]          `json:"firewall"`
	RemoteAccess RemoteAccess           `json:"remote_access"`
	Antimalware  Obs[Antimalware]       `json:"antimalware"`
	AuthEvents   Obs[AuthEvents]        `json:"auth_events"`
	Web          Obs[Web]               `json:"web"`
}

type CollectorInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Platform struct {
	OS          string `json:"os"`               // GOOS spelling: linux, windows, darwin, freebsd
	Family      string `json:"family,omitempty"` // debian, rhel, alpine, suse, arch, windows-server
	Distro      string `json:"distro,omitempty"` // os-release ID, or "windows"
	Version     string `json:"version,omitempty"`
	PrettyName  string `json:"pretty_name,omitempty"`
	Build       string `json:"build,omitempty"` // Windows CurrentBuild.UBR, macOS build
	Kernel      string `json:"kernel,omitempty"`
	Arch        string `json:"arch,omitempty"`
	InContainer bool   `json:"in_container"`
	ServerCore  bool   `json:"server_core,omitempty"`
}

// Resources is the machine's capacity as the collecting process sees it:
// cgroup limits are those of the collector's own cgroup (the service that
// runs Shentu). Zero means not known.
type Resources struct {
	MemTotalBytes     uint64  `json:"mem_total_bytes"`
	MemAvailableBytes uint64  `json:"mem_available_bytes"`
	Load1             float64 `json:"load1"`
	CgroupMemoryLimit uint64  `json:"cgroup_memory_limit,omitempty"` // lowest limit on the way up
	CgroupCPUs        int     `json:"cgroup_cpus,omitempty"`         // CPU quota, rounded up
}

type Privilege struct {
	Elevated bool `json:"elevated"` // root, or an elevated Administrator token
}

type PackageSet struct {
	Manager   string    `json:"manager"`             // dpkg, rpm, apk, msi-registry
	Ecosystem string    `json:"ecosystem,omitempty"` // OSV ecosystem, e.g. "Debian:12"
	Items     []Package `json:"items"`
}

type Package struct {
	Name    string `json:"name"`
	Source  string `json:"source,omitempty"` // source package (dpkg) when it differs
	Version string `json:"version"`
	Arch    string `json:"arch,omitempty"`
}

type Patch struct {
	ID          string `json:"id"` // KB number, advisory id
	InstalledOn string `json:"installed_on,omitempty"`
}

type Service struct {
	Name      string `json:"name"`
	Exe       string `json:"exe,omitempty"`
	StartMode string `json:"start_mode,omitempty"` // auto, manual, disabled
	State     string `json:"state,omitempty"`
	RunAs     string `json:"run_as,omitempty"`
}

type Process struct {
	PID       int    `json:"pid"`
	PPID      int    `json:"ppid"`
	Name      string `json:"name"`
	Exe       string `json:"exe,omitempty"`     // empty when it could not be read
	ExeKnown  bool   `json:"exe_known"`         // false: permission or kernel thread
	ExeExists bool   `json:"exe_exists"`        // false: deleted after start
	InTemp    bool   `json:"in_temp"`           // exe under a world-writable temp dir
	Cmdline   string `json:"cmdline,omitempty"` // secret-masked, capped
	User      string `json:"user,omitempty"`
	UID       string `json:"uid,omitempty"` // uid or SID
}

type Account struct {
	Name     string `json:"name"`
	UID      string `json:"uid"` // uid or SID
	Home     string `json:"home,omitempty"`
	Shell    string `json:"shell,omitempty"`
	CanLogin bool   `json:"can_login"`
	IsAdmin  bool   `json:"is_admin"` // uid 0, sudo/wheel/admin group, Administrators
	Disabled bool   `json:"disabled,omitempty"`
}

type Listener struct {
	Proto   string `json:"proto"` // tcp, tcp6, udp, udp6
	Addr    string `json:"addr"`
	Port    int    `json:"port"`
	PID     int    `json:"pid,omitempty"` // 0 when the owner could not be seen
	Process string `json:"process,omitempty"`
}

// PersistenceItem is anything that makes code run again without a person
// starting it.
type PersistenceItem struct {
	Kind     string `json:"kind"` // cron, systemd, ld_preload, authorized_key, run_key, schtask, service, wmi_subscription, startup_folder, launchd
	Location string `json:"location"`
	Command  string `json:"command,omitempty"` // secret-masked
	Detail   string `json:"detail,omitempty"`
}

type Firewall struct {
	Backend        string            `json:"backend"` // nftables, iptables, ufw, firewalld, windows, pf
	Enabled        bool              `json:"enabled"`
	DefaultInbound string            `json:"default_inbound,omitempty"` // allow, block
	Profiles       map[string]bool   `json:"profiles,omitempty"`        // Windows Domain/Private/Public
	Extra          map[string]string `json:"extra,omitempty"`
}

type RemoteAccess struct {
	SSH   Obs[SSHConfig]   `json:"ssh"`
	RDP   Obs[RDPConfig]   `json:"rdp"`
	WinRM Obs[WinRMConfig] `json:"winrm"`
	SMB   Obs[SMBConfig]   `json:"smb"`
}

type SSHConfig struct {
	ConfigPath string            `json:"config_path"`
	Settings   map[string]string `json:"settings"` // lower-case keys; "unknown" when a file could not be read
	Unread     []string          `json:"unread,omitempty"`
	Hash       string            `json:"hash,omitempty"`
}

type RDPConfig struct {
	Enabled       bool   `json:"enabled"`
	NLA           bool   `json:"nla"`
	Port          int    `json:"port"`
	SecurityLayer string `json:"security_layer,omitempty"`
}

type WinRMConfig struct {
	Running          bool `json:"running"`
	HTTPListener     bool `json:"http_listener"`
	AllowUnencrypted bool `json:"allow_unencrypted"`
	BasicAuth        bool `json:"basic_auth"`
}

type SMBConfig struct {
	SMB1Enabled     bool     `json:"smb1_enabled"`
	SigningRequired bool     `json:"signing_required"`
	WritableShares  []string `json:"writable_shares,omitempty"`
}

type Antimalware struct {
	Product          string   `json:"product"`
	RealTime         bool     `json:"real_time"`
	SignatureAgeDays int      `json:"signature_age_days"`
	Exclusions       []string `json:"exclusions,omitempty"`
}

type AuthEvents struct {
	WindowHours int            `json:"window_hours"`
	FailedBySrc map[string]int `json:"failed_by_source,omitempty"`
	Notable     []AuthEvent    `json:"notable,omitempty"` // log cleared, account created, ...
}

type AuthEvent struct {
	Kind string `json:"kind"`
	When string `json:"when"`
	Who  string `json:"who,omitempty"`
}

type Web struct {
	Server     string   `json:"server,omitempty"` // nginx, apache, iis
	WebRoots   []string `json:"webroots,omitempty"`
	UploadDirs []string `json:"upload_dirs,omitempty"`
}

// NewFacts returns a Facts with every observation marked not collected, so a
// collector that forgets a field leaves an honest "unknown" behind.
func NewFacts(name, version string, at time.Time) *Facts {
	nc := ReasonNotCollected
	return &Facts{
		Schema:      SchemaVersion,
		CollectedAt: at.UTC(),
		Collector:   CollectorInfo{Name: name, Version: version},
		Platform:    Unknown[Platform](nc, ""),
		Privilege:   Unknown[Privilege](nc, ""),
		Resources:   Unknown[Resources](nc, ""),
		Packages:    Unknown[PackageSet](nc, ""),
		Patches:     Unknown[[]Patch](nc, ""),
		Services:    Unknown[[]Service](nc, ""),
		Processes:   Unknown[[]Process](nc, ""),
		Accounts:    Unknown[[]Account](nc, ""),
		Listeners:   Unknown[[]Listener](nc, ""),
		Persistence: Unknown[[]PersistenceItem](nc, ""),
		Firewall:    Unknown[Firewall](nc, ""),
		RemoteAccess: RemoteAccess{
			SSH:   Unknown[SSHConfig](nc, ""),
			RDP:   Unknown[RDPConfig](nc, ""),
			WinRM: Unknown[WinRMConfig](nc, ""),
			SMB:   Unknown[SMBConfig](nc, ""),
		},
		Antimalware: Unknown[Antimalware](nc, ""),
		AuthEvents:  Unknown[AuthEvents](nc, ""),
		Web:         Unknown[Web](nc, ""),
	}
}
