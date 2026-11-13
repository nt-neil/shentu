package hostenv

// Where each Linux distribution's security fixes are published, and the
// pieces needed to match installed packages against them: OSV for the
// distributions it covers (Debian, Ubuntu, Alpine, Rocky, Alma, SUSE,
// openSUSE), ALAS updateinfo for Amazon Linux, which OSV does not carry.

import (
	"encoding/xml"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

// PatchFeed says how a host's packages are matched to security fixes.
type PatchFeed struct {
	Kind       string   `json:"kind"`                  // osv, alas; "" when none is known
	Ecosystems []string `json:"ecosystems,omitempty"`  // OSV ecosystems to query (SLES: one per module)
	Release    string   `json:"release,omitempty"`     // alas: "2" or "2023"
	Repos      []string `json:"repos,omitempty"`       // alas 2: the amazon-linux-extras topics enabled (kernel-5.10, php8.2)
	Upgrade    string   `json:"upgrade,omitempty"`     // the command that installs the fixes
	VersionFmt string   `json:"version_fmt,omitempty"` // how OSV spells versions: "evr" (epoch:version-release) or "vr" (no epoch when 0)
	NotQueried []string `json:"not_queried,omitempty"` // ecosystems the host has that OSV does not carry, so their packages are not checked
	Note       string   `json:"note,omitempty"`        // how the ecosystems were chosen, when that needs saying
}

// slesModules are the SLE 15 modules whose packages OSV lists under their
// own ecosystem ("SUSE:Linux Enterprise Module for Basesystem 15 SP5").
// The Python 3, HPC and Package Hub names were checked against OSV
// (2026-11-13: python311, slurm and chromium have advisories there); a
// module the host does not have only matches no package.
var slesModules = []string{
	"Linux Enterprise Server", "Linux Enterprise Module for Basesystem", "Linux Enterprise Module for Server Applications",
	"Linux Enterprise Module for Development Tools", "Linux Enterprise Module for Web and Scripting",
	"Linux Enterprise Module for Public Cloud", "Linux Enterprise Module for Containers", "Linux Enterprise Module for Legacy",
	"Linux Enterprise Module for Desktop Applications", "Linux Enterprise Module for Python 3",
	"Linux Enterprise Module for HPC", "Package Hub", "Linux Enterprise Live Patching",
	"Linux Enterprise High Availability Extension",
}

// slesNotInOSV are SLE 15 products a host may have that OSV does not carry
// under any name tried (kernel-rt has no advisory under "Real Time"); each
// with the product file or package that shows the host has it.
var slesNotInOSV = []string{"Linux Enterprise Real Time"}

var sleProductSigns = map[string]struct{ prod, pkg string }{
	"Linux Enterprise Real Time": {"/etc/products.d/SLE_RT.prod", "kernel-rt"},
}

// DropAbsentSLEProducts keeps the not-queried SLE products the host has:
// its products.d file, or the package that comes with it, installed.
func DropAbsentSLEProducts(f *PatchFeed, src Source, items []Package) {
	var keep []string
	for _, nq := range f.NotQueried {
		present := true
		for name, sign := range sleProductSigns {
			if !strings.Contains(nq, name) {
				continue
			}
			present = false
			if _, err := Stat(src, sign.prod); err == nil {
				present = true
			}
			for _, p := range items {
				present = present || p.Name == sign.pkg
			}
		}
		if present {
			keep = append(keep, nq)
		}
	}
	f.NotQueried = keep
}

// sledModules are where SLED 15's packages are in OSV: "Linux Enterprise
// Desktop" itself is no OSV ecosystem, and the server modules do not apply.
// Workstation Extension was checked (libreoffice has advisories there).
var sledModules = []string{
	"Linux Enterprise Module for Basesystem", "Linux Enterprise Module for Desktop Applications",
	"Linux Enterprise Module for Development Tools", "Linux Enterprise Module for Python 3",
	"Linux Enterprise Workstation Extension", "Package Hub",
}

// PatchFeedFor names the feed for a parsed os-release.
func PatchFeedFor(osr map[string]string) PatchFeed {
	id, ver := osr["ID"], osr["VERSION_ID"]
	major := strings.Split(ver, ".")[0]
	switch id {
	case "debian", "ubuntu":
		return PatchFeed{Kind: "osv", Ecosystems: []string{OSVEcosystem(osr)}, Upgrade: "apt-get update && apt-get upgrade", VersionFmt: "evr"}
	case "rocky", "almalinux":
		return PatchFeed{Kind: "osv", Ecosystems: []string{OSVEcosystem(osr)}, Upgrade: "dnf upgrade --security", VersionFmt: "evr"}
	case "alpine":
		return PatchFeed{Kind: "osv", Ecosystems: []string{OSVEcosystem(osr)}, Upgrade: "apk upgrade", VersionFmt: "evr"}
	case "opensuse-leap":
		return PatchFeed{Kind: "osv", Ecosystems: []string{"openSUSE:Leap " + ver}, Upgrade: "zypper patch --category security", VersionFmt: "vr"}
	case "opensuse-tumbleweed", "opensuse-slowroll":
		return PatchFeed{Kind: "osv", Ecosystems: []string{"openSUSE:Tumbleweed"}, Upgrade: "zypper dup", VersionFmt: "vr"}
	case "sles", "sled", "sles_sap":
		sp := slesRelease(ver)
		f := PatchFeed{Kind: "osv", Upgrade: "zypper patch --category security", VersionFmt: "vr"}
		mods := slesModules
		switch {
		case major != "15":
			mods = []string{"Linux Enterprise Server"}
			if id == "sled" {
				mods = []string{"Linux Enterprise Desktop"}
			}
			if id == "sles_sap" { // not confirmed in OSV for SLE 12
				f.NotQueried = []string{"SUSE:Linux Enterprise Server for SAP Applications " + sp + " (not confirmed in OSV)"}
			}
		case id == "sled":
			mods = sledModules
			// Not a gap: SLED's packages are all in its modules' ecosystems.
			f.Note = "SUSE:Linux Enterprise Desktop " + sp + " is no OSV ecosystem; its modules are queried"
		case id == "sles_sap":
			// The product carries the SAP packages; OSV has no "Module for SAP Applications".
			mods = append(append([]string(nil), slesModules...), "Linux Enterprise Server for SAP Applications")
			f.NotQueried = []string{"SUSE:Linux Enterprise Module for SAP Applications " + sp + " (no such OSV ecosystem)"}
		}
		for _, m := range mods {
			f.Ecosystems = append(f.Ecosystems, "SUSE:"+m+" "+sp)
		}
		if major == "15" && id != "sled" {
			for _, m := range slesNotInOSV {
				f.NotQueried = append(f.NotQueried, "SUSE:"+m+" "+sp+" (no such OSV ecosystem)")
			}
		}
		// slesNotInOSV entries stay only when the host has that product:
		// LinuxCollector.packages drops them otherwise (SLEProductPresent).
		return f
	case "amzn":
		switch ver {
		case "2":
			return PatchFeed{Kind: "alas", Release: ver, Upgrade: "yum update --security"}
		case "2023":
			return PatchFeed{Kind: "alas", Release: ver, Upgrade: "dnf upgrade --security"}
		}
		// Amazon Linux 1 (2018.03) is past its end of life: no feed, so
		// its packages cannot be told vulnerable or not.
	}
	return PatchFeed{}
}

// slesRelease turns VERSION_ID "15.5" into "15 SP5" and "15" into "15".
func slesRelease(ver string) string {
	major, minor, ok := strings.Cut(ver, ".")
	if !ok || minor == "0" {
		return major
	}
	return major + " SP" + minor
}

// FeedVersion spells an rpm "epoch:version-release" the way the feed's
// OSV records do.
func (f PatchFeed) FeedVersion(evr string) string {
	if f.VersionFmt == "vr" {
		return strings.TrimPrefix(evr, "0:")
	}
	return evr
}

// ALASMirrorList is where Amazon Linux publishes the repository for a
// release and architecture (aarch64, x86_64); public, outside AWS too.
func ALASMirrorList(release, arch string) string {
	if release == "2" {
		return "https://cdn.amazonlinux.com/2/core/latest/" + arch + "/mirror.list"
	}
	return "https://cdn.amazonlinux.com/al2023/core/mirrors/latest/" + arch + "/mirror.list"
}

// AL2ExtrasRepo is where amazon-linux-extras keeps its repositories.
const AL2ExtrasRepo = "/etc/yum.repos.d/amzn2-extras.repo"

var extrasTopic = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]*$`)

// ParseAL2Extras returns the topics amzn2-extras.repo enables: sections
// [amzn2extra-<topic>] with enabled=1, sorted.
func ParseAL2Extras(b []byte) []string {
	var out []string
	topic, enabled := "", false
	flush := func() {
		if topic != "" && enabled && extrasTopic.MatchString(topic) {
			out = append(out, topic)
		}
	}
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		switch {
		case strings.HasPrefix(l, "[") && strings.HasSuffix(l, "]"):
			flush()
			name := strings.Trim(l, "[]")
			topic, enabled = strings.TrimPrefix(name, "amzn2extra-"), false
			if topic == name { // not an extras section
				topic = ""
			}
		default: // "enabled=1" exactly: enabled_metadata and the like are other keys
			if k, v, ok := strings.Cut(l, "="); ok && strings.TrimSpace(k) == "enabled" {
				enabled = strings.TrimSpace(v) == "1"
			}
		}
	}
	flush()
	sort.Strings(out)
	return out
}

// ALASExtrasMirrorList is where an amazon-linux-extras topic's repository
// is published (Amazon Linux 2 only); "" for a name that is not a topic.
func ALASExtrasMirrorList(topic, arch string) string {
	if !extrasTopic.MatchString(topic) {
		return ""
	}
	return "https://cdn.amazonlinux.com/2/extras/" + topic + "/latest/" + arch + "/mirror.list"
}

// RPMArch is the rpm name of a GOARCH.
func RPMArch(goarch string) string {
	switch goarch {
	case "arm64":
		return "aarch64"
	case "amd64":
		return "x86_64"
	}
	return goarch
}

// Advisory is one security update of an updateinfo.xml, reduced to the
// packages a host has installed.
type Advisory struct {
	ID       string
	Severity string
	CVEs     []string
	Fixed    map[string]string // package name -> fixed epoch:version-release (highest of any arch)
	// FixedArch is the fix per package and architecture (FixedKey):
	// an advisory may fix one architecture only.
	FixedArch map[string]string
}

// FixedKey is the FixedArch key of a package and architecture.
func FixedKey(name, arch string) string { return name + "\x00" + arch }

// ScanUpdateInfo reads an updateinfo.xml stream and calls fn for each
// security advisory that names one of the installed packages, holding one
// advisory at a time: memory does not grow with the file.
func ScanUpdateInfo(r io.Reader, installed map[string]bool, fn func(Advisory)) error {
	dec := xml.NewDecoder(r)
	var adv *Advisory
	security := false
	var field string
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch t.Name.Local {
			case "update":
				adv, security = &Advisory{Fixed: map[string]string{}, FixedArch: map[string]string{}}, attr(t, "type") == "security"
			case "id", "severity":
				field = t.Name.Local
			case "reference":
				if adv != nil && attr(t, "type") == "cve" {
					if id := attr(t, "id"); id != "" {
						adv.CVEs = append(adv.CVEs, id)
					}
				}
			case "package":
				if adv != nil && installed[attr(t, "name")] {
					e := attr(t, "epoch")
					if e == "" {
						e = "0"
					}
					evr := e + ":" + attr(t, "version") + "-" + attr(t, "release")
					name := attr(t, "name")
					// An advisory lists every architecture: keep the highest fix.
					if old, ok := adv.Fixed[name]; !ok || CompareEVR(evr, old) > 0 {
						adv.Fixed[name] = evr
					}
					k := FixedKey(name, attr(t, "arch"))
					if old, ok := adv.FixedArch[k]; !ok || CompareEVR(evr, old) > 0 {
						adv.FixedArch[k] = evr
					}
				}
			}
		case xml.CharData:
			if adv != nil && field != "" {
				s := strings.TrimSpace(string(t))
				switch field {
				case "id":
					adv.ID += s
				case "severity":
					adv.Severity += s
				}
			}
		case xml.EndElement:
			switch t.Name.Local {
			case "id", "severity":
				field = ""
			case "update":
				if adv != nil && security && len(adv.Fixed) > 0 {
					fn(*adv)
				}
				adv = nil
			}
		}
	}
}

func attr(t xml.StartElement, name string) string {
	for _, a := range t.Attr {
		if a.Name.Local == name {
			return a.Value
		}
	}
	return ""
}

// CompareEVR compares two rpm "epoch:version-release" strings (a missing
// epoch is 0), as rpm does: -1, 0 or 1.
func CompareEVR(a, b string) int {
	ea, va, ra := splitEVR(a)
	eb, vb, rb := splitEVR(b)
	if ea != eb {
		if ea < eb {
			return -1
		}
		return 1
	}
	if c := RPMVerCmp(va, vb); c != 0 {
		return c
	}
	return RPMVerCmp(ra, rb)
}

func splitEVR(s string) (epoch int, version, release string) {
	if e, rest, ok := strings.Cut(s, ":"); ok {
		epoch, _ = strconv.Atoi(e)
		s = rest
	}
	if i := strings.LastIndexByte(s, '-'); i >= 0 {
		return epoch, s[:i], s[i+1:]
	}
	return epoch, s, ""
}

// RPMVerCmp is rpm's rpmvercmp: segments of digits compare as numbers,
// segments of letters as strings, digits beat letters, "~" sorts before
// anything (even the end), "^" after the end but before anything else.
func RPMVerCmp(a, b string) int {
	if a == b {
		return 0
	}
	isSep := func(r byte) bool {
		return !(r < 128 && (unicode.IsLetter(rune(r)) || unicode.IsDigit(rune(r)))) && r != '~' && r != '^'
	}
	for len(a) > 0 || len(b) > 0 {
		for len(a) > 0 && isSep(a[0]) {
			a = a[1:]
		}
		for len(b) > 0 && isSep(b[0]) {
			b = b[1:]
		}
		// Tilde: sorts before everything.
		if strings.HasPrefix(a, "~") || strings.HasPrefix(b, "~") {
			if !strings.HasPrefix(a, "~") {
				return 1
			}
			if !strings.HasPrefix(b, "~") {
				return -1
			}
			a, b = a[1:], b[1:]
			continue
		}
		// Caret: sorts after the end, before anything else.
		if strings.HasPrefix(a, "^") || strings.HasPrefix(b, "^") {
			if a == "" {
				return -1
			}
			if b == "" {
				return 1
			}
			if !strings.HasPrefix(a, "^") {
				return 1
			}
			if !strings.HasPrefix(b, "^") {
				return -1
			}
			a, b = a[1:], b[1:]
			continue
		}
		if a == "" || b == "" {
			break
		}
		digit := a[0] >= '0' && a[0] <= '9'
		seg := func(s string) (string, string) {
			i := 0
			for i < len(s) && ((digit && s[i] >= '0' && s[i] <= '9') || (!digit && s[i] < 128 && unicode.IsLetter(rune(s[i])))) {
				i++
			}
			return s[:i], s[i:]
		}
		sa, ra := seg(a)
		sb, rb := seg(b)
		if sb == "" { // different kinds: a number beats letters
			if digit {
				return 1
			}
			return -1
		}
		if digit {
			sa, sb = strings.TrimLeft(sa, "0"), strings.TrimLeft(sb, "0")
			if len(sa) != len(sb) {
				if len(sa) > len(sb) {
					return 1
				}
				return -1
			}
		}
		if c := strings.Compare(sa, sb); c != 0 {
			return c
		}
		a, b = ra, rb
	}
	switch {
	case a == "" && b == "":
		return 0
	case a == "":
		return -1
	}
	return 1
}
