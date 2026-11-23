package hostenv

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"io/fs"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// Package origin: the repository an installed package came from, when it
// is not the distribution's own. OSV publishes the distribution's packages
// only, so a php8.3 from packages.sury.org or an nginx from nginx.org is
// compared as if the distribution had built it and nothing matches. The
// origin lets the check say the package was not checked, instead of
// letting silence read as "no vulnerabilities".
//
// What tells a distribution's package apart (an apt Release's Origin, an
// rpm vendor, an apk repository path) is written by whoever publishes the
// repository: a third-party repository that calls itself Debian is taken
// for Debian. So the origin can only add packages to the "not checked"
// list; it never shows that a package is the distribution's.

// AptListsDir holds apt's downloaded indexes: one Release or InRelease per
// repository and one Packages per component, named after the URL.
const AptListsDir = "/var/lib/apt/lists"

// ApkRepositories lists the repositories apk installs from.
const ApkRepositories = "/etc/apk/repositories"

// RpmVendorFormat is rpm -qa with each package's vendor. A separate
// command from rpmArgv so the recorded fixtures keep replaying.
const RpmVendorFormat = "%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\t%{VENDOR}\n"

var rpmVendorArgv = []string{"/usr/bin/rpm", "-qa", "--qf", RpmVendorFormat}

// rpm -qa lists every package, as rpmArgv does: the same output cap and time.
func init() { registerBig(rpmVendorArgv, 16<<20, MaxTimeout) }

// How an origin was found.
const (
	OriginByIndex   = "apt-index" // the installed version is in that repository's Packages
	OriginByVersion = "version"   // the version string carries the repository's mark
	OriginByVendor  = "vendor"    // rpm's vendor is not a distribution's
)

// aptDistroOrigin: the Origin field of the distributions' own archives
// (Debian and Debian security, Debian Backports, Ubuntu with its security
// and backports, Ubuntu ESM).
func aptDistroOrigin(o string) bool {
	return o == "Debian" || o == "Debian Backports" || o == "Ubuntu" || strings.HasPrefix(o, "UbuntuESM")
}

// AptReleaseOrigin is the Origin field of a Release or InRelease file,
// "" when it has none.
func AptReleaseOrigin(b []byte) string {
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(l, "-----BEGIN PGP SIGNATURE") {
			break
		}
		if v, ok := strings.CutPrefix(strings.TrimRight(l, "\r"), "Origin:"); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// ParseAptPackages reads a Packages index: name and version of each entry,
// keyed name + "\x00" + version.
func ParseAptPackages(r io.Reader) (map[string]bool, error) {
	out := map[string]bool{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	name, ver := "", ""
	flush := func() {
		if name != "" && ver != "" {
			out[name+"\x00"+ver] = true
		}
		name, ver = "", ""
	}
	for sc.Scan() {
		l := sc.Text()
		switch {
		case l == "":
			flush()
		case strings.HasPrefix(l, "Package:"):
			name = strings.TrimSpace(l[len("Package:"):])
		case strings.HasPrefix(l, "Version:"):
			ver = strings.TrimSpace(l[len("Version:"):])
		}
	}
	flush()
	return out, sc.Err()
}

// nginxOrgVersion is the version nginx.org's packages carry:
// 1.31.9-1~bookworm, 1.30.7-1~noble. Debian's and Ubuntu's own have no "~".
var nginxOrgVersion = regexp.MustCompile(`^(\d+:)?\d+\.\d+\.\d+-\d+~[a-z]+$`)

// VersionOrigin is the repository a version string marks, "" for none:
// Ondřej Surý's builds (packages.sury.org and the ondrej PPAs) carry
// +deb.sury.org, nginx.org's nginx packages -N~codename.
func VersionOrigin(name, version string) string {
	switch {
	case strings.Contains(version, "+deb.sury.org"):
		return "deb.sury.org"
	case (name == "nginx" || strings.HasPrefix(name, "nginx-module-")) && nginxOrgVersion.MatchString(version):
		return "nginx"
	}
	return ""
}

// aptOrigins sets Origin on the packages a third-party apt repository
// installed. The index is read first; the version marks catch what it no
// longer lists (sury and nginx.org keep only their latest builds, and the
// older installed ones are the ones worth reporting). It returns the
// third-party repositories configured and why some could not be read.
func aptOrigins(src Source, items []Package) (repos []string, notes []string) {
	names, err := src.ReadDir(AptListsDir)
	if err != nil && !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, ErrNotRecorded) {
		notes = append(notes, AptListsDir+" ("+string(Classify(err))+")")
	}
	origin := map[string]string{} // list prefix -> third-party Origin
	released := map[string]bool{} // list prefixes with a Release or InRelease, read or not
	for _, n := range names {
		prefix, ok := strings.CutSuffix(n, "_InRelease")
		if !ok {
			if prefix, ok = strings.CutSuffix(n, "_Release"); !ok {
				continue
			}
		}
		if released[prefix] {
			continue
		}
		released[prefix] = true
		b, err := src.ReadFile(AptListsDir + "/" + n)
		if err != nil {
			notes = append(notes, AptListsDir+"/"+n+" ("+string(Classify(err))+")")
			continue
		}
		o := AptReleaseOrigin(b)
		if aptDistroOrigin(o) {
			continue
		}
		if o == "" {
			o, _, _ = strings.Cut(prefix, "_") // the host
		}
		origin[prefix] = o
		if !slices.Contains(repos, o) {
			repos = append(repos, o)
		}
	}
	index := map[string]string{} // name \x00 version -> Origin
	for _, n := range names {
		prefix, o := "", ""
		for p, po := range origin {
			if strings.HasPrefix(n, p+"_") && len(p) > len(prefix) {
				prefix, o = p, po
			}
		}
		if !strings.Contains(n, "_Packages") {
			continue
		}
		if prefix == "" {
			if aptReleased(released, n) {
				continue // the distribution's
			}
			// No Release at all: a flat repository apt only installs from
			// with [trusted=yes]. Every archive of a distribution has a
			// Release, so this one is a third party, named by its host.
			if o, _, _ = strings.Cut(n, "_"); o == "" {
				o = "local" // a file: repository: its list name starts with the path
			}
			if !slices.Contains(repos, o) {
				repos = append(repos, o)
			}
		}
		p := AptListsDir + "/" + n
		var r io.Reader
		switch {
		case strings.HasSuffix(n, "_Packages"):
			b, err := src.ReadFile(p)
			if err != nil {
				notes = append(notes, p+" ("+string(Classify(err))+")")
				continue
			}
			r = bytes.NewReader(b)
		case strings.HasSuffix(n, "_Packages.gz"):
			b, err := src.ReadFile(p)
			if err == nil {
				var z *gzip.Reader
				if z, err = gzip.NewReader(bytes.NewReader(b)); err == nil {
					r = io.LimitReader(z, 64<<20)
				}
			}
			if err != nil {
				notes = append(notes, p+" ("+string(Classify(err))+")")
				continue
			}
		default: // .lz4, .xz, .zst: not read
			notes = append(notes, p+" (compressed index not read)")
			continue
		}
		got, err := ParseAptPackages(r)
		if err != nil {
			notes = append(notes, p+" ("+err.Error()+")")
		}
		for k := range got {
			index[k] = o
		}
	}
	for i := range items {
		it := &items[i]
		if o, ok := index[it.Name+"\x00"+it.Version]; ok {
			it.Origin, it.OriginBy = o, OriginByIndex
		} else if o := VersionOrigin(it.Name, it.Version); o != "" {
			it.Origin, it.OriginBy = o, OriginByVersion
		}
	}
	sort.Strings(repos)
	return repos, notes
}

// aptReleased: the Packages file n belongs to a repository with a Release.
func aptReleased(released map[string]bool, n string) bool {
	for p := range released {
		if strings.HasPrefix(n, p+"_") {
			return true
		}
	}
	return false
}

// rpmDistroVendors is, by os-release ID, the vendor of that distribution's
// own rpm packages, matched case-insensitively as a substring. Only the
// host's own distribution counts: Oracle's MySQL packages on Rocky, or
// Amazon's agents on RHEL, are third party; so is EPEL ("Fedora Project")
// everywhere but Fedora.
var rpmDistroVendors = map[string]string{
	"rhel": "red hat", "centos": "centos", "rocky": "rocky", "almalinux": "almalinux", "ol": "oracle america",
	"amzn": "amazon", "fedora": "fedora", "anolis": "openanolis", "openEuler": "openeuler",
	"eurolinux": "eurolinux", "miraclelinux": "cybertrust",
	"sles": "suse", "sled": "suse", "sles_sap": "suse", "sle-micro": "suse",
	"opensuse-leap": "suse", "opensuse-tumbleweed": "suse", "opensuse-slowroll": "suse",
}

// An Open Build Service vendor (obs://build.opensuse.org/home:..., devel:...)
// names a project anyone can build in: third party, though it says suse.
func rpmDistroVendor(vendor, osID string) bool {
	d, ok := rpmDistroVendors[osID]
	v := strings.ToLower(vendor)
	return ok && !strings.HasPrefix(v, "obs://") && strings.Contains(v, d)
}

// rpmOrigins sets Origin on the packages whose rpm vendor is not the
// distribution's. A package with no vendor was built locally or by hand:
// its origin is unknown, and it is named as such.
func rpmOrigins(ctx context.Context, src Source, items []Package, osID string) (notes []string) {
	if _, ok := rpmDistroVendors[osID]; !ok {
		return []string{"rpm vendors (not judged: no known vendor for " + osID + ")"}
	}
	res, err := src.Run(ctx, rpmVendorArgv)
	cut := res.Truncated || errors.Is(err, ErrTruncated) // what was read is used, the rest said
	switch {
	case errors.Is(err, ErrNotRecorded):
		return nil
	case err != nil && !cut:
		return []string{"rpm vendors (" + string(Classify(err)) + ")"}
	case res.ExitCode != 0 && !cut:
		return []string{"rpm vendors (exit " + strconv.Itoa(res.ExitCode) + ")"}
	}
	vendor := map[string]string{}
	for _, l := range strings.Split(string(res.Stdout), "\n") {
		f := strings.Split(l, "\t")
		if len(f) == 3 && f[0] != "" {
			vendor[f[0]+"\x00"+f[1]] = f[2]
		}
	}
	missed := 0
	for i := range items {
		it := &items[i]
		v, ok := vendor[it.Name+"\x00"+it.Version]
		if !ok && cut && it.Name != "gpg-pubkey" {
			missed++
		}
		switch {
		case !ok || it.Name == "gpg-pubkey" || rpmDistroVendor(v, osID):
		case v == "" || v == "(none)":
			it.Origin, it.OriginBy = "no vendor", OriginByVendor
		default:
			it.Origin, it.OriginBy = v, OriginByVendor
		}
	}
	if missed > 0 {
		return []string{"rpm vendors (not judged: output cut short, origin of " + strconv.Itoa(missed) + " packages unknown; they were compared as the distribution's own)"}
	}
	return nil
}

// apkThirdParty is the repositories in /etc/apk/repositories that are not
// Alpine's main, community or testing. apk does not record which
// repository installed a package, so these are named, not matched.
func apkThirdParty(src Source) (repos []string, notes []string) {
	b, err := src.ReadFile(ApkRepositories)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, ErrNotRecorded) {
			notes = append(notes, ApkRepositories+" ("+string(Classify(err))+")")
		}
		return nil, notes
	}
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || l[0] == '#' {
			continue
		}
		if f := strings.Fields(l); len(f) > 1 && strings.HasPrefix(f[0], "@") {
			l = f[1] // @tag url
		}
		switch l[strings.LastIndex(l, "/")+1:] {
		case "main", "community", "testing":
			if strings.Contains(l, "/alpine/") {
				continue
			}
		}
		repos = append(repos, l)
	}
	return repos, notes
}
