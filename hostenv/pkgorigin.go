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

// AptListsDir holds apt's downloaded indexes: one Release or InRelease per
// repository and one Packages per component, named after the URL.
const AptListsDir = "/var/lib/apt/lists"

// ApkRepositories lists the repositories apk installs from.
const ApkRepositories = "/etc/apk/repositories"

// RpmVendorFormat is rpm -qa with each package's vendor. A separate
// command from rpmArgv so the recorded fixtures keep replaying.
const RpmVendorFormat = "%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\t%{VENDOR}\n"

var rpmVendorArgv = []string{"/usr/bin/rpm", "-qa", "--qf", RpmVendorFormat}

// How an origin was found.
const (
	OriginByIndex   = "apt-index" // the installed version is in that repository's Packages
	OriginByVersion = "version"   // the version string carries the repository's mark
	OriginByVendor  = "vendor"    // rpm's vendor is not a distribution's
)

// aptDistroOrigin: the Origin field of the distributions' own archives
// (Debian, Debian security and backports, Ubuntu, Ubuntu ESM).
func aptDistroOrigin(o string) bool {
	return o == "Debian" || o == "Ubuntu" || strings.HasPrefix(o, "UbuntuESM")
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
	for _, n := range names {
		prefix, ok := strings.CutSuffix(n, "_InRelease")
		if !ok {
			if prefix, ok = strings.CutSuffix(n, "_Release"); !ok {
				continue
			}
		}
		if _, dup := origin[prefix]; dup {
			continue
		}
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
		if prefix == "" || !strings.Contains(n, "_Packages") {
			continue
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

// rpmDistroVendors are the vendors of the distributions' own rpm packages,
// matched case-insensitively as substrings. EPEL's "Fedora Project" is a
// third party on every distribution but Fedora.
var rpmDistroVendors = []string{"red hat", "rocky", "almalinux", "amazon", "centos", "oracle", "suse", "openanolis", "openeuler", "eurolinux", "cybertrust"}

func rpmDistroVendor(vendor, osID string) bool {
	v := strings.ToLower(vendor)
	if strings.Contains(v, "fedora") {
		return osID == "fedora"
	}
	for _, d := range rpmDistroVendors {
		if strings.Contains(v, d) {
			return true
		}
	}
	return false
}

// rpmOrigins sets Origin on the packages whose rpm vendor is not the
// distribution's. A package with no vendor was built locally or by hand:
// its origin is unknown, and it is named as such.
func rpmOrigins(ctx context.Context, src Source, items []Package, osID string) (notes []string) {
	res, err := src.Run(ctx, rpmVendorArgv)
	switch {
	case errors.Is(err, ErrNotRecorded):
		return nil
	case err != nil:
		return []string{"rpm vendors (" + string(Classify(err)) + ")"}
	case res.ExitCode != 0:
		return []string{"rpm vendors (exit " + strconv.Itoa(res.ExitCode) + ")"}
	}
	vendor := map[string]string{}
	for _, l := range strings.Split(string(res.Stdout), "\n") {
		f := strings.Split(l, "\t")
		if len(f) == 3 && f[0] != "" {
			vendor[f[0]+"\x00"+f[1]] = f[2]
		}
	}
	for i := range items {
		it := &items[i]
		v, ok := vendor[it.Name+"\x00"+it.Version]
		switch {
		case !ok || it.Name == "gpg-pubkey" || rpmDistroVendor(v, osID):
		case v == "" || v == "(none)":
			it.Origin, it.OriginBy = "no vendor", OriginByVendor
		default:
			it.Origin, it.OriginBy = v, OriginByVendor
		}
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
