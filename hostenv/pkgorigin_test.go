package hostenv

import (
	"bytes"
	"compress/gzip"
	"context"
	"maps"
	"slices"
	"strings"
	"testing"
)

const (
	aptDebian  = AptListsDir + "/deb.debian.org_debian_dists_bookworm"
	aptSury    = AptListsDir + "/packages.example-php.test_php_dists_bookworm"
	aptNginx   = AptListsDir + "/nginx.example.test_packages_debian_dists_bookworm"
	aptSigned  = "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\n"
	aptSigTail = "-----BEGIN PGP SIGNATURE-----\n\nAAAA\n-----END PGP SIGNATURE-----\n"
)

// aptHost is debianHost with php and nginx from two third-party
// repositories: sury's PHP (Origin deb.sury.org) and nginx.org's (Origin
// nginx), next to Debian's own archive.
func aptHost() *fakeHost {
	h := debianHost(true)
	h.cmds[argvKey(dpkgArgv)] = CmdResult{Stdout: []byte(
		"bash\t\t5.2.15-2+b7\tarm64\tii \n" +
			"php8.3-fpm\tphp8.3\t8.3.10-1+0~20240802.1+debian12~1.gbp1\tarm64\tii \n" + // in sury's index
			"php8.3-cli\tphp8.3\t8.3.9-1+0~20240705.1+debian12~1.gbp1+deb.sury.org+1\tarm64\tii \n" + // older: only the mark
			"nginx\t\t1.31.2-1~bookworm\tarm64\tii \n" + // older than nginx.org's index
			"libssl3\topenssl\t3.0.14-1~deb12u2\tarm64\tii \n")}
	h.files[aptDebian+"_InRelease"] = aptSigned + "Origin: Debian\nLabel: Debian\nSuite: stable\nCodename: bookworm\n" + aptSigTail
	h.files[aptDebian+"_main_binary-arm64_Packages"] = "Package: bash\nVersion: 5.2.15-2+b7\n\nPackage: libssl3\nVersion: 3.0.14-1~deb12u2\n"
	h.files[aptSury+"_InRelease"] = aptSigned + "Origin: deb.sury.org\nLabel: PHP-FPM\nCodename: bookworm\n" + aptSigTail
	h.files[aptSury+"_main_binary-arm64_Packages"] = "Package: php8.3-fpm\nSource: php8.3\nVersion: 8.3.10-1+0~20240802.1+debian12~1.gbp1\n\n" +
		"Package: libssl3\nVersion: 3.9.9-1\n"
	h.files[aptNginx+"_Release"] = "Origin: nginx\nLabel: nginx\nCodename: bookworm\n"
	h.files[aptNginx+"_nginx_binary-arm64_Packages"] = "Package: nginx\nVersion: 1.31.9-1~bookworm\n"
	return h
}

func originOf(items []Package) map[string]string {
	out := map[string]string{}
	for _, it := range items {
		if it.Origin != "" {
			out[it.Name] = it.Origin + " by " + it.OriginBy
		}
	}
	return out
}

func TestAptOrigins(t *testing.T) {
	p := Collect(context.Background(), aptHost()).Packages
	want := map[string]string{
		"php8.3-fpm": "deb.sury.org by apt-index",
		"php8.3-cli": "deb.sury.org by version",
		"nginx":      "nginx by version",
	}
	if got := originOf(p.Value.Items); !maps.Equal(got, want) {
		t.Errorf("origins %v, want %v", got, want)
	}
	if !slices.Equal(p.Value.ThirdParty, []string{"deb.sury.org", "nginx"}) || len(p.Value.OriginNotes) != 0 {
		t.Errorf("third party %q, notes %q", p.Value.ThirdParty, p.Value.OriginNotes)
	}
	if p.Status != StatusOK {
		t.Errorf("status %s %q", p.Status, p.Detail)
	}
}

// The indexes gone (apt clean in an image): the marks still tell.
func TestAptOriginsNoLists(t *testing.T) {
	h := aptHost()
	for k := range h.files {
		if strings.HasPrefix(k, AptListsDir) {
			delete(h.files, k)
		}
	}
	p := Collect(context.Background(), h).Packages
	want := map[string]string{"php8.3-cli": "deb.sury.org by version", "nginx": "nginx by version"}
	if got := originOf(p.Value.Items); !maps.Equal(got, want) {
		t.Errorf("origins %v, want %v", got, want)
	}
	if len(p.Value.ThirdParty) != 0 || len(p.Value.OriginNotes) != 0 {
		t.Errorf("third party %q, notes %q", p.Value.ThirdParty, p.Value.OriginNotes)
	}
}

// A gzip index is read; lz4 and an unreadable one are named, never
// taken as "no third-party packages".
func TestAptOriginsIndexForms(t *testing.T) {
	h := aptHost()
	idx := aptSury + "_main_binary-arm64_Packages"
	var z bytes.Buffer
	w := gzip.NewWriter(&z)
	w.Write([]byte(h.files[idx]))
	w.Close()
	h.files[idx+".gz"] = z.String()
	delete(h.files, idx)
	h.files[aptNginx+"_nginx_binary-arm64_Packages.lz4"] = "\x04\x22\x4d\x18"
	delete(h.files, aptNginx+"_nginx_binary-arm64_Packages")
	h.files[aptSury+"_main_binary-amd64_Packages"] = "x"
	h.denied[aptSury+"_main_binary-amd64_Packages"] = true
	p := Collect(context.Background(), h).Packages
	if got := originOf(p.Value.Items); got["php8.3-fpm"] != "deb.sury.org by apt-index" {
		t.Errorf("gzip index not read: %v", got)
	}
	notes := strings.Join(p.Value.OriginNotes, "\n")
	if !strings.Contains(notes, "_Packages.lz4 (compressed index not read)") || !strings.Contains(notes, "binary-amd64_Packages (permission_denied)") {
		t.Errorf("notes %q", p.Value.OriginNotes)
	}
	// An unreadable lists folder is said too.
	h = aptHost()
	h.denied[AptListsDir] = true
	if p := Collect(context.Background(), h).Packages; !slices.Contains(p.Value.OriginNotes, AptListsDir+" (permission_denied)") {
		t.Errorf("lists denied: %q", p.Value.OriginNotes)
	}
}

func TestAptReleaseOrigin(t *testing.T) {
	for in, want := range map[string]string{
		aptSigned + "Origin: LP-PPA-example\nLabel: x\n" + aptSigTail: "LP-PPA-example",
		"Label: x\nOrigin: Ubuntu\r\nSuite: noble\n":                  "Ubuntu",
		"Label: x\nSuite: y\n":                                        "",
		aptSigned + "Label: x\n" + aptSigTail + "Origin: forged\n":    "",
	} {
		if got := AptReleaseOrigin([]byte(in)); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
	for o, want := range map[string]bool{"Debian": true, "Ubuntu": true, "UbuntuESMApps": true, "deb.sury.org": false, "nginx": false, "": false, "Debian Example": false} {
		if aptDistroOrigin(o) != want {
			t.Errorf("distro origin %q: %v", o, !want)
		}
	}
}

func TestVersionOrigin(t *testing.T) {
	for _, c := range []struct{ name, version, want string }{
		{"php8.2-fpm", "8.2.24-1+0~20240926.1+debian12~1.gbp1+deb.sury.org+1", "deb.sury.org"},
		{"php8.3", "8.3.11-1+ubuntu24.04.1+deb.sury.org+1", "deb.sury.org"},
		{"php8.2-fpm", "8.2.24-1~deb12u1", ""},
		{"nginx", "1.31.9-1~bookworm", "nginx"},
		{"nginx", "1:1.31.9-1~noble", "nginx"},
		{"nginx-module-njs", "1.31.9+0.9.1-1~bookworm", ""}, // not the plain form: unknown
		{"nginx", "1.22.1-9+deb12u2", ""},
		{"nginx", "1.24.0-2ubuntu7.1", ""},
		{"libssl3", "3.0.14-1~deb12u2", ""},
	} {
		if got := VersionOrigin(c.name, c.version); got != c.want {
			t.Errorf("%s %s: %q, want %q", c.name, c.version, got, c.want)
		}
	}
}

func rpmHost(vendors string) *fakeHost {
	h := newFake(true)
	h.files["/etc/os-release"] = "NAME=\"Rocky Linux\"\nVERSION_ID=\"9.4\"\nID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\n"
	h.files["/etc/passwd"] = "root:x:0:0::/root:/bin/bash\n"
	h.cmds[argvKey(rpmArgv)] = CmdResult{Stdout: []byte("bash\t0:5.1.8-9.el9\taarch64\nphp-fpm\t0:8.3.10-1.el9.remi\taarch64\n" +
		"nginx\t1:1.31.2-1.el9.ngx\taarch64\njq\t0:1.6-17.el9\taarch64\nhtop\t0:3.3.0-1.el9\taarch64\nlocal-tool\t0:1.0-1\taarch64\ngpg-pubkey\t0:abcd-1234\t(none)\n")}
	if vendors != "" {
		h.cmds[argvKey(rpmVendorArgv)] = CmdResult{Stdout: []byte(vendors)}
	}
	return h
}

func TestRpmOrigins(t *testing.T) {
	// The live runner must let the vendor query through.
	if r, err := NewRunner(LinuxCollector{}.Allowlist()); err != nil || !r.Allowed(rpmVendorArgv) {
		t.Errorf("rpm vendor query not allowed: %v", err)
	}
	h := rpmHost("bash\t0:5.1.8-9.el9\tRocky Enterprise Software Foundation\nphp-fpm\t0:8.3.10-1.el9.remi\tRemi's RPM repository <https://rpms.remirepo.net/>\n" +
		"nginx\t1:1.31.2-1.el9.ngx\tExample nginx packager\njq\t0:1.6-17.el9\tRocky Enterprise Software Foundation\nhtop\t0:3.3.0-1.el9\tFedora Project\n" +
		"local-tool\t0:1.0-1\t(none)\ngpg-pubkey\t0:abcd-1234\t(none)\n")
	p := Collect(context.Background(), h).Packages
	want := map[string]string{
		"php-fpm":    "Remi's RPM repository <https://rpms.remirepo.net/> by vendor",
		"nginx":      "Example nginx packager by vendor",
		"htop":       "Fedora Project by vendor", // EPEL on Rocky
		"local-tool": "no vendor by vendor",
	}
	if got := originOf(p.Value.Items); !maps.Equal(got, want) {
		t.Errorf("origins %v, want %v", got, want)
	}
	// On Fedora, Fedora Project is the distribution.
	h.files["/etc/os-release"] = "NAME=\"Fedora Linux\"\nVERSION_ID=41\nID=fedora\n"
	if got := originOf(Collect(context.Background(), h).Packages.Value.Items); got["htop"] != "" {
		t.Errorf("fedora htop: %v", got)
	}
	// The vendor query failing is said, not taken as "all the distribution's".
	p = Collect(context.Background(), rpmHost("")).Packages
	if len(p.Value.OriginNotes) != 1 || !strings.Contains(p.Value.OriginNotes[0], "rpm vendors") || len(originOf(p.Value.Items)) != 0 {
		t.Errorf("no vendor query: %q %v", p.Value.OriginNotes, originOf(p.Value.Items))
	}
}

func TestApkThirdParty(t *testing.T) {
	h := alpineHost()
	h.files[ApkRepositories] = "https://dl-cdn.alpinelinux.org/alpine/v3.20/main\nhttps://mirror.example.test/alpine/v3.20/community\n" +
		"# https://example.test/old\n@edge https://dl-cdn.alpinelinux.org/alpine/edge/testing\n" +
		"https://packages.example.test/alpine/v3.20/main\nhttps://php.example.test/apk/php83\n"
	p := Collect(context.Background(), statFake{h}).Packages
	if want := []string{"https://php.example.test/apk/php83"}; !slices.Equal(p.Value.ThirdParty, want) {
		t.Errorf("apk third party %q, want %q", p.Value.ThirdParty, want)
	}
}
