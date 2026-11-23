package hostenv

import "testing"

// The PHP check's package queries take a file or a package name as a slot:
// allowed for plain absolute paths and package names, never for anything
// that could read as an option, a pattern or a relative path.
func TestPHPPackageSlots(t *testing.T) {
	r, err := NewRunner(LinuxCollector{}.Allowlist())
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/usr/bin/php8.3", "/opt/remi/php83/root/usr/sbin/php-fpm", "/usr/lib/cgi-bin/php"} {
		if !r.Allowed(DpkgSearchArgv(p)) || !r.Allowed(RPMOwnerArgv(p)) {
			t.Errorf("%s refused", p)
		}
	}
	for _, p := range []string{"php8.3-cli", "php8.3-cli:arm64", "php85-php-fpm", "libapache2-mod-php8.2"} {
		if !r.Allowed(DpkgStatusArgv(p)) || !r.Allowed(RPMChangelogArgv(p)) {
			t.Errorf("%s refused", p)
		}
	}
	for _, p := range []string{"-a", "--admindir=/tmp", "usr/bin/php", "/usr/bin/php*", "/usr/../etc/shadow", "/usr/bin/ php", "/usr//bin/php", ""} {
		if r.Allowed(DpkgSearchArgv(p)) || r.Allowed(RPMOwnerArgv(p)) {
			t.Errorf("path %q allowed", p)
		}
	}
	for _, p := range []string{"-a", "--root=/", "php*", "php 8", "../x", ""} {
		if r.Allowed(DpkgStatusArgv(p)) || r.Allowed(RPMChangelogArgv(p)) {
			t.Errorf("package %q allowed", p)
		}
	}
}
