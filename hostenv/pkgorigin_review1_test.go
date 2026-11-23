package hostenv

import (
	"context"
	"maps"
	"slices"
	"strings"
	"testing"
)

// #208 review 1. Synthetic hosts only: made-up versions, example.test hosts.

// N-208-1: Debian Backports is Debian's own archive.
func TestReview208Backports(t *testing.T) {
	h := aptHost()
	bpo := AptListsDir + "/deb.debian.org_debian_dists_bookworm-backports"
	h.files[bpo+"_InRelease"] = aptSigned + "Origin: Debian Backports\nLabel: Debian Backports\nSuite: stable-backports\n" + aptSigTail
	h.files[bpo+"_main_binary-arm64_Packages"] = "Package: cockpit\nVersion: 300-1~bpo12+1\n"
	h.cmds[argvKey(dpkgArgv)] = CmdResult{Stdout: append(h.cmds[argvKey(dpkgArgv)].Stdout, "cockpit\t\t300-1~bpo12+1\tarm64\tii \n"...)}
	p := Collect(context.Background(), h).Packages
	if got := originOf(p.Value.Items); got["cockpit"] != "" {
		t.Errorf("backports taken as third party: %v", got)
	}
	if !slices.Equal(p.Value.ThirdParty, []string{"deb.sury.org", "nginx"}) {
		t.Errorf("third party %q", p.Value.ThirdParty)
	}
}

// N-208-2: a vendor is the distribution's only on that distribution.
func TestReview208RpmVendorByOS(t *testing.T) {
	vendors := "bash\t0:5.1.8-9.el9\tExample Linux Vendor\n" +
		"mysql-community-server\t0:8.4.9-1.el9\tOracle and/or its affiliates\n" +
		"amazon-ssm-agent\t0:3.3.9-1\tAmazon.com, Inc.\n"
	host := func(id string) *fakeHost {
		h := rpmHost(vendors)
		h.files["/etc/os-release"] = "NAME=\"Example\"\nVERSION_ID=\"9\"\nID=\"" + id + "\"\nID_LIKE=\"rhel fedora\"\n"
		h.cmds[argvKey(rpmArgv)] = CmdResult{Stdout: []byte("bash\t0:5.1.8-9.el9\taarch64\n" +
			"mysql-community-server\t0:8.4.9-1.el9\taarch64\namazon-ssm-agent\t0:3.3.9-1\taarch64\n")}
		return h
	}
	for id, want := range map[string]map[string]string{
		"rocky": {
			"bash":                   "Example Linux Vendor by vendor",
			"mysql-community-server": "Oracle and/or its affiliates by vendor",
			"amazon-ssm-agent":       "Amazon.com, Inc. by vendor",
		},
		"ol": {
			"bash":             "Example Linux Vendor by vendor",
			"amazon-ssm-agent": "Amazon.com, Inc. by vendor",
		},
		"amzn": {
			"bash":                   "Example Linux Vendor by vendor",
			"mysql-community-server": "Oracle and/or its affiliates by vendor",
		},
	} {
		p := Collect(context.Background(), host(id)).Packages
		if got := originOf(p.Value.Items); !maps.Equal(got, want) {
			t.Errorf("%s: origins %v, want %v", id, got, want)
		}
	}
	// A derivative (an ID not known, ID_LIKE rhel): its vendor is not known, said, not guessed.
	p := Collect(context.Background(), host("examplelinux")).Packages
	if len(originOf(p.Value.Items)) != 0 || !slices.ContainsFunc(p.Value.OriginNotes, func(n string) bool {
		return strings.Contains(n, "not judged")
	}) {
		t.Errorf("unknown distribution: %v %q", originOf(p.Value.Items), p.Value.OriginNotes)
	}
}

// N-208-3: a flat repository has a Packages and no Release: third party,
// named by its host. A distribution archive whose Release could not be
// read stays a note, not a third party.
func TestReview208FlatRepo(t *testing.T) {
	h := aptHost()
	h.files[AptListsDir+"/repo.example.test_._Packages"] = "Package: agent\nVersion: 2.0.1\n"
	h.cmds[argvKey(dpkgArgv)] = CmdResult{Stdout: append(h.cmds[argvKey(dpkgArgv)].Stdout, "agent\t\t2.0.1\tarm64\tii \n"...)}
	p := Collect(context.Background(), h).Packages
	if got := originOf(p.Value.Items); got["agent"] != "repo.example.test by apt-index" {
		t.Errorf("flat repository: %v", got)
	}
	if !slices.Contains(p.Value.ThirdParty, "repo.example.test") {
		t.Errorf("third party %q", p.Value.ThirdParty)
	}
	h = aptHost()
	h.denied[aptDebian+"_InRelease"] = true
	p = Collect(context.Background(), h).Packages
	if got := originOf(p.Value.Items); got["bash"] != "" || got["libssl3"] != "" || slices.Contains(p.Value.ThirdParty, "deb.debian.org") {
		t.Errorf("unreadable Release taken as a flat repository: %v %q", got, p.Value.ThirdParty)
	}
	if !slices.Contains(p.Value.OriginNotes, aptDebian+"_InRelease (permission_denied)") {
		t.Errorf("notes %q", p.Value.OriginNotes)
	}
}

// S-208-3: the vendor query is a big command, and output cut short is
// said: the packages past the cut are not silently the distribution's.
func TestReview208RpmVendorCut(t *testing.T) {
	if l, ok := bigFor(rpmVendorArgv); !ok || l.maxStdout < 16<<20 {
		t.Errorf("rpm vendor query limits %+v %v", l, ok)
	}
	h := rpmHost("bash\t0:5.1.8-9.el9\tRocky Enterprise Software Foundation\n")
	r := h.cmds[argvKey(rpmVendorArgv)]
	r.Truncated = true
	h.cmds[argvKey(rpmVendorArgv)] = r
	p := Collect(context.Background(), h).Packages
	if !slices.ContainsFunc(p.Value.OriginNotes, func(n string) bool {
		return strings.Contains(n, "output cut short: 5 packages not told apart")
	}) {
		t.Errorf("cut vendor output: %q", p.Value.OriginNotes)
	}
}
