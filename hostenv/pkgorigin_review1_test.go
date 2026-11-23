package hostenv

import (
	"context"
	"maps"
	"os"
	"regexp"
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
		"ol": { // S-208-4: repo.mysql.com's "Oracle and/or its affiliates" is not Oracle Linux
			"bash":                   "Example Linux Vendor by vendor",
			"mysql-community-server": "Oracle and/or its affiliates by vendor",
			"amazon-ssm-agent":       "Amazon.com, Inc. by vendor",
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
		return strings.HasPrefix(n, "rpm vendors (not judged: output cut short, origin of 5 packages unknown")
	}) {
		t.Errorf("cut vendor output: %q", p.Value.OriginNotes)
	}
}

// N-208-4: every rpm distribution the patch feed knows has its vendor here,
// read from PatchFeedFor's cases so a new ID cannot be missed.
func TestReview208VendorTableCoversFeed(t *testing.T) {
	b, err := os.ReadFile("linuxdistros.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	i := strings.Index(src, "func PatchFeedFor(")
	end := strings.Index(src[i:], "\n}\n")
	var ids []string
	for _, l := range strings.Split(src[i:i+end], "\n") {
		if strings.HasPrefix(l, "\tcase \"") { // the switch on the ID, not the ones inside it
			for _, q := range regexp.MustCompile(`"([^"]+)"`).FindAllStringSubmatch(l, -1) {
				ids = append(ids, q[1])
			}
		}
	}
	if !slices.Contains(ids, "sles_sap") || !slices.Contains(ids, "rocky") {
		t.Fatalf("feed IDs not read: %q", ids)
	}
	for _, id := range ids {
		switch id {
		case "debian", "ubuntu", "alpine": // not rpm
			continue
		}
		if _, ok := rpmDistroVendors[id]; !ok {
			t.Errorf("feed ID %s has no vendor", id)
		}
	}
}

// N-208-5: an Open Build Service project is third party on SUSE.
func TestReview208OBSVendor(t *testing.T) {
	for _, id := range []string{"opensuse-leap", "sles"} {
		for v, want := range map[string]bool{
			"SUSE LLC <https://www.suse.com/>":             false,
			"openSUSE":                                     false,
			"obs://build.opensuse.org/home:alice":          true,
			"obs://build.opensuse.org/devel:languages:php": true,
			"Example Vendor":                               true,
		} {
			if got := !rpmDistroVendor(v, id); got != want {
				t.Errorf("%s %q third party %v, want %v", id, v, got, want)
			}
		}
	}
}

// N-208-6: a file: flat repository has a list name starting with "_": it is
// named "local", never "".
func TestReview208LocalFlatRepo(t *testing.T) {
	h := aptHost()
	h.files[AptListsDir+"/_srv_repo_._Packages"] = "Package: agent\nVersion: 2.0.1\n"
	h.cmds[argvKey(dpkgArgv)] = CmdResult{Stdout: append(h.cmds[argvKey(dpkgArgv)].Stdout, "agent\t\t2.0.1\tarm64\tii \n"...)}
	p := Collect(context.Background(), h).Packages
	if got := originOf(p.Value.Items); got["agent"] != "local by apt-index" {
		t.Errorf("file: repository: %v", got)
	}
	if slices.Contains(p.Value.ThirdParty, "") || !slices.Contains(p.Value.ThirdParty, "local") {
		t.Errorf("third party %q", p.Value.ThirdParty)
	}
}
