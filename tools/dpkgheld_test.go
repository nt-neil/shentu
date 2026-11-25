package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// H-057-1: a held package (dpkg "hi") is asked of OSV, as an installed one
// is; one with only its configuration left is said as not checked. On
// 9a5cfb3 the held one was not asked and nothing said it. Made-up versions.
func TestPackageVulnsHeld(t *testing.T) {
	old := kevURL
	kevURL = "https://kev.example.test/kev.json"
	t.Cleanup(func() { kevURL = old })
	withHost(t, debianThirdParty("bash\t\t5.2.15-2+b7\tarm64\tii \n"+
		"libssl3\topenssl\t3.0.14-1~deb12u2\tarm64\thi \n"+
		"apache2-data\tapache2\t2.4.62-1~deb12u2\tall\trc \n"))
	out, err := PackageVulns(context.Background(), &http.Client{Transport: emptyFeeds{}}, "")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(out)
	if n, _ := out["packages_checked"].(int); n != 2 { // bash and openssl (libssl3's source)
		t.Errorf("packages_checked %v, want 2 (the held one too): %s", out["packages_checked"], b)
	}
	if !strings.Contains(string(b), `"packages_not_checked":["apache2-data 2.4.62-1~deb12u2 (config-files)"]`) {
		t.Errorf("config-files not said: %s", b)
	}
}

// A long-run host may keep dozens of packages with only their configuration
// left (old kernels): the first 20 are listed, the rest counted.
func TestPackageVulnsNotCheckedCapped(t *testing.T) {
	old := kevURL
	kevURL = "https://kev.example.test/kev.json"
	t.Cleanup(func() { kevURL = old })
	dpkg := "bash\t\t5.2.15-2+b7\tarm64\tii \n"
	for i := 1; i <= 25; i++ {
		dpkg += fmt.Sprintf("linux-image-6.1.0-%d-arm64\t\t6.1.%d-1\tarm64\trc \n", i, i)
	}
	withHost(t, debianThirdParty(dpkg))
	out, err := PackageVulns(context.Background(), &http.Client{Transport: emptyFeeds{}}, "")
	if err != nil {
		t.Fatal(err)
	}
	nc, _ := out["packages_not_checked"].([]string)
	if len(nc) != 20 || nc[19] != "linux-image-6.1.0-20-arm64 6.1.20-1 (config-files)" {
		t.Errorf("packages_not_checked %d %q, want the first 20", len(nc), nc)
	}
	if n, _ := out["packages_not_checked_more"].(int); n != 5 {
		t.Errorf("packages_not_checked_more %v, want 5", out["packages_not_checked_more"])
	}
}
