package tools

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/nt-neil/shentu/hostenv"
)

// dirHost is scriptHost that also lists folders, from its file paths.
type dirHost struct{ scriptHost }

func (h dirHost) ReadDir(p string) ([]string, error) {
	seen := map[string]bool{}
	for k := range h.memHost {
		if rest, ok := strings.CutPrefix(k, strings.TrimSuffix(p, "/")+"/"); ok {
			n, _, _ := strings.Cut(rest, "/")
			seen[n] = true
		}
	}
	if len(seen) == 0 {
		return nil, os.ErrNotExist
	}
	var out []string
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out, nil
}

// emptyFeeds answers OSV with no vulnerabilities and KEV with an empty
// catalog: what an OSV query for a third-party package returns.
type emptyFeeds struct{}

func (emptyFeeds) RoundTrip(r *http.Request) (*http.Response, error) {
	body := `{"vulnerabilities":[]}`
	if strings.HasSuffix(r.URL.Path, "/querybatch") {
		var q struct{ Queries []any }
		json.NewDecoder(r.Body).Decode(&q)
		res := make([]map[string]any, len(q.Queries))
		for i := range res {
			res[i] = map[string]any{}
		}
		b, _ := json.Marshal(map[string]any{"results": res})
		body = string(b)
	}
	return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
}

const tpLists = hostenv.AptListsDir + "/packages.example-php.test_php_dists_bookworm"

func debianThirdParty(dpkg string) dirHost {
	return dirHost{scriptHost{memHost: memHost{
		"/etc/os-release":          "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nNAME=\"Debian GNU/Linux\"\nVERSION_ID=\"12\"\nID=debian\n",
		tpLists + "_InRelease":     "Origin: deb.sury.org\nLabel: PHP\n",
		tpLists + "_main_Packages": "Package: php8.3-fpm\nVersion: 8.3.14-1+0~20241122.1+debian12~1.gbp1+deb.sury.org+1\n",
	}, cmds: map[string]hostenv.CmdResult{
		strings.Join([]string{"/usr/bin/dpkg-query", "-W", "-f", hostenv.DpkgQueryFormat}, " "): {Stdout: []byte(dpkg)},
	}}}
}

// A php8.3 from sury is named as not checked; on integ, OSV's silence for
// it read as "no vulnerabilities".
func TestPackageVulnsThirdParty(t *testing.T) {
	old := kevURL
	kevURL = "https://kev.example.test/kev.json"
	t.Cleanup(func() { kevURL = old })
	hc := &http.Client{Transport: emptyFeeds{}}
	withHost(t, debianThirdParty("bash\t\t5.2.15-2+b7\tarm64\tii \n"+
		"php8.3-fpm\tphp8.3\t8.3.9-1+0~20240705.1+debian12~1.gbp1+deb.sury.org+1\tarm64\tii \n"))
	out, err := PackageVulns(context.Background(), hc, "")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(out)
	s := string(b)
	for _, want := range []string{
		`"third_party_unchecked":[{"package":"php8.3-fpm","version":"8.3.9-1+0~20240705.1+debian12~1.gbp1+deb.sury.org+1","origin":"deb.sury.org","found_by":"version"}]`,
		`"third_party_repositories":["deb.sury.org"]`,
		`1 package(s) came from other repositories`,
		`"affected_packages":0`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %s in %s", want, s)
		}
	}

	// The repository configured, its packages not told apart: said too.
	withHost(t, debianThirdParty("bash\t\t5.2.15-2+b7\tarm64\tii \n"))
	out, err = PackageVulns(context.Background(), hc, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := out["third_party_unchecked"]; ok || !strings.Contains(out["third_party_note"].(string), "which packages they installed is unknown") {
		t.Errorf("repository only: %v", out)
	}

	// Nothing third party: no note.
	h := debianThirdParty("bash\t\t5.2.15-2+b7\tarm64\tii \n")
	delete(h.memHost, tpLists+"_InRelease")
	delete(h.memHost, tpLists+"_main_Packages")
	withHost(t, h)
	out, err = PackageVulns(context.Background(), hc, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"third_party_unchecked", "third_party_note", "third_party_repositories", "origin_unread"} {
		if _, ok := out[k]; ok {
			t.Errorf("%s on a distribution-only host: %v", k, out[k])
		}
	}
}
