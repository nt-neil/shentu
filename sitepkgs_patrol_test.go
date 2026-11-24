package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nt-neil/shentu/tools"
)

// kevLiteLLM answers OSV and KEV: litellm 1.30.0 has an advisory for a
// CVE on the KEV list.
type kevLiteLLM struct{}

func (kevLiteLLM) RoundTrip(r *http.Request) (*http.Response, error) {
	var body any = map[string]any{"vulnerabilities": []map[string]string{{"cveID": "CVE-2026-40217", "vulnerabilityName": "Test Bug", "dateAdded": "2026-11-01"}}}
	switch {
	case strings.HasSuffix(r.URL.Path, "/querybatch"):
		var q struct {
			Queries []struct {
				Package struct{ Name string }
				Version string
			}
		}
		json.NewDecoder(r.Body).Decode(&q)
		res := make([]map[string]any, len(q.Queries))
		for i, x := range q.Queries {
			res[i] = map[string]any{}
			if x.Package.Name+"@"+x.Version == "litellm@1.30.0" {
				res[i]["vulns"] = []map[string]string{{"id": "GHSA-test-lite"}}
			}
		}
		body = map[string]any{"results": res}
	case strings.Contains(r.URL.Path, "/vulns/"):
		body = map[string]any{"aliases": []string{"CVE-2026-40217"}}
	}
	b, _ := json.Marshal(body)
	return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(string(b))), Request: r}, nil
}

// The daily patrol pushes an installed Python package being exploited, as
// installed (not "pins"), and a .pth that runs code no known tool wrote; a
// tool's own .pth is not pushed.
func TestPatrolSitePackagesFindings(t *testing.T) {
	t.Cleanup(tools.SetSitePackagesForTest(nil))
	root := t.TempDir()
	sp := filepath.Join(root, "app", "venv", "lib", "python3.12", "site-packages")
	os.MkdirAll(filepath.Join(sp, "litellm-1.30.0.dist-info"), 0o755)
	os.WriteFile(filepath.Join(sp, "litellm-1.30.0.dist-info", "METADATA"), []byte("Name: litellm\nVersion: 1.30.0\n"), 0o644)
	os.WriteFile(filepath.Join(sp, "_virtualenv.pth"), []byte("import _virtualenv\n"), 0o644)
	os.WriteFile(filepath.Join(sp, "zz.pth"), []byte("import os\n"), 0o644)
	r, err := tools.AppVulns(context.Background(), &http.Client{Transport: kevLiteLLM{}}, []string{root})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]finding{}
	for _, f := range appVulnFindings(r) {
		got[f.Key] = f
	}
	kev := got["kev:"+sp+":litellm:CVE-2026-40217"]
	if kev.Severity != "critical" || !strings.Contains(kev.Summary, sp+" has litellm 1.30.0 installed") || !strings.Contains(kev.zh, "安裝了 litellm 1.30.0") {
		t.Errorf("kev finding %+v", kev)
	}
	pth := got["pth:"+filepath.Join(sp, "zz.pth")]
	if pth.Severity != "warning" || !strings.Contains(pth.zh, "有 1 行會在每次啟動 Python 時執行") {
		t.Errorf("pth finding %+v", pth)
	}
	if len(got) != 2 {
		t.Errorf("findings %v", got)
	}
}
