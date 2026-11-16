package main

import (
	"bytes"
	"strings"
	"testing"
)

// A made-up template of Nuclei's shape (not one of nuclei-templates').
const tmpl = `
id: CVE-2099-0001
info:
  name: Example Plugin - SQL Injection
  tags: cve,wordpress,sqli
  classification:
    cve-id: CVE-2099-0001
    cwe-id: CWE-89
http:
  - method: GET
    path:
      - "{{BaseURL}}/wp-admin/admin-ajax.php?action=example_get&id=1+UNION+SELECT+{{rand}}"
  - raw:
      - |
        POST /wp-json/example/v1/item?sort=1' HTTP/1.1
        Host: {{Hostname}}
    matchers:
      - type: word
        words: ["example"]
`

func TestExtract(t *testing.T) {
	d, err := Extract([]byte(tmpl))
	if err != nil {
		t.Fatal(err)
	}
	if d.ID != "nuclei-cve-2099-0001" || d.Class != "sqli" || len(d.Routes) != 2 || d.Params["id"] != "1 UNION SELECT " || d.Params["action"] != "example_get" {
		t.Fatalf("%+v", d)
	}
	var b bytes.Buffer
	d.TOML(&b, "v10.1.0")
	out := b.String()
	for _, want := range []string{"# DRAFT from Nuclei template CVE-2099-0001", `source = "nuclei"`, `license = "MIT"`, `nuclei_template = "CVE-2099-0001"`,
		`nuclei_version = "v10.1.0"`, `path = "/wp-admin/admin-ajax.php"`, `methods = ["POST"]`, `cves = ["CVE-2099-0001"]`, `contains = ["1 union select "]`} {
		if !strings.Contains(out, want) {
			t.Errorf("draft lacks %q:\n%s", want, out)
		}
	}
}

func TestExtractRefuses(t *testing.T) {
	if _, err := Extract([]byte("info:\n  name: x\n")); err == nil {
		t.Error("a template without an id")
	}
	if _, err := Extract([]byte("id: x\ninfo:\n  name: x\nhttp:\n  - matchers: []\n")); err == nil {
		t.Error("a template with no request path")
	}
	d, err := Extract([]byte("id: y\ninfo:\n  name: y\n  tags: [misc]\nhttp:\n  - path: [\"{{BaseURL}}/x\"]\n"))
	if err != nil || d.Class != "" {
		t.Fatalf("%v %+v", err, d)
	}
	var b bytes.Buffer
	d.TOML(&b, "v1")
	if !strings.Contains(b.String(), "set it by hand") {
		t.Error("no class, and not said")
	}
}
