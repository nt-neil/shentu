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

// Review 1 of #87: a template's id, name or path with a control character
// (a newline) cannot add a line to the draft, and strings are TOML's.
func TestExtractControlCharacters(t *testing.T) {
	src := "id: \"marker\\ninjected = 1\"\ninfo:\n  name: \"name\\nalso = 2\"\nhttp:\n  - path: [\"{{BaseURL}}/a\\nmore = 3\\u0007?k=v\\\"w\"]\n"
	d, err := Extract([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	d.TOML(&b, "v1\nrelease = 4")
	out := b.String()
	for _, l := range strings.Split(out, "\n") {
		for _, bad := range []string{"injected", "also", "more", "release"} {
			if strings.HasPrefix(strings.TrimSpace(l), bad) {
				t.Errorf("a line was added: %q\n%s", l, out)
			}
		}
		if strings.ContainsFunc(l, func(r rune) bool { return r < 0x20 && r != '\t' }) {
			t.Errorf("a control character in %q", l)
		}
	}
	if !strings.Contains(out, `contains = ["v\"w"]`) || !strings.Contains(out, `nuclei_template = "markerinjected = 1"`) {
		t.Errorf("strings not escaped as TOML's:\n%s", out)
	}
	if got := tomlString("a\x00b\x7f"); got != `"a\u0000b\u007F"` {
		t.Errorf("tomlString: %s", got)
	}
}
