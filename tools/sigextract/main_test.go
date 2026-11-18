package main

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
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

// Review 2 of #87: format characters (bidi overrides, zero widths) and the
// line and paragraph separators are dropped or escaped too.
func TestExtractFormatCharacters(t *testing.T) {
	src := "id: \"marker\\u202Eabc\\u2028def\\u200Bg\"\ninfo:\n  name: \"n\\u2029x\"\nhttp:\n  - path: [\"{{BaseURL}}/a\\u2066b?k=v\\u202Ew\"]\n"
	d, err := Extract([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	d.TOML(&b, "v1")
	out := b.String()
	for _, r := range []rune{'‮', ' ', ' ', '​', '⁦'} {
		if strings.ContainsRune(out, r) {
			t.Errorf("U+%04X in the draft:\n%s", r, out)
		}
	}
	if !strings.Contains(out, `nuclei_template = "markerabcdefg"`) || !strings.Contains(out, `path = "/ab"`) || !strings.Contains(out, `contains = ["vw"]`) {
		t.Errorf("draft:\n%s", out)
	}
}

// Review 3 of #87: a character past U+FFFF is escaped as TOML's \U, and
// every string decodes back (a TOML basic string decoder of its own: the
// module has no TOML dependency).
func TestTOMLStringRoundTrip(t *testing.T) {
	for _, s := range []string{"plain", "q\"b\\s", "a\nb\tc\rd", "\x00\x1f\x7f", "‮ ​", "\U000E0001x", "中文", "\U0001F600"} {
		q := tomlString(s)
		if strings.ContainsFunc(q, invisible) {
			t.Errorf("%q: an invisible character left in %q", s, q)
		}
		got, err := decodeBasic(q)
		if err != nil || got != s {
			t.Errorf("%q: %s decodes to %q (%v)", s, q, got, err)
		}
	}
	if q := tomlString("\U000E0001"); q != `"\U000E0001"` {
		t.Errorf("tomlString: %s", q)
	}
}

func decodeBasic(q string) (string, error) {
	if len(q) < 2 || q[0] != '"' || q[len(q)-1] != '"' {
		return "", fmt.Errorf("not quoted")
	}
	q = q[1 : len(q)-1]
	var b strings.Builder
	for i := 0; i < len(q); i++ {
		c := q[i]
		if c == '"' {
			return "", fmt.Errorf("unescaped quote at %d", i)
		}
		if c != '\\' {
			b.WriteByte(c)
			continue
		}
		i++
		if i >= len(q) {
			return "", fmt.Errorf("trailing backslash")
		}
		switch q[i] {
		case '"', '\\':
			b.WriteByte(q[i])
		case 'n':
			b.WriteByte('\n')
		case 't':
			b.WriteByte('\t')
		case 'r':
			b.WriteByte('\r')
		case 'u', 'U':
			n := 4
			if q[i] == 'U' {
				n = 8
			}
			if i+n >= len(q)+1 || i+1+n > len(q) {
				return "", fmt.Errorf("short escape")
			}
			v, err := strconv.ParseUint(q[i+1:i+1+n], 16, 32)
			if err != nil {
				return "", err
			}
			b.WriteRune(rune(v))
			i += n
		default:
			return "", fmt.Errorf("escape \\%c is not TOML's", q[i])
		}
	}
	return b.String(), nil
}

// P5 (n19-5, n21): DEL and the C1 controls are escaped too, and every
// draft reads back through a TOML parser with its strings as they were
// (U+1D173, a format character past U+FFFF, dropped from names).
func TestDraftReadsBack(t *testing.T) {
	for _, r := range []rune{0x7f, 0x80, 0x85, 0x9f} {
		if q := tomlString("a" + string(r) + "b"); !strings.Contains(q, fmt.Sprintf(`\u%04X`, r)) {
			t.Errorf("U+%04X: %s", r, q)
		}
	}
	src := "id: \"marker\\U0001D173x\"\ninfo:\n  name: \"n\\u0085y\"\nhttp:\n  - path: [\"{{BaseURL}}/a\\U0001D173b?k=v\\u007fw\\\"q\"]\n"
	d, err := Extract([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	d.TOML(&b, "v1")
	var f struct {
		Signature []struct {
			ID, Title      string
			NucleiTemplate string `toml:"nuclei_template"`
			Route          []struct{ Path string }
			Match          []struct {
				Param    string
				Contains []string
			}
		}
	}
	if _, err := toml.Decode(b.String(), &f); err != nil {
		t.Fatalf("the draft is not TOML: %v\n%s", err, b.String())
	}
	s := f.Signature[0]
	if s.NucleiTemplate != "markerx" || s.Title != "ny" || s.Route[0].Path != "/ab" || s.Match[0].Contains[0] != "vw\"q" {
		t.Errorf("read back %+v", s)
	}
}
