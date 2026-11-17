package main

import (
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// What a template is read as, as tools/sigextract reads it: the request a
// web server's access log keeps (method and target), not its headers,
// body or the matchers on the response.
type template struct {
	ID   string `yaml:"id"`
	Info struct {
		Tags           any `yaml:"tags"`
		Classification struct {
			CVE any `yaml:"cve-id"`
		} `yaml:"classification"`
	} `yaml:"info"`
	Variables map[string]any `yaml:"variables"`
	HTTP      []request      `yaml:"http"`
	Requests  []request      `yaml:"requests"` // the older key
}

type request struct {
	Method   string         `yaml:"method"`
	Path     []string       `yaml:"path"`
	Raw      []string       `yaml:"raw"`
	Payloads map[string]any `yaml:"payloads"`
}

// attack is one template made into requests.
type attack struct {
	ID    string   // the template's id
	File  string   // its path in nuclei-templates
	Class string   // the payload class its tags name; "" when none does
	CVEs  []string // upper case
	Lines []target // at most maxPerTemplate
}

type target struct{ Method, Target string }

const maxPerTemplate = 20

// classByTag: as tools/sigextract maps a template's tags to a class.
var classByTag = map[string]string{
	"sqli": "sqli", "lfi": "path", "traversal": "path", "file-inclusion": "path", "rce": "cmdi", "cmdi": "cmdi",
	"command-injection": "cmdi", "ssrf": "ssrf", "xss": "xss", "xxe": "xxe", "ssti": "code", "code-injection": "code",
	"deserialization": "deser", "redirect": "redirect", "upload": "upload", "fileupload": "upload",
}

var helperRe = regexp.MustCompile(`\{\{([^{}]*)\}\}`)

// convert makes a template into requests. An error says why it could not
// be: the template is counted as not converted.
func convert(file string, b []byte) (attack, error) {
	var t template
	if err := yaml.Unmarshal(b, &t); err != nil {
		return attack{}, fmt.Errorf("yaml: %v", err)
	}
	a := attack{ID: oneLine(t.ID), File: file}
	if a.ID == "" {
		return a, fmt.Errorf("no id")
	}
	for _, tag := range list(t.Info.Tags) {
		if c, ok := classByTag[strings.ToLower(strings.TrimSpace(tag))]; ok && a.Class == "" {
			a.Class = c
		}
	}
	for _, c := range list(t.Info.Classification.CVE) {
		a.CVEs = append(a.CVEs, strings.ToUpper(strings.TrimSpace(c)))
	}
	seen := map[target]bool{}
	add := func(m, tg string) {
		x := target{m, tg}
		if !seen[x] && len(a.Lines) < maxPerTemplate {
			seen[x] = true
			a.Lines = append(a.Lines, x)
		}
	}
	for _, r := range append(t.HTTP, t.Requests...) {
		vars := values(t.Variables, r.Payloads)
		method := strings.ToUpper(strings.TrimSpace(r.Method))
		if method == "" {
			method = "GET"
		}
		for _, p := range r.Path {
			p = strings.TrimSpace(p)
			for _, base := range []string{"{{BaseURL}}", "{{RootURL}}"} {
				p = strings.TrimPrefix(p, base)
			}
			if p == "" {
				p = "/"
			}
			if tg, ok := fill(p, vars); ok {
				add(method, tg)
			}
		}
		for _, raw := range r.Raw {
			line, _, _ := strings.Cut(strings.TrimLeft(raw, "\r\n\t "), "\n")
			f := strings.Fields(fillAll(strings.TrimSpace(line), vars))
			if len(f) < 2 {
				continue
			}
			if tg, ok := fill(f[1], vars); ok {
				add(strings.ToUpper(f[0]), tg)
			}
		}
	}
	if len(a.Lines) == 0 {
		return a, fmt.Errorf("no request target")
	}
	return a, nil
}

// values: the template's variables and the request's payloads, the first
// of each list, as literals (a payload read from a file is not known).
func values(vars, payloads map[string]any) map[string]string {
	out := map[string]string{}
	for k, v := range vars {
		if s, ok := v.(string); ok {
			out[strings.ToLower(k)] = s
		}
	}
	for k, v := range payloads {
		if xs, ok := v.([]any); ok && len(xs) > 0 {
			out[strings.ToLower(k)] = fmt.Sprint(xs[0])
		}
	}
	return out
}

// fill puts the values in a target and a placeholder for any other
// helper; a target that does not begin with "/" (a host, a full URL built
// from helpers) is not one a log keeps.
func fill(s string, vars map[string]string) (string, bool) {
	s = fillAll(s, vars)
	if !strings.HasPrefix(s, "/") {
		return "", false
	}
	return s, true
}

func fillAll(s string, vars map[string]string) string {
	for i := 0; i < 2; i++ { // a variable may be made of others
		s = helperRe.ReplaceAllStringFunc(s, func(m string) string {
			if v, ok := vars[strings.ToLower(strings.TrimSpace(m[2:len(m)-2]))]; ok {
				return v
			}
			return m
		})
	}
	return helperRe.ReplaceAllString(s, "x")
}

// list reads a field Nuclei writes as "a,b" or as a list.
func list(v any) []string {
	var out []string
	switch x := v.(type) {
	case string:
		for _, s := range strings.Split(x, ",") {
			if s = strings.TrimSpace(s); s != "" {
				out = append(out, s)
			}
		}
	case []any:
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

func oneLine(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == ' ' || r == ' ' {
			return -1
		}
		return r
	}, s)
}

// logLine is a request as Apache's combined format logs it: '"' and '\'
// escaped, bytes outside printable ASCII as \xhh.
func logLine(t target) string {
	var b strings.Builder
	for _, c := range []byte(t.Method + " " + t.Target + " HTTP/1.1") {
		switch {
		case c == '"' || c == '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		case c < 0x20 || c >= 0x7f:
			fmt.Fprintf(&b, `\x%02x`, c)
		default:
			b.WriteByte(c)
		}
	}
	return `203.0.113.7 - - [17/Nov/2026:12:00:00 +0000] "` + b.String() + `" 200 512 "-" "` + evalUA + `"`
}

// evalUA: one browser's, so that a scanner's name in the user agent is
// not what is measured.
const evalUA = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"
