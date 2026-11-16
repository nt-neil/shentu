// Command sigextract drafts shentu detect signatures from Nuclei templates,
// offline: it reads template files given on the command line (a checkout of
// nuclei-templates, MIT) and prints draft [[signature]] tables (TOML) for a
// person to review before any is added to detect/sig/signatures.
//
// A template's matchers look at the response; a web server's log has only
// the request. What is taken is the request: its method, the path (the
// route) and the query's parameters with their values (the payload). Each
// draft names the template id and the templates' release given with
// -release, as plan 0743f0 requires of a Nuclei signature, and is marked
// DRAFT until reviewed.
//
// It is its own module, so that its YAML dependency stays out of shentu.
package main

import (
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// Template is the part of a Nuclei template a draft is made from.
type Template struct {
	ID   string `yaml:"id"`
	Info struct {
		Name           string `yaml:"name"`
		Tags           any    `yaml:"tags"` // "a,b" or a list
		Classification struct {
			CVE any `yaml:"cve-id"`
			CWE any `yaml:"cwe-id"`
		} `yaml:"classification"`
	} `yaml:"info"`
	HTTP     []Request `yaml:"http"`
	Requests []Request `yaml:"requests"` // the older key
}

// Request is one request of a template.
type Request struct {
	Method string   `yaml:"method"`
	Path   []string `yaml:"path"`
	Raw    []string `yaml:"raw"`
}

// Draft is what is taken from one template.
type Draft struct {
	ID, Title, Class, Template string
	CVEs, CWEs                 []string
	Routes                     []Route
	Params                     map[string]string // the first payload of each parameter
	Skipped                    []string          // what could not be taken, said in the draft
}

// Route is a method and a path.
type Route struct{ Method, Path string }

// classByTag maps a template's tags to a payload class.
var classByTag = map[string]string{
	"sqli": "sqli", "lfi": "path", "traversal": "path", "file-inclusion": "path", "rce": "cmdi", "cmdi": "cmdi",
	"command-injection": "cmdi", "ssrf": "ssrf", "xss": "xss", "xxe": "xxe", "ssti": "code", "code-injection": "code",
	"deserialization": "deser", "redirect": "redirect", "upload": "upload", "fileupload": "upload",
}

var (
	idClean = regexp.MustCompile(`[^a-z0-9]+`)
	helper  = regexp.MustCompile(`\{\{[^}]*\}\}`)
)

// Extract drafts a signature from one template's YAML.
func Extract(b []byte) (Draft, error) {
	var t Template
	if err := yaml.Unmarshal(b, &t); err != nil {
		return Draft{}, err
	}
	if t.ID == "" {
		return Draft{}, fmt.Errorf("no id")
	}
	t.ID = clean(t.ID) // a newline in it would start a TOML line after the draft's comment
	d := Draft{ID: "nuclei-" + strings.Trim(idClean.ReplaceAllString(strings.ToLower(t.ID), "-"), "-"), Title: clean(t.Info.Name), Template: t.ID, Params: map[string]string{}}
	d.CVEs = list(t.Info.Classification.CVE)
	for _, c := range list(t.Info.Classification.CWE) {
		d.CWEs = append(d.CWEs, strings.ToUpper(c))
	}
	for _, tag := range list(t.Info.Tags) {
		if c, ok := classByTag[strings.ToLower(strings.TrimSpace(tag))]; ok && d.Class == "" {
			d.Class = c
		}
	}
	for _, r := range append(t.HTTP, t.Requests...) {
		method := strings.ToUpper(r.Method)
		if method == "" {
			method = "GET"
		}
		for _, p := range r.Path {
			d.take(clean(method), clean(strings.TrimPrefix(p, "{{BaseURL}}")))
		}
		for _, raw := range r.Raw {
			line, _, _ := strings.Cut(strings.TrimLeft(raw, "\n "), "\n")
			f := strings.Fields(line)
			if len(f) < 2 {
				d.Skipped = append(d.Skipped, "a raw request without a request line")
				continue
			}
			d.take(clean(strings.ToUpper(f[0])), clean(f[1]))
		}
	}
	if len(d.Routes) == 0 {
		return d, fmt.Errorf("%s: no request path to take", t.ID)
	}
	return d, nil
}

// take adds a request's route and its query's parameters.
func (d *Draft) take(method, target string) {
	if helper.MatchString(target) && !strings.HasPrefix(target, "/") {
		d.Skipped = append(d.Skipped, "a path built from helpers: "+target)
		return
	}
	p, q, _ := strings.Cut(target, "?")
	if p == "" {
		p = "/"
	}
	if helper.MatchString(p) {
		d.Skipped = append(d.Skipped, "a path with a template helper (left out of the route): "+p)
		p = helper.ReplaceAllString(p, "")
	}
	r := Route{method, p}
	seen := false
	for _, x := range d.Routes {
		seen = seen || x == r
	}
	if !seen {
		d.Routes = append(d.Routes, r)
	}
	vals, err := url.ParseQuery(q)
	if err != nil {
		d.Skipped = append(d.Skipped, "a query that does not parse: "+q)
		return
	}
	for k, vs := range vals {
		if _, ok := d.Params[k]; ok || len(vs) == 0 {
			continue
		}
		v := helper.ReplaceAllString(vs[0], "")
		if strings.TrimSpace(v) == "" {
			d.Skipped = append(d.Skipped, "parameter "+k+": only helpers ({{...}}), no literal")
			continue
		}
		d.Params[k] = v
	}
}

// TOML writes the draft as a [[signature]] table, marked for review.
func (d Draft) TOML(w io.Writer, release string) {
	fmt.Fprintf(w, "# DRAFT from Nuclei template %s (nuclei-templates %s, MIT): review before adding.\n", clean(d.Template), clean(release))
	for _, s := range d.Skipped {
		fmt.Fprintf(w, "# skipped: %s\n", clean(s))
	}
	class := d.Class
	if class == "" {
		fmt.Fprintln(w, "# class: none of the template's tags names one; set it by hand.")
	}
	fmt.Fprintf(w, "[[signature]]\nid = %s\ntitle = %s\nclass = %s\n", tomlString(d.ID), tomlString(d.Title), tomlString(class))
	if len(d.CWEs) > 0 {
		fmt.Fprintf(w, "cwe = %s\n", tomlList(d.CWEs))
	}
	if len(d.CVEs) > 0 {
		fmt.Fprintf(w, "cves = %s\n", tomlList(upper(d.CVEs)))
	}
	fmt.Fprintf(w, "source = \"nuclei\"\nlicense = \"MIT\"\nnuclei_template = %s\nnuclei_version = %s\n", tomlString(d.Template), tomlString(release))
	for _, r := range d.Routes {
		fmt.Fprintf(w, "[[signature.route]]\nmethods = [%s]\npath = %s\n", tomlString(r.Method), tomlString(r.Path))
	}
	keys := make([]string, 0, len(d.Params))
	for k := range d.Params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(w, "[[signature.match]]\npart = \"param\"\nparam = %s\ncontains = [%s]\n", tomlString(k), tomlString(strings.ToLower(d.Params[k])))
	}
	fmt.Fprintln(w)
}

func tomlList(xs []string) string {
	q := make([]string, len(xs))
	for i, x := range xs {
		q[i] = tomlString(x)
	}
	return "[" + strings.Join(q, ", ") + "]"
}

// clean drops control characters: a template's id, name or path is put in
// comments and strings of the draft, where a newline would end the line.
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
}

// tomlString is s as a TOML basic string (Go's %q is not TOML: \x00, \a,
// \v and \U escapes are Go's).
func tomlString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\t':
			b.WriteString(`\t`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == utf8.RuneError:
			b.WriteString(`\uFFFD`)
		case unicode.IsControl(r):
			fmt.Fprintf(&b, `\u%04X`, r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

func upper(xs []string) []string {
	out := make([]string, len(xs))
	for i, x := range xs {
		out[i] = strings.ToUpper(x)
	}
	return out
}

// list reads a field Nuclei writes as "a,b" or as a list.
func list(v any) []string {
	switch x := v.(type) {
	case string:
		var out []string
		for _, s := range strings.Split(x, ",") {
			if s = strings.TrimSpace(s); s != "" {
				out = append(out, s)
			}
		}
		return out
	case []any:
		var out []string
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func main() {
	release := flag.String("release", "", "the nuclei-templates release the files come from (v10.1.0): required")
	flag.Parse()
	if *release == "" || flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: sigextract -release vX.Y.Z template.yaml...")
		os.Exit(2)
	}
	failed := 0
	for _, f := range flag.Args() {
		b, err := os.ReadFile(f)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			failed++
			continue
		}
		d, err := Extract(b)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", f, err)
			failed++
			continue
		}
		d.TOML(os.Stdout, *release)
	}
	if failed > 0 {
		os.Exit(1)
	}
}
