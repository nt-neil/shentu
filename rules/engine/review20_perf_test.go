package engine

// PR #20 review: time of inputs aimed at the new code (inline HTML context
// tracking, preg_replace detection, output contexts). Logs the time; fails over 3s.

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nt-neil/shentu/rules"
)

func TestR20Perf(t *testing.T) {
	rs, _ := rules.Load()
	e, _ := New(rs)
	html := strings.Repeat("<div class=\"a\" title='b' data-x=y>", 60) // ~2KB of markup per tag
	cases := []struct{ name, lang, src string }{
		{"many open tags", "php", strings.Repeat("x<?=1?>", 40000)},
		{"many tags after long markup", "php", strings.Repeat(html+"<?php echo $_GET['a']; ?>", 120)},
		{"unclosed tag markup", "php", strings.Repeat("<a href=\"x <?php echo $_GET['a'] ?>", 20000)},
		{"preg_replace chain", "php", "<?php\n$x = " + strings.Repeat("preg_replace('/[^a-z]/', '', ", 2000) + "$_GET['x']" + strings.Repeat(")", 2000) + ";\necho $x;\n"},
		{"long echo concat", "php", "<?php\necho '<a href=\"' " + strings.Repeat(". $_GET['a'] . '\" x=\"' ", 5000) + ";\n"},
		{"long echo concat x4", "php", "<?php\necho '<a href=\"' " + strings.Repeat(". $_GET['a'] . '\" x=\"' ", 20000) + ";\n"},
		{"py response concat", "python", "def v(request):\n    return HttpResponse('<a href=\"' " + strings.Repeat("+ request.GET['a'] + '\" x=\"' ", 5000) + ")\n"},
	}
	for _, c := range cases {
		start := time.Now()
		_, err := e.Scan(c.lang, "p", []byte(c.src))
		el := time.Since(start)
		t.Logf("%-30s %7d bytes %v err=%v", c.name, len(c.src), el, err)
		if el > 3*time.Second {
			t.Errorf("%s: %v", c.name, el)
		}
	}
}

// A minified vendor file from the cvebench cache (R20_FILE) that took 2.4s on
// head in the corpus run and was not slow on base.
func TestR20PerfFile(t *testing.T) {
	p := os.Getenv("R20_FILE")
	if p == "" {
		t.Skip("R20_FILE not set")
	}
	src, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	rs, _ := rules.Load()
	e, _ := New(rs)
	for i := 0; i < 3; i++ {
		start := time.Now()
		_, err := e.Scan("js", p, src)
		t.Logf("%d bytes %v err=%v", len(src), time.Since(start), err)
	}
}
