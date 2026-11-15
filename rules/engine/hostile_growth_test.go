package engine

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Small hostile files whose cost grew with the square of their size: a
// method calling $this->q() 20,000 times (74s), [a, ...].join(a long
// separator) (98 MB from 1.2 KB), nested const [ patterns, a long literal
// before many operands of an echo, ${"{"} repeated in a template. Four times
// the input must cost about four times as much, not sixteen: the memory
// allocated (which does not depend on the machine) and, once it is long
// enough to measure, the time, the fastest of three runs. The bound is eight
// times, so a busy machine (a load of 172 failed a twofold bound) does not
// trip it while a square still does; some of the cases grew only in time
// (B1, S4, S5), so the time is checked too.
func TestHostileGrowth(t *testing.T) {
	R := strings.Repeat
	cases := []struct {
		name, lang, file string
		n                int
		gen              func(n int) string
	}{
		{"php $this calls", "php", "a.php", 2500, func(n int) string {
			var b strings.Builder
			b.WriteString("<?php\n")
			for _, c := range []string{"A", "B"} {
				fmt.Fprintf(&b, "class %s {\nfunction m() {\n%s}\nfunction q() {}\n}\n", c, R("$this->q();\n", n))
			}
			b.WriteString("system($_GET['x']);\n")
			return b.String()
		}},
		{"js join separator", "js", "a.js", 150, func(n int) string {
			return "exec([" + R("a,", n) + "a].join(" + R("s+", n) + "s));\n"
		}},
		{"js nested const [", "js", "a.js", 1500, func(n int) string {
			return "const cp = require('child_process');\n" + R("const [a, ", n) + "b" + R("]", n) + ";\ncp.exec(req.query.x);\n"
		}},
		{"php literal before operands", "php", "a.php", 250, func(n int) string {
			return "<?php $a = $_GET['a']; ?>\n<a href=\"<?php echo '" + R("X", 256*n) + "'" + R(" . $b", n) + " . $a; ?>\">x</a>\n"
		}},
		{"js ${\"{\"} in a template", "js", "a.js", 2000, func(n int) string {
			return "app.get('/x', (req, res) => {\n  res.send(`<p>" + R("${\"{\"}", n) + "${req.query.x}</p>`);\n});\n"
		}},
	}
	for _, c := range cases {
		e := engineForTest(t)
		e.Limits = Limits{MaxTokens: DefaultLimits.MaxTokens * 4, MaxTime: 30 * time.Second}
		run := func(n int) (time.Duration, uint64, error) {
			src := []byte(c.gen(n))
			runtime.GC()
			var m0, m1 runtime.MemStats
			runtime.ReadMemStats(&m0)
			start := time.Now()
			_, err := e.Scan(c.lang, c.file, src)
			took := time.Since(start)
			runtime.ReadMemStats(&m1)
			return took, m1.TotalAlloc - m0.TotalAlloc, err
		}
		fastest := func(n int) (time.Duration, uint64, error) {
			t, a, err := run(n)
			for range 2 {
				t2, a2, err2 := run(n)
				t, a = min(t, t2), min(a, a2)
				if err == nil {
					err = err2
				}
			}
			return t, a, err
		}
		t1, a1, err1 := fastest(c.n)
		t4, a4, err4 := fastest(4 * c.n)
		t.Logf("%-28s n %v %v err %v; 4n %v %v err %v", c.name, t1.Round(time.Millisecond), mb(a1), err1,
			t4.Round(time.Millisecond), mb(a4), err4)
		if err1 != nil || err4 != nil {
			t.Errorf("%s: err %v, %v; want the file read to its end", c.name, err1, err4)
		}
		if float64(a4) > 8*float64(a1) {
			t.Errorf("%s: four times the input allocated %v, from %v: more than linear", c.name, mb(a4), mb(a1))
		}
		if t4 > 200*time.Millisecond && float64(t4) > 8*float64(t1) {
			t.Errorf("%s: four times the input took %v, from %v: more than linear", c.name, t4, t1)
		}
	}
}

// Building a file's call graph is bounded by the file's clock, like the rest
// of its analysis, and a scan it stops says so (it used to have a day). The
// file takes about 75ms with no cap, so a cap of 10ms always cuts it; where
// the clock runs out (the graph, or following calls: ErrCalls) depends on
// the machine, and either way the scan must say it did not finish.
func TestCallGraphClock(t *testing.T) {
	e := engineForTest(t)
	const limit = 10 * time.Millisecond
	e.Limits = Limits{MaxTokens: DefaultLimits.MaxTokens * 4, MaxTime: limit}
	var b strings.Builder
	b.WriteString("<?php\n")
	for _, c := range []string{"A", "B"} {
		fmt.Fprintf(&b, "class %s {\nfunction m() {\n%s}\nfunction q() {}\n}\n", c, strings.Repeat("$this->q();\n", 20000))
	}
	b.WriteString("system($_GET['x']);\n")
	start := time.Now()
	_, err := e.Scan("php", "a.php", []byte(b.String()))
	took := time.Since(start)
	t.Logf("took %v err %v", took.Round(time.Millisecond), err)
	if took > limit+time.Second {
		t.Errorf("took %v, cap %v", took, limit)
	}
	if took > limit && err != ErrLimit && err != ErrCalls {
		t.Errorf("over the cap (%v) but err = %v, want ErrLimit or ErrCalls", took, err)
	}
}

func mb(n uint64) string { return fmt.Sprintf("%.1fMB", float64(n)/(1<<20)) }
