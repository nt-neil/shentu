package engine

// v0.2.5 review of the TypeScript front end (B3, B6, S6, S7): hostile type
// syntax and decorators stay within the limits, and relative imports of
// TypeScript modules resolve as JavaScript ones do.

import (
	"errors"
	"runtime"
	"runtime/debug"
	"slices"
	"strings"
	"testing"
	"time"
)

const tsfixVuln = "\napp.get('/x', (req, res) => { exec(req.query.c); });\n"

// B3: each decorator of a destructured parameter copies the pattern into the
// body; many decorators on a long pattern must not blow up the token stream.
func TestTSFixDecoratorCopies(t *testing.T) {
	e := engineForTest(t)
	for _, n := range []int{150, 500} {
		src := "class C {\n  m(" + strings.Repeat("@Body() ", n) + "{ " + strings.Repeat("a, ", n) + "}: D) { exec(a); }\n}\n" + tsfixVuln
		var m0, m1 runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&m0)
		fs, err := e.Scan("ts", "deco.ts", []byte(src))
		runtime.ReadMemStats(&m1)
		alloc := m1.TotalAlloc - m0.TotalAlloc
		t.Logf("%d decorators, %d bytes: %d MB allocated, err=%v", n, len(src), alloc>>20, err)
		if alloc > 64<<20 {
			t.Errorf("%d bytes allocated %d MB", len(src), alloc>>20)
		}
		if toks := LexTS(src); len(toks) > 8*len(LexJS(src)) {
			t.Errorf("%d tokens out of %d", len(toks), len(LexJS(src)))
		}
		if !slices.ContainsFunc(fs, func(f Finding) bool { return f.Line == strings.Count(src, "\n") }) {
			t.Errorf("the vulnerable route at the end is not reported: %v", fs)
		}
	}
	// One decorator on a pattern still becomes a statement in the body.
	fs, _ := e.Scan("ts", "nest.ts", []byte("@Controller()\nexport class C {\n  @Post()\n  run(@Body() { cmd }: Dto) {\n    return execSync(cmd);\n  }\n}\n"))
	if len(fs) == 0 {
		t.Error("@Body() { cmd } is no longer a source")
	}
}

// S6: type syntax nested very deep is cut short (ErrLimit), not followed down
// the stack.
func TestTSFixTypeDepth(t *testing.T) {
	e := engineForTest(t)
	n := 60000 // under the token cap, so the code after the type is read
	for _, c := range []struct{ name, src string }{
		{"is-chain", "function f(a): " + strings.Repeat("x is ", n) + "y { return a; }" + tsfixVuln},
		{"keyof-chain", "type A = " + strings.Repeat("keyof ", n) + "B;" + tsfixVuln},
		{"cond-chain", "type A = " + strings.Repeat("B extends C ? D : ", n/4) + "E;" + tsfixVuln},
		{"fn-type-chain", "let a: " + strings.Repeat("() => ", n) + "void;" + tsfixVuln},
	} {
		old := debug.SetMaxStack(32 << 20) // the review saw 128MB of stack
		done := make(chan struct{})
		var fs []Finding
		var err error
		go func() {
			defer close(done)
			fs, err = e.Scan("ts", c.name, []byte(c.src))
		}()
		<-done
		debug.SetMaxStack(old)
		if !errors.Is(err, ErrLimit) {
			t.Errorf("%s: err %v, want ErrLimit", c.name, err)
		}
		if len(fs) == 0 {
			t.Errorf("%s: the vulnerable route at the end is not reported", c.name)
		}
	}
}

// S7: an unclosed "<" or "(" is not read to the end of the file again from
// each position, so a hostile prefix does not hide the code after it.
func TestTSFixUnclosedLinear(t *testing.T) {
	e := engineForTest(t)
	n := 80000 / 8
	for _, c := range []struct{ name, src string }{
		{"type-lt", strings.Repeat("let a: b<\n", n)},
		{"alias-lt", strings.Repeat("type A<T\n", n)},
		{"type-paren", strings.Repeat("let a: (\n", n)},
		{"deco-paren", strings.Repeat("@d(\n", n)},
		{"interface-brace", strings.Repeat("interface A {\n", n)},
		{"enum-brace", strings.Repeat("enum E {\n", n)},
		{"lt-paren", strings.Repeat("x<(", n*2)},
		{"index-bracket", strings.Repeat("let a: b[\n", n)},
	} {
		src := c.src + tsfixVuln
		start := time.Now()
		fs, err := e.Scan("ts", c.name, []byte(src))
		d := time.Since(start)
		t.Logf("%-16s %6d bytes %v err=%v", c.name, len(src), d, err)
		if d > 500*time.Millisecond {
			t.Errorf("%s: %v for %d bytes", c.name, d, len(src))
		}
		// Braces left open 10000 deep are past the nesting limit whatever the type syntax.
		if errors.Is(err, ErrLimit) && !strings.HasSuffix(c.name, "-brace") {
			t.Errorf("%s: err %v, the file is not analysed", c.name, err)
		}
		if len(fs) == 0 {
			t.Errorf("%s: the vulnerable route at the end is not reported", c.name)
		}
	}
}

// B6: a relative import of a TypeScript module resolves as one of a
// JavaScript module does.
func TestTSFixImportExtensions(t *testing.T) {
	e := engineForTest(t)
	util := "const { exec } = require('child_process');\nexport function run(c) {\n  exec('ls ' + c);\n}\n"
	route := "import { run } from './%s';\napp.get('/x', (req, res) => { run(req.query.c); });\n"
	js, _, jsErrs := projectScanErrs(t, e, map[string]string{"src/a.js": strings.Replace(route, "%s", "util", 1), "src/util.js": util}, ProjectOptions{})
	if len(js) == 0 || len(jsErrs) != 0 {
		t.Fatalf("js project: %v %v", js, jsErrs)
	}
	for _, c := range []struct{ a, mod, util string }{
		{"src/a.ts", "util", "src/util.ts"},
		{"src/a.ts", "util", "src/util.tsx"},
		{"src/a.mts", "util", "src/util.mts"},
		{"src/a.cts", "util", "src/util.cts"},
		{"src/a.ts", "util", "src/util/index.ts"},
		{"src/a.tsx", "util", "src/util/index.tsx"},
		{"src/a.ts", "util.js", "src/util.ts"}, // ESM TypeScript names the emitted .js
	} {
		got, _, errs := projectScanErrs(t, e, map[string]string{c.a: strings.Replace(route, "%s", c.mod, 1), c.util: util}, ProjectOptions{})
		var want []string
		for _, f := range js {
			want = append(want, strings.NewReplacer("src/util.js", c.util, "src/a.js", c.a).Replace(f))
		}
		if !sameSet(got, want) || len(errs) != 0 {
			t.Errorf("%s imports './%s' from %s: %v %v, want %v as in JavaScript (%v)", c.a, c.mod, c.util, got, errs, want, js)
		}
	}
}
