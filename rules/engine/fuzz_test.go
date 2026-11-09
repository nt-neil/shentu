package engine

import (
	"sync"
	"testing"
	"time"

	"github.com/nt-neil/shentu/rules"
)

var (
	fuzzOnce   sync.Once
	fuzzEngine *Engine
)

// fuzzLex lexes, parses and scans src under small limits: nothing may panic,
// the token cap must hold, and line numbers must not go backwards.
func fuzzLex(t *testing.T, lang, src string) {
	fuzzOnce.Do(func() {
		rs, err := rules.Load()
		if err != nil {
			panic(err)
		}
		if fuzzEngine, err = New(rs); err != nil {
			panic(err)
		}
		fuzzEngine.Limits = Limits{MaxTokens: 20_000, MaxTime: time.Second}
	})
	b := newBudget(fuzzEngine.Limits)
	toks := lex(lang, src, b)
	if len(toks) > fuzzEngine.Limits.MaxTokens+1 {
		t.Fatalf("%d tokens, cap %d", len(toks), fuzzEngine.Limits.MaxTokens)
	}
	for i := 1; i < len(toks); i++ {
		if toks[i].Line < toks[i-1].Line {
			t.Fatalf("token %d on line %d after line %d", i, toks[i].Line, toks[i-1].Line)
		}
	}
	fuzzEngine.Scan(lang, "fuzz", []byte(src))
}

func seeds(f *testing.F, lang string, extra ...string) {
	rs, err := rules.Load()
	if err != nil {
		f.Fatal(err)
	}
	for _, r := range rs {
		if r.Lang == baseLang(lang) {
			for _, s := range r.Samples {
				f.Add(s.Code)
			}
		}
	}
	for _, s := range extra {
		f.Add(s)
	}
}

func FuzzLexPHP(f *testing.F) {
	seeds(f, "php", "<?php \"{$a[\"}\"]}\" <<<X\n{$b}\nX;", "<?php `$x", "<?php #[A('x')] function f() {}", "<?php if ($a): elseif ($b): else: endif;")
	f.Fuzz(func(t *testing.T, src string) { fuzzLex(t, "php", src) })
}

func FuzzLexPython(f *testing.F) {
	seeds(f, "python", "f'{a!r:{b}}' '''x\n", "def f(:\n\tif x: y\n  z", "f\"{f'{f\"{x}\"}'}\"")
	f.Fuzz(func(t *testing.T, src string) { fuzzLex(t, "python", src) })
}

func FuzzLexJS(f *testing.F) {
	seeds(f, "js", "`${`${`${a}`}`}`", "a = b\n/re/g.test(c)", "({ m() { return x => y } })", "class A { #p = 1; static { } get x() {} }")
	f.Fuzz(func(t *testing.T, src string) { fuzzLex(t, "js", src) })
}

func FuzzLexTS(f *testing.F) {
	seeds(f, "ts", "let a: Map<string, Array<number>> = new Map<string, Array<number>>();", "f<T>(x as T)!.y satisfies Z",
		"@C() class A<T> extends B<T> implements I { constructor(private readonly s: S, @Body() b: D) {} m?(): void; }",
		"type U = | 'a' | { b: string }\ninterface I { [k: string]: any }\nenum E { A = 1 }\ndeclare module 'm' { }",
		"x! / 2 / y; a < b > (c); <T,>(x: T): T => x; namespace N.M { }", "`${(a as any)!.b}`")
	f.Fuzz(func(t *testing.T, src string) {
		fuzzLex(t, "ts", src)
		fuzzLex(t, "tsx", src)
	})
}
