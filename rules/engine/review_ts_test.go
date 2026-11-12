package engine

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// TestReviewTS holds the cases of the independent review of PR #22 (409c116):
// TypeScript, JSX and module spellings that were missed or misreported. A case
// with gap is a known limit: logged, not failed.
func TestReviewTS(t *testing.T) {
	e := engineForTest(t)
	h := func(pre, body string) string { return pre + "\napp.get('/x', (req, res) => {\n" + body + "\n});\n" }
	cases := []struct {
		name, lang, src string
		want            bool
		gap             string
	}{
		// "<" that is a comparison, not type arguments
		{"cmp-generic-paren", "ts", h("", "f(a < exec(req.query.c), b > (0));"), true, ""},
		{"cmp-generic-ternary", "ts", h("", "const v = lo < hi ? exec(req.query.c) : hi > (lo);"), true, ""},
		{"cmp-generic-js", "js", h("", "f(a < exec(req.query.c), b > (0));"), true, ""},
		// decorated parameters
		{"deco-destructure", "ts", "class C {\n  @Post()\n  run(@Body() { cmd }: RunDto) {\n    exec(cmd);\n  }\n}\n", true, ""},
		{"deco-space", "ts", "class C {\n  @Post()\n  run(@ Body() dto: RunDto) {\n    exec(dto.cmd);\n  }\n}\n", true, ""},
		{"deco-two-params", "ts", "class C {\n  @Post()\n  run(@Query('a') a: string, @Body() dto: RunDto) {\n    exec(dto.cmd);\n  }\n}\n", true, ""},
		{"deco-after-plain", "ts", "class C {\n  @Post()\n  run(x: number, @Body('cmd') cmd: string) {\n    exec(cmd);\n  }\n}\n", true, ""},
		{"deco-wrong-pos", "ts", "class C {\n  @Post()\n  run(@Body('cmd') cmd: string, other: string) {\n    exec(other);\n  }\n}\n", false, ""},
		{"deco-headers", "ts", "class C {\n  @Get()\n  run(@Headers('x-cmd') cmd: string) {\n    exec(cmd);\n  }\n}\n", true, ""},
		{"deco-req-url", "ts", "class C {\n  @Get()\n  run(@Req() r: Request) {\n    exec('curl ' + r.originalUrl);\n  }\n}\n", true, ""},
		{"deco-req-get", "ts", "class C {\n  @Get()\n  run(@Req() r: Request) {\n    exec('echo ' + r.get('x-cmd'));\n  }\n}\n", true, ""},
		{"deco-default-int-pipe", "ts", "class C {\n  @Get()\n  one(@Query('p', new DefaultValuePipe(1), ParseIntPipe) p: number) {\n    return this.ds.query(`SELECT * FROM u LIMIT ${p}`);\n  }\n}\n", false, ""},
		{"deco-field", "ts", "class C {\n  @Input() name: string;\n  @Post()\n  run(@Body() dto: D) { exec(dto.c); }\n}\n", true, ""},
		{"deco-args-arrow", "ts", "class C {\n  @UseGuards(() => { return true; })\n  @Post()\n  run(@Body() dto: D) { exec(dto.c); }\n}\n", true, ""},
		{"deco-validation-dto", "ts", "class Dto { @IsInt() id!: number }\nclass C {\n  @Get()\n  one(@Body() dto: Dto) {\n    return this.ds.query(`SELECT * FROM u WHERE id = ${dto.id}`);\n  }\n}\n", false,
			"class-validator decorators on the DTO are not read: a @Body() DTO is input whatever its field types say (a design choice)"},
		// JSX text and children
		{"tsx-jsx-text-colon", "tsx", "export async function GET(request: Request) {\n  return render((<p>Name, out: {execSync(request.url)}</p>));\n}\n", true, ""},
		{"tsx-jsx-text-url", "tsx", "export async function GET(request: Request) {\n  const q = request.url;\n  const v = <p>See https://example.com {execSync(q)}</p>;\n}\n", true, ""},
		{"jsx-jsx-text-url", "jsx", h("", "const v = <p>See https://example.com {execSync(req.query.c)}</p>;"), true, ""},
		{"tsx-jsx-apostrophe", "tsx", "export async function GET(request: Request) {\n  const v = <p>It's {execSync(request.url)}</p>;\n}\n", true, ""},
		{"jsx-apostrophe", "jsx", h("", "const v = <p>It's {execSync(req.query.c)}</p>;"), true, ""},
		{"jsx-stale-state-regex", "jsx", h("", "const v = <p>It's</p>;\n  if (a </'/.test(b)) exec(req.query.c);"), true, ""},
		{"jsx-closing-tag-regex", "jsx", h("", "const v = <b>x</b>; exec(req.query.c);"), true, ""},
		{"tsx-class-field-jsx", "tsx", "export async function GET(request: Request) {\n  class A {\n    v = <p>a, b: {execSync(request.url)}</p>;\n  }\n}\n", true, ""},
		{"tsx-fragment", "tsx", "export async function GET(request: Request) {\n  const v = <><b>{a}</b>{execSync(request.url)}</>;\n}\n", true, ""},
		{"tsx-attr-expr", "tsx", "export async function GET(request: Request) {\n  const v = <A b={x < y ? execSync(request.url) : z} c={<B d={1} />} />;\n}\n", true, ""},
		{"tsx-nested", "tsx", "export async function GET(request: Request) {\n  const v = <A><B><C>{execSync(request.url)}</C></B></A>;\n}\n", true, ""},
		{"tsx-generic-arrow", "tsx", "export async function GET(request: Request) {\n  const f = <T,>(x: T) => execSync(x as any);\n  exec(request.url);\n}\n", true, ""},
		// second review (a8d8c90)
		{"tsx-type-alias-generic-fn", "tsx", "type F = <T>(x: T) => T;\nexport const h = (req: Request) => execSync(req.query.c as string);\n", true, ""},
		{"tsx-generic-default", "tsx", "const f = <T = unknown,>(x: T) => x;\nexport const h = (req: Request) => execSync(req.query.c as string);\n", true, ""},
		{"tsx-generic-extends", "tsx", "const f = <T extends object>(x: T) => x;\nexport const h = (req: Request) => execSync(req.query.c as string);\n", true, ""},
		{"gen-paren-callee", "ts", h("", "f(a < (exec)(req.query.c), b > (0));"), true, ""},
		{"gen-indirect-eval", "ts", h("", "f(a < (0, eval)(req.body.code), b > (1));"), true, ""},
		{"js-paren-callee", "js", h("", "(exec)(req.query.c);"), true, ""},
		{"next-req-url", "ts", "export async function GET(req: Request) {\n  const { searchParams } = new URL(req.url);\n  await pool.query(`SELECT * FROM t WHERE a = '${searchParams.get('a')}'`);\n}\n", true, ""},
		{"sql-join", "js", h("", "db.query(['SELECT * FROM u WHERE id =', req.query.id].join(' '));"), true, ""},
		{"sql-join-spread", "js", h("", "db.query(['SELECT', ...cols, 'FROM u WHERE id =', req.query.id].join(' '));"), true, ""},
		{"sql-join-safe", "js", h("", "db.query(['SELECT * FROM u', 'WHERE id = ?'].join(' '), [req.query.id]);"), false, ""},
		{"sql-object-sql", "js", h("", "db.query({ sql: 'SELECT * FROM u WHERE id = ' + req.query.id });"), true, ""},
		{"sql-join-pushed", "js", h("", "const parts = ['SELECT * FROM u WHERE id ='];\n  parts.push(req.query.id);\n  db.query(parts.join(' '));"), true,
			"values pushed into an array before .join() are not followed"},
		{"alias-voided-by-param", "js", "const c = require('child_process');\nfunction noop(c) { return c; }\n" + h("", "c.exec('ls ' + req.query.c);"), true, ""},
		{"alias-two-handlers", "js", "app.get('/a', (req, res) => {\n  const { exec: run } = require('child_process');\n  run('ls ' + req.query.c);\n});\napp.get('/b', (req, res) => {\n  const { exec: run } = require('child_process');\n  run('ls ' + req.query.d);\n});\n", true, ""},
		{"alias-if-header", "js", "const run = require('child_process').execSync;\nif (run) { }\n" + h("", "run('ls ' + req.query.c);"), true, ""},
		{"fp-alias-shadow-inner", "js", "const run = require('child_process').execSync;\n" + h("", "const run = (q) => q;\n  run(req.query.c);"), false, ""},
		{"fp-alias-shadow-param", "js", "const c = require('child_process');\nfunction f(c) { c.exec(req.query.c); }\n", false, ""},
		{"fs-no-require", "js", h("", "fs.readFileSync(req.query.f);"), true,
			"a core module name is a module only where the file requires or imports it"},
		// type syntax
		{"ts-string-type", "ts", "type K = '}{';\nlet a: `${'('}` = 'x';" + h("", "exec(req.query.c);"), true, ""},
		{"ts-cond-type", "ts", "type A<T> = T extends string ? { a: T } : never" + h("", "exec(req.query.c);"), true, ""},
		{"ts-satisfies-obj", "ts", h("", "const o = { c: req.query.c } satisfies { c: string };\n  exec(o.c);"), true, ""},
		{"ts-class-field-ternary-nl", "ts", h("", "class A {\n    h =\n      ok ? (x) : exec(req.query.c);\n  }"), true, ""},
		{"ts-class-extends-obj", "ts", h("", "class A extends mix(B, { a: exec(req.query.c) }) {}"), true,
			"the parser skips a class header (extends ...), in .js as well"},
		// Next.js
		{"next-server-action", "ts", "export async function act(formData: FormData) {\n  'use server';\n  exec('echo ' + formData.get('x'));\n}\n", true, ""},
		{"next-cookies", "ts", "export async function GET() {\n  return pool.query(`SELECT * FROM t WHERE a = '${cookies().get('x')!.value}'`);\n}\n", true, ""},
		{"next-params", "ts", "export async function GET(req: Request, { params }: { params: { f: string } }) {\n  exec('cat ' + params.f);\n}\n", true,
			"Next.js route and page params ({ params }) need the route model (P4b)"},
		{"fp-url-searchParams", "js", "const u = new URL(process.env.BASE);" + h("", "db.query('SELECT * FROM t ORDER BY ' + u.searchParams.get('sort'));"), false, ""},
		{"fp-this-request-url", "js", "import FS from 'fs';\nclass Fetch {\n  async send() {\n    const p = this.request.url;\n    return FS.promises.readFile(p);\n  }\n}\n", false, ""},
		{"fp-searchParams-const", "js", h("", "const searchParams = new URLSearchParams({ sort: 'name' });\ndb.query('SELECT * FROM t ORDER BY ' + searchParams.get('sort'));"), false, ""},
		// module spellings
		{"mod-destructure-alias", "js", h("const { exec: run } = require('child_process');", "run('ls ' + req.query.c);"), true, ""},
		{"mod-member-of-require", "js", h("const run = require('child_process').exec;", "run('ls ' + req.query.c);"), true, ""},
		{"mod-copy-alias", "js", h("const cp0 = require('child_process');\nconst c = cp0;", "c.exec('ls ' + req.query.c);"), true, ""},
		{"mod-destructure-from-alias", "js", h("const cp0 = require('child_process');\nconst { exec: run } = cp0;", "run('ls ' + req.query.c);"), true, ""},
		{"mod-vm-destructure", "js", h("const { runInNewContext: r } = require('vm');", "r(req.query.c);"), true, ""},
		{"mod-fs-readfilesync", "js", h("const fs = require('fs');", "fs.readFileSync(req.query.f);"), true, ""},
		{"fp-mod-regex-exec", "js", h("const { exec } = require('child_process');\nconst RE = /^[a-z]+$/;", "const m = RE.exec(req.query.c);"), false, ""},
		{"fp-mod-shadow-local", "js", h("const { execSync: run } = require('child_process');", "const run = (q) => q.trim();\nrun(req.query.c);"), false, ""},
		{"fp-mod-unbound-vm", "js", h("const vm = /^[a-z]+$/;", "const m = vm.exec(req.query.c);"), false, ""},
		{"fp-mod-execfile-alias", "js", h("const { execFile: run } = require('child_process');", "run('ls', [req.query.c]);"), false, ""},
	}
	// Spellings the module rewrite does not follow (base does not either).
	for _, g := range []struct{ name, pre, body string }{
		{"reassign", "let c;\nc = require('child_process');", "c.exec('ls ' + req.query.c);"},
		{"conditional", "const c = process.env.X ? require('child_process') : null;", "c.exec('ls ' + req.query.c);"},
		{"dynamic-concat", "const c = require('child_' + 'process');", "c.exec('ls ' + req.query.c);"},
		{"dynamic-var", "const M = 'child_process';\nconst c = require(M);", "c.exec('ls ' + req.query.c);"},
		{"spread", "const c = { ...require('child_process') };", "c.exec('ls ' + req.query.c);"},
		{"second-declarator", "const a = 1, c = require('child_process');", "c.exec('ls ' + req.query.c);"},
		{"bracket", "const c = require('child_process');", "c['exec']('ls ' + req.query.c);"},
		{"call-method", "const { exec } = require('child_process');", "exec.call(null, 'ls ' + req.query.c);"},
		{"module-require", "const c = module.require('child_process');", "c.exec('ls ' + req.query.c);"},
		{"dynamic-import", "", "import('node:child_process').then(c => c.exec('ls ' + req.query.c));"},
		{"await-import-destructure", "", "(async () => { const { exec: run } = await import('child_process'); run('ls ' + req.query.c); })();"},
		{"nested-promises", "const { promises: { readFile: rf } } = require('fs');", "rf(req.query.f);"},
	} {
		cases = append(cases, struct {
			name, lang, src string
			want            bool
			gap             string
		}{"mod-" + g.name, "js", h(g.pre, g.body), true, "module spelling not followed (left to cross-file analysis, P4)"})
	}
	for _, c := range cases {
		fs, err := e.Scan(c.lang, c.name, []byte(c.src))
		if err != nil && !errors.Is(err, ErrPartial) {
			t.Errorf("%s: %v", c.name, err)
		}
		got := len(fs) > 0
		switch {
		case got == c.want && c.gap != "":
			t.Errorf("%s: marked as a known gap but now passes; remove the mark", c.name)
		case got != c.want && c.gap != "":
			t.Logf("known gap, %s: %s", c.name, c.gap)
		case got != c.want:
			t.Errorf("%s: reported %v, want %v\n%s", c.name, got, c.want, c.src)
		}
	}
}

// TestReviewTSUnclosed: a declaration whose bracket never closes leaves the rest
// of the file to be read as code and is reported as not fully analysed.
func TestReviewTSUnclosed(t *testing.T) {
	e := engineForTest(t)
	vuln := "\napp.get('/x', (req, res) => { exec(req.query.c); });\n"
	for _, pre := range []string{"interface I {", "enum E {", "type A = {", "@D(", "declare module 'm' {"} {
		fs, err := e.Scan("ts", pre, []byte(pre+vuln))
		if !errors.Is(err, ErrPartial) {
			t.Errorf("%q: err %v, want ErrPartial", pre, err)
		}
		if len(fs) == 0 {
			t.Errorf("%q: the code after it is not analysed", pre)
		}
	}
}

// TestReviewTSUnclosedJSX: JSX that never closes is reported as partial.
func TestReviewTSUnclosedJSX(t *testing.T) {
	e := engineForTest(t)
	for _, c := range []struct{ lang, src string }{
		{"tsx", "const v = <p>text\napp.get('/x', (req, res) => { exec(req.query.c); });\n"},
		{"jsx", "const v = <div><b>x</b>\n"},
	} {
		if _, err := e.Scan(c.lang, "x", []byte(c.src)); !errors.Is(err, ErrPartial) {
			t.Errorf("%s %q: err %v, want ErrPartial", c.lang, c.src, err)
		}
	}
}

// TestReviewTSHostile: hostile TypeScript stays within the limits.
func TestReviewTSHostile(t *testing.T) {
	e := engineForTest(t)
	vuln := "\napp.get('/x', (req, res) => { exec(req.query.c); });\n"
	n := 60000
	for _, c := range []struct{ name, lang, src string }{
		{"lt-paren-unclosed", "ts", strings.Repeat("x<(", n)},
		{"lt-chain", "ts", strings.Repeat("a<", n)},
		{"lt-ident-paren", "ts", strings.Repeat("a<b,(c)", n)},
		{"keyof-chain", "ts", "type A = " + strings.Repeat("keyof ", n) + "B;" + vuln},
		{"cond-chain", "ts", "type A = " + strings.Repeat("B extends C ? D : ", n) + "E;" + vuln},
		{"paren-type-chain", "ts", "let a: " + strings.Repeat("(", n) + strings.Repeat(")", n) + vuln},
		{"angle-type-chain", "ts", "let a: " + strings.Repeat("<T>() => ", n) + "void;" + vuln},
		{"decorators", "ts", strings.Repeat("@a.b.c(", n) + vuln},
		{"jsx-open", "tsx", strings.Repeat("<a b={", n) + vuln},
		{"jsx-lt-c", "tsx", "const v = <p>" + strings.Repeat("<a", n) + vuln},
		{"require-many", "js", strings.Repeat("const a = require('fs');\n", n/4) + vuln},
		{"alias-many", "js", strings.Repeat("const run = require('child_process').exec;\nfunction f(run) { run(x); }\n", n/8) + strings.Repeat("run(y);\n", n/4) + "app.get('/x', (req, res) => { run('ls ' + req.query.c); });\n"},
		{"type-alias-walk", "tsx", "type A" + strings.Repeat("<B", n/4) + strings.Repeat(">", n/4) + " = <T>(x: T) => T;\nexport const h = (req: Request) => execSync(req.query.c as string);\n"},
	} {
		start := time.Now()
		fs, err := e.Scan(c.lang, c.name, []byte(c.src))
		if d := time.Since(start); d > 2*DefaultLimits.MaxTime {
			t.Errorf("%s: %v, over twice the time limit", c.name, d)
		}
		// Past a cap the engine must fail toward detection.
		if (c.name == "alias-many" || c.name == "type-alias-walk") && len(fs) == 0 {
			t.Errorf("%s: the vulnerable code at the end is not reported", c.name)
		}
		if (c.name == "alias-many" || c.name == "type-alias-walk") && !errors.Is(err, ErrLimit) {
			t.Errorf("%s: err %v, a file past a cap must be reported as not fully analysed", c.name, err)
		}
	}
}
