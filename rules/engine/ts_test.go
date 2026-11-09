package engine

import (
	"strings"
	"testing"
)

// tsText joins the tokens of a lexed TypeScript file with spaces, strings in
// double quotes and template fields as ${...}.
func tsText(toks []Token) string {
	var b strings.Builder
	for i, t := range toks {
		if i > 0 {
			b.WriteByte(' ')
		}
		switch {
		case t.Kind == Str && len(t.Parts) > 0:
			b.WriteByte('`')
			last := 0
			for _, p := range t.Parts {
				b.WriteString(t.Text[last:p.Off])
				b.WriteString("${" + tsText(p.Toks) + "}")
				last = p.Off
				for last < len(t.Text) && t.Text[last] != '}' {
					last++
				}
				last++
			}
			if last < len(t.Text) {
				b.WriteString(t.Text[last:])
			}
			b.WriteByte('`')
		case t.Kind == Str:
			b.WriteString(`"` + t.Text + `"`)
		default:
			b.WriteString(t.Text)
		}
	}
	return b.String()
}

// TestLexTS checks that type syntax is taken out and values are kept.
func TestLexTS(t *testing.T) {
	cases := []struct{ name, src, want string }{
		{"annotations", "let a: string = x, b: number[] = y;\nconst c: Map<string, Array<number>> = new Map<string, Array<number>>();",
			`let a = x , b = y ; const c = new Map ( ) ;`},
		{"function", "function f<T extends object>(a: T, b?: string, ...r: Array<T>): Promise<T | null> { return g<T>(a); }",
			`function f ( a , b , ... r ) { return g ( a ) ; }`},
		{"arrow", "const f = async (a: A, { b }: { b: string } = {}): Promise<void> => { h(a, b) }",
			`const f = async ( a , { b } = { } ) => { h ( a , b ) }`},
		{"generic arrow", "const id = <T,>(x: T): T => x;", `const id = ( x ) => x ;`},
		{"comparison kept", "if (a < b && c > (d)) { e = a < b; f = g > h }", `if ( a < b && c > ( d ) ) { e = a < b ; f = g > h }`},
		{"comparison loop", "for (let i = 0; i < n; i++) x(i < m, y >= z)", `for ( let i = 0 ; i < n ; i ++ ) x ( i < m , y >= z )`},
		{"as satisfies", "const a = (b as any).c as string; const o = { k: 1 } satisfies R; const l = [1] as const;",
			`const a = ( b ) . c ; const o = { k : 1 } ; const l = [ 1 ] ;`},
		{"cast", "const a = <string>b;", `const a = b ;`},
		{"export satisfies", "export const p = (async () => ({\n  a: 1,\n})) satisfies P<{ a: number }>;\nexport default x as Y;",
			`export const p = ( async ( ) => ( { a : 1 , } ) ) ; export default x ;`},
		{"non-null", "const v = a!.b!.c! + d![0]; let e!: number; if (!f) g(!h);", `const v = a . b . c + d [ 0 ] ; let e ; if ( ! f ) g ( ! h ) ;`},
		{"non-null regex", "const n = x! / 2 / y;", `const n = x / 2 / y ;`},
		{"ternary object", "const a = b ? { c: d } : e; const f = { g: h ? i : j, k: l };", `const a = b ? { c : d } : e ; const f = { g : h ? i : j , k : l } ;`},
		{"switch", "switch (a) { case B.c: x(); break; default: y() }", `switch ( a ) { case B . c : x ( ) ; break ; default : y ( ) }`},
		{"interface", "export interface A<T> extends B { a: string; m(x: number): void }\nf();", `f ( ) ;`},
		{"type alias", "type U =\n  | 'a'\n  | { b: string };\nexport type V<T> = T[];\ng();", `g ( ) ;`},
		{"type word kept", "const type = req.body.type; let o = { type: 1 }; type = 2;", `const type = req . body . type ; let o = { type : 1 } ; type = 2 ;`},
		{"enum", "export const enum E { A = 1, B }\nenum F { X }\nh(E.A);", `h ( E . A ) ;`},
		{"declare", "declare const x: number;\ndeclare module 'm' {\n  export function f(): void;\n}\ndeclare global { interface W {} }\nk();", `k ( ) ;`},
		{"import export", "import type { A } from 'a';\nimport { type B, c as d } from 'b';\nimport * as e from 'e';\nexport { f as g };\nimport h = require('h');",
			`import { A } from "a" ; import { B , c as d } from "b" ; import * as e from "e" ; export { f as g } ; const h = require ( "h" ) ;`},
		{"class", "export abstract class A<T> extends B<T> implements C, D<T> {\n  private readonly x: number = 1;\n  public static y?: string;\n  protected abstract z(): void;\n  constructor(private svc: Svc, public readonly n: number) { super(); }\n  m?(): void {}\n  get v(): T { return this.x as T; }\n}",
			`export class A extends B { x = 1 ; static y ; z ( ) ; constructor ( svc , n ) { super ( ) ; } m ( ) { } get v ( ) { return this . x ; } }`},
		{"decorators", "@Controller('u')\nexport class U {\n  @Get(':id')\n  find(@Param('id') id: string, @Query() q: Q) {\n    return id;\n  }\n}",
			`export class U { find ( id , q ) { id = @Param ( "id" ) ; q = @Query ( ) ; return id ; } }`},
		{"decorator pipe", "class U { m(@Param('id', ParseIntPipe) id: number, @Body() b: B) { } }", `class U { m ( id , b ) { b = @Body ( ) ; } }`},
		{"decorator req", "class U { m(@Req() r: Request): void { } }",
			`class U { m ( r ) { r . query = @Req ( ) ; r . body = @Req ( ) ; r . params = @Req ( ) ; r . headers = @Req ( ) ; r . cookies = @Req ( ) ; } }`},
		{"optional chain", "const a = b?.c?.[d]?.(e) ?? f;", `const a = b ?. c ?. [ d ] ?. ( e ) ?? f ;`},
		{"template", "const s = `a${(x as any).y}b`;", "const s = `a${( x ) . y}b` ;"},
		{"namespace", "namespace N.M { export const a = 1; }", `{ export const a = 1 ; }`},
		{"this param", "function f(this: Window, a: string) {}", `function f ( a ) { }`},
		{"predicate", "function isS(x: unknown): x is string { return typeof x === 'string'; }", `function isS ( x ) { return typeof x === "string" ; }`},
		{"label", "outer: for (const a of b) { continue outer; }", `outer : for ( const a of b ) { continue outer ; }`},
		{"object method", "const o = { m(a: string): number { return 1; }, n: (b: B): C => b };", `const o = { m ( a ) { return 1 ; } , n : ( b ) => b } ;`},
		{"overload", "function f(a: string): void;\nfunction f(a: any) { g(a); }", `function f ( a ) ; function f ( a ) { g ( a ) ; }`},
		{"catch", "try { a() } catch (e: unknown) { b(e) }", `try { a ( ) } catch ( e ) { b ( e ) }`},
	}
	for _, c := range cases {
		if got := tsText(LexTS(c.src)); got != c.want {
			t.Errorf("%s:\n got %s\nwant %s", c.name, got, c.want)
		}
	}
}

// TestLexTSX: in .tsx, "<T>" after an operator is an element (lexed as in .jsx),
// and "</" closes one.
func TestLexTSX(t *testing.T) {
	cases := []struct{ src, want string }{
		{"const e = <div className={a as string}>{b!}</div>;", `const e = < div className = { a } > { b } < / div > ;`},
		{"const [s, set] = useState<string>('');", `const [ s , set ] = useState ( "" ) ;`},
		{"const f = <T,>(x: T) => x;", `const f = ( x ) => x ;`},
		{"const t = <b>[x]</b>;\nconst s = `${y}`;", "const t = < b > [ x ] < / b > ; const s = `${y}` ;"},
	}
	for _, c := range cases {
		if got := tsText(LexTSX(c.src)); got != c.want {
			t.Errorf("%s:\n got %s\nwant %s", c.src, got, c.want)
		}
	}
}

// TestRegexAfterLess: outside .tsx, "</" may start a regular expression, so a
// quote inside it cannot hide the code after it.
func TestRegexAfterLess(t *testing.T) {
	e := engineForTest(t)
	src := "app.get('/x', (req, res) => { if (a </'/.test(b)) exec(req.query.c); });\n"
	for _, lang := range []string{"js", "ts"} {
		if fs, _ := e.Scan(lang, "x", []byte(src)); len(fs) == 0 {
			t.Errorf("%s: exec after a </'/ regular expression not reported", lang)
		}
	}
}

// TestSinkAfterClosingTag: in .jsx and .tsx a closing tag hides no code after it.
func TestSinkAfterClosingTag(t *testing.T) {
	e := engineForTest(t)
	src := "app.get('/x', (req, res) => { const v = <b>x</b>; exec(req.query.c); });\n"
	for _, lang := range []string{"jsx", "tsx"} {
		if fs, _ := e.Scan(lang, "x", []byte(src)); len(fs) == 0 {
			t.Errorf("%s: exec after a closing tag not reported", lang)
		}
	}
}

// TestJSXEvasion: "</" closes a tag only among an element's children, and a
// .jsx file may start with a hashbang.
func TestJSXEvasion(t *testing.T) {
	e := engineForTest(t)
	srcs := []string{
		"app.get('/x', (req, res) => { const y = a </x'/.test(s) ? 0 : exec(req.query.c); });\n",
		"app.get('/x', (req, res) => { const v = <b>{a </b>/.test(s) ? 0 : exec(req.query.c)}</b>; });\n",
		"app.get('/x', (req, res) => { const v = <b c={a </b>/.test(s) ? 0 : exec(req.query.c)} />; });\n",
		"#!/usr/bin/env node\napp.get('/x', (req, res) => { const v = <i>x</i>; exec(req.query.c); });\n",
	}
	for i, src := range srcs {
		for _, lang := range []string{"jsx", "tsx"} {
			if fs, _ := e.Scan(lang, "x", []byte(src)); len(fs) == 0 {
				t.Errorf("%s case %d: exec not reported", lang, i)
			}
		}
	}
}

func TestLangOfTS(t *testing.T) {
	for name, want := range map[string]string{"a.ts": "ts", "a.mts": "ts", "a.CTS": "ts", "a.tsx": "tsx", "a.d.ts": "ts", "a.js": "js", "a.jsx": "jsx"} {
		if got := LangOf(name); got != want {
			t.Errorf("LangOf(%q) = %q, want %q", name, got, want)
		}
	}
}

// TestHeldOutTS runs TypeScript cases written apart from the rule samples.
func TestHeldOutTS(t *testing.T) {
	e := engineForTest(t)
	cases := []struct {
		name, lang, src string
		vulnerable      bool
	}{
		{"nest body sql", "ts", "@Controller('u')\nexport class U {\n  constructor(private readonly ds: DataSource) {}\n  @Post()\n  async create(@Body() dto: CreateDto): Promise<void> {\n    await this.ds.query(`INSERT INTO u (n) VALUES ('${dto.name}')`);\n  }\n}\n", true},
		{"nest param exec", "ts", "export class C {\n  @Get(':h')\n  ping(@Param('h') host: string) {\n    exec('ping -c1 ' + host, () => {});\n  }\n}\n", true},
		{"nest query eval", "ts", "class C {\n  @Get()\n  calc(@Query('e') e: string): number {\n    return eval(e as string);\n  }\n}\n", true},
		{"nest req query", "ts", "class C {\n  @Get()\n  dl(@Req() req: Request, @Res() res: Response) {\n    const f = req.query.f as string;\n    res.sendFile(f);\n  }\n}\n", true},
		{"nest req user safe", "ts", "class C {\n  @Get()\n  me(@Req() r: Request) {\n    return this.ds.query(`SELECT * FROM u WHERE id = ${r.user.id}`);\n  }\n}\n", false},
		{"nest parseint safe", "ts", "class C {\n  @Get(':id')\n  one(@Param('id', ParseIntPipe) id: number) {\n    return this.ds.query(`SELECT * FROM u WHERE id = ${id}`);\n  }\n}\n", false},
		{"nest bound safe", "ts", "class C {\n  @Get()\n  q(@Query('n') n: string) {\n    return this.ds.query('SELECT * FROM u WHERE n = $1', [n]);\n  }\n}\n", false},
		{"next route sql", "ts", "export async function GET(request: NextRequest) {\n  const q = request.nextUrl.searchParams.get('q')!;\n  const rows = await pool.query(`SELECT * FROM t WHERE n = '${q}'`);\n  return NextResponse.json(rows);\n}\n", true},
		{"next json exec", "ts", "export async function POST(req: Request) {\n  const { cmd } = (await req.json()) as { cmd: string };\n  execSync(cmd);\n  return new Response('ok');\n}\n", true},
		{"next url searchParams", "ts", "export async function GET(request: Request) {\n  const { searchParams } = new URL(request.url);\n  const file = searchParams.get('file') ?? '';\n  return new Response(fs.createReadStream(file) as any);\n}\n", true},
		{"next page searchParams tsx", "tsx", "export default async function Page({ searchParams }: { searchParams: Promise<{ q?: string }> }) {\n  const { q } = await searchParams;\n  const rows = await sql.query(`SELECT * FROM p WHERE t = '${q}'`);\n  return <ul>{rows.map((r: Row) => <li key={r.id}>{r.t}</li>)}</ul>;\n}\n", true},
		{"next safe number", "ts", "export async function GET(request: NextRequest) {\n  const id = Number(request.nextUrl.searchParams.get('id'));\n  return Response.json(await pool.query('SELECT * FROM t WHERE id = ' + id));\n}\n", false},
		{"generic typed express", "ts", "app.get('/f', (req: Request<{}, {}, {}, { f: string }>, res: Response) => {\n  const f: string = req.query.f;\n  res.sendFile(path.join(ROOT, f));\n});\n", true},
		{"generic call sink", "ts", "export async function GET(req: NextRequest) {\n  const rows = await pool.query<Row[]>(\"SELECT * FROM t WHERE a = '\" + req.nextUrl.searchParams.get('a') + \"'\");\n  return Response.json(rows);\n}\n", true},
		{"enum and modifiers", "ts", "enum Mode { Fast = 'fast', Slow = 'slow' }\nexport abstract class Base {\n  protected abstract run(m: Mode): void;\n}\nexport class Job extends Base {\n  @Post() protected run(@Body('m') m: Mode): void { exec(`job --mode ${m}`); }\n}\n", true},
		{"optional chain source", "ts", "app.get('/x', (req: Request, res: Response) => {\n  const n = req.query?.n as string | undefined;\n  exec(`ls ${n ?? '.'}`);\n});\n", true},
		{"optional chain safe", "ts", "app.get('/x', (req: Request, res: Response) => {\n  const n = Number(req.query?.n);\n  exec(`ls ${n}`);\n});\n", false},
		{"type-only file", "ts", "export interface Q { exec(cmd: string): void }\nexport type R = { query: string };\ndeclare function eval(x: string): any;\n", false},
	}
	for _, c := range cases {
		fs, err := e.Scan(c.lang, c.name, []byte(c.src))
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
		}
		if got := len(fs) > 0; got != c.vulnerable {
			t.Errorf("%s: reported %v (%v), want %v\n%s", c.name, got, fs, c.vulnerable, tsText(LexTS(c.src)))
		}
	}
}
