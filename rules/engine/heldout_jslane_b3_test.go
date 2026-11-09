package engine

import "testing"

// heldOutJSLaneB3 are held-out cases for batch 3 of the JavaScript rule lane:
// NestJS and Next.js (TypeScript) in shapes apart from the rule samples.
var heldOutJSLaneB3 = []struct {
	name, lang, rule, src string
	vulnerable            bool
	gap                   string
}{
	// Next.js and NestJS sources in the SSRF, XSS, redirect, NoSQL and LDAP rules
	{"next proxy endpoint", "ts", "js-ssrf-http-request", "export async function GET(req: Request) {\n  const endpoint = new URL(req.url).searchParams.get('endpoint')!;\n  return fetch(endpoint);\n}\n", true, ""},
	{"nest webhook query", "ts", "js-ssrf-http-request", "class C {\n  @Post('hook') send(@Query('url') url: string) { return fetch(url, { method: 'POST' }); }\n}\n", true, ""},
	{"nest body host template", "ts", "js-ssrf-http-request", "class C {\n  @Post() login(@Body() body: Dto) { const { host_url } = body; return axios.get(`${host_url}/rest/currentUser`); }\n}\n", true, ""},
	{"next text body url", "ts", "js-ssrf-http-request", "export async function POST(req: Request) {\n  const url = new URL(await req.text());\n  return fetch(url.toString());\n}\n", true, ""},
	{"next fixed api with id", "ts", "js-ssrf-http-request", "export async function GET(req: Request) {\n  const id = new URL(req.url).searchParams.get('id') ?? '';\n  return fetch(`https://api.example.com/items/${encodeURIComponent(id)}`);\n}\n", false, ""},
	{"nest html param", "ts", "js-xss-response", "class C {\n  @Get(':name') hi(@Param('name') name: string, @Res() res: Response) { res.send('<b>Hi ' + name + '</b>'); }\n}\n", true, ""},
	{"nest redirect query", "ts", "js-open-redirect-redirect", "class C {\n  @Get('out') out(@Query('u') u: string, @Res() res: Response) { return res.redirect(302, u); }\n}\n", true, ""},
	{"nest mongo filter body", "ts", "js-nosqli-mongo-query", "class C {\n  @Post('find') find(@Body() filter: any) { return this.model.find(filter); }\n}\n", true, ""},
	{"new URL path override", "ts", "js-ssrf-http-request", "export async function GET(req: Request) {\n  const p = new URL(req.url).pathname.slice('/img'.length);\n  return fetch(new URL(p, IMAGE_ORIGIN));\n}\n", true, ""},
	{"env base with the path in a query", "ts", "js-ssrf-http-request", "export async function middleware(request: NextRequest) {\n  const p = request.nextUrl.pathname;\n  return fetch(`${process.env.CMS_URL}/lookup?path=${p}`);\n}\n", false,
		"a configured base (${process.env.X}) leading the URL is not counted as a fixed prefix"},
	{"hostname allowlist on the parsed URL", "js", "js-ssrf-http-request", "app.get('/p', async (req, res) => {\n  const u = new URL(req.query.url);\n  if (!HOSTS.has(u.hostname)) return res.sendStatus(400);\n  res.send(await (await fetch(u)).text());\n});\n", false,
		"a check on u.hostname validates that member only, not u: needs the engine to clean an object by a check on its host (rules engine)"},
	{"hostname rebuilt from the allowlist", "js", "js-ssrf-http-request", "app.get('/p', async (req, res) => {\n  const u = new URL(req.query.url);\n  const host = HOSTS.has(u.hostname) ? u.hostname : 'cdn.example.com';\n  res.send(await (await fetch('https://' + host + '/feed')).text());\n});\n", false, ""},
	// js-open-redirect-next
	{"next return url", "ts", "js-open-redirect-next", "export async function GET(request: NextRequest) {\n  const next = request.nextUrl.searchParams.get('returnUrl') ?? '/';\n  return NextResponse.redirect(new URL(next, request.url));\n}\n", true, ""},
	{"server action redirect", "ts", "js-open-redirect-next", "export async function signIn(formData: FormData) {\n  'use server';\n  redirect(formData.get('returnUrl') as string);\n}\n", true, ""},
	{"forwarded host redirect", "ts", "js-open-redirect-next", "export async function GET(request: NextRequest) {\n  const host = request.headers.get('x-forwarded-host');\n  return NextResponse.redirect(`https://${host}/home`);\n}\n", true, ""},
	{"page searchParams redirect", "tsx", "js-open-redirect-next", "export default async function Page({ searchParams }: { searchParams: Promise<{ to?: string }> }) {\n  const { to } = await searchParams;\n  redirect(to ?? '/');\n}\n", true, ""},
	{"login fixed", "ts", "js-open-redirect-next", "export async function GET(request: NextRequest) {\n  return NextResponse.redirect(new URL('/login', request.url));\n}\n", false, ""},
	{"origin of request", "ts", "js-open-redirect-next", "export async function GET(request: NextRequest) {\n  const origin = new URL(request.url).origin;\n  return NextResponse.redirect(origin + '/dashboard');\n}\n", false, ""},
	{"slash checked", "ts", "js-open-redirect-next", "export async function GET(request: NextRequest) {\n  const raw = request.nextUrl.searchParams.get('next') ?? '';\n  const next = raw.startsWith('/') && !raw.startsWith('//') && !raw.startsWith('/\\\\') ? raw : '/';\n  return NextResponse.redirect(new URL(next, request.url));\n}\n", true,
		"a single-slash check is no redirect check (/\\t/evil.example becomes //evil.example); reported once p1-classes 21e50ae is in integ"},
	{"helper sanitizer", "ts", "js-open-redirect-next", "export async function GET(request: NextRequest) {\n  const next = sanitizeReturnUrl(request.nextUrl.searchParams.get('next'));\n  return NextResponse.redirect(new URL(next, request.url));\n}\n", false,
		"a project helper that checks the path (sanitizeReturnUrl) is not followed into"},
}

func TestHeldOutJSLaneB3(t *testing.T) {
	e := engineForTest(t)
	pass := 0
	for _, c := range heldOutJSLaneB3 {
		fs, err := e.Scan(c.lang, c.name, []byte(c.src))
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
		}
		found := false
		for _, f := range fs {
			found = found || f.RuleID == c.rule
		}
		ok := found == c.vulnerable && (c.vulnerable || len(fs) == 0)
		switch {
		case ok:
			pass++
			if c.gap != "" {
				t.Errorf("%s: marked as a known gap but now passes; remove the mark", c.name)
			}
		case c.gap != "":
			t.Logf("known gap, %s: %s", c.name, c.gap)
		case c.vulnerable:
			t.Errorf("%s: not reported by %s (got %+v)", c.name, c.rule, fs)
		default:
			t.Errorf("%s: reported %+v", c.name, fs)
		}
	}
	t.Logf("JS lane batch 3 held-out cases right: %d/%d", pass, len(heldOutJSLaneB3))
}
