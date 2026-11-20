package engine

import (
	"maps"
	"slices"
	"strings"

	"github.com/nt-neil/shentu/rules"
)

// A route handler's request is the rules' input whatever it is called. The
// rules write their sources for Express's req and Koa's ctx (req.get('host'),
// ctx.request.header.host); reqs keeps, per function, the names that hold a
// handler's request or a part of it, and srcMatch reads a source written for
// req or ctx at such a name too:
//
//	(r, s) => r.hostname                  r stands for req (ctx for a Koa context)
//	const q = r; q.headers.host           q too
//	const h = r.headers; h['x-name']      h for req.headers
//	({ headers }, s) => headers.host      headers for req.headers
//	const { hostname: hn } = r            hn for req.hostname
//	find(@Req() r)                        NestJS, its file importing @nestjs (sourcenot.go)

// handlerRoots is what a handler's request parameter stands for: req and ctx
// themselves (so that q = req and { host } = req.headers follow), ctx for one
// a Koa handler uses as its context
// (c.request, c.state, c.body = ...), req for any other. Koa's ctx.body is
// the response, never the request's body.
func handlerRoots(name string, body []*stmt) []string {
	switch {
	case name == "req" || name == "ctx":
		return []string{name}
	case koaContext(body, name):
		return []string{"ctx"}
	}
	return []string{"req"}
}

// koaContext reports whether statements use name as a Koa context.
func koaContext(body []*stmt, name string) bool {
	for _, s := range body {
		t := s.toks
		for i := 0; i+2 < len(t); i++ {
			if t[i].Kind != Ident || t[i].Text != name || !t[i+1].op(".") || i > 0 && memberOp(false, t[i-1]) {
				continue
			}
			switch m := t[i+2].Text; {
			case m == "request" || m == "response" || m == "state" || m == "throw" || m == "assert":
				return true
			case (m == "body" || m == "status" || m == "type") && i+3 < len(t) && t[i+3].op("="):
				return true
			}
		}
		for _, f := range s.funcs {
			if f != nil && koaContext(f.body, name) {
				return true
			}
		}
		for _, sub := range append(append(append(s.body, s.els...), s.orelse...), flat(s.handlers, s.cases)...) {
			if koaContext([]*stmt{sub}, name) {
				return true
			}
		}
		if s.fn != nil && koaContext(s.fn.body, name) {
			return true
		}
	}
	return false
}

func flat(lists ...[][]*stmt) []*stmt {
	var out []*stmt
	for _, l := range lists {
		for _, x := range l {
			out = append(out, x...)
		}
	}
	return out
}

// fnReqs is the reqs of a function: its enclosing function's for a closure,
// none for a named or fresh one; without its parameters, which shadow them;
// with its own request parameter when a route model makes it a handler.
func (a *analysis) fnReqs(f *fn, outer map[string][]string) map[string][]string {
	if !a.js {
		return nil
	}
	out := map[string][]string{}
	if !f.fresh && f.name == "" {
		maps.Copy(out, outer)
	}
	parts := splitTop(f.params, isComma)
	for _, p := range parts {
		for _, tk := range p {
			if tk.Kind == Ident {
				delete(out, tk.Text)
			}
		}
	}
	sd := a.routes[f]
	if sd == nil {
		if a.mws[f] && len(parts) > 0 && len(parts[0]) > 0 {
			// Koa middleware, app.use(async (ctx, next) => ...): its context is
			// the request's as a handler's is, for the rules' ctx. sources
			switch p := parts[0]; {
			case p[0].Kind == Ident && (len(p) == 1 || p[1].op(":") || p[1].op("=")):
				out[p[0].Text] = []string{"ctx"}
			case p[0].op("{"):
				reqPattern(out, p[:closeOf(p, 0)+1], []string{"ctx"})
			}
		}
		return out
	}
	for i, p := range parts {
		if sd.params != nil && !sd.params[i+1] || len(p) == 0 {
			continue
		}
		switch {
		case p[0].Kind == Ident && (len(p) == 1 || p[1].op(":") || p[1].op("=")):
			out[p[0].Text] = handlerRoots(p[0].Text, f.body)
		case p[0].op("{"):
			pat := p[:closeOf(p, 0)+1]
			root := []string{"req"} // ({ query, headers }, res): Express's request
			if koaPattern(pat) && a.koaFile() {
				root = []string{"ctx"} // ({ request, state }) => ...: Koa's context, in a Koa application
			}
			reqPattern(out, pat, root)
		}
	}
	return out
}

// koaPattern reports whether an object pattern takes a member a Koa context
// has (request, response, state, throw, assert), as koaContext does for a
// name. Express's request may carry such a member too (req.state, set by a
// middleware), so it counts only in a Koa application (koaFile).
func koaPattern(p []Token) bool {
	c := closeOf(p, 0)
	if c <= 0 {
		return false
	}
	for _, e := range splitTop(inside(p, 0, c), isComma) {
		if len(e) > 0 && (e[0].Kind == Ident || reqStrKey(e[0])) {
			switch e[0].Text {
			case "request", "response", "state", "throw", "assert":
				return true
			}
		}
	}
	return false
}

// reqPattern records the names an object pattern takes from paths ({ headers,
// hostname: hn, ...rest } = r), or with paths nil, forgets them.
func reqPattern(out map[string][]string, p []Token, paths []string) {
	c := closeOf(p, 0)
	if c <= 0 {
		return
	}
	for _, e := range splitTop(inside(p, 0, c), isComma) {
		switch {
		case len(e) == 2 && e[0].op("...") && e[1].Kind == Ident:
			setReq(out, e[1].Text, paths) // the rest of the request
		case len(e) == 0:
		case e[0].Kind == Ident && (len(e) == 1 || e[1].op("=")):
			setReq(out, e[0].Text, reqMembers(paths, e[0].Text))
		case len(e) >= 3 && e[1].op(":") && (e[0].Kind == Ident || reqStrKey(e[0])):
			sub := reqMembers(paths, e[0].Text)
			if e[0].Kind == Str {
				sub = reqIndex(paths, e[0].Text) // { 'x-forwarded-host': xfh }
			}
			switch c2 := closeOf(e, 2); {
			case e[2].Kind == Ident && (len(e) == 3 || e[3].op("=")):
				setReq(out, e[2].Text, sub)
			case e[2].op("{") && c2 > 2 && (c2 == len(e)-1 || e[c2+1].op("=")):
				reqPattern(out, e[2:c2+1], sub) // { headers: { host } }
			}
		}
	}
}

// reqStrKey reports whether a pattern's key is a string written out that a
// path can hold ('x-forwarded-host'): no interpolation, no dot.
func reqStrKey(tk Token) bool {
	return tk.Kind == Str && len(tk.Parts) == 0 && tk.Text != "" && !strings.ContainsAny(tk.Text, ".\x02")
}

// reqIndex is reqMembers for a member read by a string index
// (req.headers['x-forwarded-host']), which a path writes as "." + reqIdx + key.
func reqIndex(paths []string, key string) []string {
	return reqMembers(paths, reqIdx+key)
}

// reqIdx marks a path's member read by a string index (reqIndex).
const reqIdx = "\x02"

// reqCall marks a path's root that is a call of no arguments (headers()).
const reqCall = "\x03"

// nextHeaders reports whether t is Next's headers() or await headers(), whole.
func nextHeaders(t []Token) bool {
	if len(t) > 0 && t[0].word("await") {
		t = stripParens(t[1:])
	}
	return len(t) == 3 && t[0].Kind == Ident && t[0].Text == "headers" && t[1].op("(") && t[2].op(")")
}

// readsNextHeaders reports whether a rule has a source written for Next's
// headers() (^headers().get(), which a name holding its result is read by.
func readsNextHeaders(r *crule) bool {
	for _, s := range r.sources {
		if len(s.toks) > 0 && s.toks[0].word("headers") {
			return true
		}
	}
	return false
}

// importsModule reports whether the tokens import module m (import ... from
// 'm', import 'm', require('m')).
func importsModule(t []Token, m string) bool {
	for i, tk := range t {
		if tk.Kind == Str && len(tk.Parts) == 0 && tk.Text == m && i > 0 &&
			(t[i-1].word("from") || t[i-1].word("import") || i > 1 && t[i-1].op("(") && t[i-2].word("require")) {
			return true
		}
	}
	return false
}

// nextHeadersFile reports whether the file imports Next's next/headers, whose
// headers() is the request's headers.
func (a *analysis) nextHeadersFile() bool {
	if a.ifacts == nil && len(a.ftoks) > 0 {
		a.ifacts = fileFacts(a.ftoks, nil)
	}
	return a.ifacts["m:next/headers"]
}

func setReq(out map[string][]string, name string, paths []string) {
	if paths == nil {
		delete(out, name)
	} else {
		out[name] = paths
	}
}

func reqMembers(paths []string, m string) []string {
	if paths == nil {
		return nil
	}
	out := make([]string, len(paths))
	for i, p := range paths {
		out[i] = p + "." + m
	}
	return out
}

// reqPaths is what a path of names stands for when it starts at a name of
// reqs (r, r.headers): nil for anything else.
func (a *analysis) reqPaths(t []Token) []string {
	if len(t) == 0 || t[0].Kind != Ident {
		return nil
	}
	paths := a.reqs[t[0].Text]
	for j := 1; paths != nil && j < len(t); j += 2 {
		if j+1 >= len(t) || !t[j].op(".") || t[j+1].Kind != Ident {
			return nil
		}
		paths = reqMembers(paths, t[j+1].Text)
	}
	return paths
}

// reqAssign keeps reqs up to date over an assignment: q = r and
// { headers } = r make names of it, anything else assigned to a name
// forgets it. A name destructured to what is a source of the rule
// (const { hostname } = r: req.hostname) is that input, as hostname = r.hostname is.
func (a *analysis) reqAssign(st state, lhs, rhs []Token, op string) {
	if a.reqs == nil || len(lhs) == 0 {
		return
	}
	var paths []string
	if op == "=" {
		paths = a.reqPaths(stripParens(rhs))
		if paths == nil && nextHeaders(stripParens(rhs)) && a.nextHeadersFile() {
			// Next's const h = await headers() (or headers()): h stands for
			// headers(), so the rules' ^headers().get( sources read h.get(name)
			paths = []string{"headers" + reqCall}
		}
		if paths == nil && nestHeaders(stripParens(rhs)) && a.nestFile() {
			// NestJS's @Headers() h, whole, is the request's headers object: h
			// stands for req.headers, so its index is lower case as Node stores
			// it and route_not leaves h['Host'] out as it does req.headers['host']
			paths = []string{"req.headers"}
		}
	}
	switch {
	case len(lhs) == 1 && lhs[0].Kind == Ident:
		setReq(a.reqs, lhs[0].Text, paths)
		if len(paths) > 0 && !a.noSrc {
			a.reqRouteNotUnder(st, lhs[0].Text, paths)
		}
	case lhs[0].op("{") && closeOf(lhs, 0) == len(lhs)-1:
		reqPattern(a.reqs, lhs, paths)
		if paths == nil || a.noSrc {
			return
		}
		for _, tg := range a.targetList(lhs) {
			if len(tg) != 1 || tg[0].Kind != Ident {
				continue
			}
			name := tg[0].Text
			// const { host } = r.headers: route_not leaves it to another rule;
			// a name that also holds another path (h was r.query on some path)
			// keeps that one, which this rule still reads
			if rest := a.reqRouteNotRest(a.reqs[name]); len(rest) < len(a.reqs[name]) {
				a.reqs[name] = rest
				if len(rest) == 0 {
					st[name] = entry{}
					continue
				}
			}
			if a.reqIsSource(tg[0]) {
				st[name] = entry{taint: !a.nonced(st), raw: true}
			}
		}
	}
}

// reqRouteNotUnder: after x = h where h holds a request's headers (x holds
// req.headers on every path: h = r.headers, NestJS's h = @Headers()), the
// members route_not leaves out of them are not input under x either, as
// sourceNot leaves them out under h. A name that also holds another path (x
// was r.query on some path) keeps them: that path may carry them.
func (a *analysis) reqRouteNotUnder(st state, name string, paths []string) {
	for _, rn := range a.r.rule.RouteNot {
		mem, n, ok := strings.Cut(rn, ".")
		if !ok || slices.ContainsFunc(paths, func(p string) bool {
			return !strings.HasSuffix(strings.ToLower(strings.ReplaceAll(p, reqIdx, "")), "."+strings.ToLower(mem))
		}) {
			continue
		}
		st[name+sepCh+"."+n], st[name+sepCh+"["+n+"]"] = entry{}, entry{}
	}
}

// reqRouteNotRest is paths without those ending in a member the rule's
// route_not names (req.headers.host for headers.host).
func (a *analysis) reqRouteNotRest(paths []string) []string {
	var rest []string
	for _, p := range paths {
		q := strings.ToLower(strings.ReplaceAll(p, reqIdx, "")) // req.headers['x-forwarded-host'] as req.headers.x-forwarded-host
		if !slices.ContainsFunc(a.r.rule.RouteNot, func(rn string) bool { return strings.HasSuffix(q, "."+strings.ToLower(rn)) }) {
			rest = append(rest, p)
		}
	}
	return rest
}

// reqIsSource reports whether a name of reqs stands for a whole source of the
// rule (hostname for req.hostname).
func (a *analysis) reqIsSource(name Token) bool {
	vs, adds := a.reqVariants([]Token{name}, 0)
	for k, v := range vs {
		for _, s := range a.r.sources {
			end, ok := a.srcMatchAt(s, v, 0)
			// the whole path, or a source ending in the index's "[" whose
			// index ends it (req.headers['x-forwarded-host'] for xfh)
			if ok && (end == adds[k]+1 || end > 0 && v[end-1].op("[") && closeOf(v, end-1) == len(v)-1) {
				return true
			}
		}
	}
	return false
}

// reqVariants is t with the name at i written as each path it stands for
// (r.hostname as req.hostname and ctx.hostname), and how many tokens each
// adds: none when t[i] is no name of reqs, or a member of something else.
func (a *analysis) reqVariants(t []Token, i int) ([][]Token, []int) {
	if a.reqs == nil || i >= len(t) || t[i].Kind != Ident || i > 0 && (memberOp(false, t[i-1]) || t[i-1].op("?.")) {
		return nil, nil
	}
	paths := a.reqs[t[i].Text]
	if len(paths) == 0 {
		return nil, nil
	}
	var out [][]Token
	var adds []int
	for _, p := range paths {
		if p == t[i].Text {
			continue // req itself: the sources read it as written
		}
		var path []Token
		for k, n := range strings.Split(p, ".") {
			if name, ok := strings.CutSuffix(n, reqCall); ok && k == 0 { // headers(): a call of no arguments
				path = append(path, Token{Kind: Ident, Text: name, Line: t[i].Line}, Token{Kind: Op, Text: "(", Line: t[i].Line},
					Token{Kind: Op, Text: ")", Line: t[i].Line})
				continue
			}
			if key, ok := strings.CutPrefix(n, reqIdx); ok { // ['x-forwarded-host']
				path = append(path, Token{Kind: Op, Text: "[", Line: t[i].Line}, Token{Kind: Str, Text: key, Line: t[i].Line},
					Token{Kind: Op, Text: "]", Line: t[i].Line})
				continue
			}
			if k > 0 {
				path = append(path, Token{Kind: Op, Text: ".", Line: t[i].Line})
			}
			path = append(path, Token{Kind: Ident, Text: n, Line: t[i].Line})
		}
		v := make([]Token, 0, len(t)+len(path))
		v = append(append(append(v, t[:i]...), path...), t[i+1:]...)
		out = append(out, v)
		adds = append(adds, len(path)-1) // paths of one name may differ in length after a branch (unionReqs)
	}
	return out, adds
}

// unionReqs adds to reqs what before held: a name holds each path it held on
// either side of a block.
func unionReqs(reqs, before map[string][]string) {
	for name, ps := range before {
		cur, ok := reqs[name]
		if !ok {
			reqs[name] = ps
			continue
		}
		out := slices.Clone(cur)
		for _, p := range ps {
			if !slices.Contains(out, p) {
				out = append(out, p)
			}
		}
		reqs[name] = out
	}
}

// reqCanon is a request path's key as the rules' sources write it, for
// requestHeaders (r<sep>.headers: req.headers).
func (a *analysis) reqCanon(key string) []string {
	base, rest, _ := strings.Cut(key, sepCh)
	paths := a.reqs[base]
	if len(paths) == 0 {
		return nil
	}
	rest = strings.ReplaceAll(rest, sepCh, "")
	out := make([]string, len(paths))
	for i, p := range paths {
		out[i] = p + rest
	}
	return out
}

// nestFile reports whether the file is a NestJS application's: it imports
// @nestjs, or another file of its project does (a decorator re-exported by
// the project's own module). A @Req() decorator of another library is not
// NestJS's request.
func (a *analysis) nestFile() bool {
	if a.ifacts == nil && len(a.ftoks) > 0 {
		a.ifacts = fileFacts(a.ftoks, nil)
	}
	for _, m := range nestModules {
		if a.ifacts["m:"+m] {
			return true
		}
	}
	return a.proj != nil && a.proj.nestjs || a.cproj != nil && a.cproj.nestjs
}

// koaFile reports whether the file is a Koa application's: it imports Koa or
// its router, or another file of its project does.
func (a *analysis) koaFile() bool {
	if a.ifacts == nil && len(a.ftoks) > 0 {
		a.ifacts = fileFacts(a.ftoks, nil)
	}
	for _, m := range koaModules {
		if a.ifacts["m:"+m] {
			return true
		}
	}
	return a.proj != nil && a.proj.koa || a.cproj != nil && a.cproj.koa
}

// koaMiddleware finds, in a Koa application's file (it or another file of the
// project imports Koa), the functions app.use(fn) registers: middleware, which
// the route models leave out (they register handlers by path). Their first
// parameter is the context, followed by the rules' ctx. sources through
// aliases and destructuring as a route handler's is; nothing else of them is
// input that was not before.
func koaMiddleware(lang string, toks []Token, tree []*stmt, ff *fileFuncs, proj *Project) map[*fn]bool {
	if lang != "js" || !(slices.ContainsFunc(koaModules, func(m string) bool { return importsModule(toks, m) }) || proj != nil && proj.koa) {
		return nil
	}
	use := []*croute{{r: rules.Route{Handler: -1}, register: []callName{{recv: "*", name: "use"}}}}
	out := map[*fn]bool{}
	mark := func(_ *croute, f *fn, _ []Token) {
		if f != nil {
			out[f] = true
		}
	}
	var e Engine
	var walk func(ss []*stmt, depth int)
	walk = func(ss []*stmt, depth int) {
		if depth > maxNest {
			return
		}
		for _, s := range ss {
			e.registrations(false, s, use, ff, mark)
			for _, f := range s.funcs {
				if f != nil {
					walk(f.body, depth+1)
				}
			}
			if s.fn != nil {
				walk(s.fn.body, depth+1)
			}
			walk(s.body, depth+1)
			walk(s.els, depth+1)
			walk(s.orelse, depth+1)
			for _, h := range s.handlers {
				walk(h, depth+1)
			}
			for _, c := range s.cases {
				walk(c, depth+1)
			}
		}
	}
	walk(tree, 0)
	return out
}

// koaModules are the modules a Koa application imports.
var koaModules = []string{"koa", "@koa/router", "koa-router"}

// nestModules are the modules a NestJS application imports its decorators from.
var nestModules = []string{"@nestjs/common", "@nestjs/core"}
