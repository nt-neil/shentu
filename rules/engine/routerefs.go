package engine

import (
	"slices"
	"sort"
	"strings"
)

// RouteRef names a route that registers the handler a finding's sink sits in.
// It says only where the sink is, not that request data was traced to it
// along this route: a reader matching web server logs against findings
// (shentu detect) uses it to know which URL reaches the vulnerable code.
//
// It is filled only when that is certain from the one file: the sink is
// inside a function this file registers (a call such as app.get or
// Route::post, a decorator, or a method a framework calls by its class), and
// the innermost such function is the one meant. A handler registered in
// another file (urls.py, routes/web.php) or a sink reached through a call to
// another file gets none. Filling it changes no finding. Findings carry a
// line, not a column: a sink on the line of a one-line handler but outside
// it (app.get('/a', function () {}); exec(x)) is still given that handler's
// routes.
//
// Pattern is the path as the registering call writes it, without the prefix
// a router or group may be mounted under (app.use('/api', router), a Flask
// blueprint's url_prefix, FastAPI's APIRouter(prefix=), Laravel's
// Route::prefix): a URL in a log is to end with it, not equal it. A hook
// (WordPress add_shortcode) has no URL, and no Pattern.
type RouteRef struct {
	Model     string `json:"model"`             // the route model's id (rules/routes): express-handler
	Framework string `json:"framework"`         // express, laravel, wordpress, django, fastapi, flask
	Method    string `json:"method,omitempty"`  // the registering call's name in lower case (get, post, any); empty for a decorator or a class method
	Pattern   string `json:"pattern,omitempty"` // the path as written (/users/{id}), maybe lacking a mount prefix; for register_rest_route /wp-json/<namespace>/<route>; empty when not a literal or for a hook
	Handler   string `json:"handler,omitempty"` // the handler function's name; empty for a function literal
	File      string `json:"file"`              // where the route is registered
	Line      int    `json:"line"`              // the registering call's or decorator's line
}

// routeSite is one registration of one handler.
type routeSite struct {
	f   *fn
	ref RouteRef
}

// Bounds on the route annotation, outside the scan's budget: a file written
// to register thousands of handlers costs no more than this.
const (
	maxRouteSites       = 4096 // registrations kept per file
	maxRoutesPerFinding = 16
)

// annotateRoutes fills Routes on the findings of path whose line is inside a
// handler that this file registers. Only the innermost handler holding the
// line counts; a handler registered several times gets one entry for each,
// up to maxRoutesPerFinding. Lines are all a finding has: when two handlers
// hold the line and neither holds the other (two on one line), which one the
// sink is in is not known, and none is named. One handler on the line and
// the sink outside it cannot be told apart from the sink inside it: that
// handler's routes are given.
func (e *Engine) annotateRoutes(out []Finding, lang, path string, toks []Token, tree []*stmt, ff *fileFuncs) {
	mine := false
	for i := range out {
		if out[i].Path == path {
			mine = true
			break
		}
	}
	if !mine {
		return
	}
	sites, cut := e.routeSites(lang, path, toks, tree, ff)
	if cut {
		for i := range out {
			if out[i].Path == path {
				out[i].RoutesTruncated = true
			}
		}
	}
	if len(sites) == 0 {
		return
	}
	type handler struct {
		lo, hi int
		refs   []RouteRef
		cut    bool // registered more than maxRoutesPerFinding times
	}
	var hs []*handler // in the order first registered, so that ties go the same way every time
	byFn := map[*fn]*handler{}
	for _, s := range sites {
		h, ok := byFn[s.f]
		if !ok {
			lo, hi, ok := fnSpan(s.f)
			if !ok {
				byFn[s.f] = nil
				continue
			}
			h = &handler{lo: lo, hi: hi}
			byFn[s.f], hs = h, append(hs, h)
		}
		if h == nil || slices.Contains(h.refs, s.ref) {
			continue
		}
		if len(h.refs) >= maxRoutesPerFinding {
			h.cut = true
			continue
		}
		h.refs = append(h.refs, s.ref)
	}
	for _, h := range hs {
		sort.Slice(h.refs, func(a, b int) bool {
			ra, rb := h.refs[a], h.refs[b]
			if ra.Line != rb.Line {
				return ra.Line < rb.Line
			}
			return ra.Model+ra.Method+ra.Pattern < rb.Model+rb.Method+rb.Pattern
		})
	}
	for i := range out {
		if out[i].Path != path {
			continue
		}
		var in []*handler
		var best *handler
		for _, h := range hs {
			if out[i].Line >= h.lo && out[i].Line <= h.hi {
				in = append(in, h)
				if best == nil || h.hi-h.lo < best.hi-best.lo {
					best = h
				}
			}
		}
		if best == nil {
			continue
		}
		known := true
		for _, h := range in { // every other handler holding the line must hold best, and more than it
			if h != best && !(h.lo <= best.lo && h.hi >= best.hi && h.hi-h.lo > best.hi-best.lo) {
				known = false
				break
			}
		}
		if known {
			out[i].Routes = slices.Clone(best.refs)
			out[i].RoutesTruncated = out[i].RoutesTruncated || best.cut
		}
	}
}

// routeSites lists every registration of a handler in the file, the way
// handlers finds them, but keeping each one: handlers keeps only the first,
// which is all the taint analysis needs. cut: past maxRouteSites, some were
// left out.
func (e *Engine) routeSites(lang, path string, toks []Token, tree []*stmt, ff *fileFuncs) (_ []routeSite, cut bool) {
	var rs []*croute
	for _, c := range e.routes[lang] {
		if len(c.requires) == 0 || namesAny(toks, c.requires) {
			rs = append(rs, c)
		}
	}
	if len(rs) == 0 {
		return nil, false
	}
	php := lang == "php"
	var out []routeSite
	add := func(c *croute, f *fn, ref RouteRef) {
		if f == nil {
			return
		}
		if len(out) >= maxRouteSites {
			cut = true
			return
		}
		ref.Model, ref.Framework, ref.File, ref.Handler = c.r.ID, c.r.Framework, path, f.name
		out = append(out, routeSite{f, ref})
	}
	var walk func(ss []*stmt, depth int)
	walk = func(ss []*stmt, depth int) {
		if depth > maxNest {
			return
		}
		var decos [][]Token
		for _, s := range ss {
			if s.kind == sSimple && len(s.toks) > 1 && s.toks[0].op("@") {
				decos = append(decos, s.toks[1:])
				continue
			}
			if s.fn != nil {
				for _, d := range decos {
					for _, c := range rs {
						if t, ok := matchDecorator(d, c.deco); ok {
							add(c, s.fn, RouteRef{Pattern: literal(t), Line: d[0].Line})
						}
					}
				}
				for _, c := range rs {
					if c.r.Extends != "" && strings.EqualFold(s.fn.name, c.r.Method) && s.fn.class != "" &&
						strings.EqualFold(shortClass(s.fn.parent), shortClass(c.r.Extends)) {
						if lo, _, ok := fnSpan(s.fn); ok {
							add(c, s.fn, RouteRef{Line: lo})
						}
					}
				}
			}
			decos = nil
			routeCalls(php, s, rs, ff, add)
			for _, f := range s.funcs {
				walk(f.body, depth+1)
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
	return out, cut
}

// routeCalls is registrations keeping the call: its name, path and line.
func routeCalls(php bool, s *stmt, rs []*croute, ff *fileFuncs, add func(*croute, *fn, RouteRef)) {
	t := s.toks
	for i := 0; i+1 < len(t); i++ {
		if t[i].Kind != Ident || !t[i+1].op("(") {
			continue
		}
		for _, c := range rs {
			if !callMatches(php, t, i, c.register) {
				continue
			}
			args := splitTop(inside(t, i+1, closeOf(t, i+1)), isComma)
			if c.r.Path && (len(args) == 0 || !pathLiteral(args[0])) {
				continue
			}
			k := c.r.Handler - 1
			if c.r.Handler < 0 {
				k = len(args) - 1
			}
			if k < 0 || k >= len(args) {
				continue
			}
			hs := [][]Token{args[k]}
			if c.r.Key != "" {
				hs = routeKeyValues(args[k], c.r.Key)
			}
			ref := RouteRef{Method: strings.ToLower(t[i].Text), Line: t[i].Line}
			if strings.EqualFold(t[i].Text, "register_rest_route") {
				if len(args) >= 2 {
					if ns, r := literal(args[0]), literal(args[1]); ns != "" && r != "" {
						ref.Pattern = "/wp-json/" + strings.Trim(ns, "/") + "/" + strings.TrimLeft(r, "/")
					}
				}
				ref.Method = ""
			} else if len(args) > 0 {
				ref.Pattern = literal(args[0])
			}
			if c.r.Framework == "wordpress" && ref.Method != "" { // add_shortcode and the like: a hook, no HTTP verb and no URL
				ref.Method, ref.Pattern = "", ""
			}
			for _, h := range hs {
				for _, f := range handlerFuncs(php, s, h, ff) {
					add(c, f, ref)
				}
			}
		}
	}
}

// literal is a single string token's text, or "".
func literal(t []Token) string {
	if len(t) == 1 && t[0].Kind == Str {
		return t[0].Text
	}
	return ""
}

// fnSpan is the first and last line a function's parameters and body reach.
// A decorator above a Python def is not part of it.
func fnSpan(f *fn) (lo, hi int, ok bool) {
	see := func(l int) {
		if l <= 0 {
			return
		}
		if !ok || l < lo {
			lo = l
		}
		if !ok || l > hi {
			hi = l
		}
		ok = true
	}
	for _, t := range f.params {
		see(t.Line)
	}
	var walk func(ss []*stmt, depth int)
	walk = func(ss []*stmt, depth int) {
		if depth > maxNest {
			return
		}
		for _, s := range ss {
			for _, t := range s.toks {
				see(t.Line)
			}
			for _, g := range s.funcs {
				for _, t := range g.params {
					see(t.Line)
				}
				walk(g.body, depth+1)
			}
			if s.fn != nil {
				for _, t := range s.fn.params {
					see(t.Line)
				}
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
	walk(f.body, 0)
	return lo, hi, ok
}
