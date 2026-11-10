package engine

import (
	"regexp"
	"slices"
	"strings"

	"github.com/nt-neil/shentu/rules"
)

// Route models (rules/routes, rules.Route) make the application's own
// functions that a framework calls with request data entry points: their
// parameters are input for every rule of the language, the way $_GET is,
// without each rule listing them. A file is checked for them once, before
// the rules run; a handler found is analyzed with those parameters tainted.

type croute struct {
	r        rules.Route
	register []callName
	deco     []callName
	requires map[string]bool
	exclude  map[string]bool
	params   map[int]bool
}

// callName is a registering call or a decorator as a route model writes it:
// add_shortcode (a plain call), Route::get (that receiver), *.get (any).
type callName struct{ recv, name string }

func parseCallName(s string) callName {
	for _, sep := range []string{"::", "."} {
		if i := strings.LastIndex(s, sep); i > 0 {
			return callName{s[:i], s[i+len(sep):]}
		}
	}
	return callName{"", s}
}

// seed is what makes a function a handler: which of its parameters carry input.
type seed struct {
	params  map[int]bool    // by position from 1; nil: all
	names   map[string]bool // only these names (the path template); nil: any
	members []string        // only these members of each parameter
	exclude map[string]bool // a parameter declared with one of these words is no input
	bound   bool            // a parameter declared with a class type is no input (route model binding)
}

// compileRoutes adds the route models to the engine: their handlers by
// language, and their sources to every rule of the language.
func (e *Engine) compileRoutes(rs []rules.Route) error {
	for _, r := range rs {
		c := &croute{r: r, requires: map[string]bool{}, exclude: map[string]bool{}}
		for _, n := range r.Register {
			c.register = append(c.register, parseCallName(n))
		}
		for _, n := range r.Decorator {
			c.deco = append(c.deco, parseCallName(n))
		}
		for _, w := range r.Requires {
			c.requires[w] = true
		}
		for _, w := range r.Exclude {
			c.exclude[w] = true
		}
		if len(r.Params) > 0 {
			c.params = map[int]bool{}
			for _, p := range r.Params {
				c.params[p] = true
			}
		}
		for _, raw := range r.Sources {
			p, err := compilePattern(r.Lang, raw, false)
			if err != nil {
				return err
			}
			for _, cr := range e.byLang[r.Lang] {
				cr.sources = append(cr.sources, p)
			}
		}
		if len(c.register) > 0 || len(c.deco) > 0 || r.Extends != "" {
			e.routes[r.Lang] = append(e.routes[r.Lang], c)
			e.routeByID[r.ID] = c
		}
	}
	return nil
}

// handlers finds the functions of a file that the route models make entry points.
func (e *Engine) handlers(lang string, toks []Token, tree []*stmt, ff *fileFuncs) map[*fn]*seed {
	var rs []*croute
	for _, c := range e.routes[lang] {
		if len(c.requires) == 0 || namesAny(toks, c.requires) {
			rs = append(rs, c)
		}
	}
	if len(rs) == 0 {
		return nil
	}
	out := map[*fn]*seed{}
	mark := func(c *croute, f *fn, template []Token) {
		if f == nil || out[f] != nil {
			return
		}
		sd := &seed{params: c.params, members: c.r.Members, exclude: c.exclude, bound: c.r.Bound}
		if c.r.Template {
			sd.names = templateNames(template)
		}
		out[f] = sd
	}
	php := lang == "php"
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
							mark(c, s.fn, t)
						}
					}
				}
				for _, c := range rs {
					if c.r.Extends != "" && strings.EqualFold(s.fn.name, c.r.Method) && s.fn.class != "" &&
						strings.EqualFold(shortClass(s.fn.parent), shortClass(c.r.Extends)) {
						mark(c, s.fn, nil)
					}
				}
			}
			decos = nil
			e.registrations(php, s, rs, ff, mark)
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
	if len(out) == 0 {
		return nil
	}
	return out
}

// registrations finds the calls in s that register a handler.
func (e *Engine) registrations(php bool, s *stmt, rs []*croute, ff *fileFuncs, mark func(*croute, *fn, []Token)) {
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
			h := args[k]
			if c.r.Key != "" {
				h = keyValue(h, c.r.Key)
			}
			var template []Token
			if len(args) > 0 {
				template = args[0]
			}
			for _, f := range handlerFuncs(php, s, h, ff) {
				mark(c, f, template)
			}
		}
	}
}

// callMatches reports whether the call named at t[i] is one of names.
func callMatches(php bool, t []Token, i int, names []callName) bool {
	for _, n := range names {
		if t[i].Text != n.name && !(php && strings.EqualFold(t[i].Text, n.name)) { // PHP names ignore case
			continue
		}
		member := i > 0 && memberOp(php, t[i-1])
		switch {
		case n.recv == "":
			if !member {
				return true
			}
		case n.recv == "*":
			if member {
				return true
			}
		default:
			if member && i >= 2 && (strings.EqualFold(shortClass(t[i-2].Text), n.recv) || t[i-2].Text == n.recv) {
				return true
			}
		}
	}
	return false
}

// matchDecorator reports whether a decorator (the tokens after @) is one of
// names, and returns its first argument (the route's path).
func matchDecorator(d []Token, names []callName) ([]Token, bool) {
	j := 0
	for j+1 < len(d) && d[j].Kind == Ident && d[j+1].op(".") {
		j += 2
	}
	if j >= len(d) || d[j].Kind != Ident {
		return nil, false
	}
	recv := ""
	if j >= 2 {
		recv = d[j-2].Text
	}
	ok := false
	for _, n := range names {
		if d[j].Text == n.name && (n.recv == "*" && j >= 2 || n.recv == recv) {
			ok = true
		}
	}
	if !ok {
		return nil, false
	}
	if j+1 < len(d) && d[j+1].op("(") {
		if args := splitTop(inside(d, j+1, closeOf(d, j+1)), isComma); len(args) > 0 {
			return args[0], true
		}
	}
	return nil, true
}

// handlerFuncs resolves a handler argument to the file's functions: a
// function literal, a function's name ('cb', cb), 'Class::m', or a method
// as [$this, 'm'], array($obj, 'm'), [Foo::class, 'm'].
func handlerFuncs(php bool, s *stmt, h []Token, ff *fileFuncs) []*fn {
	if len(h) == 0 || ff == nil {
		return nil
	}
	if len(h) == 1 && h[0].Kind == Func && h[0].Fn < len(s.funcs) {
		return []*fn{s.funcs[h[0].Fn]}
	}
	byKey := func(k string) []*fn {
		if php {
			k = strings.ToLower(k)
		}
		var out []*fn
		for _, fi := range ff.byKey[k] {
			out = append(out, fi.f)
		}
		return out
	}
	method := func(name string) []*fn { // the method of that name, in whichever class of the file declares it
		if php {
			name = strings.ToLower(name)
		}
		var out []*fn
		for k, infos := range ff.byKey {
			if strings.HasSuffix(k, "::"+name) {
				for _, fi := range infos {
					out = append(out, fi.f)
				}
			}
		}
		return out
	}
	switch {
	case len(h) == 1 && h[0].Kind == Str && len(h[0].Parts) == 0:
		if c, m, ok := strings.Cut(h[0].Text, "::"); ok && c != "" {
			return byKey(shortClass(c) + "::" + m)
		}
		return byKey(h[0].Text)
	case len(h) == 1 && h[0].Kind == Ident:
		return byKey(h[0].Text)
	case h[0].op("[") || len(h) > 1 && h[0].word("array") && h[1].op("("):
		open := 0
		if !h[0].op("[") {
			open = 1
		}
		parts := splitTop(inside(h, open, closeOf(h, open)), isComma)
		if len(parts) == 2 && len(parts[1]) == 1 && parts[1][0].Kind == Str {
			return method(parts[1][0].Text)
		}
	}
	return nil
}

// keyValue returns the value of key in an array or object literal
// (array('callback' => f), ['callback' => f], {callback: f}).
func keyValue(t []Token, key string) []Token {
	if len(t) == 0 {
		return nil
	}
	open := 0
	if !t[0].op("[") && !t[0].op("{") {
		if len(t) < 2 || !t[0].word("array") || !t[1].op("(") {
			return nil
		}
		open = 1
	}
	for _, part := range splitTop(inside(t, open, closeOf(t, open)), isComma) {
		if len(part) > 2 && (part[0].Kind == Str || part[0].Kind == Ident) && part[0].Text == key && (part[1].op("=>") || part[1].op(":")) {
			return part[2:]
		}
	}
	return nil
}

// pathLiteral reports whether t is a string literal starting with "/".
func pathLiteral(t []Token) bool {
	return len(t) == 1 && t[0].Kind == Str && strings.HasPrefix(t[0].Text, "/")
}

var templateParam = regexp.MustCompile(`<(?:([A-Za-z_]+):)?([A-Za-z_][A-Za-z0-9_]*)>|\{([A-Za-z_][A-Za-z0-9_]*)\??(?::[^}]*)?\}`)

// numericConverters cannot carry an attack (Flask <int:id>).
var numericConverters = map[string]bool{"int": true, "float": true, "uuid": true}

// templateNames lists the parameters a path template names: <name>,
// <conv:name> (Flask) and {name}, {name?}, {name:path} (FastAPI, Laravel).
func templateNames(t []Token) map[string]bool {
	out := map[string]bool{}
	if len(t) != 1 || t[0].Kind != Str {
		return out
	}
	for _, m := range templateParam.FindAllStringSubmatch(t[0].Text, -1) {
		switch {
		case m[2] != "" && !numericConverters[m[1]]:
			out[m[2]] = true
		case m[3] != "":
			out[m[3]] = true
		}
	}
	return out
}

func namesAny(t []Token, words map[string]bool) bool {
	for _, tk := range t {
		if tk.Kind == Ident && words[tk.Text] {
			return true
		}
	}
	return false
}

// shortClass is a class name without its namespace (\Elementor\Widget_Base: Widget_Base).
func shortClass(c string) string {
	c = strings.TrimPrefix(c, `\`)
	if i := strings.LastIndex(c, `\`); i >= 0 {
		return c[i+1:]
	}
	return c
}

// classTyped reports whether a PHP parameter is declared with a class type (Foo $x, ?Foo $x).
func classTyped(part []Token) bool {
	for k := 0; k+1 < len(part); k++ {
		if part[k].Kind == Ident && part[k+1].Kind == Var {
			return !scalarTypes[strings.ToLower(part[k].Text)] && !numericCasts[strings.ToLower(part[k].Text)]
		}
	}
	return false
}

// routeParams taints the parameters a route model makes input.
func (a *analysis) routeParams(f *fn, x state) {
	sd := a.routes[f]
	if sd == nil {
		return
	}
	fi := paramInfo(f, a.lang())
	parts := splitTop(f.params, isComma)
	for i, p := range fi.params {
		if p == "" || fi.numeric[i] || sd.params != nil && !sd.params[i+1] || sd.names != nil && !sd.names[strings.TrimPrefix(p, "$")] {
			continue
		}
		if i < len(parts) && namesAny(parts[i], sd.exclude) {
			continue // FastAPI's Depends(...), a Request: not a value from the request
		}
		if sd.bound && i < len(parts) && classTyped(parts[i]) {
			continue // Laravel's Invoice $invoice: the model the framework looked up
		}
		if len(sd.members) == 0 {
			x[p] = entry{taint: true}
			continue
		}
		for _, m := range sd.members {
			x[p+sepCh+"."+m] = entry{taint: true}
		}
	}
}

// routeRef is a registration naming a handler that may be in another file
// (urls.py's path('u/<name>/', views.profile), routes/web.php's
// Route::get('/u/{id}', [UserController::class, 'show'])): kept in the
// project's index (fileIndex.Routes) and resolved once all files are indexed.
type routeRef struct {
	Route string   `json:"r"`
	Class string   `json:"c,omitempty"` // PHP: the controller class as written
	Recv  string   `json:"v,omitempty"` // Python: the module the view is named through (views)
	Func  string   `json:"f"`
	Names []string `json:"n,omitempty"` // the path template's parameters
}

// routeRefs lists a file's registrations whose handler is named rather than
// written in place: a method of a class, a function of a module, a name.
func (e *Engine) routeRefs(lang string, tree []*stmt) []routeRef {
	idents := map[string]bool{}
	walkToks(tree, 0, func(t []Token) {
		for _, tk := range t {
			if tk.Kind == Ident {
				idents[tk.Text] = true
			}
		}
	})
	var rs []*croute
	for _, c := range e.routes[lang] {
		if len(c.register) == 0 {
			continue
		}
		ok := len(c.requires) == 0
		for w := range c.requires {
			ok = ok || idents[w]
		}
		if ok {
			rs = append(rs, c)
		}
	}
	if len(rs) == 0 {
		return nil
	}
	php := lang == "php"
	var out []routeRef
	walkToks(tree, 0, func(t []Token) {
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
				h := args[k]
				if c.r.Key != "" {
					h = keyValue(h, c.r.Key)
				}
				ref, ok := namedHandler(php, h)
				if !ok {
					continue
				}
				ref.Route = c.r.ID
				if c.r.Template && len(args) > 0 {
					for n := range templateNames(args[0]) {
						ref.Names = append(ref.Names, n)
					}
					slices.Sort(ref.Names)
				}
				out = append(out, ref)
			}
		}
	})
	return out
}

// namedHandler reads a handler named rather than written in place:
// [Foo::class, 'm'], 'Foo@m', 'Foo::m' (PHP); views.profile, profile (Python).
func namedHandler(php bool, h []Token) (routeRef, bool) {
	switch {
	case php && len(h) > 0 && h[0].op("["):
		parts := splitTop(inside(h, 0, closeOf(h, 0)), isComma)
		if len(parts) == 2 && len(parts[1]) == 1 && parts[1][0].Kind == Str {
			c := parts[0]
			if n := len(c); n >= 3 && c[n-1].word("class") && c[n-2].op("::") {
				var q strings.Builder
				for _, tk := range c[:n-2] {
					q.WriteString(tk.Text)
				}
				return routeRef{Class: q.String(), Func: parts[1][0].Text}, true
			}
		}
	case php && len(h) == 1 && h[0].Kind == Str && len(h[0].Parts) == 0:
		for _, sep := range []string{"@", "::"} {
			if c, m, ok := strings.Cut(h[0].Text, sep); ok && c != "" && m != "" {
				return routeRef{Class: c, Func: m}, true
			}
		}
	case !php && len(h) == 3 && h[0].Kind == Ident && h[1].op(".") && h[2].Kind == Ident:
		return routeRef{Recv: h[0].Text, Func: h[2].Text}, true
	case !php && len(h) == 1 && h[0].Kind == Ident:
		return routeRef{Func: h[0].Text}, true
	}
	return routeRef{}, false
}

// routeTarget is a handler of a file, found through another file's registration.
type routeTarget struct {
	key   string // the function's key in its file (Class::m in lower case for PHP)
	route string
	names []string
}

// resolveRoutes finds, for every file's registrations, the file and function
// they name (once, after indexing).
func (p *Project) resolveRoutes() {
	p.routeTo = map[string][]routeTarget{}
	var paths []string
	for f, fi := range p.files {
		if len(fi.Routes) > 0 {
			paths = append(paths, f)
		}
	}
	slices.Sort(paths)
	for _, f := range paths {
		fi := p.files[f]
		for _, ref := range fi.Routes {
			file, key := "", ""
			switch {
			case ref.Class != "":
				cf, ci := p.class(f, fi, ref.Class)
				if cf != "" {
					file, key = cf, strings.ToLower(shortClass(ci.Name))+"::"+strings.ToLower(ref.Func)
				}
			case ref.Recv != "":
				if m, ok := fi.Imports[ref.Recv]; ok {
					mod := m.Module
					if m.Name != "" { // from . import views: the module .views
						if !strings.HasSuffix(mod, ".") {
							mod += "."
						}
						mod += m.Name
					}
					file, key = p.module(f, fi.Lang, mod, ""), ref.Func
				}
			default:
				if m, ok := fi.Imports[ref.Func]; ok && m.Name != "" { // from .views import profile
					file, key = p.module(f, fi.Lang, m.Module, m.Name), m.Name
				}
			}
			p.unsure, p.ambig = false, ""
			if file != "" {
				p.routeTo[file] = append(p.routeTo[file], routeTarget{key: key, route: ref.Route, names: ref.Names})
			}
		}
	}
}

// projectHandlers adds to a file's handlers those other files' registrations name.
func (e *Engine) projectHandlers(proj *Project, path string, ff *fileFuncs, out map[*fn]*seed) map[*fn]*seed {
	if proj == nil || len(proj.routeTo[path]) == 0 {
		return out
	}
	for _, t := range proj.routeTo[path] {
		c := e.routeByID[t.route]
		if c == nil {
			continue
		}
		for _, fi := range ff.byKey[t.key] {
			if out == nil {
				out = map[*fn]*seed{}
			}
			if out[fi.f] != nil {
				continue
			}
			sd := &seed{params: c.params, members: c.r.Members, exclude: c.exclude, bound: c.r.Bound}
			if c.r.Template {
				sd.names = map[string]bool{}
				for _, n := range t.names {
					sd.names[n] = true
				}
			}
			out[fi.f] = sd
		}
	}
	return out
}
