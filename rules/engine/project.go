package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path"
	"path/filepath"
	"runtime/metrics"
	"slices"
	"sort"
	"strings"
	"time"
)

// A Project follows calls across the files of one source tree. NewProject
// indexes every file once: the functions and classes it declares (with each
// class's parent), and how it names other files: PHP include/require targets,
// namespace and use lines and composer.json PSR-4 prefixes; Python import and
// from-import; JavaScript require and import. Scanning a file then resolves a
// call that names no function of its own file through the index and uses the
// callee's summary, computed in the callee's file (interproc.go):
//
//   - a plain call: the function of that name in an imported module, in an
//     included file, or in the only file declaring it;
//   - Class::m(), $this->m() or parent::m() of an inherited method, and
//     $x->m() after $x = new Class(...): the method in the class's file, up the
//     parent chain;
//   - module.f() after import module or require('./module').
//
// The index holds names and paths, never code. It is cached by file content
// (CacheFile), so a later scan indexes only the files that changed. Files,
// tokens kept parsed, heap and time are capped; past a cap the project stops
// following calls across files, scans each file on its own as before, and
// Stopped tells why. A Project is not safe for concurrent use.
type Project struct {
	e         *Engine
	opt       ProjectOptions
	files     map[string]*fileIndex
	bySuffix  map[string][]string // "pkg/mod.py", "mod.py" → paths
	byClean   map[string]string   // cleaned slash path → path
	read      func(string) ([]byte, error)
	funcs     map[string]map[string][]string // lang → top-level function name → paths
	classes   map[string]map[string][]string // lang → class name (short and qualified) → paths
	psr4      []psr4Prefix
	declared  map[string]map[string][]string // lang → function or method name (PHP: lower case) → paths
	ctx       map[string]*fileCtx
	lru       []string
	resident  int
	sums      map[string]*summaries          // rule id + "\x00" + path
	kept      map[string]map[string]*summary // finished summaries of files no longer kept parsed
	incl      map[string][]string            // memo of includes()
	fnMemo    map[string]string              // memo of function(): from + "\x00" + name → file
	relMemo   map[string]bool                // memo of relevant(): rule, file, key
	seen      map[string]bool                // findings already returned: rule, path, line
	stopped   string
	byMachine bool                       // stopped by the clock or the heap: where depends on the machine
	unsteady  bool                       // the current scan met a file it could not read, or parse in time
	unread    map[string]bool            // files that could not be read, or parsed in time, since indexed
	skip      map[string]bool            // ScanCallsPart: rules to leave out
	part      []string                   // ... rules followed to their end in this scan
	partCut   bool                       // ... one of them cut short by a cap
	partAt    string                     // ... the rule the clock cut short
	deps      map[string]map[string]bool // file → files its functions' calls were followed into
	routeTo   map[string][]routeTarget   // file → its functions other files register as handlers (routes.go)
	busy      int                        // summaries asked for while being worked out (cycles across files)
	relGuess  int                        // relevance asked for while being worked out
	unsure    bool                       // the last resolution met a name it could not pin to one file
	ambig     string                     // ... a PHP function declared in several files
	deadline  time.Time
	depth     int
	heapAt    time.Time
}

// ProjectOptions are the caps of a Project. Zero values take the defaults.
type ProjectOptions struct {
	CacheFile string        // index cache, written with mode 0600; "" keeps none
	MaxFiles  int           // files indexed (default 30,000)
	MaxTokens int           // tokens kept parsed in memory at once (default 3,000,000)
	MaxHeap   uint64        // heap in use past which calls stop crossing files (default 1 GiB)
	MaxTime   time.Duration // time for indexing and following calls across files (default 90s)
}

// indexVersion changes whenever fileIndex changes, so an old cache is ignored.
const indexVersion = "4"

type fileIndex struct {
	Hash      string            `json:"h"`
	Lang      string            `json:"l"`
	Funcs     []string          `json:"f,omitempty"` // top-level functions (and closures assigned to a name)
	Classes   []classIndex      `json:"c,omitempty"`
	Namespace string            `json:"ns,omitempty"`
	Uses      map[string]string `json:"u,omitempty"`  // PHP: short class name → qualified name
	Includes  []string          `json:"n,omitempty"`  // PHP: include/require targets as written, relative paths
	Imports   map[string]imp    `json:"i,omitempty"`  // Python, JS: local name → module and name in it; JS re-exports too ("*1": export * from)
	Default   string            `json:"d,omitempty"`  // JS: the name of the default export
	Limited   bool              `json:"x,omitempty"`  // could not be read to the end: not used for calls
	Empty     []string          `json:"e,omitempty"`  // top-level functions with an empty body (stubs: noop.php)
	Guarded   []string          `json:"g,omitempty"`  // PHP: "f:name" / "c:name" (lower case) declared under if (!function_exists / !class_exists)
	Routes    []routeRef        `json:"rt,omitempty"` // registrations naming a handler, maybe in another file (routes.go)
}

type classIndex struct {
	Name    string   `json:"n"`
	Parent  string   `json:"p,omitempty"`
	Methods []string `json:"m,omitempty"`
}

// imp is one imported name: the module as written (".mod", "pkg.mod",
// "./mod") and the name inside it ("" for the module itself).
type imp struct {
	Module string `json:"m"`
	Name   string `json:"n,omitempty"`
}

type psr4Prefix struct{ ns, dir string }

type fileCtx struct {
	lang   string
	tree   []*stmt
	ff     *fileFuncs
	tokens int
	rdefs  map[string][][]Token // Python: what the file's names hold, for the receiver condition (receiver.go)
}

// NewProject indexes the files at paths. read returns a file's content; paths
// are what findings will name (relative ones are fine).
func (e *Engine) NewProject(paths []string, read func(string) ([]byte, error), opt ProjectOptions) *Project {
	if opt.MaxFiles <= 0 {
		opt.MaxFiles = 30_000
	}
	if opt.MaxTokens <= 0 {
		opt.MaxTokens = 3_000_000
	}
	if opt.MaxHeap == 0 {
		opt.MaxHeap = 1 << 30
	}
	if opt.MaxTime <= 0 {
		opt.MaxTime = 90 * time.Second
	}
	p := &Project{e: e, opt: opt, read: read, files: map[string]*fileIndex{}, bySuffix: map[string][]string{}, byClean: map[string]string{},
		funcs: map[string]map[string][]string{}, classes: map[string]map[string][]string{}, declared: map[string]map[string][]string{},
		ctx: map[string]*fileCtx{}, sums: map[string]*summaries{}, kept: map[string]map[string]*summary{}, seen: map[string]bool{},
		incl: map[string][]string{}, fnMemo: map[string]string{}, relMemo: map[string]bool{}, deps: map[string]map[string]bool{}, unread: map[string]bool{},
		deadline: time.Now().Add(opt.MaxTime)}
	cache := loadIndexCache(opt.CacheFile)
	fresh := map[string]*fileIndex{}
	n := 0
	for _, f := range paths {
		full := LangOf(f) // jsx, ts and tsx lex on their own and index as js
		lang := baseLang(full)
		if lang == "" {
			if path.Base(filepath.ToSlash(f)) == "composer.json" {
				if b, err := read(f); err == nil {
					p.readComposer(f, b)
				}
			}
			continue
		}
		if n++; n > opt.MaxFiles {
			p.stop("the project has more than the file limit")
			break
		}
		if time.Now().After(p.deadline) {
			p.stop("indexing ran out of time")
			p.byMachine = true
			break
		}
		b, err := read(f)
		if err != nil {
			continue
		}
		sum := sha256.Sum256(b)
		h := hex.EncodeToString(sum[:])
		fi := cache[f]
		if fi == nil || fi.Hash != h || fi.Lang != lang {
			fi = safeIndex(e, full, b)
			fi.Hash = h
		}
		fresh[f] = fi
		p.add(f, fi)
	}
	saveIndexCache(opt.CacheFile, fresh)
	p.resolveRoutes()
	return p
}

// declaredElsewhere reports whether a function or method of that name is
// declared in another file of the project.
func (p *Project) declaredElsewhere(lang, name, file string) bool {
	if p.stopped != "" {
		return false // calls no longer cross files
	}
	if lang == "php" {
		name = strings.ToLower(name)
	}
	for _, f := range p.declared[lang][name] {
		if f != file {
			return true
		}
	}
	return false
}

// importedRelative reports whether the call at t[i] names something the file
// imports from a module of its own project (./m, .mod): the call goes there,
// found or not.
func (p *Project) importedRelative(file string, t []Token, i int) bool {
	fi := p.files[file]
	if fi == nil || p.stopped != "" {
		return false
	}
	name := t[i].Text
	if i >= 2 && memberOp(fi.Lang == "php", t[i-1]) {
		name = t[i-2].Text // db.q(): the module db
	}
	m, ok := fi.Imports[name]
	return ok && strings.HasPrefix(m.Module, ".")
}

// dep records that a call in file from was followed into file to.
func (p *Project) dep(from, to string) {
	if to == "" || to == from {
		return
	}
	if p.deps[from] == nil {
		p.deps[from] = map[string]bool{}
	}
	p.deps[from][to] = true
}

// Deps lists the files whose functions calls in file f's functions were
// followed into, by any scan of the project so far. A result that followed
// calls from f depends on these files, theirs on their own Deps, and all of
// them on the names the project declares (IndexDigest).
func (p *Project) Deps(f string) []string {
	var out []string
	for g := range p.deps[f] {
		out = append(out, g)
	}
	sort.Strings(out)
	return out
}

// IndexDigest is a digest of what the project declares in one language: its
// files' paths and names (functions, classes, includes, imports), not their
// code, and for PHP the composer.json PSR-4 prefixes. Calls are resolved
// through these, so a result that followed calls holds while the digest of its
// language stays the same and its Deps' content does too.
func (p *Project) IndexDigest(lang string) string {
	h := sha256.New()
	var paths []string
	for f := range p.files {
		paths = append(paths, f)
	}
	sort.Strings(paths)
	for _, f := range paths {
		fi := *p.files[f]
		if fi.Lang != lang {
			fmt.Fprintf(h, "%q\n", f) // other languages' files still name modules (bySuffix)
			continue
		}
		fi.Hash = ""
		b, _ := json.Marshal(fi)
		fmt.Fprintf(h, "%q %s\n", f, b)
	}
	if lang == "php" {
		var ps []string
		for _, x := range p.psr4 {
			ps = append(ps, fmt.Sprintf("psr4 %q %q\n", x.ns, x.dir))
		}
		sort.Strings(ps) // read from a JSON object: no order of their own
		for _, x := range ps {
			h.Write([]byte(x))
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Unsteady reports whether the last scan met a file it could not read (gone
// or changed since it was indexed) or parse in time: its result holds for
// this audit but is not one to keep for the next.
func (p *Project) Unsteady() bool { return p.unsteady }

// Stopped tells why calls stopped crossing files, or "" when they did not.
func (p *Project) Stopped() string { return p.stopped }

func (p *Project) stop(reason string) {
	if p.stopped == "" {
		p.stopped = reason
	}
}

func (p *Project) add(f string, fi *fileIndex) {
	p.files[f] = fi
	s := path.Clean(filepath.ToSlash(f))
	p.byClean[s] = f
	for {
		p.bySuffix[s] = append(p.bySuffix[s], f)
		i := strings.Index(s, "/")
		if i < 0 {
			break
		}
		s = s[i+1:]
	}
	if fi.Limited {
		return
	}
	if p.funcs[fi.Lang] == nil {
		p.funcs[fi.Lang] = map[string][]string{}
		p.classes[fi.Lang] = map[string][]string{}
	}
	if p.declared[fi.Lang] == nil {
		p.declared[fi.Lang] = map[string][]string{}
	}
	// once per file: a name declared twice in it (if/else) is still that file's
	once := func(m map[string][]string, n string) {
		if l := m[n]; len(l) == 0 || l[len(l)-1] != f {
			m[n] = append(l, f)
		}
	}
	declare := func(n string) {
		if fi.Lang == "php" {
			n = strings.ToLower(n)
		}
		once(p.declared[fi.Lang], n)
	}
	for _, fn := range fi.Funcs {
		once(p.funcs[fi.Lang], fn)
		declare(fn)
	}
	for _, c := range fi.Classes {
		for _, m := range c.Methods {
			declare(m)
		}
	}
	for _, c := range fi.Classes {
		name, q := c.Name, fi.Namespace+`\`+c.Name
		if fi.Lang == "php" {
			name, q = strings.ToLower(name), strings.ToLower(q) // PHP class names ignore case
		}
		once(p.classes[fi.Lang], name)
		if fi.Namespace != "" {
			once(p.classes[fi.Lang], q)
		}
	}
}

func (p *Project) readComposer(f string, b []byte) {
	var c struct {
		Autoload struct {
			PSR4 map[string]any `json:"psr-4"`
		} `json:"autoload"`
	}
	if json.Unmarshal(b, &c) != nil {
		return
	}
	dir := path.Dir(filepath.ToSlash(f))
	for ns, d := range c.Autoload.PSR4 {
		var dirs []string
		switch v := d.(type) {
		case string:
			dirs = []string{v}
		case []any:
			for _, x := range v {
				if s, ok := x.(string); ok {
					dirs = append(dirs, s)
				}
			}
		}
		for _, d := range dirs {
			p.psr4 = append(p.psr4, psr4Prefix{strings.TrimSuffix(ns, `\`), path.Join(dir, d)})
		}
	}
}

// safeIndex is indexFile; a panic leaves the file out of calls (Limited) rather
// than stopping the scan.
func safeIndex(e *Engine, lang string, src []byte) (fi *fileIndex) {
	defer func() {
		if recover() != nil {
			fi = &fileIndex{Lang: baseLang(lang), Limited: true}
		}
	}()
	return indexFile(e, lang, src)
}

// indexFile reads one file's declarations and the names it imports. lang is
// the file's own (LangOf); the index keeps the base language (baseLang).
func indexFile(e *Engine, lang string, src []byte) *fileIndex {
	b := newBudget(e.Limits)
	toks := lex(lang, string(src), b)
	lang = baseLang(lang)
	fi := &fileIndex{Lang: lang}
	if b.hit {
		fi.Limited = true
		return fi
	}
	tree := parse(lang, toks, b)
	classes := map[string]*classIndex{}
	var order []string
	for key, infos := range collectFuncs(tree, lang) {
		name := key[strings.LastIndex(key, ":")+1:]
		for _, x := range infos {
			if x.f.class == "" {
				if !x.f.method {
					fi.Funcs = append(fi.Funcs, name)
					if len(x.f.body) == 0 && x.f.name != "" && len(infos) == 1 {
						fi.Empty = append(fi.Empty, name)
					}
				}
				continue
			}
			c := classes[x.f.class]
			if c == nil {
				c = &classIndex{Name: x.f.class, Parent: x.f.parent}
				classes[x.f.class] = c
				order = append(order, x.f.class)
			}
			c.Methods = append(c.Methods, name)
		}
	}
	sort.Strings(fi.Funcs)
	sort.Strings(fi.Empty)
	sort.Strings(order)
	for _, n := range order {
		sort.Strings(classes[n].Methods)
		fi.Classes = append(fi.Classes, *classes[n])
	}
	switch lang {
	case "php":
		indexPHP(toks, fi)
		fi.Guarded = guardedDecls(tree)
		fi.Routes = e.routeRefs(lang, tree)
	case "python":
		indexPython(toks, fi)
		fi.Routes = e.routeRefs(lang, tree)
	case "js":
		indexJS(toks, fi)
	}
	if b.hit || b.limited {
		fi.Limited = true
	}
	return fi
}

// guardedDecls lists the functions ("f:name") and classes ("c:name"), in lower
// case, declared inside if (!function_exists('name')) or if (!class_exists('Name')).
func guardedDecls(tree []*stmt) []string {
	set := map[string]bool{}
	var walk func(ss []*stmt, guards map[string]bool, depth int)
	walk = func(ss []*stmt, guards map[string]bool, depth int) {
		if depth > maxNest {
			return
		}
		for _, s := range ss {
			if s.fn != nil && s.fn.name != "" {
				if s.fn.class == "" && !s.fn.method && guards["f:"+strings.ToLower(s.fn.name)] {
					set["f:"+strings.ToLower(s.fn.name)] = true
				}
				if s.fn.class != "" && guards["c:"+strings.ToLower(s.fn.class)] {
					set["c:"+strings.ToLower(s.fn.class)] = true
				}
				continue // a function's body declares nothing the file declares
			}
			inner := guards
			if s.kind == sIf {
				if g := existsGuards(s.toks); len(g) > 0 {
					inner = maps.Clone(guards)
					if inner == nil {
						inner = map[string]bool{}
					}
					maps.Copy(inner, g)
				}
			}
			walk(s.body, inner, depth+1)
			walk(s.els, guards, depth+1)
		}
	}
	walk(tree, nil, 0)
	out := slices.Sorted(maps.Keys(set))
	return out
}

// existsGuards reads !function_exists('f') and !class_exists('C') in a condition.
func existsGuards(t []Token) map[string]bool {
	var g map[string]bool
	for i := 1; i+2 < len(t); i++ {
		kind := ""
		switch strings.ToLower(t[i].Text) {
		case "function_exists":
			kind = "f:"
		case "class_exists":
			kind = "c:"
		}
		j := i - 1
		if j > 0 && t[j].op(`\`) {
			j-- // !\function_exists(
		}
		if kind == "" || t[i].Kind != Ident || !t[j].op("!") || !t[i+1].op("(") || t[i+2].Kind != Str || len(t[i+2].Parts) > 0 {
			continue
		}
		if g == nil {
			g = map[string]bool{}
		}
		g[kind+strings.ToLower(strings.TrimPrefix(t[i+2].Text, `\`))] = true
	}
	return g
}

func indexPHP(t []Token, fi *fileIndex) {
	for i := 0; i < len(t); i++ {
		tk := t[i]
		if tk.Kind != Ident || i > 0 && memberOp(true, t[i-1]) {
			continue
		}
		switch strings.ToLower(tk.Text) {
		case "namespace":
			if fi.Namespace == "" {
				fi.Namespace = strings.Trim(qualifiedName(t, i+1), `\`)
			}
		case "use":
			// use Foo\Bar; use Foo\Bar as Baz; use Foo\{A, B}; (inside a class, a trait use)
			q := strings.Trim(qualifiedName(t, i+1), `\`)
			j := i + 1
			for j < len(t) && (t[j].Kind == Ident || t[j].op(`\`)) {
				j++
			}
			if q == "" || j < len(t) && t[j].op("{") {
				continue
			}
			short := q[strings.LastIndex(q, `\`)+1:]
			if j+1 < len(t) && t[j].word("as") && t[j+1].Kind == Ident {
				short = t[j+1].Text
			}
			if fi.Uses == nil {
				fi.Uses = map[string]string{}
			}
			fi.Uses[strings.ToLower(short)] = q // PHP class names ignore case
		case "include", "include_once", "require", "require_once":
			// The last string literal of the statement that names a PHP file:
			// __DIR__ . '/inc/a.php', dirname(__FILE__) . '/a.php', 'a.php'.
			// A variable in the path ($dir . '/run.php') leaves the folder unknown:
			// such an include is marked "?" and counts only where the file name is unique.
			last, varying := "", false
			for j := i + 1; j < len(t) && !t[j].op(";") && t[j].Line-tk.Line < 3; j++ {
				if t[j].Kind == Str && len(t[j].Parts) == 0 && LangOf(t[j].Text) == "php" { // .php, .inc, .phtml, .php5
					last = t[j].Text
				} else if t[j].Kind == Var || t[j].Kind == Str && len(t[j].Parts) > 0 {
					varying = true
				}
			}
			if last != "" {
				inc := strings.TrimPrefix(last, "/")
				if varying {
					inc = "?" + inc
				}
				fi.Includes = append(fi.Includes, inc)
			}
		}
	}
}

func indexPython(t []Token, fi *fileIndex) {
	add := func(local, module, name string) {
		if fi.Imports == nil {
			fi.Imports = map[string]imp{}
		}
		fi.Imports[local] = imp{module, name}
	}
	dotted := func(i int) (string, int) { // a.b.c, .mod, ..pkg.mod: names and dots alternate
		var b strings.Builder
		for ; i < len(t) && (t[i].Kind == Ident || t[i].op(".")); i++ {
			if t[i].Kind == Ident && i > 0 && t[i-1].Kind == Ident && b.Len() > 0 || t[i].word("import") { // from . import x: the module is "."
				break
			}
			b.WriteString(t[i].Text)
		}
		return b.String(), i
	}
	for i := 0; i < len(t); i++ {
		if i > 0 && t[i-1].Kind != Newline && t[i-1].Kind != Indent && t[i-1].Kind != Dedent {
			continue
		}
		switch {
		case t[i].word("import"):
			for j := i + 1; j < len(t) && t[j].Kind != Newline; {
				m, k := dotted(j)
				if m == "" {
					break
				}
				local := strings.SplitN(m, ".", 2)[0]
				if k+1 < len(t) && t[k].word("as") && t[k+1].Kind == Ident {
					local, k = t[k+1].Text, k+2
					add(local, m, "")
				} else {
					add(local, local, "")
				}
				if k < len(t) && t[k].op(",") {
					k++
				}
				j = k
			}
		case t[i].word("from"):
			m, k := dotted(i + 1)
			if k >= len(t) || !t[k].word("import") {
				continue
			}
			for j := k + 1; j < len(t) && t[j].Kind != Newline; j++ {
				if t[j].Kind != Ident {
					continue
				}
				local := t[j].Text
				if j+2 < len(t) && t[j+1].word("as") && t[j+2].Kind == Ident {
					local = t[j+2].Text
					add(local, m, t[j].Text)
					j += 2
					continue
				}
				add(local, m, t[j].Text)
			}
		}
	}
}

func indexJS(t []Token, fi *fileIndex) {
	add := func(local, module, name string) {
		if fi.Imports == nil {
			fi.Imports = map[string]imp{}
		}
		fi.Imports[local] = imp{module, name}
	}
	for i := 0; i < len(t); i++ {
		switch {
		// const x = require('./m'); const {a, b: c} = require('./m');
		case t[i].word("require") && i+3 < len(t) && t[i+1].op("(") && t[i+2].Kind == Str && t[i+3].op(")") && i >= 2 && t[i-1].op("="):
			mod := t[i+2].Text
			switch lhs := t[i-2]; {
			case lhs.Kind == Ident:
				add(lhs.Text, mod, "")
			case lhs.op("}"):
				open := openOf(t, i-2)
				for _, part := range splitTop(t[open+1:i-2], isComma) {
					if len(part) == 1 && part[0].Kind == Ident {
						add(part[0].Text, mod, part[0].Text)
					} else if len(part) == 3 && part[1].op(":") && part[0].Kind == Ident && part[2].Kind == Ident {
						add(part[2].Text, mod, part[0].Text)
					}
				}
			}
		// export default function q() {}; export default q;
		case t[i].word("export") && i+1 < len(t) && t[i+1].word("default"):
			j := i + 2
			if j < len(t) && t[j].word("async") {
				j++
			}
			if j+1 < len(t) && (t[j].word("function") || t[j].word("class")) && t[j+1].Kind == Ident {
				fi.Default = t[j+1].Text
			} else if j < len(t) && t[j].Kind == Ident && (j+1 >= len(t) || t[j+1].op(";") || t[j+1].Line > t[j].Line) {
				fi.Default = t[j].Text
			}
		// export {a, b as c} from './m'; export * from './m'
		case t[i].word("export") && i+1 < len(t) && (t[i+1].op("{") || t[i+1].op("*")):
			j := i + 1
			if t[j].op("{") {
				j = closeOf(t, j)
			}
			if j < 0 || j+2 >= len(t) || !t[j+1].word("from") || t[j+2].Kind != Str {
				continue
			}
			mod := t[j+2].Text
			if t[i+1].op("*") {
				add(fmt.Sprintf("*%d", len(fi.Imports)+1), mod, "")
				continue
			}
			for _, part := range splitTop(t[i+2:j], isComma) {
				if len(part) == 1 && part[0].Kind == Ident {
					add(part[0].Text, mod, part[0].Text)
				} else if len(part) == 3 && part[1].word("as") && part[0].Kind == Ident && part[2].Kind == Ident {
					add(part[2].Text, mod, part[0].Text)
				}
			}
		// module.exports = require('./impl')
		case t[i].word("module") && i+7 < len(t) && t[i+1].op(".") && t[i+2].word("exports") && t[i+3].op("=") &&
			t[i+4].word("require") && t[i+5].op("(") && t[i+6].Kind == Str && t[i+7].op(")"):
			add(fmt.Sprintf("*%d", len(fi.Imports)+1), t[i+6].Text, "")
		// import x from './m'; import {a, b as c} from './m'; import * as x from './m';
		case t[i].word("import") && (i == 0 || !t[i-1].op(".")):
			j := i + 1
			for j < len(t) && !t[j].word("from") && !t[j].op(";") && t[j].Kind != Str && j-i < 64 {
				j++
			}
			if j+1 >= len(t) || !t[j].word("from") || t[j+1].Kind != Str {
				continue
			}
			mod := t[j+1].Text
			spec := t[i+1 : j]
			for k := 0; k < len(spec); k++ {
				switch {
				case spec[k].op("*") && k+2 < len(spec) && spec[k+1].word("as"):
					add(spec[k+2].Text, mod, "")
					k += 2
				case spec[k].op("{"):
					c := closeOf(spec, k)
					for _, part := range splitTop(spec[k+1:max(k+1, c)], isComma) {
						if len(part) == 1 && part[0].Kind == Ident {
							add(part[0].Text, mod, part[0].Text)
						} else if len(part) == 3 && part[1].word("as") {
							add(part[2].Text, mod, part[0].Text)
						}
					}
					k = c
				case spec[k].Kind == Ident:
					add(spec[k].Text, mod, "default")
				}
			}
		}
	}
}

// ---- resolution ----

// summary returns the summary of the function a call reaches in another file.
func (p *Project) summary(a *analysis, c callee) *summary {
	f, name := p.resolve(a, c)
	if f == "" {
		return nil
	}
	x := p.analysisFor(a, f)
	if x == nil || x.sc == nil {
		return nil
	}
	p.depth++
	defer func() { p.depth-- }()
	if p.depth > maxSumDepth {
		a.b.tooDeep()
		return nil
	}
	if x.sc.busy[name] {
		p.busy++ // a cycle across files: the caller's summary is not kept (summaryOf)
		return nil
	}
	s := x.summaryOf(name)
	if a.b.hit && s != nil { // computed with the caller's budget cut short: do not keep it
		delete(x.sc.done, name)
	}
	return s // name is the key in that file (Class::m for a method)
}

// busyCount is how often a summary was asked for while being worked out in
// another file (0 outside a project).
func (p *Project) busyCount() int {
	if p == nil {
		return 0
	}
	return p.busy
}

// relevant reports whether a call reaches a function of another file that
// matters to the rule.
func (p *Project) relevant(a *analysis, c callee) bool {
	f, name := p.resolve(a, c)
	if f == "" {
		return false
	}
	mk := a.r.rule.ID + "\x00" + f + "\x00" + name
	if r, ok := p.relMemo[mk]; ok {
		return r
	}
	x := p.analysisFor(a, f)
	if x != nil && x.sc != nil && x.sc.relBusy {
		// That file's relevance is being worked out (a cycle across files): not
		// known yet. Nothing worked out from this answer is remembered.
		p.relGuess++
		return false
	}
	guess := p.relGuess
	r := x != nil && x.sc != nil && len(x.sc.funcs[name]) > 0 && x.relevant(name)
	if p.relGuess == guess && (x != nil || !p.unread[f]) { // an unread file is asked again, so each caller hears of it
		p.relMemo[mk] = r
	}
	return r
}

// analysisFor returns an analysis of file f for the same rule, sharing the
// caller's budget and the project's summaries of f.
func (p *Project) analysisFor(a *analysis, f string) *analysis {
	ctx := p.context(f)
	if ctx == nil {
		return nil
	}
	p.dep(a.file, f)
	key := a.r.rule.ID + "\x00" + f
	sc, ok := p.sums[key]
	if !ok {
		sc = newSummaries(ctx.ff)
		if done := p.kept[key]; sc != nil && done != nil {
			sc.done = done // computed before the file was let go
			delete(p.kept, key)
		}
		p.sums[key] = sc
	}
	return &analysis{r: a.r, php: ctx.lang == "php", py: ctx.lang == "python", js: ctx.lang == "js", b: a.b,
		kw: keywords[ctx.lang], seen: map[loc]bool{}, sc: sc, proj: p, file: f, rdefs: ctx.rdefs}
}

// context returns the parsed file, parsing it if it is not kept.
func (p *Project) context(f string) *fileCtx {
	if c, ok := p.ctx[f]; ok {
		return c
	}
	fi := p.files[f]
	if fi == nil || fi.Limited || !p.ok() {
		return nil
	}
	if p.unread[f] {
		p.unsteady = true
		return nil
	}
	src, err := p.read(f)
	if err != nil {
		p.unread[f], p.unsteady = true, true // gone or changed since it was indexed
		return nil
	}
	b := newBudget(p.e.Limits)
	toks := lex(LangOf(f), string(src), b)
	if b.hit {
		if b.timeHit {
			p.unread[f], p.unsteady = true, true
		}
		return nil
	}
	c := &fileCtx{lang: fi.Lang, tree: parse(fi.Lang, toks, b), tokens: len(toks), rdefs: fileRecvDefs(fi.Lang, toks)}
	if b.timeHit {
		p.unread[f], p.unsteady = true, true
	}
	c.ff = newFileFuncs(collectFuncs(c.tree, fi.Lang), fi.Lang)
	p.keep(f, c)
	return c
}

func (p *Project) keep(f string, c *fileCtx) {
	p.ctx[f] = c
	p.lru = append(p.lru, f)
	p.resident += c.tokens
	for p.resident > p.opt.MaxTokens && len(p.lru) > 1 {
		old := p.lru[0]
		p.lru = p.lru[1:]
		if oc, ok := p.ctx[old]; ok {
			p.resident -= oc.tokens
			delete(p.ctx, old)
			// Keep what was worked out, drop the tree: the summaries are small and
			// computing them again is what costs.
			for k, sc := range p.sums {
				if strings.HasSuffix(k, "\x00"+old) {
					if len(sc.done) > 0 {
						p.kept[k] = sc.done
					}
					delete(p.sums, k)
				}
			}
		}
	}
}

// ok checks the time and heap caps; once one is passed, calls stop crossing files.
func (p *Project) ok() bool {
	if p.stopped != "" {
		return false
	}
	if time.Now().After(p.deadline) {
		p.stop("following calls across files ran out of time")
		p.byMachine = true
		return false
	}
	// The heap is read at most every 100ms, and without stopping the program
	// (runtime/metrics; ReadMemStats stops the world and cost more than the scan).
	if now := time.Now(); now.Sub(p.heapAt) > 100*time.Millisecond {
		p.heapAt = now
		sample := []metrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}}
		metrics.Read(sample)
		if sample[0].Value.Kind() == metrics.KindUint64 && sample[0].Value.Uint64() > p.opt.MaxHeap {
			p.stop("following calls across files reached the memory limit")
			p.byMachine = true
			return false
		}
	}
	return true
}

// resolve finds the file and the function name a call in a's file reaches.
func (p *Project) resolve(a *analysis, c callee) (string, string) {
	p.unsure, p.ambig = false, ""
	f, name := p.resolve1(a, c)
	p.dep(a.file, f) // also when the answer about f comes from a memo
	unsure, ambig := p.unsure, p.ambig
	p.unsure, p.ambig = false, ""
	if f == "" && ambig != "" {
		// Several files declare it and none is included: unsure only if one of
		// them matters to the rule.
		for _, cand := range p.funcs["php"][ambig] {
			if x := p.analysisFor(a, cand); x != nil && x.sc != nil && len(x.sc.funcs[ambig]) > 0 && x.relevant(ambig) {
				unsure = true
				break
			}
		}
	}
	if f == "" && unsure {
		a.b.tooDeep() // the call may reach another file: the file's result says calls were not followed
	}
	return f, name
}

func (p *Project) resolve1(a *analysis, c callee) (string, string) {
	from := p.files[a.file]
	if from == nil || !p.ok() {
		return "", ""
	}
	lang := from.Lang
	switch {
	case c.recv == "":
		if m, ok := from.Imports[c.name]; ok && m.Name != "" { // from mod import f; const {f} = require('./m')
			if f := p.module(a.file, lang, m.Module, m.Name); f != "" {
				if g, n := p.exported(f, m.Name, 0); g != "" {
					return g, n
				}
			}
		}
		name := c.name
		if lang == "php" && !strings.HasPrefix(name, "$") {
			name = strings.ToLower(name) // PHP function names ignore case; the index keeps them in lower case
		}
		if lang != "php" {
			return "", "" // Python and JavaScript reach another file's function only through an import
		}
		return p.function(a.file, from, name), name
	case c.recv == "this" || c.recv == "parent":
		if a.parent == "" {
			return "", ""
		}
		return p.method(a.file, from, a.parent, c.name, 0)
	}
	if m, ok := from.Imports[c.recv]; ok && m.Name == "" { // import mod; mod.f()  /  const m = require('./m'); m.f()
		if f := p.module(a.file, lang, m.Module, ""); f != "" {
			return p.exported(f, c.name, 0)
		}
		return "", ""
	}
	cls := c.recv
	if strings.HasPrefix(cls, "$") || lang != "php" && a.types[cls] != "" {
		cls = a.types[cls] // $x = new Foo(); $x->m()
	}
	if cls == "" {
		return "", ""
	}
	return p.method(a.file, from, cls, c.name, 0)
}

// exported finds where the name a module exports is declared: in the module,
// or through its re-exports (export {q} from './impl', export * from,
// module.exports = require('./impl')); "default" is the default export.
func (p *Project) exported(f, name string, depth int) (string, string) {
	fi := p.files[f]
	if fi == nil || depth > 5 {
		return "", ""
	}
	if name == "default" {
		if fi.Default == "" {
			return "", ""
		}
		name = fi.Default
	}
	if p.declares(f, name) {
		return f, name
	}
	if m, ok := fi.Imports[name]; ok && m.Name != "" {
		if g := p.module(f, fi.Lang, m.Module, m.Name); g != "" {
			return p.exported(g, m.Name, depth+1)
		}
		return "", ""
	}
	var stars []string
	for k := range fi.Imports {
		if strings.HasPrefix(k, "*") {
			stars = append(stars, k)
		}
	}
	sort.Strings(stars)
	for _, k := range stars {
		if g := p.module(f, fi.Lang, fi.Imports[k].Module, ""); g != "" {
			if r, n := p.exported(g, name, depth+1); r != "" {
				return r, n
			}
		}
	}
	return "", ""
}

func (p *Project) declares(f, name string) bool {
	fi := p.files[f]
	if fi == nil {
		return false
	}
	php := fi.Lang == "php"
	for _, n := range fi.Funcs {
		if n == name || php && strings.EqualFold(n, name) {
			return true
		}
	}
	for _, c := range fi.Classes {
		for _, m := range c.Methods {
			if m == name || php && strings.EqualFold(m, name) {
				return true
			}
		}
	}
	return false
}

// function finds the file declaring a plain function: one the file includes,
// else the only one declaring it.
func (p *Project) function(from string, fi *fileIndex, name string) string {
	mk := from + "\x00" + name
	if f, ok := p.fnMemo[mk]; ok {
		if f == "?" {
			p.ambig = name
			return ""
		}
		return f
	}
	f := p.function1(from, fi, name)
	p.fnMemo[mk] = f
	if f == "?" {
		p.ambig = name
		return ""
	}
	return f
}

func (p *Project) function1(from string, fi *fileIndex, name string) string {
	cands := p.funcs[fi.Lang][name]
	switch len(cands) {
	case 0:
		return ""
	case 1:
		if cands[0] == from {
			return ""
		}
		return cands[0]
	}
	for _, inc := range p.includes(from, fi, 3) {
		for _, c := range cands {
			if c == inc {
				return c
			}
		}
	}
	if c := p.preferred(fi.Lang, name, cands); c != "" {
		if c == from {
			return ""
		}
		return c
	}
	return "?" // declared in several files and none included: ambiguous
}

// preferred picks, among files declaring a function, the one that runs: a
// stub with an empty body (WordPress's noop.php, for load-scripts.php) adds
// nothing, and one declared under if (!function_exists(...)) is a fallback,
// used only when no other file declared the function first (pluggable.php,
// cache-compat.php). "" when that leaves no single file.
func (p *Project) preferred(lang, name string, cands []string) string {
	pick := func(keep func(*fileIndex) bool) []string {
		var out []string
		for _, c := range cands {
			if fi := p.files[c]; fi != nil && keep(fi) {
				out = append(out, c)
			}
		}
		return out
	}
	if full := pick(func(fi *fileIndex) bool { return !slices.Contains(fi.Empty, name) }); len(full) > 0 {
		cands = full
	}
	if len(cands) > 1 && lang == "php" {
		g := "f:" + strings.ToLower(name)
		if first := pick(func(fi *fileIndex) bool { return !slices.Contains(fi.Guarded, g) }); len(first) > 0 {
			cands = first
		}
	}
	if len(cands) == 1 {
		return cands[0]
	}
	return ""
}

// includes lists the files a PHP file includes, to the given depth.
func (p *Project) includes(from string, fi *fileIndex, depth int) []string {
	if out, ok := p.incl[from]; ok {
		return out
	}
	out := p.includes1(from, fi, depth)
	p.incl[from] = out
	return out
}

func (p *Project) includes1(from string, fi *fileIndex, depth int) []string {
	var out []string
	seen := map[string]bool{from: true}
	var walk func(f string, fi *fileIndex, d int)
	walk = func(f string, fi *fileIndex, d int) {
		if d == 0 || fi == nil {
			return
		}
		for _, inc := range fi.Includes {
			t := ""
			if rest, ok := strings.CutPrefix(inc, "?"); ok {
				t = p.unique(rest)
			} else if t = p.byPath(path.Join(path.Dir(filepath.ToSlash(f)), inc)); t == "" {
				t = p.unique(inc)
			}
			if t != "" && !seen[t] {
				seen[t] = true
				out = append(out, t)
				walk(t, p.files[t], d-1)
			}
		}
	}
	walk(from, fi, depth)
	return out
}

// method finds the file of a class that declares method, following parents,
// and the method's key there (Class::method).
func (p *Project) method(from string, fi *fileIndex, class, method string, depth int) (string, string) {
	if depth > 5 || class == "" {
		return "", ""
	}
	f, ci := p.class(from, fi, class)
	if f == "" {
		return "", ""
	}
	php := p.files[f] != nil && p.files[f].Lang == "php"
	for _, m := range ci.Methods {
		if m == method || php && strings.EqualFold(m, method) {
			if php {
				return f, strings.ToLower(ci.Name) + "::" + strings.ToLower(method)
			}
			return f, ci.Name + "::" + method
		}
	}
	return p.method(f, p.files[f], ci.Parent, method, depth+1)
}

// class finds the file declaring a class as named in file from.
func (p *Project) class(from string, fi *fileIndex, name string) (string, classIndex) {
	lang := fi.Lang
	name = strings.TrimPrefix(name, `\`)
	q := name
	if lang == "php" {
		short := name[strings.LastIndex(name, `\`)+1:]
		switch {
		case fi.Uses[strings.ToLower(short)] != "" && !strings.Contains(name, `\`):
			q = fi.Uses[strings.ToLower(short)]
		case !strings.Contains(name, `\`) && fi.Namespace != "":
			q = fi.Namespace + `\` + name
		}
		name = short
	} else if m, ok := fi.Imports[name]; ok && m.Name != "" {
		if f := p.module(from, lang, m.Module, ""); f != "" {
			return p.classIn(f, m.Name)
		}
	}
	kq, kn := q, name
	if lang == "php" {
		kq, kn = strings.ToLower(q), strings.ToLower(name)
	}
	cands := p.classes[lang][kq]
	if len(cands) == 0 {
		cands = p.classes[lang][kn]
	}
	if len(cands) > 1 && lang == "php" {
		if f := p.psr4Path(q); f != "" {
			cands = []string{f}
		} else {
			for _, inc := range p.includes(from, fi, 3) { // require 'a/Db.php'; Db::run()
				if slices.Contains(cands, inc) {
					cands = []string{inc}
					break
				}
			}
		}
		if len(cands) > 1 { // one declared under if (!class_exists(...)) is a fallback
			g := "c:" + strings.ToLower(name)
			var first []string
			for _, c := range cands {
				if cf := p.files[c]; cf != nil && !slices.Contains(cf.Guarded, g) {
					first = append(first, c)
				}
			}
			if len(first) == 1 {
				cands = first
			}
		}
	}
	if len(cands) != 1 {
		for _, c := range cands {
			if c == from {
				return p.classIn(c, name)
			}
		}
		if len(cands) > 1 {
			p.unsure = true // a class of this name in several files, none of them sure
		}
		return "", classIndex{}
	}
	return p.classIn(cands[0], name)
}

func (p *Project) classIn(f, name string) (string, classIndex) {
	if fi := p.files[f]; fi != nil {
		for _, c := range fi.Classes {
			if c.Name == name || fi.Lang == "php" && strings.EqualFold(c.Name, name) {
				return f, c
			}
		}
	}
	return "", classIndex{}
}

// psr4Path is the file composer's PSR-4 autoload would load for a class.
func (p *Project) psr4Path(q string) string {
	for _, x := range p.psr4 {
		if rest, ok := strings.CutPrefix(q, x.ns+`\`); ok {
			if f := p.byPath(path.Join(x.dir, strings.ReplaceAll(rest, `\`, "/")+".php")); f != "" {
				return f
			}
		}
	}
	return ""
}

// module finds the file of an imported module, or of name inside a package.
func (p *Project) module(from, lang, mod, name string) string {
	dir := path.Dir(filepath.ToSlash(from))
	switch lang {
	case "python":
		rel := strings.TrimLeft(mod, ".")
		base := ""
		if dots := len(mod) - len(rel); dots > 0 {
			base = dir
			for i := 1; i < dots; i++ {
				base = path.Dir(base)
			}
		}
		p1 := path.Join(base, strings.ReplaceAll(rel, ".", "/"))
		for _, c := range []string{p1 + ".py", p1 + "/__init__.py", path.Join(p1, name) + ".py"} {
			if base != "" {
				if f := p.byPath(c); f != "" {
					return f
				}
			} else if f := p.unique(c); f != "" {
				return f
			} else if len(p.bySuffix[path.Clean(c)]) > 1 {
				p.unsure = true // two util.py: which one the import means depends on sys.path
				return ""
			}
		}
		if base != "" {
			p.unsure = true // a relative import of a module the project does not have
		}
	case "js":
		if !strings.HasPrefix(mod, ".") {
			return "" // a package from node_modules
		}
		p1 := path.Join(dir, mod)
		for _, c := range []string{p1, p1 + ".js", p1 + ".mjs", p1 + ".cjs", p1 + ".jsx", p1 + "/index.js", p1 + "/index.jsx"} {
			if f := p.byPath(c); f != "" {
				return f
			}
		}
		p.unsure = true // a relative module the project does not have
	}
	return ""
}

// byPath returns the indexed file at exactly this path.
func (p *Project) byPath(s string) string { return p.byClean[path.Clean(s)] }

// unique returns the one indexed file whose path ends with s.
func (p *Project) unique(s string) string {
	if c := p.bySuffix[path.Clean(s)]; len(c) == 1 {
		return c[0]
	}
	return ""
}

// ---- index cache ----

type indexCache struct {
	Version string                `json:"v"`
	Files   map[string]*fileIndex `json:"files"`
}

func loadIndexCache(name string) map[string]*fileIndex {
	if name == "" {
		return nil
	}
	b, err := os.ReadFile(name)
	if err != nil {
		return nil
	}
	var c indexCache
	if json.Unmarshal(b, &c) != nil || c.Version != indexVersion {
		return nil
	}
	return c.Files
}

// saveIndexCache writes the index with mode 0600 (it names the application's
// files and functions), replacing the old one in one step.
func saveIndexCache(name string, files map[string]*fileIndex) {
	if name == "" {
		return
	}
	b, err := json.Marshal(indexCache{Version: indexVersion, Files: files})
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(name), 0o700); err != nil {
		return
	}
	tmp, err := os.CreateTemp(filepath.Dir(name), ".codeindex-")
	if err != nil {
		return
	}
	ok := false
	defer func() {
		if !ok {
			os.Remove(tmp.Name())
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return
	}
	if tmp.Close() != nil {
		return
	}
	ok = os.Rename(tmp.Name(), name) == nil
}
