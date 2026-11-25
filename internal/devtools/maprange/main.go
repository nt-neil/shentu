// Command maprange lists every place in a Go package that goes over a map in
// Go's random order: a range over a map, and a maps.Keys, maps.Values or
// maps.All that is not sorted right away (slices.Sorted, slices.SortedFunc,
// slices.SortedStableFunc). For each it says which of the given functions the
// loop body can reach through the package's static call graph, and which calls
// in the body the graph cannot follow.
//
//	go run ./internal/devtools/maprange [-reach F,G] DIR
//
// prints file:line, the enclosing function, what is ranged over, its ordinal
// among the same function's ranges over the same expression, a hash of the
// loop's body, the functions reached and the calls not followed. The test next to it compares the list of
// rules/engine with approved.tsv, so a new range over a map fails until it is
// classified.
//
// The call graph covers the package's own functions and methods, named or
// referenced as values; a closure is part of the function that declares it.
// Not followed: calls of func values (variables, struct fields, parameters)
// and of interface methods, which the list names for reading by hand. Test
// files are left out.
package main

import (
	"crypto/sha256"
	"flag"
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/scanner"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// engineReach are the functions that change which files a Project holds: a
// loop in map order that reaches them can change what a scan keeps.
var engineReach = []string{"Project.keep", "Project.shrink", "Project.context", "Project.analysisFor"}

type site struct {
	pos     string // file:line
	fn      string // enclosing function, Type.method for a method
	expr    string // what is ranged over
	n       int    // ordinal among fn's ranges over expr, from 1
	body    string // hash of the loop body's tokens, comments and line breaks left out; "" for a maps iterator that is not ranged over
	reach   []string
	unknown []string
}

func main() {
	reach := flag.String("reach", strings.Join(engineReach, ","), "functions to report reaching, comma separated")
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: maprange [-reach F,G] DIR")
		os.Exit(2)
	}
	sites, err := list(flag.Arg(0), strings.Split(*reach, ","))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for _, s := range sites {
		fmt.Printf("%s\t%s\t%s\t%d\t%s\t%s\t%s\n", s.pos, s.fn, s.expr, s.n, s.body, strings.Join(s.reach, ","), strings.Join(s.unknown, ","))
	}
}

func list(dir string, reachNames []string) ([]site, error) {
	fset := token.NewFileSet()
	names, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		return nil, err
	}
	slices.Sort(names)
	var files []*ast.File
	srcs := map[string][]byte{}
	for _, m := range names {
		if strings.HasSuffix(m, "_test.go") {
			continue
		}
		src, err := os.ReadFile(m)
		if err != nil {
			return nil, err
		}
		f, err := parser.ParseFile(fset, m, src, 0)
		if err != nil {
			return nil, err
		}
		files, srcs[m] = append(files, f), src
	}
	// bodyHash identifies a loop's body by its tokens, so that a loop taken
	// out and another put in its place, over the same thing and reaching the
	// same, is not taken for the one approved.
	bodyHash := func(body ast.Node) string {
		p, e := fset.Position(body.Pos()), fset.Position(body.End())
		var sc scanner.Scanner
		h := sha256.New()
		sc.Init(token.NewFileSet().AddFile("", -1, e.Offset-p.Offset), srcs[p.Filename][p.Offset:e.Offset], nil, 0)
		for {
			_, tok, lit := sc.Scan()
			if tok == token.EOF {
				break
			}
			if tok == token.SEMICOLON && lit == "\n" {
				continue
			}
			fmt.Fprintf(h, "%s %s\n", tok, lit)
		}
		return fmt.Sprintf("%x", h.Sum(nil))[:12]
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("%s: no Go files", dir)
	}
	info := &types.Info{Types: map[ast.Expr]types.TypeAndValue{}, Defs: map[*ast.Ident]types.Object{}, Uses: map[*ast.Ident]types.Object{}}
	var typeErrs []string
	conf := types.Config{Importer: importer.ForCompiler(fset, "source", nil), Error: func(e error) { typeErrs = append(typeErrs, e.Error()) }}
	pkg, _ := conf.Check(files[0].Name.Name, fset, files, info)
	if len(typeErrs) > 0 { // types missing would leave ranges out without a word
		return nil, fmt.Errorf("type-checking %s: %s", dir, strings.Join(typeErrs, "; "))
	}

	name := func(f *types.Func) string {
		if r := f.Type().(*types.Signature).Recv(); r != nil {
			t := r.Type()
			if p, ok := t.(*types.Pointer); ok {
				t = p.Elem()
			}
			if n, ok := t.(*types.Named); ok {
				return n.Obj().Name() + "." + f.Name()
			}
		}
		return f.Name()
	}
	isIfaceMethod := func(f *types.Func) bool {
		r := f.Type().(*types.Signature).Recv()
		if r == nil {
			return false
		}
		_, ok := r.Type().Underlying().(*types.Interface)
		return ok
	}
	// funcsIn: the package's functions named anywhere in n, called or taken as
	// a value; unknown: calls the graph cannot follow.
	funcsIn := func(n ast.Node) (fs []*types.Func, unknown []string) {
		ast.Inspect(n, func(x ast.Node) bool {
			switch e := x.(type) {
			case *ast.Ident:
				if o, ok := info.Uses[e].(*types.Func); ok && o.Pkg() == pkg && !isIfaceMethod(o) {
					fs = append(fs, o)
				}
			case *ast.CallExpr:
				fun := ast.Unparen(e.Fun)
				switch ix := fun.(type) {
				case *ast.IndexExpr:
					fun = ix.X
				case *ast.IndexListExpr:
					fun = ix.X
				}
				var id *ast.Ident
				switch f := fun.(type) {
				case *ast.Ident:
					id = f
				case *ast.SelectorExpr:
					id = f.Sel
				case *ast.FuncLit:
					return true // its body is part of n
				default:
					unknown = append(unknown, types.ExprString(e.Fun))
					return true
				}
				switch o := info.Uses[id].(type) {
				case *types.Func:
					if isIfaceMethod(o) {
						unknown = append(unknown, "iface "+types.ExprString(e.Fun))
					}
				case *types.Builtin, *types.TypeName, nil:
				default: // a variable, parameter or field of func type
					unknown = append(unknown, "value "+types.ExprString(e.Fun))
				}
			}
			return true
		})
		slices.Sort(unknown)
		return fs, slices.Compact(unknown)
	}

	graph := map[*types.Func][]*types.Func{}
	byName := map[string]*types.Func{}
	for _, f := range files {
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Body != nil {
				o := info.Defs[fd.Name].(*types.Func)
				byName[name(o)] = o
				graph[o], _ = funcsIn(fd.Body)
			}
		}
	}
	reaches := map[*types.Func]bool{}
	for _, s := range reachNames {
		o := byName[s]
		if o == nil {
			return nil, fmt.Errorf("%s: no function %s", dir, s)
		}
		reaches[o] = true
	}
	for changed := true; changed; {
		changed = false
		for f, cs := range graph {
			if !reaches[f] && slices.ContainsFunc(cs, func(c *types.Func) bool { return reaches[c] }) {
				reaches[f], changed = true, true
			}
		}
	}

	mapsIter := func(e ast.Expr) bool { // maps.Keys, maps.Values or maps.All of something
		c, ok := ast.Unparen(e).(*ast.CallExpr)
		if !ok {
			return false
		}
		s, ok := ast.Unparen(c.Fun).(*ast.SelectorExpr)
		if !ok {
			return false
		}
		o, ok := info.Uses[s.Sel].(*types.Func)
		return ok && o.Pkg() != nil && o.Pkg().Path() == "maps" && (o.Name() == "Keys" || o.Name() == "Values" || o.Name() == "All")
	}
	settled := map[ast.Expr]bool{} // maps iterators sorted at once, or ranged over (listed as the range)
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.CallExpr:
				if s, ok := ast.Unparen(x.Fun).(*ast.SelectorExpr); ok && len(x.Args) > 0 {
					if o, ok := info.Uses[s.Sel].(*types.Func); ok && o.Pkg() != nil && o.Pkg().Path() == "slices" &&
						(o.Name() == "Sorted" || o.Name() == "SortedFunc" || o.Name() == "SortedStableFunc") {
						settled[ast.Unparen(x.Args[0])] = true
					}
				}
			case *ast.RangeStmt:
				settled[ast.Unparen(x.X)] = true
			}
			return true
		})
	}

	var sites []site
	seen := map[string]int{}
	add := func(p token.Pos, fn string, x ast.Expr, body ast.Node) {
		s := site{pos: fmt.Sprintf("%s:%d", filepath.Base(fset.Position(p).Filename), fset.Position(p).Line), fn: fn, expr: types.ExprString(x)}
		k := fn + "\t" + s.expr
		seen[k]++
		s.n = seen[k]
		if body != nil {
			s.body = bodyHash(body)
			cs, unk := funcsIn(body)
			for _, c := range cs {
				if reaches[c] && !slices.Contains(s.reach, name(c)) {
					s.reach = append(s.reach, name(c))
				}
			}
			slices.Sort(s.reach)
			s.unknown = unk
		}
		sites = append(sites, s)
	}
	for _, f := range files {
		for _, d := range f.Decls {
			fn := "(package)"
			if fd, ok := d.(*ast.FuncDecl); ok {
				fn = name(info.Defs[fd.Name].(*types.Func))
			}
			ast.Inspect(d, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.RangeStmt:
					t := info.TypeOf(x.X)
					if t == nil {
						return true
					}
					if _, ok := t.Underlying().(*types.Map); ok || mapsIter(x.X) {
						add(x.Pos(), fn, x.X, x.Body)
					}
				case *ast.CallExpr:
					if mapsIter(x) && !settled[x] {
						add(x.Pos(), fn, x, nil)
					}
				}
				return true
			})
		}
	}
	return sites, nil
}
