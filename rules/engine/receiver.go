package engine

import "strings"

// recvDefs maps, for one file, a name to what the code says it holds: the
// right side of each assignment to it (x = ..., self.x = ..., with or without
// an annotation) and the annotation of a parameter or variable of that name
// (db: Database). self.x and cls.x are kept as "self.x". The receiver
// condition of [[args]] follows a receiver back through these.
func recvDefs(toks []Token) map[string][][]Token {
	defs := map[string][][]Token{}
	stmt := func(i int) []Token { // the rest of the line, or of the bracketed expression
		depth := 0
		j := i
		for ; j < len(toks); j++ {
			if depth == 0 && (j > i && toks[j].Line != toks[j-1].Line || toks[j].op(";") || toks[j].Kind == Newline) {
				break
			}
			switch {
			case toks[j].op("(") || toks[j].op("[") || toks[j].op("{"):
				depth++
			case toks[j].op(")") || toks[j].op("]") || toks[j].op("}"):
				if depth == 0 {
					return toks[i:j]
				}
				depth--
			}
			if j-i > 256 {
				break
			}
		}
		return toks[i:j]
	}
	for i := 0; i < len(toks); i++ {
		// from pkg.mod import a, b as c / import pkg.mod as m: the module path is
		// what the name holds, but only for the standard library and well-known
		// packages that are not MongoDB (notMongo). A module of the project
		// itself (from app.db import mongo, from .db import mongo) or any other
		// package says nothing about it, so the name stays unknown.
		if toks[i].word("from") && lineStart(toks, i) {
			line := stmt(i)
			k := 1
			for k < len(line) && !line[k].word("import") {
				k++
			}
			if k >= len(line) || k == 1 || !notMongo[line[1].Text] {
				continue
			}
			mod := line[1:k]
			for _, part := range splitTop(stripParens(line[k+1:]), isComma) {
				if n := len(part); n > 0 && part[n-1].Kind == Ident {
					defs[part[n-1].Text] = append(defs[part[n-1].Text], mod)
				}
			}
			continue
		}
		if toks[i].word("import") && lineStart(toks, i) {
			for _, part := range splitTop(stmt(i+1), isComma) {
				if n := len(part); n > 0 && part[n-1].Kind == Ident && notMongo[part[0].Text] {
					name := part[0].Text
					if n > 2 && part[n-2].word("as") {
						name = part[n-1].Text
					}
					defs[name] = append(defs[name], part)
				}
			}
			continue
		}
		if i+2 >= len(toks) || toks[i].Kind != Ident && toks[i].Kind != Var {
			continue
		}
		key, k := toks[i].Text, i+1
		if (key == "self" || key == "cls") && toks[i+1].op(".") && toks[i+2].Kind == Ident {
			if i > 0 && toks[i-1].op(".") {
				continue
			}
			key, k = "self."+toks[i+2].Text, i+3
		} else if i > 0 && toks[i-1].op(".") {
			continue // a member of something else
		}
		if k >= len(toks) {
			continue
		}
		switch {
		case toks[k].op("="):
			if k+1 < len(toks) {
				defs[key] = append(defs[key], stmt(k+1))
			}
		case toks[k].op(":"): // an annotation: a parameter, or a variable declared with its type
			if k+1 < len(toks) {
				ann := stmt(k + 1)
				for j, t := range ann {
					if t.op(",") || t.op("=") {
						ann = ann[:j]
						break
					}
				}
				defs[key] = append(defs[key], ann)
			}
		}
	}
	return defs
}

// fileRecvDefs is recvDefs for a Python file kept by a project, so an analysis
// of one of its functions made from another file (analysisFor) reads this
// file's names, not the caller's. Other languages have no receiver rules.
func fileRecvDefs(lang string, toks []Token) map[string][][]Token {
	if lang != "python" {
		return nil
	}
	return recvDefs(toks)
}

// recvIs reports whether the receiver of a method sink may be one of the kinds
// the patterns name: one appears in it, or in what its root (x, self.x) is
// assigned, annotated or imported with in the file, followed a few steps. A
// root the file says nothing about (db imported with a relative import, a
// parameter without a type, a name from another file) may be one; a literal
// or a name the file ties only to other things is not.
func (a *analysis) recvIs(ps []*pat, recv []Token) bool {
	if a.rdefs == nil {
		a.rdefs = recvDefs(a.ftoks)
	}
	seen := map[string]bool{}
	var is func(t []Token, depth int) bool
	is = func(t []Token, depth int) bool {
		for i := range t {
			for _, p := range ps {
				if p.at(t, i, false) {
					return true
				}
			}
		}
		if depth >= 4 || len(t) == 0 || t[0].Kind != Ident {
			return false
		}
		key := t[0].Text
		if (key == "self" || key == "cls") && len(t) > 2 && t[1].op(".") && t[2].Kind == Ident {
			key = "self." + t[2].Text
		}
		if seen[key] {
			return false
		}
		seen[key] = true
		ds, ok := a.rdefs[key]
		if !ok {
			return depth == 0 // the receiver's own root not known here: it may be a collection
		}
		for _, d := range ds {
			if is(d, depth+1) {
				return true
			}
		}
		return false
	}
	return is(recv, 0)
}

// recvSurely reports whether the receiver of a method sink is surely an object
// of one of the classes the patterns name: new Class(...) itself, or a name
// whose every assignment in the file is one, followed a few steps. A name the
// file says nothing about, or assigns anything else too, is not.
func (a *analysis) recvSurely(ps []*pat, recv []Token) bool {
	if a.rdefs == nil {
		a.rdefs = recvDefs(a.ftoks)
	}
	seen := map[string]bool{}
	var is func(t []Token, depth int) bool
	is = func(t []Token, depth int) bool {
		t = stripParens(t)
		if len(t) >= 2 && strings.EqualFold(t[0].Text, "new") && t[0].Kind == Ident {
			k := 1
			if t[k].op("\\") && len(t) > 2 {
				k++ // new \WP_Query
			}
			for _, p := range ps {
				if p.at(t, k, false) {
					return true
				}
			}
			return false
		}
		if depth >= 4 || len(t) != 1 || t[0].Kind != Ident && t[0].Kind != Var || seen[t[0].Text] {
			return false
		}
		seen[t[0].Text] = true
		ds := a.rdefs[t[0].Text]
		for _, d := range ds {
			if !is(d, depth+1) {
				return false
			}
		}
		return len(ds) > 0
	}
	return is(recv, 0)
}

func lineStart(toks []Token, i int) bool {
	return i == 0 || toks[i-1].Line != toks[i].Line || toks[i-1].Kind == Newline || toks[i-1].Kind == Indent || toks[i-1].Kind == Dedent
}

// notMongo are top-level Python modules of the standard library and well-known
// packages that hold no MongoDB client: a name imported from one is not a
// collection.
var notMongo = words("os posixpath ntpath re json sys io pathlib shutil glob fnmatch subprocess string typing " +
	"collections itertools functools operator datetime time calendar logging urllib http xml html csv base64 " +
	"binascii hashlib hmac secrets random math statistics decimal fractions tempfile zipfile tarfile gzip bz2 " +
	"lzma pickle copy uuid enum abc dataclasses contextlib inspect ast textwrap unicodedata email mimetypes " +
	"socket ssl sqlite3 configparser argparse warnings traceback threading multiprocessing asyncio concurrent " +
	"queue struct codecs gettext locale difflib pprint shlex platform signal weakref heapq bisect array " +
	"django flask werkzeug jinja2 markupsafe starlette fastapi pydantic sqlalchemy requests httpx urllib3 " +
	"bs4 lxml yaml rest_framework celery numpy pandas PIL")
