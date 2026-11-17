package engine

import "strings"

// A rule's route_not (headers.host) leaves the member out of the rule's own
// sources too, where a source ends in that member (req.headers, ctx.request.headers,
// NestJS's @Headers(), Koa's ctx.request.header[): req.headers.host,
// req.headers['host'], req.headers.get('host') (a Fetch Headers object),
// @Headers('host'), and h.host after h = @Headers() are not the rule's input,
// as they are not in a route handler's parameters (routes.go).

// setNotMembers records on each source the names route_not leaves out of it.
func (c *crule) setNotMembers() {
	for _, p := range c.sources {
		base := strings.ToLower(strings.TrimPrefix(p.name, "@"))
		n := len(p.toks)
		if base == "" || n == 0 {
			continue
		}
		last := p.toks[n-1]
		if !last.op("[") && !last.op("(") && !(last.Kind == Ident && last.Text == p.name) {
			continue
		}
		if (last.op("[") || last.op("(")) && (n < 2 || p.toks[n-2].Kind != Ident || p.toks[n-2].Text != p.name) {
			continue
		}
		for _, rn := range c.rule.RouteNot {
			if mem, name, ok := strings.Cut(rn, "."); ok && strings.EqualFold(mem, base) {
				p.notMembers = append(p.notMembers, strings.ToLower(name))
			}
		}
	}
}

// litArg returns the lower-case text of a call's or index's first argument
// when it is a string literal: t[open] is the "(" or "[".
func litArg(t []Token, open int) (string, bool) {
	if open >= len(t) || !(t[open].op("(") || t[open].op("[")) {
		return "", false
	}
	args := splitTop(inside(t, open, closeOf(t, open)), isComma)
	if len(args) == 0 {
		return "", false
	}
	arg := stripParens(args[0])
	if len(arg) != 1 || arg[0].Kind != Str || len(arg[0].Parts) > 0 {
		return "", false
	}
	return strings.ToLower(arg[0].Text), true
}

// notMember reports whether the source s, matched in t up to end, reads one of
// the members route_not leaves out of it.
func notMember(s *pat, t []Token, end int) bool {
	if len(s.notMembers) == 0 {
		return false
	}
	has := func(v string, ok bool) bool {
		if !ok {
			return false
		}
		for _, n := range s.notMembers {
			if n == v {
				return true
			}
		}
		return false
	}
	if last := s.toks[len(s.toks)-1]; last.op("[") || last.op("(") {
		return has(litArg(t, end-1)) // req.headers['host'], @Headers('host')
	}
	if end+1 < len(t) && (t[end].op(".") || t[end].op("?.")) && t[end+1].Kind == Ident {
		if t[end+1].Text == "get" && end+2 < len(t) && t[end+2].op("(") {
			return has(litArg(t, end+2)) // request.headers.get('host')
		}
		return has(strings.ToLower(t[end+1].Text), true) // req.headers.host
	}
	return end < len(t) && t[end].op("[") && has(litArg(t, end)) // req.headers['host']
}

// sourceNot: after h = req.headers or h = @Headers(), the members route_not
// leaves out of that source are not input under h either, whether the source
// is the rule's own or a route handler's parameter.
func (a *analysis) sourceNot(st state, tg, rhs []Token, op string) {
	if op != "=" {
		return
	}
	rhs = stripParens(rhs)
	key, _, ok := a.pathKey(tg)
	if !ok || len(rhs) == 0 {
		return
	}
	for _, s := range a.r.sources {
		if len(s.notMembers) == 0 {
			continue
		}
		end, ok := s.match(rhs, 0, false)
		if !ok {
			continue
		}
		if last := s.toks[len(s.toks)-1]; last.op("(") {
			if closeOf(rhs, end-1) != len(rhs)-1 {
				continue
			}
			if _, lit := litArg(rhs, end-1); lit {
				continue // @Headers('x-name'): one header, not the object
			}
		} else if last.op("[") || end != len(rhs) {
			continue
		}
		for _, n := range s.notMembers {
			st[key+sepCh+"."+n], st[key+sepCh+"["+n+"]"] = entry{}, entry{}
		}
	}
	// h = req.headers inside a route: the members route_not leaves out of the
	// route's req.headers are not input under h either.
	if rk, _, ok := a.pathKey(rhs); ok {
		for _, rn := range a.r.rule.RouteNot {
			mem, n, _ := strings.Cut(rn, ".")
			if e, had := st[rk+sepCh+"."+n]; had && !e.taint && strings.EqualFold(lastName(rhs), mem) {
				st[key+sepCh+"."+n], st[key+sepCh+"["+n+"]"] = entry{}, entry{}
			}
		}
		// ...and those route_only takes from it are input under h too
		for _, ro := range a.r.rule.RouteOnly {
			mem, n, _ := strings.Cut(ro, ".")
			if e, had := st[rk+sepCh+"."+n]; had && e.taint && strings.EqualFold(lastName(rhs), mem) {
				st[key+sepCh+"."+n], st[key+sepCh+"["+n+"]"] = e, e
			}
		}
	}
	// NestJS's @Req() r is a route handler's request whatever it is called:
	// the TypeScript lowering writes r.headers = @Req() (lex_typescript.go), so
	// route_not leaves those members out under it and route_only takes them.
	if nestReq(rhs) {
		tn := lastName(tg)
		for _, rn := range a.r.rule.RouteNot {
			if mem, n, _ := strings.Cut(rn, "."); strings.EqualFold(tn, mem) {
				st[key+sepCh+"."+n], st[key+sepCh+"["+n+"]"] = entry{}, entry{}
			}
		}
		for _, ro := range a.r.rule.RouteOnly {
			if mem, n, _ := strings.Cut(ro, "."); strings.EqualFold(tn, mem) && !a.noSrc {
				e := entry{taint: !a.nonced(st), raw: true}
				st[key+sepCh+"."+n], st[key+sepCh+"["+n+"]"] = e, e
			}
		}
	}
	a.sourceOnly(st, key, rhs)
}

// nestReq reports whether t is NestJS's @Req() or @Request(), whole.
func nestReq(t []Token) bool {
	return len(t) >= 3 && t[0].Kind == Ident && (t[0].Text == "@Req" || t[0].Text == "@Request") &&
		t[1].op("(") && closeOf(t, 1) == len(t)-1
}

// lastName is the last identifier of a path (req.headers: headers).
func lastName(t []Token) string {
	for k := len(t) - 1; k >= 0; k-- {
		if t[k].Kind == Ident {
			return t[k].Text
		}
	}
	return ""
}

// sourceOnly: a source read by name, whose source_args take only some names
// (req.headers[ or @Headers( with "host" and "x-forwarded-host"), makes those
// members input when the whole object is assigned: after h = req.headers or
// h = @Headers(), h.host and h['host'] are input, h.referer is not.
func (a *analysis) sourceOnly(st state, key string, rhs []Token) {
	if a.noSrc || nestReq(rhs) {
		return // NestJS's @Req(): the request, whose headers route_only names (sourceNot)
	}
	for _, s := range a.r.sources {
		n := len(s.toks)
		if s.srcArg != 1 || len(s.srcVals) == 0 || n < 2 || s.srcVals["*"] || s.srcVals["?"] {
			continue
		}
		whole := false
		switch last := s.toks[n-1]; {
		case last.op("["):
			whole = len(rhs) == n-1
		case last.op("("):
			whole = len(rhs) == n+1 && rhs[n].op(")")
		}
		for k := 0; whole && k < n-1; k++ {
			whole = tokEq(s.toks[k], rhs[k])
		}
		if !whole {
			continue
		}
		for v := range s.srcVals {
			if strings.HasPrefix(v, "!") {
				continue
			}
			e := entry{taint: !a.nonced(st), raw: true}
			st[key+sepCh+"["+v+"]"] = e
			if !strings.Contains(v, "-") {
				st[key+sepCh+"."+v] = e
			}
		}
	}
}
