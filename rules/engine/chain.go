package engine

// A PHP facade is often called through a chain: Process::timeout(30)->run($cmd),
// Process::path($dir)->run($cmd). A sink written as a static call (Process::run()
// is matched there too: for each sink "Class::method(" the rule also has
// "->method(", which matches only at the end of a chain that starts at Class::.

// chainSinks makes the chain form of a rule's static-call sinks, with the same
// argument conditions.
func (c *crule) chainSinks() {
	if c.rule.Lang != "php" {
		return
	}
	for _, s := range c.sinks {
		t := s.toks
		if len(t) != 4 || t[0].Kind != Ident || !t[1].op("::") || t[2].Kind != Ident || !t[3].op("(") || s.chain != "" {
			continue
		}
		m := &pat{raw: "->" + t[2].Text + "(", php: true, member: true, name: t[2].Text, chain: t[0].Text,
			toks: []Token{{Kind: Op, Text: "->"}, t[2], t[3]}}
		c.sinks = append(c.sinks, m)
		if cond, ok := c.args[s]; ok {
			c.args[m] = cond
		}
	}
}

// chainFrom reports whether the "->" at toks[i] ends a chain of calls that starts
// at cls:: (cls::a(...)->b(...)->).
func chainFrom(toks []Token, i int, cls string) bool {
	j := i - 1
	for steps := 0; j >= 1 && steps < 32; steps++ {
		if !toks[j].op(")") {
			return false
		}
		open := openOf(toks, j)
		if open < 2 || toks[open-1].Kind != Ident {
			return false
		}
		j = open - 2 // before the method's name
		switch {
		case toks[j].op("::"):
			return j >= 1 && toks[j-1].word(cls)
		case toks[j].op("->"):
			j--
		default:
			return false
		}
	}
	return false
}
