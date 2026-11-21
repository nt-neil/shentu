package engine

import (
	"fmt"
	"slices"
	"testing"
)

// yields_to leaves a finding out only where the rule it yields to reports
// the same line through the same sink call (yields.go): another sink on that
// line, or another line, still reports.
func TestYieldsTo(t *testing.T) {
	e := engineForTest(t)
	cases := []struct {
		name, src string
		want      []string // line:rule
	}{
		// php-sqli-orderby-identifier yields to php-sqli-laravel-raw
		{"DB::raw inside DB::select: laravel-raw's", "<?php\n$rows = DB::select(DB::raw(\"SELECT * FROM t WHERE id = \" . $_GET['id']));\n",
			[]string{"2:php-sqli-laravel-raw"}},
		{"DB::raw in orderBy: orderby-identifier's", "<?php\n$rows = $q->orderBy(DB::raw($_GET['o']))->get();\n",
			[]string{"2:php-sqli-orderby-identifier"}},
		{"ORDER BY in DB::select(DB::raw()): orderby-identifier's", "<?php\n$rows = DB::select(DB::raw(\"SELECT * FROM t ORDER BY \" . $_GET['o']));\n",
			[]string{"2:php-sqli-orderby-identifier"}},
		{"same line, another sink: both stay", "<?php\n$a = DB::select(\"SELECT * FROM t WHERE a = \" . $_GET['a']); $b = $q->orderBy(DB::raw($_GET['o']))->get();\n",
			[]string{"2:php-sqli-laravel-raw", "2:php-sqli-orderby-identifier"}},
		{"another line: both stay", "<?php\n$a = DB::select(\"SELECT * FROM t WHERE a = \" . $_GET['a']);\n$b = $q->orderBy(DB::raw($_GET['o']))->get();\n",
			[]string{"2:php-sqli-laravel-raw", "3:php-sqli-orderby-identifier"}},
		// php-sqli-drupal-db-query and php-sqli-codeigniter-query yield to php-sqli-yii-query
		{"->where( with $_GET: yii-query's", "<?php\n$rows = $query->where(\"id = \" . $_GET['id'])->all();\n",
			[]string{"2:php-sqli-yii-query"}},
		{"->orWhere( with $_GET: yii-query's", "<?php\n$rows = $query->orWhere(\"id = \" . $_GET['id'])->all();\n",
			[]string{"2:php-sqli-yii-query"}},
		{"Symfony's own input stays doctrine's", "<?php\n$qb->where(\"u.id = \" . $request->attributes->get('id'));\n",
			[]string{"2:php-sqli-doctrine-query-text"}},
		{"Symfony's query input, Drupal's too: doctrine's", "<?php\n$qb->where(\"u.id = \" . $request->query->get('id'));\n",
			[]string{"2:php-sqli-doctrine-query-text"}},
		{"Symfony's query input and Drupal's own on one line: each its own", "<?php\n$qb->where(\"u.id = \" . $request->query->get('id'))->where('b = ' . $form_state->getValue('b'));\n",
			[]string{"2:php-sqli-doctrine-query-text", "2:php-sqli-drupal-db-query"}},
		{"Joomla's own input stays its", "<?php\n$query->where('a = ' . $input->getString('a'));\n",
			[]string{"2:php-sqli-joomla-query"}},
		{"CodeIgniter's own input stays its", "<?php\n$this->db->where(\"id = \" . $this->input->get('id'));\n",
			[]string{"2:php-sqli-codeigniter-query"}},
		{"Drupal's own input stays its", "<?php\n$query->where('nid = ' . $form_state->getValue('nid'));\n",
			[]string{"2:php-sqli-drupal-db-query"}},
		{"same line, two ->where( calls: each its own", "<?php\n$query->where(\"a = \" . $_GET['a'])->where('b = ' . $form_state->getValue('b'));\n",
			[]string{"2:php-sqli-drupal-db-query", "2:php-sqli-yii-query"}},
		{"$_GET in ->where( on another line than Drupal's input", "<?php\n$query->where(\"a = \" . $_GET['a']);\n$query->where('b = ' . $form_state->getValue('b'));\n",
			[]string{"2:php-sqli-yii-query", "3:php-sqli-drupal-db-query"}},
	}
	for _, c := range cases {
		fs, err := e.Scan("php", "a.php", []byte(c.src))
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, f := range fs {
			if k := fmt.Sprintf("%d:%s", f.Line, f.RuleID); f.CWE == "CWE-89" && !slices.Contains(got, k) {
				got = append(got, k)
			}
		}
		slices.Sort(got)
		if !slices.Equal(got, c.want) {
			t.Errorf("%s: reported %v, want %v", c.name, got, c.want)
		}
	}
}

// yields is the decision alone: every call the rule reported the line through
// must be held by, or hold, a call of a rule it yields to that reports it.
func TestYieldsSpans(t *testing.T) {
	l := loc{"a.php", 2}
	in, out, other := "\x01a\x01", "\x01b\x01a\x01c\x01", "\x01z\x01"
	f := Finding{RuleID: "y", Path: "a.php", Line: 2}
	cases := []struct {
		name     string
		own, won []string
		reported bool
		want     bool
	}{
		{"held by the other's call", []string{in}, []string{out}, true, true},
		{"holds the other's call", []string{out}, []string{in}, true, true},
		{"another call", []string{in}, []string{other}, true, false},
		{"one of two calls is another", []string{in, other}, []string{out}, true, false},
		{"a call not written out", []string{in, ""}, []string{out}, true, false},
		{"the other rule does not report the line", []string{in}, []string{out}, false, false},
		{"no call recorded", nil, []string{out}, true, false},
	}
	for _, c := range cases {
		spans := map[string]map[loc][]string{"y": {l: c.own}, "w": {l: c.won}}
		if got := yields(f, []string{"w"}, spans, func(string) bool { return c.reported }); got != c.want {
			t.Errorf("%s: yields %v, want %v", c.name, got, c.want)
		}
	}
}

// A rule the second pass runs (a call can change its result) makes the rules
// it yields to run there too, so a call both report stays the one it is
// left to although no call changes that rule (v053 integ review S-1). Here
// col() returns get_query_var('o'), php-sqli-orderby-identifier's input
// only: before, orderby-identifier ran alone in the second pass and found no
// laravel-raw finding to leave DB::raw inside DB::select to.
func TestYieldsSecondPass(t *testing.T) {
	e := engineForTest(t)
	// no ORDER BY in the text: orderby-identifier's text sink would be another
	// sink, which yields_to never leaves (yields.go)
	src := "<?php\nfunction col() {\n    return get_query_var('o');\n}\n$rows = DB::select(DB::raw(\"SELECT * FROM t WHERE a = \" . $_GET['a'] . \" AND b = \" . col()));\n"
	plain := "<?php\n$rows = DB::select(DB::raw(\"SELECT * FROM t WHERE a = \" . $_GET['a']));\n"
	for _, c := range []struct {
		name, src string
		want      []string
	}{
		{"a call only orderby-identifier follows: laravel-raw's", src, []string{"5:php-sqli-laravel-raw"}},
		{"no call (control)", plain, []string{"2:php-sqli-laravel-raw"}},
	} {
		pr := e.NewProject([]string{"a.php"}, func(string) ([]byte, error) { return []byte(c.src), nil }, ProjectOptions{})
		var got []string
		for _, f := range auditPath(t, e, pr, "a.php", []byte(c.src)) {
			if f.CWE == "CWE-89" {
				got = append(got, fmt.Sprintf("%d:%s", f.Line, f.RuleID))
			}
		}
		slices.Sort(got)
		if !slices.Equal(got, c.want) {
			t.Errorf("%s: reported %v, want %v", c.name, got, c.want)
		}
		fs, err := e.Scan("php", "a.php", []byte(c.src))
		if err != nil {
			t.Fatal(err)
		}
		got = nil
		for _, f := range fs {
			if f.CWE == "CWE-89" {
				got = append(got, fmt.Sprintf("%d:%s", f.Line, f.RuleID))
			}
		}
		slices.Sort(got)
		if !slices.Equal(got, c.want) {
			t.Errorf("%s, Engine.Scan: reported %v, want %v", c.name, got, c.want)
		}
	}
}
