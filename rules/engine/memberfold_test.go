package engine

import (
	"slices"
	"strconv"
	"testing"
)

// TestPHPMemberNamesAnyCase: the method and class names of member patterns
// with no "(" ($wpdb->query, DB::raw, Rule::in) match in any case, as PHP
// calls them, in sinks and in sanitizers. A variable keeps its case, as PHP's
// do. On the code audit's path.
func TestPHPMemberNamesAnyCase(t *testing.T) {
	e := engineForTest(t)
	for _, c := range []struct {
		name, rule, src string
		want            []string // lines
	}{
		{"$wpdb->Query(", "php-sqli-wpdb-unprepared", "<?php\n$wpdb->Query(\"DELETE FROM t WHERE id = \" . $_GET['id']);\n", []string{"2"}},
		{"$wpdb->GET_RESULTS(", "php-sqli-wpdb-unprepared", "<?php\n$rows = $wpdb->GET_RESULTS(\"SELECT * FROM t WHERE id = \" . $_GET['id']);\n", []string{"2"}},
		{"$wpdb->Prepare( cleans", "php-sqli-wpdb-unprepared", "<?php\n$wpdb->query($wpdb->Prepare(\"DELETE FROM t WHERE id = %d\", $_GET['id']));\n", nil},
		{"lower case still reports (control)", "php-sqli-wpdb-unprepared", "<?php\n$wpdb->query(\"DELETE FROM t WHERE id = \" . $_GET['id']);\n", []string{"2"}},
		{"$WPDB is another variable (control)", "php-sqli-wpdb-unprepared", "<?php\n$WPDB->query(\"DELETE FROM t WHERE id = \" . $_GET['id']);\n", nil},
		{"db::RAW( and DB::Raw(", "php-sqli-orderby-identifier", "<?php\nuse Illuminate\\Support\\Facades\\DB;\n$a = db::RAW($_GET['s']);\n$b = DB::Raw($_GET['t']);\n", []string{"3", "4"}},
		{"$this->DB is not $this->db: its escape( cleans nothing", "php-sqli-codeigniter-query", "<?php\nclass M extends CI_Model {\n    function f() {\n        return $this->db->simple_query(\"SELECT * FROM t WHERE id = \" . $this->DB->escape($_GET['id']));\n    }\n}\n", []string{"4"}},
		{"$this->DB->simple_query( is not $this->db's (control)", "php-sqli-codeigniter-query", "<?php\nclass M extends CI_Model {\n    function f() {\n        return $this->DB->simple_query(\"SELECT * FROM t WHERE id = \" . $_GET['id']);\n    }\n}\n", nil},
		{"$this->db->escape( cleans (control)", "php-sqli-codeigniter-query", "<?php\nclass M extends CI_Model {\n    function f() {\n        return $this->db->simple_query(\"SELECT * FROM t WHERE id = \" . $this->db->escape($_GET['id']));\n    }\n}\n", nil},
		{"DB::raw( (control)", "php-sqli-orderby-identifier", "<?php\nuse Illuminate\\Support\\Facades\\DB;\n$a = DB::raw($_GET['s']);\n", []string{"3"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			pr := e.NewProject([]string{"a.php"}, func(string) ([]byte, error) { return []byte(c.src), nil }, ProjectOptions{})
			var got []string
			for _, f := range auditPath(t, e, pr, "a.php", []byte(c.src)) {
				if f.RuleID == c.rule {
					got = append(got, strconv.Itoa(f.Line))
				}
			}
			slices.Sort(got)
			if !slices.Equal(got, c.want) {
				t.Errorf("%s lines %v, want %v", c.rule, got, c.want)
			}
		})
	}
}
