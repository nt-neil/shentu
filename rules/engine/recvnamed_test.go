package engine

import (
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/nt-neil/shentu/rules"
)

// A method sink of a rule with receivers is the project's own method when the
// project never names the library, declares a method of that name, and was
// indexed to its end (Project.ownMethodOnly, v0.5.8 v058-array-fp-cheap B-2):
// newsletters' $Db->find() on its SQL helper is no MongoDB query. Any mention
// of the library, in code, a string, composer.json, composer.lock or a
// vendor/ path, a project declaring no such method, or a file not read to its
// end keeps it reported.
func TestReceiversOwnMethod(t *testing.T) {
	const rule = "php-nosqli-mongo-query"
	hooks := "<?php\nrequire 'model.php';\nadd_action('wp_ajax_nopriv_bounce', function () {\n  bounce($_POST['email']);\n});\n"
	model := "<?php\nfunction bounce($email) {\n  global $Db;\n  return $Db->find(array('email' => $email));\n}\n"
	helper := "<?php\nclass DbHelper {\n  function find($conditions = array()) {\n    global $wpdb;\n    return $wpdb->get_row(\"SELECT * FROM t WHERE email = '\" . esc_sql($conditions['email']) . \"'\");\n  }\n}\n"
	noFind := "<?php\nclass DbHelper {\n  function get($conditions = array()) {\n    return null;\n  }\n}\n"
	big := "<?php\n" + strings.Repeat("$x = 1;\n", 400)
	for _, c := range []struct {
		name   string
		extra  map[string]string // more files; "" content: the file cannot be read
		helper string
		small  bool // an engine whose token limit big.php exceeds
		want   bool
	}{
		{"the project's own find(), no MongoDB anywhere", nil, helper, false, false},
		{"no class of the project declares find()", nil, noFind, false, true},
		{"another file uses MongoDB\\Client", map[string]string{"m.php": "<?php\nuse MongoDB\\Client;\n$c = new Client();\n"}, helper, false, true},
		{"a string names MongoDB\\Client", map[string]string{"m.php": "<?php\n$cls = 'MongoDB\\\\Client';\n"}, helper, false, true},
		{"new MongoClient() elsewhere", map[string]string{"m.php": "<?php\n$m = new MongoClient();\n"}, helper, false, true},
		{"class_alias of a MongoDB class", map[string]string{"m.php": "<?php\nclass_alias('MongoDB\\\\Collection', 'Coll');\n"}, helper, false, true},
		{"composer.json requires mongodb/mongodb, the code never names it", map[string]string{"composer.json": `{"require": {"mongodb/mongodb": "^1.15"}}`}, helper, false, true},
		{"composer.json requires ext-mongodb", map[string]string{"composer.json": `{"require": {"ext-mongodb": "*"}}`}, helper, false, true},
		{"composer.lock holds mongodb/mongodb", map[string]string{"composer.lock": `{"packages": [{"name": "mongodb/mongodb"}]}`}, helper, false, true},
		{"a vendor/ path of mongodb/mongodb", map[string]string{"vendor/mongodb/mongodb/README.md": "MongoDB PHP library"}, helper, false, true},
		{"composer.json of other packages only", map[string]string{"composer.json": `{"require": {"guzzlehttp/guzzle": "^7"}}`}, helper, false, false},
		{"Mongolia in a string is not MongoDB", map[string]string{"m.php": "<?php\n$c = 'Mongolia';\n"}, helper, false, false},
		{"a method named mongo() is not the library", map[string]string{"m.php": "<?php\n$x->mongo();\n"}, helper, false, false},
		{"a file that cannot be read", map[string]string{"gone.php": ""}, helper, false, true},
		{"a file too big to index to its end", map[string]string{"big.php": big}, helper, true, true},
		{"the same token limit, no file over it", nil, helper, true, false},
		{"composer.json that cannot be parsed", map[string]string{"composer.json": `{"require": `}, helper, false, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := engineForTest(t)
			if c.small {
				rs, err := rules.Load()
				if err != nil {
					t.Fatal(err)
				}
				if e, err = New(rs); err != nil {
					t.Fatal(err)
				}
				e.Limits.MaxTokens = 1000
			}
			files := map[string]string{"hooks.php": hooks, "model.php": model, "db.php": c.helper}
			paths := []string{"hooks.php", "model.php", "db.php"}
			for p, b := range c.extra {
				files[p] = b
				paths = append(paths, p)
			}
			read := func(p string) ([]byte, error) {
				if files[p] == "" {
					return nil, errors.New("unreadable")
				}
				return []byte(files[p]), nil
			}
			pr := e.NewProject(paths, read, ProjectOptions{})
			got := false
			var all []string
			for _, p := range []string{"hooks.php", "model.php", "db.php"} {
				for _, f := range taintOnly(auditPath(t, e, pr, p, []byte(files[p]))) {
					at := f.Path + ":" + strconv.Itoa(f.Line)
					all = append(all, at+" "+f.RuleID)
					got = got || at == "model.php:4" && f.RuleID == rule
				}
			}
			if got != c.want {
				t.Errorf("%s at model.php:4: %v, want %v; all: %v", rule, got, c.want, all)
			}
		})
	}
}

// The same for a framework SQL rule (wp-recall's RQ::tbl(...)->where(...)),
// and its framework's names: a CodeIgniter model keeps $this->db->where()
// reported, as does a call of get_instance().
func TestReceiversFrameworkSQL(t *testing.T) {
	const rule = "php-sqli-codeigniter-query"
	hooks := "<?php\nrequire 'forum.php';\nadd_action('wp_ajax_topic', function () {\n  add_topic($_POST['slug']);\n});\n"
	forum := "<?php\nfunction add_topic($slug) {\n  return RQ::tbl(new Topics())->select(['id'])->where(\"slug = '\" . $slug . \"'\")->get_var();\n}\n"
	query := "<?php\nclass Rcl_Query {\n  function select($cols) {\n    return $this;\n  }\n  function where($w) {\n    $this->w = $w;\n    return $this;\n  }\n}\n"
	for _, c := range []struct {
		name  string
		extra map[string]string
		want  bool
	}{
		{"the project's own where(), no CodeIgniter anywhere", nil, false},
		{"a class extends CI_Model elsewhere", map[string]string{"m.php": "<?php\nclass Topics_model extends CI_Model {\n}\n"}, true},
		{"get_instance() elsewhere", map[string]string{"m.php": "<?php\n$CI =& get_instance();\n"}, true},
		{"a get_instance() method is not CodeIgniter's", map[string]string{"m.php": "<?php\nclass S {\n  static function i() {\n    return self::get_instance();\n  }\n}\n"}, false},
		{"composer.lock holds codeigniter4/framework", map[string]string{"composer.lock": `{"packages": [{"name": "codeigniter4/framework"}]}`}, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := engineForTest(t)
			files := map[string]string{"hooks.php": hooks, "forum.php": forum, "q.php": query}
			paths := []string{"hooks.php", "forum.php", "q.php"}
			for p, b := range c.extra {
				files[p] = b
				paths = append(paths, p)
			}
			pr := e.NewProject(paths, func(p string) ([]byte, error) { return []byte(files[p]), nil }, ProjectOptions{})
			got := false
			var all []string
			for _, p := range []string{"hooks.php", "forum.php", "q.php"} {
				for _, f := range taintOnly(auditPath(t, e, pr, p, []byte(files[p]))) {
					at := f.Path + ":" + strconv.Itoa(f.Line)
					all = append(all, at+" "+f.RuleID)
					got = got || at == "forum.php:3" && f.RuleID == rule
				}
			}
			if got != c.want {
				t.Errorf("%s at forum.php:3: %v, want %v; all: %v", rule, got, c.want, all)
			}
		})
	}
}
