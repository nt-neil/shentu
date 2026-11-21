package engine

import (
	"slices"
	"strconv"
	"strings"
	"testing"
)

// Each SQL injection line is reported by the one rule that owns it, and by
// one at least: an ORDER BY identifier is php-sqli-orderby-identifier's
// (unless_after in php-sqli-wpdb-unprepared, php-sqli-prepare-query-text,
// php-sqli-string-concat and php-sqli-laravel-raw), $wpdb's queries php-sqli-wpdb-unprepared's (not_receiver
// $wpdb in php-sqli-string-concat), SQL text into sequelize.query()
// js-sqli-raw-interpolation's, a Sequelize.literal() js-sqli-sequelize-literal's,
// text() python-sqli-sqlalchemy-text's, SQL text into execute()
// python-sqli-dbapi-format's.
func TestSQLiOwner(t *testing.T) {
	e := engineForTest(t)
	cases := []struct {
		name, lang, src string
		want            []string
	}{
		{"wpdb ORDER BY interpolated", "php", "<?php\n$col = $_GET['orderby'];\n$rows = $wpdb->get_results(\"SELECT * FROM {$wpdb->posts} ORDER BY $col\");\n",
			[]string{"php-sqli-orderby-identifier"}},
		{"wpdb ORDER BY concatenated", "php", "<?php\n$rows = $wpdb->get_results(\"SELECT * FROM t ORDER BY \" . $_GET['orderby']);\n",
			[]string{"php-sqli-orderby-identifier"}},
		{"wpdb ORDER BY from get_query_var", "php", "<?php\n$o = get_query_var('o');\n$rows = $wpdb->get_results(\"SELECT * FROM t ORDER BY $o\");\n",
			[]string{"php-sqli-orderby-identifier"}},
		{"wpdb input before ORDER BY", "php", "<?php\n$id = $_GET['id'];\n$col = $_GET['orderby'];\n$rows = $wpdb->get_results(\"SELECT * FROM t WHERE id = $id ORDER BY $col\");\n",
			[]string{"php-sqli-orderby-identifier", "php-sqli-wpdb-unprepared"}},
		{"wpdb WHERE only", "php", "<?php\n$id = $_GET['id'];\n$rows = $wpdb->get_results(\"SELECT * FROM t WHERE id = $id\");\n",
			[]string{"php-sqli-wpdb-unprepared"}},
		{"wpdb query concatenated", "php", "<?php\n$wpdb->query(\"DELETE FROM t WHERE id IN (\" . implode(',', $_POST['ids']) . \")\");\n",
			[]string{"php-sqli-wpdb-unprepared"}},
		{"wpdb query from a cookie", "php", "<?php\n$wpdb->query(\"DELETE FROM t WHERE k = '\" . $_COOKIE['k'] . \"'\");\n",
			[]string{"php-sqli-wpdb-unprepared"}},
		{"another db's query", "php", "<?php\n$db->query(\"DELETE FROM t WHERE id = \" . $_GET['id']);\n",
			[]string{"php-sqli-string-concat"}},
		{"db ORDER BY concatenated", "php", "<?php\n$db->query(\"SELECT * FROM t ORDER BY \" . $_GET['o']);\n",
			[]string{"php-sqli-orderby-identifier"}},
		{"db ORDER BY interpolated", "php", "<?php\n$col = $_GET['o'];\n$db->query(\"SELECT * FROM t ORDER BY $col\");\n",
			[]string{"php-sqli-orderby-identifier"}},
		{"mysqli ORDER BY", "php", "<?php\nmysqli_query($c, \"SELECT * FROM t ORDER BY \" . $_GET['o']);\n",
			[]string{"php-sqli-orderby-identifier"}},
		{"pg_query ORDER BY", "php", "<?php\npg_query($c, \"SELECT * FROM t ORDER BY \" . $_GET['o']);\n",
			[]string{"php-sqli-orderby-identifier"}},
		{"CodeIgniter ORDER BY", "php", "<?php\nclass C extends CI_Controller { function i() { $this->db->query(\"SELECT * FROM t ORDER BY \" . $this->input->get('o')); } }\n",
			[]string{"php-sqli-orderby-identifier"}},
		{"db input before ORDER BY", "php", "<?php\n$db->query(\"SELECT * FROM t WHERE id = \" . $_GET['id'] . \" ORDER BY \" . $_GET['o']);\n",
			[]string{"php-sqli-orderby-identifier", "php-sqli-string-concat"}},
		{"db ORDER BY string in parentheses", "php", "<?php\n$db->query((\"SELECT * FROM t ORDER BY \") . $_GET['c']);\n",
			[]string{"php-sqli-string-concat"}},
		{"mysqli ORDER BY string in parentheses", "php", "<?php\nmysqli_query($c, (\"SELECT * FROM t ORDER BY \") . $_GET['c']);\n",
			[]string{"php-sqli-string-concat"}},
		{"laravel ORDER BY string in parentheses", "php", "<?php\nclass C { function i(Request $request) { return DB::select((\"SELECT * FROM t ORDER BY \") . $request->input('o')); } }\n",
			[]string{"php-sqli-laravel-raw"}},
		{"laravel ORDER BY", "php", "<?php\nclass C { function i(Request $request) { return DB::select(\"SELECT * FROM t ORDER BY \" . $request->input('o')); } }\n",
			[]string{"php-sqli-orderby-identifier"}},
		{"laravel ORDER BY in DB::raw", "php", "<?php\nclass C { function i(Request $request) { return DB::select(DB::raw(\"SELECT * FROM t ORDER BY \" . $request->query('o'))); } }\n",
			[]string{"php-sqli-orderby-identifier"}},
		{"laravel ORDER BY from Request::input", "php", "<?php\nclass C { function i() { return DB::select(\"SELECT * FROM t ORDER BY \" . Request::input('o')); } }\n",
			[]string{"php-sqli-orderby-identifier"}},
		{"laravel input before ORDER BY", "php", "<?php\nclass C { function i(Request $request) { return DB::select(\"SELECT * FROM t WHERE r = '\" . $request->input('r') . \"' ORDER BY \" . $request->input('o')); } }\n",
			[]string{"php-sqli-laravel-raw", "php-sqli-orderby-identifier"}},
		{"laravel WHERE only", "php", "<?php\nclass C { function i(Request $request) { return DB::select(\"SELECT * FROM t WHERE r = '\" . $request->all()['r'] . \"'\"); } }\n",
			[]string{"php-sqli-laravel-raw"}},
		{"prepare ORDER BY in the format", "php", "<?php\n$col = $_GET['sort'];\n$rows = $wpdb->get_results($wpdb->prepare(\"SELECT * FROM t ORDER BY $col LIMIT %d\", 10));\n",
			[]string{"php-sqli-orderby-identifier"}},
		{"prepare WHERE in the format", "php", "<?php\n$id = $_GET['id'];\n$rows = $wpdb->get_results($wpdb->prepare(\"SELECT * FROM t WHERE id = $id LIMIT %d\", 10));\n",
			[]string{"php-sqli-prepare-query-text"}},
		{"sequelize.query", "js", "router.get('/p', async (req, res) => {\n  const t = req.query.tag;\n  res.json(await sequelize.query(`SELECT * FROM items WHERE tag = '${t}'`));\n});\n",
			[]string{"js-sqli-raw-interpolation"}},
		{"Sequelize.literal in a where", "js", "router.get('/p', async (req, res) => {\n  const b = req.query.before;\n  res.json(await Message.findAll({ where: Sequelize.where(Sequelize.literal(`d < '${b}'`), true) }));\n});\n",
			[]string{"js-sqli-sequelize-literal"}},
		{"an object from the query in a where", "js", "router.get('/p', async (req, res) => {\n  res.json(await Message.findAll({ where: req.query.filter }));\n});\n",
			[]string{"js-sqli-object-input"}},
		{"execute(f-string)", "python", "@app.route('/u')\ndef u():\n    name = request.args.get('name', '')\n    cur = db.cursor()\n    cur.execute(f\"SELECT id FROM users WHERE name = '{name}'\")\n    return jsonify(cur.fetchall())\n",
			[]string{"python-sqli-dbapi-format"}},
		{"execute(text(f-string))", "python", "@app.get('/s')\ndef s():\n    col = request.args.get('column', 'price')\n    row = db.session.execute(text(f\"SELECT max({col}) FROM orders\")).scalar()\n    return {'max': row}\n",
			[]string{"python-sqli-sqlalchemy-text"}},
		{"Laravel magic property $request->sort into orderBy (a3)", "php", "<?php\nclass C extends Controller {\n    public function index(Request $request) {\n        return Post::query()->orderBy($request->sort)->get();\n    }\n}\n",
			[]string{"php-sqli-orderby-identifier"}},
		{"Laravel $request->user()->name is a method's result, no input (a3 control)", "php", "<?php\nclass C extends Controller {\n    public function index(Request $request) {\n        return Post::query()->orderBy($request->user()->name)->get();\n    }\n}\n",
			nil},
		{"Symfony bag $request->query->get('s') stays its own source (a3 control)", "php", "<?php\nclass C extends Controller {\n    public function index(Request $request) {\n        return Post::query()->orderBy($request->query->get('s'))->get();\n    }\n}\n",
			[]string{"php-sqli-orderby-identifier"}},
		{"Laravel $request->sort checked with in_array (a3 control)", "php", "<?php\nclass C extends Controller {\n    public function index(Request $request) {\n        $s = in_array($request->sort, ['a', 'b'], true) ? $request->sort : 'a'; return Post::query()->orderBy($s)->get();\n    }\n}\n",
			nil},
		{"Laravel ->when($request->query('sort'), fn ($q, $s) => $q->orderBy($s)) (a3)", "php", "<?php\nclass C extends Controller {\n    public function index(Request $request) {\n        return Post::query()->when($request->query('sort'), fn ($q, $s) => $q->orderBy($s))->get();\n    }\n}\n",
			[]string{"php-sqli-orderby-identifier"}},
		{"Laravel ->when with a function ($q, $sort) body (a3)", "php", "<?php\nclass C extends Controller {\n    public function index(Request $request) {\n        return Post::query()->when($request->input('sort'), function ($q, $sort) { return $q->orderBy($sort); })->get();\n    }\n}\n",
			[]string{"php-sqli-orderby-identifier"}},
		{"Laravel ->when with a fixed value (a3 control)", "php", "<?php\nclass C extends Controller {\n    public function index(Request $request) {\n        return Post::query()->when('created_at', fn ($q, $s) => $q->orderBy($s))->get();\n    }\n}\n",
			nil},
		{"Laravel ->when with an allowlisted value, as orderBy($s) itself (a3 control)", "php", "<?php\nclass C extends Controller {\n    public function index(Request $request) {\n        $s = in_array($request->sort, ['a', 'b'], true) ? $request->sort : null; return Post::query()->when($s, fn ($q, $v) => $q->orderBy($v))->get();\n    }\n}\n",
			nil},
		{"Laravel ->when, the closure's first parameter is the query (a3 control)", "php", "<?php\nclass C extends Controller {\n    public function index(Request $request) {\n        return Post::query()->when($request->query('sort'), fn ($q, $s) => $q->orderBy('created_at'))->get();\n    }\n}\n",
			nil},
		{"a DTO that happens to be called $request, no Laravel (v053 r1 S-1)", "php", "<?php\nclass Search {\n    public function run() {\n        $request = new SearchRequest('created_at');\n        return $this->db->table('t')->orderBy($request->column)->get();\n    }\n}\n",
			nil},
		{"Laravel: use Illuminate, $request->sort (v053 r1 S-1 control)", "php", "<?php\nuse Illuminate\\Support\\Facades\\DB;\nfunction run($request) {\n    return DB::table('t')->orderBy($request->sort)->get();\n}\n",
			[]string{"php-sqli-orderby-identifier"}},
		{"Laravel: a FormRequest parameter, $request->sort (v053 r1 S-1 control)", "php", "<?php\nclass C extends Controller {\n    public function index(IndexPostRequest $request) {\n        return Post::query()->orderBy($request->sort)->get();\n    }\n}\n",
			[]string{"php-sqli-orderby-identifier"}},
		{"Laravel: a class extending Controller, an untyped $request (security review)", "php", "<?php\nclass C extends Controller {\n    public function index($request) {\n        return Post::query()->orderBy($request->sort)->get();\n    }\n}\n",
			[]string{"php-sqli-orderby-identifier"}},
		{"Httpful's Request::get is an HTTP client, no request input (b4, PR B S-2)", "php", "<?php\nuse Httpful\\Request;\nclass C {\n    public function run($q) {\n        $sort = Request::get('https://api.example.org/sort')->send()->body;\n        return $q->orderBy($sort)->get();\n    }\n}\n",
			nil},
		{"Laravel's Request facade imported (b4 control)", "php", "<?php\nuse Illuminate\\Support\\Facades\\Request;\nclass C {\n    public function run($q) {\n        return $q->orderBy(Request::get('sort'))->get();\n    }\n}\n",
			[]string{"php-sqli-orderby-identifier"}},
		{"Request facade by its alias, no use (b4 control)", "php", "<?php\nclass C {\n    public function run($q) {\n        return $q->orderBy(Request::get('sort'))->get();\n    }\n}\n",
			[]string{"php-sqli-orderby-identifier"}},
		{"Django input in text()", "python", "def s(request):\n    col = request.GET.get('column')\n    row = db.session.execute(text(f\"SELECT max({col}) FROM orders\")).scalar()\n    return JsonResponse({'max': row})\n",
			[]string{"python-sqli-sqlalchemy-text"}},
	}
	for _, c := range cases {
		fs, err := e.Scan(c.lang, "a."+map[string]string{"php": "php", "js": "js", "python": "py"}[c.lang], []byte(c.src))
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, f := range fs {
			if f.CWE == "CWE-89" && !slices.Contains(got, f.RuleID) {
				got = append(got, f.RuleID)
			}
		}
		slices.Sort(got)
		if !slices.Equal(got, c.want) {
			t.Errorf("%s: SQL injection reported by %v, want %v", c.name, got, c.want)
		}
	}
}

// A call over several lines is reported where the ORDER BY identifier is
// written, the string's line, not the call's first line.
func TestOrderByLine(t *testing.T) {
	e := engineForTest(t)
	src := "<?php\n$col = $_GET['orderby'];\n$rows = $wpdb->get_results(\n    \"SELECT * FROM t ORDER BY $col\"\n);\n"
	fs, err := e.Scan("php", "a.php", []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	var lines []int
	for _, f := range fs {
		if f.CWE == "CWE-89" {
			if f.RuleID != "php-sqli-orderby-identifier" {
				t.Errorf("reported by %s", f.RuleID)
			}
			lines = append(lines, f.Line)
		}
	}
	if !slices.Equal(lines, []int{4}) {
		t.Errorf("reported at lines %v, want [4]", lines)
	}
}

// In a Laravel project (some file uses a class of Illuminate), a service's
// untyped $request parameter is the request a controller passed on; a typed
// one is that type (v053 r2 S-2). Scanned as the code audit scans a project
// (tools/codeaudit.go: ScanTimed, then ScanCallsPart), not with Project.Scan.
func TestLaravelProjectService(t *testing.T) {
	e := engineForTest(t)
	ctl := "<?php\nnamespace App\\Http\\Controllers;\nuse Illuminate\\Http\\Request;\nuse App\\Services\\Sorter;\nclass PostController extends Controller {\n    public function index(Request $request, Sorter $sorter) {\n        return $sorter->apply(Post::query(), $request);\n    }\n}\n"
	plain := "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Services\\Sorter;\nclass PostController {\n    public function index($input, Sorter $sorter) {\n        return $sorter->apply(Post::query(), $input);\n    }\n}\n"
	svc := "<?php\nnamespace App\\Services;\nclass Sorter {\n    public function apply($q, $request) {\n        return $q->orderBy($request->sort)->get();\n    }\n}\n"
	typed := "<?php\nnamespace App\\Services;\nclass Sorter {\n    public function apply($q, SearchQuery $request) {\n        return $q->orderBy($request->column)->get();\n    }\n}\n"
	groupUse := strings.Replace(ctl, "use Illuminate\\Http\\Request;", "use Illuminate\\{Http\\Request, Support\\Facades\\DB};", 1)
	lower := strings.Replace(ctl, "use Illuminate\\Http\\Request;", "use illuminate\\http\\Request;", 1)
	byRef := strings.Replace(svc, "apply($q, $request)", "apply($q, &$request)", 1)
	refFn := strings.Replace(svc, "public function apply(", "public function &apply(", 1)
	for _, c := range []struct {
		name, ctl, svc string
		want           []string
	}{
		{"a Laravel project: the service's untyped $request", ctl, svc, []string{"php-sqli-orderby-identifier"}},
		{"no file uses Illuminate (control)", plain, svc, nil},
		{"a Laravel project: a typed DTO parameter (control)", ctl, typed, nil},
		{"a group use of Illuminate (security review)", groupUse, svc, []string{"php-sqli-orderby-identifier"}},
		{"Illuminate written in lower case (security review)", lower, svc, []string{"php-sqli-orderby-identifier"}},
		{"a by-reference $request parameter (security review)", ctl, byRef, []string{"php-sqli-orderby-identifier"}},
		{"a method returning by reference (security review)", ctl, refFn, []string{"php-sqli-orderby-identifier"}},
	} {
		files := map[string]string{"app/Http/Controllers/PostController.php": c.ctl, "app/Services/Sorter.php": c.svc}
		read := func(p string) ([]byte, error) { return []byte(files[p]), nil }
		pr := e.NewProject([]string{"app/Http/Controllers/PostController.php", "app/Services/Sorter.php"}, read, ProjectOptions{})
		fs := auditPath(t, e, pr, "app/Services/Sorter.php", []byte(c.svc))
		var got []string
		for _, f := range fs {
			if f.CWE == "CWE-89" && !slices.Contains(got, f.RuleID) {
				got = append(got, f.RuleID)
			}
		}
		if !slices.Equal(got, c.want) {
			t.Errorf("%s: reported by %v, want %v", c.name, got, c.want)
		}
	}
}

// In a Laravel project the second pass runs php-sqli-orderby-identifier for
// an untyped $request, and with it the rules it yields to, so that one call
// two rules report stays one rule's there too (v053 r4 N-1): DB::raw inside
// DB::select is php-sqli-laravel-raw's, as in v043c's c-dbraw-in-select.
func TestLaravelProjectYields(t *testing.T) {
	e := engineForTest(t)
	ctl := "<?php\nnamespace App\\Http\\Controllers;\nuse Illuminate\\Http\\Request;\nclass PostController extends Controller {\n    public function index(Request $request) {\n        return view('p');\n    }\n}\n"
	plain := "<?php\nclass PostController {\n    public function index($input) {\n        return $input;\n    }\n}\n"
	q := "<?php\n$rows = DB::select(DB::raw(\"SELECT * FROM t WHERE id = \" . $_GET['id']));\n"
	svc := "<?php\nnamespace App\\Services;\nclass Sorter {\n    public function apply($q, $request) {\n        return $q->orderBy($request->sort)->get();\n    }\n}\n"
	for _, c := range []struct {
		name, ctl, path, src string
		want                 []string
	}{
		{"a Laravel project: DB::raw inside DB::select is laravel-raw's", ctl, "q.php", q, []string{"2:php-sqli-laravel-raw"}},
		{"no Laravel project: the same (control)", plain, "q.php", q, []string{"2:php-sqli-laravel-raw"}},
		{"a Laravel project: the service's untyped $request still reported", ctl, "app/Services/Sorter.php", svc, []string{"5:php-sqli-orderby-identifier"}},
	} {
		files := map[string]string{"app/Http/Controllers/PostController.php": c.ctl, c.path: c.src}
		read := func(p string) ([]byte, error) { return []byte(files[p]), nil }
		pr := e.NewProject([]string{"app/Http/Controllers/PostController.php", c.path}, read, ProjectOptions{})
		var got []string
		for _, f := range auditPath(t, e, pr, c.path, []byte(c.src)) {
			if f.CWE == "CWE-89" {
				got = append(got, strconv.Itoa(f.Line)+":"+f.RuleID)
			}
		}
		slices.Sort(got)
		if !slices.Equal(got, c.want) {
			t.Errorf("%s: reported %v, want %v", c.name, got, c.want)
		}
	}
}

// auditPath scans a file of a project as tools/codeaudit.go does: the file on
// its own (Engine.ScanTimed), then what the project adds (Project.ScanCallsPart),
// one finding per rule, file and line.
func auditPath(t *testing.T, e *Engine, pr *Project, path string, src []byte) []Finding {
	t.Helper()
	own, _, err := e.ScanTimed(LangOf(path), path, src)
	if err != nil {
		t.Fatal(err)
	}
	part, err := pr.ScanCallsPart(path, src, nil)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	var out []Finding
	for _, f := range append(own, part.Found...) {
		if k := f.RuleID + "\x00" + f.Path + "\x00" + strconv.Itoa(f.Line); !seen[k] {
			seen[k] = true
			out = append(out, f)
		}
	}
	return out
}
