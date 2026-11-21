package engine

import (
	"slices"
	"testing"
)

// A class a use statement aliases is read as the class itself where code names
// a class (phpAliases): Req:: of use Illuminate\Support\Facades\Request as Req
// is Request::, and S:: of use App\Services\Sorter as S calls Sorter. An alias
// of another library's Request stays no source (phpUseOther), and PHP keywords
// ignore case (AS). On the code audit's path.
func TestPHPUseAliases(t *testing.T) {
	e := engineForTest(t)
	cls := func(use, body string) string {
		return "<?php\n" + use + "\nclass C {\n    public function run($q) {\n" + body + "\n    }\n}\n"
	}
	for _, c := range []struct {
		name  string
		files map[string]string
		want  []string
	}{
		{"the Request facade by an alias is a source", map[string]string{"a.php": cls(`use Illuminate\Support\Facades\Request as Req;`,
			"        return $q->orderBy(Req::get('sort'))->get();")}, []string{"a.php:5:php-sqli-orderby-identifier"}},
		{"USE ... AS: keywords ignore case", map[string]string{"a.php": cls(`USE Illuminate\Support\Facades\Request AS Req;`,
			"        return $q->orderBy(Req::get('sort'))->get();")}, []string{"a.php:5:php-sqli-orderby-identifier"}},
		{"Httpful's Request by an alias stays no source", map[string]string{"a.php": cls(`use Httpful\Request as R;`,
			"        $sort = R::get('https://api.example.org/sort')->send()->body;\n        return $q->orderBy($sort)->get();")}, nil},
		{"use Httpful\\Http AS Request: Request:: is no facade (#160 review S-1)", map[string]string{"a.php": cls(`use Httpful\Http AS Request;`,
			"        $sort = Request::get('https://api.example.org/sort')->send()->body;\n        return $q->orderBy($sort)->get();")}, nil},
		{"no use statement: Request:: is the facade's alias (control)", map[string]string{"a.php": cls(``,
			"        return $q->orderBy(Request::get('sort'))->get();")}, []string{"a.php:5:php-sqli-orderby-identifier"}},
		{"a class called by its own name in another file (control)", map[string]string{
			"app/Http/Controllers/PostController.php": "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Services\\Sorter;\nclass PostController {\n    public function index($q) {\n        return Sorter::by($q, $_GET['o']);\n    }\n}\n",
			"app/Services/Sorter.php":                 "<?php\nnamespace App\\Services;\nclass Sorter {\n    public static function by($q, $col) {\n        return $q->orderBy($col)->get();\n    }\n}\n",
		}, []string{"app/Http/Controllers/PostController.php:5:php-sqli-orderby-identifier"}},
		{"a class called by its alias in another file", map[string]string{
			"app/Http/Controllers/PostController.php": "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Services\\Sorter as S;\nclass PostController {\n    public function index($q) {\n        return S::by($q, $_GET['o']);\n    }\n}\n",
			"app/Services/Sorter.php":                 "<?php\nnamespace App\\Services;\nclass Sorter {\n    public static function by($q, $col) {\n        return $q->orderBy($col)->get();\n    }\n}\n",
		}, []string{"app/Http/Controllers/PostController.php:5:php-sqli-orderby-identifier"}},
	} {
		var paths []string
		for p := range c.files {
			paths = append(paths, p)
		}
		slices.Sort(paths)
		pr := e.NewProject(paths, func(p string) ([]byte, error) { return []byte(c.files[p]), nil }, ProjectOptions{})
		var got []string
		for _, p := range paths {
			for _, f := range auditPath(t, e, pr, p, []byte(c.files[p])) {
				if f.CWE == "CWE-89" {
					got = append(got, p+":"+itoa(f.Line)+":"+f.RuleID)
				}
			}
		}
		slices.Sort(got)
		got = slices.Compact(got)
		if !slices.Equal(got, c.want) {
			t.Errorf("%s: reported %v, want %v", c.name, got, c.want)
		}
	}
}
