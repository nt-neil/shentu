package engine

import (
	"fmt"
	"slices"
	"testing"
	"time"
)

// What the index and the per-file call graph record does not depend on the
// order Go ranges over a map: each of these is worked out many times over
// and must come out the same every time.

const mapOrderRuns = 50

func phpTree(t *testing.T, src string) []*stmt {
	t.Helper()
	b := newBudget(Limits{MaxTokens: DefaultLimits.MaxTokens, MaxTime: 10 * time.Second})
	return parse("php", lex("php", src, b), b)
}

// Two classes of one file with the same name in different namespaces share
// one entry for their parent and traits (names are kept without their
// namespace). The entry is always the same one.
func TestFileFuncsSameShortClassFixed(t *testing.T) {
	src := "<?php\nnamespace A;\nclass User extends Base { use LogsA; function foo() { return 1; } }\n" +
		"namespace B;\nclass User extends Other { use LogsB; function bar() { return 2; } }\n"
	tree := phpTree(t, src)
	run := func() string {
		ff := newFileFuncs(collectFuncs(tree, "php"), "php")
		return fmt.Sprint(ff.parents, ff.traits)
	}
	want := run()
	for i := range mapOrderRuns {
		if got := run(); got != want {
			t.Fatalf("run %d: %s, first run %s", i+2, got, want)
		}
	}
}

// A class declared twice in one file (in the two branches of an if) is
// indexed with the parent of the same declaration every time.
func TestIndexClassDeclaredTwiceFixed(t *testing.T) {
	e := engineForTest(t)
	src := []byte("<?php\nif (PHP_VERSION_ID >= 80000) {\n\tclass Cache extends NewStore { function get($k) { return 1; } }\n" +
		"} else {\n\tclass Cache extends OldStore { function fetch($k) { return 2; } }\n}\n")
	run := func() string { return fmt.Sprintf("%+v", indexFile(e, "php", src).Classes) }
	want := run()
	for i := range mapOrderRuns {
		if got := run(); got != want {
			t.Fatalf("run %d: %s, first run %s", i+2, got, want)
		}
	}
}

// PSR-4 prefixes are tried longest first, as Composer does, whichever order
// composer.json lists them in: App\Http\Kernel is the file under the
// App\Http\ directory, not the one under App\'s.
func TestPSR4LongestPrefixFirst(t *testing.T) {
	e := engineForTest(t)
	for _, composer := range []string{
		`{"autoload": {"psr-4": {"App\\": "app/", "App\\Http\\": "http/"}}}`,
		`{"autoload": {"psr-4": {"App\\Http\\": "http/", "App\\": "app/"}}}`,
	} {
		files := map[string]string{
			"composer.json":       composer,
			"app/Http/Kernel.php": "<?php\nnamespace App\\Http;\nclass Kernel { function handle() { return 1; } }\n",
			"http/Kernel.php":     "<?php\nnamespace App\\Http;\nclass Kernel { function handle() { return 2; } }\n",
			"app/Models/User.php": "<?php\nnamespace App\\Models;\nclass User { function name() { return 3; } }\n",
		}
		paths := []string{"app/Http/Kernel.php", "app/Models/User.php", "composer.json", "http/Kernel.php"}
		read := func(p string) ([]byte, error) { return []byte(files[p]), nil }
		for i := range mapOrderRuns {
			pr := e.NewProject(paths, read, ProjectOptions{})
			if got := pr.psr4Path(`App\Http\Kernel`); got != "http/Kernel.php" {
				t.Fatalf("%s, run %d: App\\Http\\Kernel is %q, want http/Kernel.php", composer, i+1, got)
			}
			if got := pr.psr4Path(`App\Models\User`); got != "app/Models/User.php" { // the shorter prefix still serves what the longer one lacks
				t.Fatalf("%s, run %d: App\\Models\\User is %q, want app/Models/User.php", composer, i+1, got)
			}
		}
	}
}

// A route handler given as [$obj, 'name'] stands for the method of that name
// in every class of the file declaring one, in the same order every time
// (routeSites keeps the first ones when a file has too many).
func TestHandlerMethodsFixedOrder(t *testing.T) {
	var src string
	for i := range 6 {
		src += fmt.Sprintf("class C%d { function handle() { return %d; } }\n", i, i)
	}
	src = "<?php\n" + src + "add_action('init', [$x, 'handle']);\n"
	tree := phpTree(t, src)
	ff := newFileFuncs(collectFuncs(tree, "php"), "php")
	var h []Token
	b := newBudget(Limits{MaxTokens: DefaultLimits.MaxTokens, MaxTime: 10 * time.Second})
	toks := lex("php", "<?php [$x, 'handle'];", b)
	for i, tk := range toks {
		if tk.op("[") {
			h = toks[i : len(toks)-1]
			break
		}
	}
	run := func() []string {
		var out []string
		for _, f := range handlerFuncs(true, &stmt{}, h, ff) {
			out = append(out, f.class)
		}
		return out
	}
	want := run()
	if len(want) != 6 {
		t.Fatalf("handler [$x, 'handle'] stands for %v, want the 6 classes' methods", want)
	}
	for i := range mapOrderRuns {
		if got := run(); !slices.Equal(got, want) {
			t.Fatalf("run %d: %v, first run %v", i+2, got, want)
		}
	}
}
