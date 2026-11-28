package engine

import (
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/nt-neil/shentu/rules"
)

// handleEngine is an engine with one rule: request input written to a socket
// with fwrite or fputs, the handle made by fsockopen or stream_socket_client.
func handleEngine(t *testing.T) *Engine {
	t.Helper()
	one, two := 1, 2
	e, err := New([]rules.Rule{{
		ID: "php-test-socket-write", Lang: "php", Class: "cmdi", Severity: "high", Title: "t",
		Sources: []string{"$_GET"}, Sinks: []string{"fwrite(", "fputs("},
		Args: []rules.Args{{Arg: &two, Handle: one, Receiver: []string{"fsockopen(", "stream_socket_client("}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestHandleCondition(t *testing.T) {
	e := handleEngine(t)
	for _, c := range []struct {
		name, src string
		want      bool
	}{
		{"socket", "<?php\n$fp = fsockopen($host, 80);\nfwrite($fp, \"GET /\" . $_GET['p'] . \" HTTP/1.0\\r\\n\");\n", true},
		{"socket in parentheses", "<?php\n$fp = @fsockopen($host, 80);\nfputs(($fp), $_GET['p']);\n", true},
		{"through another name", "<?php\n$sock = stream_socket_client($url);\n$fp = $sock;\nfwrite($fp, $_GET['p']);\n", true},
		{"property", "<?php\nclass C {\n  function connect() { $this->fp = stream_socket_client($this->url); }\n  function put() { fputs($this->fp, $_GET['p'] . \"\\r\\n\"); }\n}\n", true},
		{"file", "<?php\n$fp = fopen('log.txt', 'a');\nfwrite($fp, $_GET['p']);\n", false},
		{"stdout", "<?php\n$out = fopen('php://stdout', 'w');\nfwrite($out, $_GET['p']);\nfwrite(STDOUT, $_GET['p']);\n", false},
		{"parameter of unknown origin", "<?php\nfunction put($fp) {\n  fwrite($fp, $_GET['p']);\n}\n", false},
		{"socket, input as the handle only", "<?php\n$fp = fsockopen($_GET['h'], 80);\nfwrite($fp, 'PING');\n", false},
		// another function's $fp of the same name (review H1)
		{"another function's socket", "<?php\nfunction a() {\n  $fp = fopen('log.txt', 'a');\n  fwrite($fp, $_GET['p']);\n}\nfunction b() {\n  $fp = fsockopen($host, 80);\n  fwrite($fp, 'PING');\n}\n", false},
		// the nearest assignment before the sink counts (review H3)
		{"reopened as a file", "<?php\n$fp = fsockopen($host, 80);\nfclose($fp);\n$fp = fopen('f.txt', 'w');\nfwrite($fp, $_GET['p']);\n", false},
		{"a file, then a socket", "<?php\n$fp = fopen('f.txt', 'w');\nfclose($fp);\n$fp = fsockopen($host, 80);\nfwrite($fp, $_GET['p']);\n", true},
		{"in place", "<?php\nfwrite(fsockopen($host, 80), $_GET['p']);\n", true},
		// a property reassigned in the same method: the nearest assignment decides, not the file's table (S-295-4)
		{"a property reopened as a file in the method", "<?php\nclass C {\n  function put() {\n    $this->fp = fsockopen($h, 80);\n    fclose($this->fp);\n    $this->fp = fopen('f.txt', 'w');\n    fwrite($this->fp, $_GET['p']);\n  }\n}\n", false},
		{"a property set to a file here, a socket in another method", "<?php\nclass C {\n  function connect() { $this->fp = fsockopen($h, 80); }\n  function log() {\n    $this->fp = fopen('f.txt', 'w');\n    fwrite($this->fp, $_GET['p']);\n  }\n}\n", false},
		// an assignment on one branch only does not hide the property table from the other path
		{"a property set to a file on one branch only", "<?php\nclass C {\n  function connect() { $this->fp = fsockopen($h, 80); }\n  function put($log) {\n    if ($log) {\n      $this->fp = fopen('f.txt', 'w');\n    }\n    fwrite($this->fp, $_GET['p']);\n  }\n}\n", true},
		{"a socket on one branch", "<?php\nif ($remote) {\n  $fp = fsockopen($h, 80);\n} else {\n  $fp = fopen('f.txt', 'w');\n}\nfwrite($fp, $_GET['p']);\n", true},
		{"a compound assignment keeps the socket", "<?php\nclass C {\n  function connect() { $this->fp = fsockopen($h, 80); }\n  function put() {\n    $this->fp .= '';\n    fwrite($this->fp, $_GET['p']);\n  }\n}\n", true},
		// known over-report: list() gives every target the whole right side
		{"list() over-reports", "<?php\n[$a, $fp] = [$x, fsockopen($h, 80)];\nfwrite($a, $_GET['p']);\n", true},
		{"through a ternary", "<?php\n$fp = $ssl ? stream_socket_client($u) : fsockopen($h, 80);\nfwrite($fp, $_GET['p']);\n", true},
		{"a chained assignment", "<?php\n$a = $fp = fsockopen($h, 80);\nfwrite($a, $_GET['p']);\n", true},
		// known limits: not followed, so not reported
		{"a method's return value", "<?php\nclass C {\n  function open() { return fsockopen($this->h, 80); }\n  function put() { $this->fp = $this->open(); fputs($this->fp, $_GET['p']); }\n}\n", false},
		{"a static property in the same method", "<?php\nclass C {\n  static $conn;\n  function put() { self::$conn = fsockopen($h, 80); fputs(self::$conn, $_GET['p']); }\n}\n", true},
		{"a static property set in another method", "<?php\nclass C {\n  static $conn;\n  function open() { self::$conn = fsockopen($h, 80); }\n  function put() { fputs(self::$conn, $_GET['p']); }\n}\n", false},
	} {
		fs, err := e.Scan("php", "a.php", []byte(c.src))
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
		}
		if got := len(fs) > 0; got != c.want {
			t.Errorf("%s: reported %v, want %v (%v)", c.name, got, c.want, fs)
		}
	}
}

// A handle kept in a property set in another method of a class in another
// file: the calls across files follow the input there and read that file's
// assignments.
func TestHandleConditionAcrossFiles(t *testing.T) {
	e := handleEngine(t)
	files := map[string]string{
		"a.php": "<?php\nfunction show() {\n    $c = new Client();\n    $c->connect();\n    $c->send($_GET['uid']);\n}\n",
		"b.php": "<?php\nclass Client {\n    public $fp;\n    function connect() {\n        $this->fp = stream_socket_client('tcp://mail:143');\n    }\n    function send($uid) {\n        fputs($this->fp, \"A1 UID FETCH $uid (BODY)\\r\\n\");\n    }\n}\n",
	}
	pr := e.NewProject([]string{"a.php", "b.php"}, func(p string) ([]byte, error) { return []byte(files[p]), nil }, ProjectOptions{})
	part, err := pr.ScanCallsPart("a.php", []byte(files["a.php"]), nil)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range part.Found {
		if f.Path == "b.php" && f.Line == 8 {
			found = true
		}
	}
	if !found {
		t.Errorf("the write to the socket in b.php is not reported: %v", part.Found)
	}
}

func TestHandleNeedsReceiver(t *testing.T) {
	two := 2
	if _, err := New([]rules.Rule{{ID: "x", Lang: "php", Class: "cmdi", Severity: "high", Title: "t", Sources: []string{"$_GET"}, Sinks: []string{"fwrite("},
		Args: []rules.Args{{Arg: &two, Handle: 1}}}}); err == nil {
		t.Error("handle without receiver: accepted")
	}
}

// N-295-1: the handle condition costs nothing without a rule that has one, and
// a file of very many assignments (a crafted 1 MiB file) is read within a
// bound: no token is copied, and past maxHandleProps the table is given up.
func TestHandleCost(t *testing.T) {
	var b strings.Builder
	b.WriteString("<?php\nclass C { function f() {\n")
	for b.Len() < 1<<20 {
		b.WriteString("$this->a=$this->a=$this->a=$this->a=1;\n")
	}
	b.WriteString("} }\n")
	toks := lex("php", b.String(), newBudget(Limits{}))

	rs, err := rules.Load()
	if err != nil {
		t.Fatal(err)
	}
	var none []rules.Rule // the shipped rules but those with a handle condition
	for _, r := range rs {
		if !slices.ContainsFunc(r.Args, func(a rules.Args) bool { return a.Handle > 0 }) {
			none = append(none, r)
		}
	}
	plain, err := New(none)
	if err != nil {
		t.Fatal(err)
	}
	if h := plain.fileHandleProps("php", toks); h != nil {
		t.Errorf("no handle rule: a property table was built")
	}
	if allocs := testing.AllocsPerRun(3, func() { plain.fileHandleProps("php", toks) }); allocs != 0 {
		t.Errorf("no handle rule: %v allocations", allocs)
	}

	e := handleEngine(t)
	var h *handleProps
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	h = e.fileHandleProps("php", toks)
	runtime.ReadMemStats(&after)
	if h == nil || !h.cut {
		t.Fatalf("past %d property assignments the table is not given up: %+v", maxHandleProps, h)
	}
	if got := after.TotalAlloc - before.TotalAlloc; got > 1<<20 {
		t.Errorf("reading the property table allocated %d bytes, want under 1 MiB", got)
	}
}

// A handle read from a file whose property table was given up is not known:
// not reported, and the scan says so (handle-table).
func TestHandleTableCut(t *testing.T) {
	var b strings.Builder
	b.WriteString("<?php\nclass C {\n  function f() {\n")
	for i := 0; i <= maxHandleProps; i++ {
		b.WriteString("    $this->x = 1;\n")
	}
	b.WriteString("  }\n  function connect() { $this->fp = fsockopen($h, 80); }\n  function put() { fputs($this->fp, $_GET['p']); }\n}\n")
	fs, err := handleEngine(t).Scan("php", "a.php", []byte(b.String()))
	if len(fs) != 0 {
		t.Errorf("reported %v", fs)
	}
	if CutOf(err)&CutHandles == 0 {
		t.Errorf("cut %q (%v), want handle-table", CutOf(err), err)
	}
}
