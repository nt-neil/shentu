package engine

import (
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
