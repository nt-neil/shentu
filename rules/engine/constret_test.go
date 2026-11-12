package engine

import (
	"testing"

	"github.com/nt-neil/shentu/rules"
)

// A helper returning a string constant instead of its argument is followed:
// what it returns is clean (the Python lane's rd3: self.safe_next() in a base
// class returning '/'). One returning its argument, or a string holding it,
// still passes the input on.
func TestConstantReturnHelpers(t *testing.T) {
	one := 1
	e, err := New([]rules.Rule{{ID: "redirect", Lang: "python", Class: "open-redirect", CWE: "CWE-601", Severity: "medium", Title: "t",
		Sources: []string{"self.get_argument("}, Sinks: []string{"self.redirect("}, Sanitizers: []string{},
		Args: []rules.Args{{Arg: &one, Leading: true}}}})
	if err != nil {
		t.Fatal(err)
	}
	handler := "class Login(BaseHandler):\n    def get(self):\n        self.redirect(self.safe_next(self.get_argument('next', '/')))\n"
	base := func(body string) string {
		return "import tornado.web\nclass BaseHandler(tornado.web.RequestHandler):\n    def safe_next(self, url):\n" + body + "\n" + handler
	}
	for _, c := range []struct {
		name, src string
		want      bool
	}{
		{"rd3: a base class's helper returning '/'", base("        return '/'\n"), false},
		{"a plain function returning '/'", "def safe_next(url):\n    return '/'\nclass Login(RequestHandler):\n    def get(self):\n        self.redirect(safe_next(self.get_argument('n')))\n", false},
		{"assigned first", "class Login(RequestHandler):\n    def safe_next(self, url):\n        return '/'\n    def get(self):\n        n = self.safe_next(self.get_argument('n'))\n        self.redirect(n)\n", false},
		{"returning its argument", base("        return url\n"), true},
		{"returning a string holding it", base("        return '/' + url\n"), true},
		{"a constant on one path, the argument on another", base("        if url == 'x':\n            return '/'\n        return url\n"), true},
	} {
		fs, err := e.ScanFile("a.py", []byte(c.src))
		if err != nil || (len(fs) > 0) != c.want {
			t.Errorf("%s: %v (err %v), want reported %v", c.name, fs, err, c.want)
		}
	}
}
