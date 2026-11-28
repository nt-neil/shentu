package hostenv

import (
	"context"
	"strings"
	"testing"
	"time"
)

// N-286-4: a command line known as its arguments is masked argument by
// argument, so a ; | & in a password is the password's. Product path: the
// parsers of /proc's cmdline, ps's args and a Windows process's command line.
func TestMaskArgvSemicolonInPassword(t *testing.T) {
	dl := "cu" + "rl"
	s := fakeSecret()
	cases := []struct {
		argv []string
		want string
	}{
		{[]string{"mysql", "-u", "root", "-pab;" + s, "db"}, "mysql -u root -p[REDACTED] db"},
		{[]string{"mysql", "-u", "root", "-pab|" + s}, "mysql -u root -p[REDACTED]"},
		{[]string{"tool", "--password", "ab&" + s}, "tool --password [REDACTED]"},
		{[]string{"tool", "--password=ab;" + s}, "tool --password=[REDACTED]"},
		{[]string{dl, "-u", "bob:ab;" + s, "https://x.example.test"}, dl + " -u bob:[REDACTED] https://x.example.test"},
		{[]string{dl, "-ubob:ab&" + s}, dl + " -u" + "bob:[REDACTED]"},
		{[]string{"/usr/bin/mysqldump", "-pab;" + s, "--all"}, "/usr/bin/mysqldump -p[REDACTED] --all"},
		// not secrets: a daemon's -port=, -p before the program, a bare -p,
		// --password then an option
		{[]string{"/usr/sbin/mysqld", "--user=mysql", "-port=3306"}, "/usr/sbin/mysqld --user=mysql -port=3306"},
		{[]string{"docker", "run", "-p", "8080:80", "mysql"}, "docker run -p 8080:80 mysql"},
		{[]string{"mysql", "-p", "shop"}, "mysql -p shop"},
		{[]string{"tool", "--password", "--next"}, "tool --password --next"},
		// the security review: a program after a shell's ; ( $( in one
		// argument (ps joins sh -c's line with spaces)
		{[]string{"sh", "-c", "x;mysql", "-pab;" + s}, "sh -c x;mysql -p[REDACTED]"},
		{[]string{"sh", "-c", "$(mysql", "-p" + s + ")"}, "sh -c $(mysql -p[REDACTED]"},
		// S-286-10: a user's name is no program
		{[]string{"psql", "-U", "mysql", "-p5432"}, "psql -U mysql -p5432"},
		{[]string{"tool", "--user", "mysql", "-p5432"}, "tool --user mysql -p5432"},
	}
	for _, c := range cases {
		if got := ParseCmdline([]byte(strings.Join(c.argv, "\x00") + "\x00")); got != c.want {
			t.Errorf("/proc %q = %q, want %q", c.argv, got, c.want)
		}
		ps := "  11 1 501 alice 01:00 /bin/x\n"
		src := fakeMac{cmds: map[string]string{key(macPsArgv): ps, key(macPsArgsArgv): "  11 " + strings.Join(c.argv, " ") + "\n"}}
		if o := (DarwinCollector{}).Processes(context.Background(), src, time.Now()); len(o.Value) != 1 || o.Value[0].Cmdline != c.want {
			t.Errorf("ps %q = %+v, want %q", c.argv, o.Value, c.want)
		}
		if got := capCmdline(strings.Join(c.argv, " ")); got != c.want {
			t.Errorf("windows %q = %q, want %q", c.argv, got, c.want)
		}
	}
	// A Windows command line keeps its quotes; a quoted path is one argument.
	win := `"C:\Program Files\MySQL\bin\mysql.exe" -u root -pab;` + s + ` db`
	if got := capCmdline(win); got != `"C:\Program Files\MySQL\bin\mysql.exe" -u root -p[REDACTED] db` {
		t.Errorf("windows quoted path: %q", got)
	}
	// S-286-9: \\ before a quote is a backslash: the quote ends there.
	if got := capCmdline(`"C:\dir\\" mysql.exe -p` + s); got != `"C:\dir\\" mysql.exe -p[REDACTED]` {
		t.Errorf("windows \\\\ before a quote: %q", got)
	}
	// Text that is not argv (a log line, a shell's history) keeps the line
	// rules: a command ends at an unquoted ; there.
	if got := MaskSecrets("mysql -pab" + s + ";rm -rf /tmp/x"); got != "mysql -p[REDACTED];rm -rf /tmp/x" {
		t.Errorf("text: %q", got)
	}
}

func TestSplitWinCmdline(t *testing.T) {
	got := SplitWinCmdline(`"C:\a b\x.exe"  -p"c d" e\"f g` + "\t" + `h "C:\dir\\" i a\\\"b c`)
	want := []string{`"C:\a b\x.exe"`, `-p"c d"`, `e\"f`, `g`, `h`, `"C:\dir\\"`, `i`, `a\\\"b`, `c`}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("%q", got)
	}
}

// The joined argv's pass leaves out exactly the four text rules of a
// command's own password (mysql -p, --password, curl's two).
func TestArgvTextRules(t *testing.T) {
	n := 0
	for _, r := range secretRules {
		if argvTextRule(r.re.String()) {
			n++
		}
	}
	if n != 4 {
		t.Errorf("%d argv text rules, want 4", n)
	}
}
