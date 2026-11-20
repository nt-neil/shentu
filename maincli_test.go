package main

import (
	"bytes"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// usageCmdRe finds "shentu <command>" (or "sudo shentu <command>") at the
// start of a usage line.
var usageCmdRe = regexp.MustCompile(`(?m)^\s*(?:sudo )?shentu ([a-z][a-z-]*)`)

// mainCommands are the commands main.go's main handles: the cases of its
// switch on cmd and the commands it compares cmd with.
func mainCommands(t *testing.T) map[string]bool {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), "main.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "main" {
			continue
		}
		isCmd := func(e ast.Expr) bool { id, ok := e.(*ast.Ident); return ok && id.Name == "cmd" }
		lit := func(e ast.Expr) {
			if bl, ok := e.(*ast.BasicLit); ok && bl.Kind == token.STRING {
				s, _ := strconv.Unquote(bl.Value)
				out[s] = true
			}
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.SwitchStmt:
				if isCmd(x.Tag) {
					for _, c := range x.Body.List {
						for _, e := range c.(*ast.CaseClause).List {
							lit(e)
						}
					}
				}
			case *ast.BinaryExpr:
				if x.Op == token.EQL && isCmd(x.X) {
					lit(x.Y)
				}
			}
			return true
		})
	}
	delete(out, "help")
	delete(out, "--help")
	delete(out, "-h")
	return out
}

// B-CL1: every command main handles gets past the check before the
// config, and the check lets nothing else through.
func TestCommandsKnown(t *testing.T) {
	handled := mainCommands(t)
	if !handled["dispatch"] || !handled["chat"] {
		t.Fatalf("main's commands were not found: %v", handled)
	}
	for c := range handled {
		if !knownCommand(c) {
			t.Errorf("main handles %q but refuses it before the config", c)
		}
	}
	for _, c := range commands {
		if !handled[c] {
			t.Errorf("%q is let through but main does not handle it", c)
		}
	}
}

// B-CL1: the built binary, as an operator runs it.
func TestCLIBinary(t *testing.T) {
	if testing.Short() || runtime.GOOS == "windows" {
		t.Skip("builds the binary")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "shentu")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	state := filepath.Join(dir, "state")
	cfgPath := filepath.Join(dir, "shentu.toml")
	os.WriteFile(cfgPath, []byte("state_dir = "+strconv.Quote(state)+"\n"), 0o600)
	run := func(args ...string) (int, string) {
		cmd := exec.Command(bin, args...)
		cmd.Env = append(os.Environ(), "SHENTU_CONFIG="+cfgPath)
		var out bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &out
		err := cmd.Run()
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode(), out.String()
		}
		if err != nil {
			t.Fatal(err)
		}
		return 0, out.String()
	}
	root := os.Geteuid() == 0
	if code, out := run("dispatch", "stats"); root && code != 0 || !root && (code != 1 || !strings.Contains(out, "sudo shentu dispatch stats")) {
		t.Errorf("dispatch stats: exit %d\n%s", code, out)
	}
	if code, out := run("dispatch", "repair"); root && code != 0 || !root && (code != 1 || !strings.Contains(out, "sudo shentu dispatch repair")) {
		t.Errorf("dispatch repair: exit %d\n%s", code, out)
	}
	if code, out := run("dispatch", "wipe"); code != 1 || !strings.Contains(out, "usage: shentu dispatch") {
		t.Errorf("dispatch wipe: exit %d\n%s", code, out)
	}
	// S-CLI-1: every command the usage names, read from the binary's own
	// help, gets past the check, however main tells it apart.
	_, help := run("help")
	named := map[string]bool{}
	for _, m := range usageCmdRe.FindAllStringSubmatch(help+usage, -1) {
		named[m[1]] = true
	}
	if !named["dispatch"] || !named["chat"] || len(named) < 10 {
		t.Fatalf("commands in the usage: %v", named)
	}
	for c := range named {
		if !knownCommand(c) {
			t.Errorf("the usage names %q but the check before the config refuses it", c)
		}
	}
	if code, out := run("dispatchx"); code != 2 {
		t.Errorf("an unknown command: exit %d\n%s", code, out)
	}
	// The light ones of the other commands get past the check (exit 2 is
	// the usage of a command the check refused); chat, patrol, survey,
	// setup and service do real work and are covered by TestCommandsKnown.
	for _, args := range [][]string{{"version"}, {"usage"}, {"budget"}, {"bot", "status"}, {"detect", "--since", "1h", "--json"}, {"log-trust", "suggest"}} {
		if code, out := run(args...); code == 2 && strings.Contains(out, "Usage:") {
			t.Errorf("%v was refused before the config:\n%s", args, out)
		}
	}
}

// N-CL1: stats asks for root first, as repair does; as root it reports.
func TestDispatchStatsCommandRoot(t *testing.T) {
	s := testStore(t)
	cfg := &Config{StateDir: filepath.Dir(s.dir)}
	if err := dispatchCommand(cfg, []string{"stats"}, false); err == nil || !strings.Contains(err.Error(), adminHint("shentu dispatch stats")) {
		t.Errorf("not root: %v", err)
	}
	if err := dispatchCommand(cfg, []string{"stats", "--days", "3"}, true); err != nil {
		t.Errorf("root: %v", err)
	}
}

// The Windows acceptance: a user who is not elevated got the configuration
// refused (the state folder denied) instead of the hint. dispatch stats and
// repair say it before the configuration is read, the same on every
// platform; here the configuration cannot be read at all.
func TestCLIDispatchHintBeforeConfig(t *testing.T) {
	if testing.Short() || runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("builds the binary; needs a user who is not root")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "shentu")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	bad := filepath.Join(dir, "shentu.toml") // a configuration that cannot be read, as the state folder could not be on Windows
	os.WriteFile(bad, []byte("state_dir = [\n"), 0o600)
	for _, sub := range []string{"stats", "repair"} {
		cmd := exec.Command(bin, "dispatch", sub)
		cmd.Env = append(os.Environ(), "SHENTU_CONFIG="+bad)
		out, err := cmd.CombinedOutput()
		var ee *exec.ExitError
		if !errors.As(err, &ee) || ee.ExitCode() != 1 || !strings.Contains(string(out), "sudo shentu dispatch "+sub) ||
			strings.Contains(string(out), "configuration") || strings.Contains(string(out), "toml") || strings.Contains(string(out), "shentu.toml") {
			t.Errorf("dispatch %s: %v\n%s", sub, err, out)
		}
	}
}

// The same on Windows, at the function main calls before the config.
func TestDispatchPreflight(t *testing.T) {
	for _, sub := range []string{"stats", "repair"} {
		err := dispatchPreflight([]string{sub}, false, "windows")
		if err == nil || !strings.Contains(err.Error(), "Run as administrator") || !strings.Contains(err.Error(), "shentu dispatch "+sub) {
			t.Errorf("windows %s: %v", sub, err)
		}
		if err := dispatchPreflight([]string{sub}, false, "linux"); err == nil || !strings.Contains(err.Error(), "`sudo shentu dispatch "+sub+"`") {
			t.Errorf("linux %s: %v", sub, err)
		}
		if err := dispatchPreflight([]string{sub}, true, "windows"); err != nil {
			t.Errorf("elevated %s: %v", sub, err)
		}
	}
	if err := dispatchPreflight([]string{"wipe"}, false, "linux"); err != nil {
		t.Errorf("another subcommand: %v", err)
	}
}
