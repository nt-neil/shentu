// Package rules holds Shentu's own rules for injection-class vulnerabilities in
// application code (PHP, Python, JavaScript). Each rule is one TOML file at
// rules/<lang>/<class>/<id>.toml; the format and the way rules are added are in
// README.md. Package rules/engine applies them; rules_test.go checks the format.
package rules

import (
	"embed"
	"fmt"
	"io/fs"
	"strings"

	"github.com/BurntSushi/toml"
)

//go:embed */*/*.toml
var files embed.FS

// Rule describes one source-to-sink pattern: user input (Sources) that reaches a
// dangerous call (Sinks) without passing through a sanitizer is a finding. A rule
// with no sources is about how a call is made (a weak cipher, a password written
// in the code): every sink call whose argument conditions hold is a finding.
type Rule struct {
	ID         string       `toml:"id"`
	Lang       string       `toml:"lang"`
	Class      string       `toml:"class"`
	CWE        string       `toml:"cwe"`
	Severity   string       `toml:"severity"`
	Tier       string       `toml:"tier"` // "info" (the default): shown in app_code_audit and chat only; "alert": also in the patrol report
	Title      string       `toml:"title"`
	Frameworks []string     `toml:"frameworks"`
	Sources    []string     `toml:"sources"`
	Sinks      []string     `toml:"sinks"`
	Sanitizers []string     `toml:"sanitizers"`
	Text       []string     `toml:"text"`        // entries of Sources or Sinks matched inside string literals
	Args       []Args       `toml:"args"`        // conditions on a sink call's arguments
	SourceArgs []SourceArgs `toml:"source_args"` // sources that are input only with a given argument
	Fix        string       `toml:"fix"`
	Refs       []string     `toml:"refs"`
	Samples    []Sample     `toml:"samples"`

	File string `toml:"-"` // path inside rules/, set by Load
}

// Args describes which argument of a sink call carries the attack, and when the
// call is or is not dangerous because of its other arguments.
type Args struct {
	Sinks    []string `toml:"sinks"`    // the rule's sinks this applies to; empty means all
	Arg      *int     `toml:"arg"`      // the argument (from 1) that must be tainted; 0 is the receiver; nil is any
	When     []string `toml:"when"`     // the call is a sink only if one of these is among its arguments
	Unless   []string `toml:"unless"`   // the call is not a sink if one of these is among its arguments
	Whole    bool     `toml:"whole"`    // the argument must be the input itself, not a literal holding a part of it
	Leading  bool     `toml:"leading"`  // the input must be at the start of the argument; a fixed prefix makes the call safe
	Context  []string `toml:"context"`  // output sinks: only input written in one of these HTML contexts counts (html, attr, url, js)
	Literal  bool     `toml:"literal"`  // the argument (arg, or the value of a when option) must be a non-empty string literal
	Key      string   `toml:"key"`      // the argument is an object, dict or array: only the value under this key counts (any case)
	Keys     bool     `toml:"keys"`     // an argument that is an array, object or dict literal counts by its keys only, not its values
	MinLen   int      `toml:"min_len"`  // with literal: the string must be at least this long
	Exclude  []string `toml:"exclude"`  // with literal: a string matching one of these regular expressions (any case) does not count
	Receiver []string `toml:"receiver"` // a method sink counts only when its receiver, followed through the file's assignments and annotations, holds one of these
}

// SourceArgs makes call sources input only when an argument is one of a few
// strings: Joomla's $input->get($name, $default, 'raw') returns the raw value,
// while the default filter ('cmd') leaves only safe characters.
type SourceArgs struct {
	Sources []string `toml:"sources"` // the rule's call sources this applies to
	Arg     int      `toml:"arg"`     // the argument (from 1) that must be a string literal
	Values  []string `toml:"values"`  // the values (any case) that make the call a source; any other value, or none, does not
}

// Sample is a minimal, self-written snippet: "vulnerable" must be reported, "safe" must not.
type Sample struct {
	Kind string `toml:"kind"`
	Code string `toml:"code"`
	Note string `toml:"note"`
}

// Load parses every rule file. Unknown keys are an error, so a typo in a field
// name cannot silently drop it.
func Load() ([]Rule, error) {
	var out []Rule
	err := fs.WalkDir(files, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".toml") {
			return err
		}
		b, err := files.ReadFile(path)
		if err != nil {
			return err
		}
		var r Rule
		md, err := toml.Decode(string(b), &r)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if extra := md.Undecoded(); len(extra) > 0 {
			return fmt.Errorf("%s: unknown keys %v", path, extra)
		}
		if !md.IsDefined("sources") {
			return fmt.Errorf("%s: sources must be present (use [] for a rule about how a call is made, not about input)", path)
		}
		if !md.IsDefined("sanitizers") {
			return fmt.Errorf("%s: sanitizers must be present (use [] when nothing makes input safe for these sinks)", path)
		}
		if r.Tier == "" {
			r.Tier = "info"
		}
		r.File = path
		out = append(out, r)
		return nil
	})
	return out, err
}
