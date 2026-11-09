// Package rules holds Shentu's own rules for injection-class vulnerabilities in
// application code (PHP, Python, JavaScript). Each rule is one TOML file at
// rules/<lang>/<class>/<id>.toml; the format and the way rules are added are in
// README.md. The scanning engine that applies them is not written yet, so for now
// the package only loads the files, and rules_test.go checks them.
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
// dangerous call (Sinks) without passing through a sanitizer is a finding.
type Rule struct {
	ID         string   `toml:"id"`
	Lang       string   `toml:"lang"`
	Class      string   `toml:"class"`
	CWE        string   `toml:"cwe"`
	Severity   string   `toml:"severity"`
	Title      string   `toml:"title"`
	Frameworks []string `toml:"frameworks"`
	Sources    []string `toml:"sources"`
	Sinks      []string `toml:"sinks"`
	Sanitizers []string `toml:"sanitizers"`
	Fix        string   `toml:"fix"`
	Refs       []string `toml:"refs"`
	Samples    []Sample `toml:"samples"`

	File string `toml:"-"` // path inside rules/, set by Load
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
		if !md.IsDefined("sanitizers") {
			return fmt.Errorf("%s: sanitizers must be present (use [] when nothing makes input safe for these sinks)", path)
		}
		r.File = path
		out = append(out, r)
		return nil
	})
	return out, err
}
