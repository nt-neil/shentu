package main

import (
	"embed"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Skills are SKILL.md files: YAML-style frontmatter (name, description) and
// instructions for the model. Built-in skills are embedded; files in
// <config dir>/skills/<name>/SKILL.md add to them or replace them by name.

//go:embed skills
var builtinSkills embed.FS

type skill struct {
	Name, Description, Body string
}

func loadSkills(extraDir string) map[string]skill {
	out := map[string]skill{}
	fs.WalkDir(builtinSkills, "skills", func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.Name() == "SKILL.md" {
			if b, err := builtinSkills.ReadFile(p); err == nil {
				if s, ok := parseSkill(string(b)); ok {
					out[s.Name] = s
				}
			}
		}
		return nil
	})
	files, _ := filepath.Glob(filepath.Join(extraDir, "*", "SKILL.md"))
	for _, f := range files {
		if b, err := os.ReadFile(f); err == nil {
			if s, ok := parseSkill(string(b)); ok {
				out[s.Name] = s
			}
		}
	}
	return out
}

func parseSkill(text string) (skill, bool) {
	rest, ok := strings.CutPrefix(text, "---\n")
	if !ok {
		return skill{}, false
	}
	front, body, ok := strings.Cut(rest, "\n---\n")
	if !ok {
		return skill{}, false
	}
	var s skill
	for _, line := range strings.Split(front, "\n") {
		k, v, _ := strings.Cut(line, ":")
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		switch strings.TrimSpace(k) {
		case "name":
			s.Name = v
		case "description":
			s.Description = v
		}
	}
	s.Body = strings.TrimSpace(body)
	return s, s.Name != ""
}

func skillIndex(skills map[string]skill) string {
	names := make([]string, 0, len(skills))
	for n := range skills {
		names = append(names, n)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, n := range names {
		b.WriteString("- " + n + ": " + skills[n].Description + "\n")
	}
	return b.String()
}
