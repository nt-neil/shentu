package tools

// Test Sources shared by the tools tests on every platform.

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/nt-neil/shentu/hostenv"
)

// withHost points the tools at src for one test.
func withHost(t *testing.T, src hostenv.Source) {
	old := hostSource
	hostSource = func() hostenv.Source { return src }
	t.Cleanup(func() { hostSource = old })
}

// memHost is a tiny file-only Source for edge cases.
type memHost map[string]string

func (memHost) Info() hostenv.SourceInfo { return hostenv.SourceInfo{GOOS: "linux"} }
func (m memHost) ReadFile(p string) ([]byte, error) {
	if s, ok := m[p]; ok {
		return []byte(s), nil
	}
	return nil, os.ErrNotExist
}
func (memHost) ReadDir(string) ([]string, error) { return nil, os.ErrNotExist }
func (memHost) Readlink(string) (string, error)  { return "", os.ErrNotExist }
func (memHost) Run(context.Context, []string) (hostenv.CmdResult, error) {
	return hostenv.CmdResult{}, os.ErrNotExist
}

// scriptHost is a Source with files, links and canned command results.
type scriptHost struct {
	memHost
	cmds map[string]hostenv.CmdResult
	stat map[string]bool
}

func (h scriptHost) Run(_ context.Context, argv []string) (hostenv.CmdResult, error) {
	if r, ok := h.cmds[strings.Join(argv, " ")]; ok {
		return r, nil
	}
	return hostenv.CmdResult{}, os.ErrNotExist
}
func (h scriptHost) Stat(p string) (hostenv.FileStat, error) {
	if h.stat[p] {
		return hostenv.FileStat{}, nil
	}
	if _, ok := h.memHost[p]; ok {
		return hostenv.FileStat{}, nil
	}
	return hostenv.FileStat{}, os.ErrNotExist
}
