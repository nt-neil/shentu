package hostenv

import (
	"path"
	"path/filepath"
	"runtime"
)

// PathOps are path operations as the host read spells its paths: a Linux
// or macOS host's with "/" (package path) wherever the check runs, a
// Windows host's as filepath does on Windows (S-272-2: a Linux recording
// read on a Windows machine joined "\" into its paths). A Windows host
// read on another OS is spelled as that OS's filepath does: not handled.
type PathOps struct {
	Join      func(elem ...string) string
	Dir       func(p string) string
	Base      func(p string) string
	Clean     func(p string) string
	Ext       func(p string) string
	Match     func(pattern, name string) (bool, error)
	FromSlash func(p string) string
	IsAbs     func(p string) bool
	Sep       string
}

var (
	posixPaths  = PathOps{path.Join, path.Dir, path.Base, path.Clean, path.Ext, path.Match, func(p string) string { return p }, path.IsAbs, "/"}
	nativePaths = PathOps{filepath.Join, filepath.Dir, filepath.Base, filepath.Clean, filepath.Ext, filepath.Match, filepath.FromSlash, filepath.IsAbs, string(filepath.Separator)}
)

// PathFor is the path operations of the host src reads.
func PathFor(src Source) PathOps {
	goos := ""
	if _, live := src.(*Live); live {
		goos = runtime.GOOS // Live's Info also asks for elevation: not needed here
	} else {
		goos = src.Info().GOOS
	}
	if goos == "windows" {
		return nativePaths
	}
	return posixPaths
}
