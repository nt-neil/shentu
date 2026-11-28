package hostenv

import (
	"path"
	"path/filepath"
	"runtime"
)

// PathOps are path operations as the host read spells its paths: a Linux
// or macOS host's with "/" (package path) wherever the check runs, a
// Windows host's as Windows spells them: filepath on Windows, winPaths
// elsewhere (S-272-2: a Linux recording read on a Windows machine joined
// "\" into its paths; v0.5.9: a Windows one read on Linux joined "/").
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
	return PathForGOOS(goos)
}

// PathForGOOS is the path operations of a host of goos.
func PathForGOOS(goos string) PathOps {
	if goos == "windows" {
		if runtime.GOOS == "windows" {
			return nativePaths
		}
		return winPaths
	}
	return posixPaths
}
