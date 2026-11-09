package main

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/nt-neil/shentu/rules/engine"
)

// Caps on one release, so a hostile or broken archive cannot fill the disk.
const (
	maxFiles     = 100_000
	maxFileSize  = 256 << 20
	maxTotalSize = 2 << 30
)

// unpack extracts a .zip or .tar.gz into dest, an empty directory. It drops the
// archive's top-level directory and writes only regular files in a rule
// language (the engine reads nothing else; links, devices and other files are
// skipped). Every entry name is checked first: one that would land outside
// dest fails the whole release. Nothing is made executable.
func unpack(archive, dest string) error {
	u := &unpacker{dest: dest}
	if strings.HasSuffix(archive, ".zip") {
		return u.zip(archive)
	}
	return u.tarGz(archive)
}

type unpacker struct {
	dest  string
	files int
	total int64
}

func (u *unpacker) zip(name string) error {
	r, err := zip.OpenReader(name)
	if err != nil {
		return err
	}
	defer r.Close()
	for _, f := range r.File {
		mode := f.Mode()
		switch {
		case mode.IsDir():
			if err := u.dir(f.Name); err != nil {
				return err
			}
		case mode.IsRegular():
			rc, err := f.Open()
			if err != nil {
				return err
			}
			err = u.file(f.Name, rc)
			rc.Close()
			if err != nil {
				return err
			}
		default:
			if _, err := target(u.dest, f.Name); err != nil {
				return err
			}
		}
	}
	return nil
}

func (u *unpacker) tarGz(name string) error {
	fh, err := os.Open(name)
	if err != nil {
		return err
	}
	defer fh.Close()
	gz, err := gzip.NewReader(fh)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		switch h.Typeflag {
		case tar.TypeDir:
			if err := u.dir(h.Name); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := u.file(h.Name, tr); err != nil {
				return err
			}
		case tar.TypeXGlobalHeader, tar.TypeXHeader:
			// pax metadata, not a file
		default:
			if _, err := target(u.dest, h.Name); err != nil {
				return err
			}
		}
	}
}

func (u *unpacker) dir(name string) error {
	t, err := target(u.dest, name)
	if err != nil || t == "" {
		return err
	}
	return os.MkdirAll(t, 0o755)
}

func (u *unpacker) file(name string, r io.Reader) error {
	t, err := target(u.dest, name)
	if err != nil || t == "" || engine.LangOf(t) == "" {
		return err
	}
	if u.files++; u.files > maxFiles {
		return fmt.Errorf("more than %d files", maxFiles)
	}
	if err := os.MkdirAll(filepath.Dir(t), 0o755); err != nil {
		return err
	}
	// O_EXCL: a second entry with the same name is an error, never an overwrite.
	out, err := os.OpenFile(t, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	n, err := io.Copy(out, io.LimitReader(r, maxFileSize+1))
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if n > maxFileSize {
		return fmt.Errorf("%s is larger than %d MiB", name, maxFileSize>>20)
	}
	if u.total += n; u.total > maxTotalSize {
		return fmt.Errorf("release is larger than %d MiB unpacked", maxTotalSize>>20)
	}
	return nil
}

var errEscape = errors.New("archive entry would land outside the release directory")

// target maps an archive entry name to a path under dest with the top-level
// directory removed. It returns "" for the top-level directory itself and for
// entries beside it, and an error for any name that is absolute, holds a
// backslash or NUL, or climbs out with "..".
func target(dest, name string) (string, error) {
	if name == "" || strings.ContainsAny(name, "\\\x00") || path.IsAbs(name) || filepath.VolumeName(name) != "" {
		return "", fmt.Errorf("%w: %q", errEscape, name)
	}
	clean := path.Clean(name)
	if clean == ".." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("%w: %q", errEscape, name)
	}
	_, rest, ok := strings.Cut(clean, "/")
	if !ok || rest == "" {
		return "", nil
	}
	t := filepath.Join(dest, filepath.FromSlash(rest))
	if !strings.HasPrefix(t, filepath.Clean(dest)+string(filepath.Separator)) {
		return "", fmt.Errorf("%w: %q", errEscape, name)
	}
	return t, nil
}
