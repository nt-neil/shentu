package hostenv

// Streaming reads for logs and command output that can be far larger than
// the memory Shentu may use (it must run on a 512 MB VPS): lines are
// handed to a callback one at a time, so memory stays flat whatever the
// size of the file.

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"os"
	"regexp"
	"strings"
)

// MaxLineBytes is the longest line a scan accepts; a longer one ends the
// scan with bufio.ErrTooLong, as tools' readLines did.
const MaxLineBytes = 1 << 20

// Opener is implemented by Sources that can stream a file.
type Opener interface {
	Open(path string) (io.ReadCloser, error)
}

// LineRunner is implemented by Sources that can stream a command's stdout.
type LineRunner interface {
	RunLines(ctx context.Context, argv []string, fn func(line string)) (CmdResult, error)
}

// ScanLines calls fn for each line of path (gunzipped when it ends in
// .gz), secret-masked, without holding the file in memory. Sources that
// cannot stream fall back to ReadFile (bounded by MaxFileBytes).
func ScanLines(src Source, path string, fn func(line string)) error {
	var r io.Reader
	if o, ok := src.(Opener); ok {
		f, err := o.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		r = f
	} else {
		b, err := src.ReadFile(path)
		if err != nil && !errors.Is(err, ErrTruncated) {
			return err
		}
		r = bytes.NewReader(b)
	}
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(r)
		if err != nil {
			return err
		}
		defer gz.Close()
		r = gz
	}
	return scan(r, fn)
}

// pemBegin and pemEnd frame a private key block, which spans lines: line
// by line masking alone would let its body through.
var (
	pemBegin = regexp.MustCompile("-----BEGIN [A-Z ]*PRIVATE KEY-----")
	pemEnd   = regexp.MustCompile("-----END [A-Z ]*PRIVATE KEY-----")
)

func scan(r io.Reader, fn func(string)) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), MaxLineBytes)
	inKey := false
	for sc.Scan() {
		l := sc.Text()
		if inKey {
			if loc := pemEnd.FindStringIndex(l); loc != nil {
				inKey = false
				if rest := l[loc[1]:]; strings.TrimSpace(rest) != "" {
					fn(MaskSecrets(rest))
				}
			}
			continue // the key body never reaches fn
		}
		if loc := pemBegin.FindStringIndex(l); loc != nil && pemEnd.FindStringIndex(l[loc[1]:]) == nil {
			inKey = true
			fn(MaskSecrets(l[:loc[0]]) + "[REDACTED PRIVATE KEY]")
			continue
		}
		fn(MaskSecrets(l))
	}
	return sc.Err()
}

// RunLines streams argv's stdout to fn line by line through src; Sources
// that cannot stream fall back to Run.
func RunLines(ctx context.Context, src Source, argv []string, fn func(line string)) (CmdResult, error) {
	if lr, ok := src.(LineRunner); ok {
		return lr.RunLines(ctx, argv, fn)
	}
	res, err := src.Run(ctx, argv)
	if err == nil || errors.Is(err, ErrTruncated) {
		if serr := scan(bytes.NewReader(res.Stdout), fn); serr != nil && err == nil {
			err = serr
		}
	}
	res.Stdout = nil
	return res, err
}

// Open streams a regular file (no size cap; callers scan it).
func (l *Live) Open(path string) (io.ReadCloser, error) {
	f, err := openRead(l.path(path), false)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !st.Mode().IsRegular() {
		f.Close()
		return nil, &os.PathError{Op: "read", Path: path, Err: notRegular("not a regular file")}
	}
	return f, nil
}

// RunLines streams an allowlisted command's stdout (Runner.RunLines).
func (l *Live) RunLines(ctx context.Context, argv []string, fn func(line string)) (CmdResult, error) {
	return l.Runner.RunLines(ctx, argv, fn)
}

// Recorder streams through the inner Source and keeps at most
// MaxFileBytes of what passed, for the fixture.
func (r *Recorder) Open(path string) (io.ReadCloser, error) {
	var buf bytes.Buffer
	err := ScanLinesRaw(r.Inner, path, &buf)
	data := buf.Bytes()
	if !strings.HasSuffix(path, ".gz") {
		data = []byte(MaskSecrets(string(data))) // whole buffer: key blocks across lines too
	}
	r.put(&entry{Op: "file", Path: path, Err: errCode(err), data: data})
	if err != nil {
		return nil, err
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

// ScanLinesRaw copies at most MaxFileBytes of path (not gunzipped) to w.
func ScanLinesRaw(src Source, path string, w io.Writer) error {
	if o, ok := src.(Opener); ok {
		f, err := o.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = io.Copy(w, io.LimitReader(f, MaxFileBytes))
		return err
	}
	b, err := src.ReadFile(path)
	w.Write(b)
	return err
}

func (r *Recorder) RunLines(ctx context.Context, argv []string, fn func(line string)) (CmdResult, error) {
	var buf bytes.Buffer
	res, err := RunLines(ctx, r.Inner, argv, func(l string) {
		if buf.Len() < MaxFileBytes {
			buf.WriteString(l)
			buf.WriteByte('\n')
		}
		fn(l)
	})
	r.put(&entry{Op: "cmd", Argv: append([]string(nil), argv...), Err: errCode(err), data: buf.Bytes(),
		ExitCode: res.ExitCode, Stderr: res.Stderr})
	return res, err
}

func (rp *Replay) Open(path string) (io.ReadCloser, error) {
	b, err := rp.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return io.NopCloser(bytes.NewReader(b)), nil
}
