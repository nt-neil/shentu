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

// A private key block spans lines, so line-by-line masking alone would
// let its body through. A block starts only at a line that is exactly a
// BEGIN ... PRIVATE KEY marker (a log line always has a prefix, so text an
// attacker puts into a log message cannot open one), holds only PEM-shaped
// lines (base64, a "Name: value" header, blank), and is at most
// maxKeyLines long; anything else ends it and is passed on, masked.
var (
	pemBeginLine = regexp.MustCompile(`^-----BEGIN [A-Z ]*PRIVATE KEY-----$`)
	pemEndLine   = regexp.MustCompile(`^-----END [A-Z ]*PRIVATE KEY-----`)
	pemBody      = regexp.MustCompile(`^(?:[A-Za-z0-9+/=]*|[A-Za-z-]+: .*)$`)
)

const maxKeyLines = 120 // a 8192-bit RSA key in PEM is about 100 lines

// keyMasker is the line state machine shared by scans and recordings.
type keyMasker struct {
	inKey bool
	lines int
}

// line returns what to pass on for l, and false to pass nothing.
func (k *keyMasker) line(l string) (string, bool) {
	t := strings.TrimSpace(l)
	if k.inKey {
		if pemEndLine.MatchString(t) {
			k.inKey = false
			return "", false
		}
		if k.lines++; k.lines <= maxKeyLines && pemBody.MatchString(t) {
			return "", false // the key body never leaves
		}
		k.inKey = false // not a key after all: back to normal lines
	}
	if pemBeginLine.MatchString(t) {
		k.inKey, k.lines = true, 0
		return "[REDACTED PRIVATE KEY]", true
	}
	return MaskSecrets(l), true
}

func scan(r io.Reader, fn func(string)) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), MaxLineBytes)
	var km keyMasker
	for sc.Scan() {
		if out, ok := km.line(sc.Text()); ok {
			fn(out)
		}
	}
	return sc.Err()
}

// maskLines masks a whole buffer with the same line rules as scan, with no
// line length limit, keeping the buffer's own line ends. Every Source uses
// it for whole files, so a BEGIN marker planted at the top of a file the
// attacker can write (a crontab, authorized_keys) hides only a bounded,
// PEM-shaped block, never the rest of the file.
func maskLines(b []byte) []byte {
	var km keyMasker
	lines := strings.SplitAfter(string(b), "\n")
	var out strings.Builder
	out.Grow(len(b))
	for _, l := range lines {
		if l == "" {
			continue
		}
		body := strings.TrimRight(l, "\n")
		end := l[len(body):]
		if masked, ok := km.line(body); ok {
			out.WriteString(masked)
			out.WriteString(end)
		}
	}
	return []byte(out.String())
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
		data = maskLines(data) // the scan's own bounded rules, line by line
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
