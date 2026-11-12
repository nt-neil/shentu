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
	return scanFile(src, path, true, fn)
}

// scanFile streams path's lines; masked says whether each is secret-masked.
// Only tables that hold numbers (/proc/net) skip it, for speed.
func scanFile(src Source, path string, masked bool, fn func(line string)) error {
	var r io.Reader
	var cut error // a ReadFile fallback that was cut short: the lines read count, the scan is not complete
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
		cut = err
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
	var err error
	if masked {
		err = scan(r, fn)
	} else {
		err = scanPlain(r, fn)
	}
	if err == nil {
		err = cut
	}
	return err
}

// A private key block spans lines, so line-by-line masking alone would
// let its body through. A BEGIN ... PRIVATE KEY marker anywhere in a line
// opens a block (the rest of that line is masked); the block then swallows
// PEM-shaped lines only (base64, optionally quoted or ending in "\n", a
// "Name: value" header, blank) until its END line. The first line that is
// not PEM-shaped ends it and is passed on, masked: a log line always has a
// time stamp and spaces, so a marker an attacker writes into a log message
// cannot hide the lines after it.
var (
	pemBegin = regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)
	pemEnd   = regexp.MustCompile(`-----END [A-Z ]*PRIVATE KEY-----`)
	pemBody  = regexp.MustCompile(`^(?:["']?[A-Za-z0-9+/=]*(?:\\n)?["']?,?|[A-Za-z-]+: .*)$`)
)

// keyMasker is the line state machine shared by scans and recordings.
type keyMasker struct{ inKey bool }

// line returns what to pass on for l, and false to pass nothing.
func (k *keyMasker) line(l string) (string, bool) {
	if k.inKey {
		if loc := pemEnd.FindStringIndex(l); loc != nil {
			k.inKey = false
			if rest := strings.TrimSpace(l[loc[1]:]); rest != "" {
				return k.line(l[loc[1]:])
			}
			return "", false
		}
		if pemBody.MatchString(strings.TrimSpace(l)) {
			return "", false // the key body never leaves
		}
		k.inKey = false // not a key after all: back to normal lines
	}
	if loc := pemBegin.FindStringIndex(l); loc != nil && pemEnd.FindStringIndex(l[loc[1]:]) == nil {
		k.inKey = true
		return MaskSecrets(l[:loc[0]]) + "[REDACTED PRIVATE KEY]", true
	}
	return MaskSecrets(l), true
}

// ScanLinesUnmasked is ScanLines without masking, for parsers that match
// the text as written (sshd's log lines: a mask must not change a count)
// and mask only what they output.
func ScanLinesUnmasked(src Source, path string, fn func(line string)) error {
	return scanFile(src, path, false, fn)
}

func scanPlain(r io.Reader, fn func(string)) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), MaxLineBytes)
	for sc.Scan() {
		fn(sc.Text())
	}
	return sc.Err()
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

// RawLineRunner is implemented by Sources that can stream a command's
// stdout unmasked.
type RawLineRunner interface {
	RunLinesUnmasked(ctx context.Context, argv []string, fn func(line string)) (CmdResult, error)
}

// RunLinesUnmasked is RunLines without masking (see ScanLinesUnmasked).
// A Source that cannot give the text unmasked (a replayed fixture, already
// masked) gives what it has.
func RunLinesUnmasked(ctx context.Context, src Source, argv []string, fn func(line string)) (CmdResult, error) {
	if lr, ok := src.(RawLineRunner); ok {
		return lr.RunLinesUnmasked(ctx, argv, fn)
	}
	if lr, ok := src.(LineRunner); ok {
		return lr.RunLines(ctx, argv, fn)
	}
	res, err := src.Run(ctx, argv)
	if err == nil || errors.Is(err, ErrTruncated) {
		if serr := scanPlain(bytes.NewReader(res.Stdout), fn); serr != nil && err == nil {
			err = serr
		}
	}
	res.Stdout = nil
	return res, err
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

// RunLinesUnmasked streams an allowlisted command's stdout as written.
func (l *Live) RunLinesUnmasked(ctx context.Context, argv []string, fn func(line string)) (CmdResult, error) {
	return l.Runner.RunLinesUnmasked(ctx, argv, fn)
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

// RunLinesUnmasked passes the text as written to fn and keeps it masked
// for the fixture.
func (r *Recorder) RunLinesUnmasked(ctx context.Context, argv []string, fn func(line string)) (CmdResult, error) {
	var buf bytes.Buffer
	var km keyMasker
	res, err := RunLinesUnmasked(ctx, r.Inner, argv, func(l string) {
		if m, ok := km.line(l); ok && buf.Len() < MaxFileBytes {
			buf.WriteString(m)
			buf.WriteByte('\n')
		}
		fn(l)
	})
	r.put(&entry{Op: "cmd", Argv: append([]string(nil), argv...), Err: errCode(err), data: buf.Bytes(),
		ExitCode: res.ExitCode, Stderr: res.Stderr})
	return res, err
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
