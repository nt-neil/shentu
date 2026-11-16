package hostenv

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
)

// CutLineRunner is implemented by Sources that can stream a command's
// output with lines past max cut (their start given, the rest skipped)
// rather than end the read, as a scanner's ErrTooLong does.
type CutLineRunner interface {
	RunLinesCut(ctx context.Context, argv []string, max int, fn func(line string, cut bool)) (CmdResult, error)
}

// RunLinesCut runs argv through src, giving each output line (unmasked) to
// fn, a line longer than max cut to its first max bytes with cut set. A
// Source that cannot stream gives its whole output, split the same way.
func RunLinesCut(ctx context.Context, src Source, argv []string, max int, fn func(line string, cut bool)) (CmdResult, error) {
	if c, ok := src.(CutLineRunner); ok {
		return c.RunLinesCut(ctx, argv, max, fn)
	}
	res, err := src.Run(ctx, argv)
	if err == nil || errors.Is(err, ErrTruncated) {
		if serr := scanCut(bytes.NewReader(res.Stdout), max, fn); serr != nil && err == nil {
			err = serr
		}
	}
	res.Stdout = nil
	return res, err
}

func (l *Live) RunLinesCut(ctx context.Context, argv []string, max int, fn func(line string, cut bool)) (CmdResult, error) {
	return l.Runner.runStream(ctx, argv, func(r io.Reader) error { return scanCut(r, max, fn) })
}

// scanCut reads r line by line; a line past max is given cut and the read
// goes on after its newline.
func scanCut(r io.Reader, max int, fn func(string, bool)) error {
	br := bufio.NewReaderSize(r, 64*1024)
	var buf []byte
	cut := false
	for {
		chunk, err := br.ReadSlice('\n')
		if len(buf)+len(chunk) > max {
			if !cut {
				buf = append(buf, chunk[:max-len(buf)]...)
			}
			cut = true
		} else if !cut {
			buf = append(buf, chunk...)
		}
		switch {
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case err == nil, errors.Is(err, io.EOF):
			line := bytes.TrimSuffix(bytes.TrimSuffix(buf, []byte("\n")), []byte("\r"))
			if len(line) > 0 || err == nil {
				fn(string(line), cut)
			}
			if err != nil {
				return nil
			}
			buf, cut = buf[:0], false
		default:
			return err
		}
	}
}
