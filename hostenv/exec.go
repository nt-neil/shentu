package hostenv

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"time"
)

var (
	ErrNotAllowed = errors.New("hostenv: command not in allowlist")
	ErrTimeout    = errors.New("hostenv: command timed out")
	ErrTruncated  = errors.New("hostenv: output truncated")
)

// CmdResult is what a command produced. A non-zero exit is not an error: the
// caller decides what it means.
type CmdResult struct {
	Stdout    []byte `json:"-"`
	Stderr    string `json:"stderr,omitempty"`
	ExitCode  int    `json:"exit_code"`
	Truncated bool   `json:"truncated,omitempty"`
}

// Runner runs allowlisted, read-only commands. The zero value refuses
// everything; build one with NewRunner.
type Runner struct {
	allow     map[string]bool
	Timeout   time.Duration // per command; default 10s, never above MaxTimeout
	MaxStdout int           // bytes kept; default 4 MiB
	MaxStderr int           // bytes kept; default 64 KiB
}

const (
	DefaultTimeout   = 10 * time.Second
	MaxTimeout       = 60 * time.Second
	DefaultMaxStdout = 4 << 20
	DefaultMaxStderr = 64 << 10
)

// shells and script hosts are refused even if someone allowlists them: an
// allowlisted shell would turn the exact-argv rule into "anything".
var interpreters = map[string]bool{
	"sh": true, "bash": true, "dash": true, "zsh": true, "ksh": true, "csh": true, "tcsh": true, "fish": true,
	"busybox": true, "env": true, "xargs": true, "sudo": true, "su": true, "doas": true,
	"python": true, "python3": true, "perl": true, "ruby": true, "node": true, "php": true,
	"cmd": true, "powershell": true, "pwsh": true, "wscript": true, "cscript": true, "mshta": true, "rundll32": true,
}

// NewRunner allows exactly the given argv lists. Each argv[0] must be an
// absolute path and must not be a shell or script interpreter.
func NewRunner(allow [][]string) (*Runner, error) {
	r := &Runner{allow: map[string]bool{}}
	for _, argv := range allow {
		if err := checkArgv(argv); err != nil {
			return nil, err
		}
		r.allow[argvKey(argv)] = true
	}
	return r, nil
}

func checkArgv(argv []string) error {
	if len(argv) == 0 {
		return fmt.Errorf("%w: empty argv", ErrNotAllowed)
	}
	if !isAbs(argv[0]) {
		return fmt.Errorf("%w: %q is not an absolute path", ErrNotAllowed, argv[0])
	}
	base := strings.ToLower(baseName(argv[0]))
	base = strings.TrimSuffix(base, ".exe")
	if interpreters[base] || strings.HasPrefix(base, "python") {
		return fmt.Errorf("%w: %q is an interpreter", ErrNotAllowed, argv[0])
	}
	return nil
}

// isAbs accepts both "/usr/bin/x" and "C:\Windows\x.exe" whatever the build OS,
// so allowlists for every platform are checked by the same tests.
func isAbs(p string) bool {
	if strings.HasPrefix(p, "/") {
		return true
	}
	return len(p) > 3 && p[1] == ':' && (p[2] == '\\' || p[2] == '/') &&
		(p[0]|0x20 >= 'a' && p[0]|0x20 <= 'z')
}

func baseName(p string) string {
	return path.Base(filepath.ToSlash(strings.ReplaceAll(p, `\`, "/")))
}

// argvKey joins argv with NUL, which cannot appear inside an argument.
func argvKey(argv []string) string { return strings.Join(argv, "\x00") }

// Allowed reports whether argv is on the list.
func (r *Runner) Allowed(argv []string) bool {
	return r != nil && checkArgv(argv) == nil && r.allow[argvKey(argv)]
}

// Run executes argv with no shell, no stdin, a fixed environment, a timeout
// and capped output. Stdout and stderr are secret-masked before returning.
func (r *Runner) Run(ctx context.Context, argv []string) (CmdResult, error) {
	if !r.Allowed(argv) {
		return CmdResult{}, fmt.Errorf("%w: %q", ErrNotAllowed, argv)
	}
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	timeout = min(timeout, MaxTimeout)
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Env = fixedEnv()
	cmd.Stdin = nil
	cmd.WaitDelay = 2 * time.Second // do not hang on a child that keeps our pipes open
	stdout := &capBuffer{max: orDefault(r.MaxStdout, DefaultMaxStdout)}
	stderr := &capBuffer{max: orDefault(r.MaxStderr, DefaultMaxStderr)}
	cmd.Stdout, cmd.Stderr = stdout, stderr

	err := cmd.Run()
	res := CmdResult{
		Stdout:    []byte(MaskSecrets(stdout.String())),
		Stderr:    MaskSecrets(stderr.String()),
		Truncated: stdout.over || stderr.over,
	}
	if ctx.Err() == context.DeadlineExceeded {
		return res, ErrTimeout
	}
	var exit *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exit):
		res.ExitCode = exit.ExitCode()
	default:
		return res, err // not found, permission: the caller classifies it
	}
	if res.Truncated {
		return res, ErrTruncated
	}
	return res, nil
}

func orDefault(v, d int) int {
	if v <= 0 {
		return d
	}
	return v
}

// capBuffer keeps the first max bytes and quietly drains the rest, so the
// child never blocks on a full pipe.
// It must not embed bytes.Buffer: exec copies with io.Copy, which would use
// the promoted ReadFrom and bypass the cap.
type capBuffer struct {
	buf  bytes.Buffer
	max  int
	over bool
}

func (b *capBuffer) String() string { return b.buf.String() }

func (b *capBuffer) Write(p []byte) (int, error) {
	if room := b.max - b.buf.Len(); room > 0 {
		if len(p) > room {
			b.buf.Write(p[:room])
			b.over = true
		} else {
			b.buf.Write(p)
		}
	} else if len(p) > 0 {
		b.over = true
	}
	return len(p), nil
}
