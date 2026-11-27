package main

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"strings"
	"syscall"
	"testing"
)

// S-275-1: a failed request to a model outside this host is said by its
// kind only: synthetic errors, no port opened. Neither the URL nor a
// secret in it is in what is said.
func TestOpaqueDoError(t *testing.T) {
	secret := strings.Join([]string{"sk", "test", "SECRET", "0123456789"}, "-")
	u := "https://llm.example.test/t/" + secret + "/v1/chat"
	wrap := func(err error) error { return &url.Error{Op: "Post", URL: u, Err: err} }
	dial := func(errno error) error {
		return wrap(&net.OpError{Op: "dial", Net: "tcp", Err: &os.SyscallError{Syscall: "connect", Err: errno}})
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for name, c := range map[string]struct {
		ctx  context.Context
		err  error
		want string
	}{
		"refused":          {context.Background(), dial(syscall.ECONNREFUSED), "connection refused"},
		"reset":            {context.Background(), dial(syscall.ECONNRESET), "connection failed"},
		"EOF":              {context.Background(), wrap(io.EOF), "connection failed"},
		"name lookup":      {context.Background(), wrap(&net.DNSError{Err: "no such host", Name: "llm.example.test", IsNotFound: true}), "name lookup failed"},
		"timeout":          {context.Background(), wrap(timeoutErr{}), "timeout"},
		"TLS":              {context.Background(), wrap(x509.UnknownAuthorityError{}), "TLS failed"},
		"context ended":    {canceled, wrap(context.Canceled), "context canceled"},
		"the far end said": {context.Background(), errors.New("server said: " + secret + " at " + u), "connection failed"},
	} {
		got := opaqueDoError(c.ctx, c.err).Error()
		if !strings.HasSuffix(got, c.want) || strings.Contains(got, secret) || strings.Contains(got, "llm.example.test") {
			t.Errorf("%s: %q, want ...%q and no URL or secret", name, got, c.want)
		}
	}
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }
