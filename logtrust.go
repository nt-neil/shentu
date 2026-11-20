package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/nt-neil/shentu/hostenv"
)

// logTrustCommand is shentu log-trust suggest: what the operator may
// change so that more web logs are verified, printed and never applied.
func logTrustCommand(ctx context.Context, args []string, out io.Writer) error {
	if len(args) != 1 || args[0] != "suggest" {
		return errors.New("usage: shentu log-trust suggest")
	}
	if detectOS != "linux" {
		return errors.New("log-trust: Linux only")
	}
	src, err := detectSource()
	if err != nil {
		return err
	}
	return printLogTrust(ctx, src, out)
}

func printLogTrust(ctx context.Context, src hostenv.Source, out io.Writer) error {
	ss := hostenv.LinuxCollector{}.LogTrustSuggestions(src)
	fmt.Fprintln(out, "shentu changes nothing here: apply what you choose yourself; the next patrol judges the logs again.")
	if len(ss) == 0 {
		fmt.Fprintln(out, "\nNothing to suggest: no change shentu knows of would verify more of this host's web logs.")
	}
	for i, s := range ss {
		fmt.Fprintf(out, "\n%d. %s\n   applies: %s\n   file:    %s\n", i+1, s.ID, s.Applies, s.File)
		for _, ln := range strings.Split(s.Snippet, "\n") {
			fmt.Fprintln(out, "       "+ln)
		}
		if s.Then != "" {
			fmt.Fprintf(out, "   then:    %s\n", s.Then)
		}
		fmt.Fprintf(out, "   stops:   %s\n   costs:   %s\n", s.Stops, s.Costs)
	}
	journal := false // nginx's log goes, or is to go, through journald: say what journald dropped
	for _, s := range ss {
		journal = journal || s.ID == "journald-rate-limit"
	}
	for _, s := range (hostenv.LinuxCollector{}).WebLogs(src).Value {
		journal = journal || s.Journal != ""
	}
	if journal {
		n, err := hostenv.JournalSuppressed(ctx, src, "nginx.service", time.Now().Add(-24*time.Hour))
		if err != nil {
			fmt.Fprintf(out, "\njournald's drops from nginx.service in the last 24 hours: not read (%v)\n", err)
		} else {
			fmt.Fprintf(out, "\njournald dropped %d messages from nginx.service in the last 24 hours.\n", n)
		}
	}
	return nil
}
