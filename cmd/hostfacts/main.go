// Command hostfacts is the developer tool for the hostenv module: print this
// host's facts, record them as a masked fixture, or replay a fixture.
//
//	hostfacts                       facts for this host, as JSON
//	hostfacts -checks               findings from package checks instead
//	hostfacts -record DIR           also save a masked fixture to DIR
//	hostfacts -replay DIR           facts from a fixture instead of the host
//
// Recording masks the host name, every human account (uid 1000-60000),
// extra names given with -mask-user/-mask-host, IP addresses, GECOS fields
// and SSH key material. Review the fixture and run gitleaks before
// committing it.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/nt-neil/shentu/checks"
	"github.com/nt-neil/shentu/hostenv"
)

func main() {
	record := flag.String("record", "", "save a masked fixture of this host to `dir`")
	replay := flag.String("replay", "", "read facts from the fixture in `dir`")
	runChecks := flag.Bool("checks", false, "print findings instead of facts")
	var users, hosts list
	flag.Var(&users, "mask-user", "extra user `name` to mask (repeatable)")
	flag.Var(&hosts, "mask-host", "extra host `name` to mask (repeatable)")
	flag.Parse()
	if err := run(*record, *replay, *runChecks, users, hosts); err != nil {
		fmt.Fprintln(os.Stderr, "hostfacts:", err)
		os.Exit(1)
	}
}

type list []string

func (l *list) String() string     { return strings.Join(*l, ",") }
func (l *list) Set(s string) error { *l = append(*l, s); return nil }

func run(record, replay string, runChecks bool, users, hosts []string) error {
	ctx := context.Background()
	var src hostenv.Source
	var rec *hostenv.Recorder
	if replay != "" {
		rp, err := hostenv.LoadReplay(replay)
		if err != nil {
			return err
		}
		src = rp
	} else {
		live, err := hostenv.NewLive(hostenv.ForOS(runtime.GOOS).Allowlist())
		if err != nil {
			return err
		}
		src = live
		if record != "" {
			rec = hostenv.NewRecorder(live)
			src = rec
		}
	}
	facts := hostenv.Collect(ctx, src)
	if rec != nil {
		m := &hostenv.Masker{Users: append(humanUsers(facts), users...), Hosts: append(hostNames(), hosts...)}
		if err := rec.Save(record, m); err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "hostfacts: fixture written to", record, "- review it and run gitleaks before committing")
	}
	var out any = facts
	if runChecks {
		out = checks.Run(facts)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func humanUsers(f *hostenv.Facts) []string {
	var out []string
	for _, a := range f.Accounts.Value {
		if uid, err := strconv.Atoi(a.UID); err == nil && uid >= 1000 && uid < 60000 {
			out = append(out, a.Name)
		}
	}
	return out
}

func hostNames() []string {
	var out []string
	if h, err := os.Hostname(); err == nil {
		out = append(out, h)
		if short, _, ok := strings.Cut(h, "."); ok {
			out = append(out, short)
		}
	}
	if b, err := os.ReadFile("/etc/hostname"); err == nil {
		out = append(out, strings.TrimSpace(string(b)))
	}
	return out
}
