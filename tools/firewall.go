package tools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/nt-neil/shentu/hostenv"
)

// All blocks live in their own nftables table, so shentu never touches the
// administrator's own rules and `nft delete table inet shentu` removes everything.
const nftTable = "shentu"

const nftSetup = `table inet shentu {
	set block4 { type ipv4_addr; flags timeout; }
	set block6 { type ipv6_addr; flags timeout; }
	chain input {
		type filter hook input priority -10; policy accept;
		ip saddr @block4 drop
		ip6 saddr @block6 drop
	}
}
`

type ipArgs struct {
	IP     string `json:"ip"`
	TTL    string `json:"ttl"`
	Reason string `json:"reason"`
	// OverrideUnverified blocks an IP whose SSH login events come only from
	// text logs (verified=false), which anyone on the host can write to. Set
	// only after the operator has checked those logs; the preview shows it.
	OverrideUnverified bool `json:"override_unverified"`
}

// RemoteRefused says why a control tool call from a chat channel (env.Remote)
// is refused before it is shown for confirmation; nil when it is not. A
// remote request cannot override the login gate, at any interaction level:
// the operator checks the logs on the server and blocks with shentu chat.
func RemoteRefused(env *Env, name string, args json.RawMessage) error {
	if env == nil || !env.Remote || name != "block_ip" {
		return nil
	}
	var a ipArgs
	if decode(args, &a) == nil && !a.OverrideUnverified {
		return nil
	}
	return errors.New("override_unverified is not accepted from a chat channel: check the logs on the server and block it there with shentu chat")
}

// loginSummary is SSHSummary, textLogins counts ip's SSH login events in
// the text auth logs alone, and sshdJournal the journal lines sshd itself
// wrote about ip (tests replace all three).
var (
	sshdJournal = func(ctx context.Context, since, until time.Time, ip string) (SSHSource, error) {
		return hostenv.SSHDJournalLines(ctx, hostSource(), since, until, ip)
	}
	loginSummary = SSHSummary
	textLogins   = func(env *Env, ip string) (n int, files, unread []string) {
		// Whatever a line's time says: a forged line may be dated before any
		// window, and ssh_logins could have been asked about it. Each log
		// path is read on its own, to name the files the events are in.
		for _, p := range env.LogPaths {
			c := hostenv.NewSSHLogins(time.Time{}, time.Now(), ip)
			read, un := linux.ScanTextAuthLogs(hostSource(), []string{p}, time.Time{}, c.Add)
			unread = append(unread, un...)
			list, _ := hostenv.MaxLogins(c)
			k := 0
			for _, s := range list {
				k += s.Failed + s.InvalidUser + s.Accepted
			}
			if k > 0 {
				n += k
				files = append(files, read...)
			}
		}
		return n, files, unread
	}
)

// block_ip looks for the IP's SSH logins over the last day first, and over
// loginGateWindow (as long as the longest block, since ssh_logins may have
// been asked about any span before it) only when the day has none: a month
// of journald may take past its timeout, which would leave the logins
// unverified and the operator overriding for nothing.
const (
	loginGateFirst  = 24 * time.Hour
	loginGateWindow = 720 * time.Hour
)

// loginGate refuses to block ip when its SSH login events may be forged:
// events for it in the text logs (which anyone on the host can write sshd
// lines to) that journald does not confirm with events of its own, a summary
// that is unverified and has some, or a summary that could not be read in
// full. The text logs are read whatever journald holds, since ssh_logins may
// have read them for a shorter span in which journald was empty. override
// lets the operator, having checked the logs, go ahead. An IP with no login
// events anywhere is not blocked for its logins: the gate does not apply.
func loginGate(ctx context.Context, env *Env, ip net.IP, override bool) error {
	if override {
		return nil
	}
	_, err := loginCheck(ctx, env, ip)
	return err
}

// HostGOOS is the platform block_ip runs on; tests swap it.
var HostGOOS = runtime.GOOS

// blockUnsupported refuses block_ip where nftables is not: before any check,
// so macOS does not read a month of its unified log to refuse.
func blockUnsupported() error {
	if SupportedOn("block_ip", HostGOOS) {
		return nil
	}
	return coded(BlockUnsupported, fmt.Errorf("block_ip is not supported on %s: it blocks with nftables, which only Linux has", HostGOOS))
}

// loginMemoTTL is how long a read-only check (RemoteBlockCheck: the dispatch
// archive, the proposal buttons, a chat channel's precheck) reuses
// loginCheck's answer for the same address, so one dispatch reads up to a
// month of logs once per address rather than once per check. block_ip's Run
// always reads again. An answer cut short by its context is not kept. (A
// var: the tests, which swap the readers, set it to 0.)
var loginMemoTTL = 2 * time.Minute

type loginMemoKey struct{}

type loginMemoEntry struct {
	at       time.Time
	verified bool
	err      error
}

var (
	loginMemoMu sync.Mutex
	loginMemo   = map[string]loginMemoEntry{}
	memoNow     = time.Now // tests move the clock
)

func withLoginMemo(ctx context.Context) context.Context {
	return context.WithValue(ctx, loginMemoKey{}, true)
}

// loginCheck is loginGate's check: an error refuses; verified says the IP
// has SSH login events journald itself confirms (nil and not verified: it
// has none anywhere). Under withLoginMemo a recent answer for the same
// address and log paths is reused; a check its context cut short refuses
// with BlockTimeout.
func loginCheck(ctx context.Context, env *Env, ip net.IP) (verified bool, err error) {
	memo := ctx.Value(loginMemoKey{}) != nil
	var paths []string
	if env != nil {
		paths = env.LogPaths
	}
	// The key is the address and the log paths only. That holds because one
	// process has one setting: what else decides the answer (the journal
	// read, its caps, env.Remote) is the same for every check in it. A key
	// that comes to vary with more of these (an index, other caps, Remote)
	// must take them in too, or one setting's answer is given to another.
	key := hostenv.CanonicalIP(ip.String()) + "\x00" + strings.Join(paths, "\x00")
	if memo {
		loginMemoMu.Lock()
		e, ok := loginMemo[key]
		loginMemoMu.Unlock()
		if age := memoNow().Sub(e.at); ok && age >= 0 && age < loginMemoTTL {
			return e.verified, e.err
		}
	}
	verified, err = loginCheckRead(ctx, env, ip)
	if ctx.Err() != nil {
		if err != nil {
			err = coded(BlockTimeout, fmt.Errorf("refusing to block %s: the check of its SSH logins ran out of time (%v); ask again later, or check it on the server", ip, err))
		}
		return verified, err
	}
	if memo && loginMemoTTL > 0 {
		now := memoNow()
		loginMemoMu.Lock()
		for k, e := range loginMemo {
			if now.Sub(e.at) >= loginMemoTTL || now.Before(e.at) {
				delete(loginMemo, k)
			}
		}
		loginMemo[key] = loginMemoEntry{at: now, verified: verified, err: err}
		loginMemoMu.Unlock()
	}
	return verified, err
}

// loginCheckRead is loginCheck's read of the logs: from the login index
// when it answers (loginindex.go), else by reading the whole window.
func loginCheckRead(ctx context.Context, env *Env, ip net.IP) (verified bool, err error) {
	want := hostenv.CanonicalIP(ip.String())
	x, err := updateLoginIndex(ctx)
	switch {
	case err == nil:
		seen, err := x.indexedLogins(ip, indexNow())
		if errors.Is(err, errIndexDoesNotCover) {
			break
		}
		if err != nil || seen {
			return err == nil, err // seen, and sshd itself wrote every event in the window
		}
		return textLoginCheck(env, ip, want, false, "journald")
	case !errors.Is(err, errNoLoginIndex) && ctx.Err() != nil: // the index read on as far as it could in the time: the next check goes on
		return false, coded(BlockTimeout, fmt.Errorf("refusing to block %s: its SSH logins could not be read in time (%v)", ip, err))
	}
	var r map[string]any
	seen, complete := false, false
	var summarySince, summaryUntil time.Time // the window the summary last read
	for _, back := range []time.Duration{loginGateFirst, loginGateWindow} {
		var err error
		summarySince = time.Now().Add(-back)
		if r, err = loginSummary(ctx, env, summarySince, want); err != nil {
			return false, coded(BlockStateError, fmt.Errorf("refusing to block %s: its SSH logins could not be read to check whether they are real (%v); if the block rests on other evidence, ask again with override_unverified", ip, err))
		}
		// The summary read up to now (journald without --until): the
		// confirming read must cover all it may have counted, an attack
		// still going on included.
		summaryUntil = time.Now()
		sources, _ := r["sources"].([]SSHSource)
		seen = false
		for _, s := range sources {
			if hostenv.CanonicalIP(s.IP) == want && s.Failed+s.InvalidUser+s.Accepted > 0 {
				seen = true
			}
		}
		// SSHSummary reports a log it could not read in r, not as an error.
		complete, _ = r["complete"].(bool)
		if e, _ := r["error"].(string); e != "" {
			complete = false
		}
		if seen || !complete {
			break // the day already tells, or cannot tell
		}
	}
	verified, _ = r["verified"].(bool)
	if !complete {
		why := fmt.Sprint(r["source"])
		if e, _ := r["error"].(string); e != "" {
			why += ": " + e
		}
		return false, coded(BlockStateError, fmt.Errorf("refusing to block %s: its SSH logins could not be read in full (%s), so forged ones cannot be ruled out; check the logs as root and, if they are real, ask again with override_unverified", ip, why))
	}
	if seen && verified {
		// journald has the IP's logins in sshd's units; a user's shell left
		// in that cgroup (no pam_systemd) can write sshd lines with logger,
		// so they count only when sshd itself wrote them (_COMM, _UID).
		// Every event the summary counted must be sshd's own, kind by
		// kind, over the very window the summary read (later events
		// cannot make up for forged ones).
		var claimed SSHSource
		sources, _ := r["sources"].([]SSHSource)
		for _, s := range sources {
			if hostenv.CanonicalIP(s.IP) == want {
				claimed.Failed, claimed.InvalidUser, claimed.Accepted = claimed.Failed+s.Failed, claimed.InvalidUser+s.InvalidUser, claimed.Accepted+s.Accepted
			}
		}
		own, err := sshdJournal(ctx, summarySince, summaryUntil, want)
		if err != nil {
			return false, coded(BlockStateError, fmt.Errorf("refusing to block %s: whether its SSH login events in journald were written by sshd itself could not be checked (%v); check them as root and, if they are real, ask again with override_unverified", ip, err))
		}
		if own.Failed < claimed.Failed || own.InvalidUser < claimed.InvalidUser || own.Accepted < claimed.Accepted {
			return false, coded(BlockUnverified, fmt.Errorf("refusing to block %s: of its SSH login events in journald (failed %d, invalid user %d, accepted %d), sshd itself wrote failed %d, invalid user %d, accepted %d (the others came from another program in sshd's unit, e.g. logger), so they may be forged; check them as root and, if they are real, ask again with override_unverified",
				ip, claimed.Failed, claimed.InvalidUser, claimed.Accepted, own.Failed, own.InvalidUser, own.Accepted))
		}
		return true, nil // sshd itself logged the IP: the text logs need not be read
	}
	return textLoginCheck(env, ip, want, seen, fmt.Sprint(r["source"]))
}

// textLoginCheck is the check of the text auth logs, when journald does not
// show sshd itself logging ip: seen says the logins read had events for it
// (unverified ones), source what they were read from.
func textLoginCheck(env *Env, ip net.IP, want string, seen bool, source string) (verified bool, err error) {
	text, files, unread := textLogins(env, want)
	switch {
	case len(unread) > 0:
		return false, coded(BlockStateError, fmt.Errorf("refusing to block %s: the text auth logs could not all be read (%s), so forged SSH logins in them cannot be ruled out; check them as root and, if the block is right, ask again with override_unverified", ip, strings.Join(unread, ", ")))
	case seen, text > 0: // seen here means unverified
		// Name the text logs the events are in, not the summary's source
		// (that is "journald" when journald had other sshd entries).
		where := strings.Join(files, ", ")
		if where == "" {
			where = source
		}
		return false, coded(BlockUnverified, fmt.Errorf("refusing to block %s: its SSH login events come from text logs (%s), which anyone on this host can write to, so they may be forged; check them (journalctl -u ssh, the IP's other traffic) and, if they are real, ask again with override_unverified", ip, where))
	}
	return false, nil
}

var blockIP = Tool{
	Name:        "block_ip",
	Description: "Block all inbound traffic from one IP address with nftables, for a limited time. Requires the operator to confirm. Refuses loopback, this server's own addresses and the IPs of current SSH sessions. An IP attack detection saw is blocked only for a verified L2 or L3 group of its own (not an overflow summary); one seen only from unverified sources needs override_unverified, from the server's terminal only. Any other IP is refused when its SSH login events are only in text logs anyone here can write to, or could not be read in full (override_unverified likewise). From a chat channel (Telegram) only an IP with verified evidence is blocked: a verified L2 or L3 group listing it, or SSH login events sshd itself logged; any other is refused, for the operator on the server. On the server, that check covers SSH login evidence only: a block based on other logs (log_search over syslog, nginx) is not checked, so say where the evidence came from; from a chat channel such a block is refused.",
	Control:     true,
	Params: schema(`{"type":"object","required":["ip","reason"],"properties":{
		"ip":{"type":"string","description":"single IPv4 or IPv6 address"},
		"ttl":{"type":"string","description":"how long, e.g. 1h, 24h, 168h (default 24h, max 720h)"},
		"reason":{"type":"string","description":"why, shown to the operator"},
		"override_unverified":{"type":"boolean","description":"block even though the IP's SSH login events come only from text logs (verified=false); only after the operator has checked those logs"}}}`),
	Preview: func(args json.RawMessage) (string, error) {
		if err := blockUnsupported(); err != nil {
			return "", err
		}
		a, ip, ttl, err := checkBlock(args)
		if err != nil {
			return "", err
		}
		s := fmt.Sprintf("nft add element inet %s %s { %s timeout %ds }   # %s", nftTable, setFor(ip), ip, int(ttl.Seconds()), a.Reason)
		if a.OverrideUnverified {
			s += "\n# override_unverified: blocks even if this IP's SSH logins come only from text logs anyone here can write to; confirm only if you checked them"
		}
		return s, nil
	},
	Run: func(ctx context.Context, env *Env, args json.RawMessage) (any, error) {
		if err := RemoteRefused(env, "block_ip", args); err != nil {
			return nil, err
		}
		if err := blockUnsupported(); err != nil {
			return nil, err
		}
		a, ip, ttl, err := checkBlock(args)
		if err != nil {
			return nil, err
		}
		if err := blockGate(ctx, env, ip, a.OverrideUnverified); err != nil {
			return nil, err
		}
		if err := ensureTable(ctx); err != nil {
			return nil, err
		}
		elem := fmt.Sprintf("{ %s timeout %ds }", ip, int(ttl.Seconds()))
		if err := nft(ctx, "add", "element", "inet", nftTable, setFor(ip), elem); err != nil {
			return nil, err
		}
		return map[string]any{"blocked": ip.String(), "until": time.Now().Add(ttl), "undo": "unblock_ip " + ip.String()}, nil
	},
}

var unblockIP = Tool{
	Name:        "unblock_ip",
	Description: "Remove an IP address that block_ip blocked. Requires the operator to confirm.",
	Control:     true,
	Params: schema(`{"type":"object","required":["ip"],"properties":{
		"ip":{"type":"string"}}}`),
	Preview: func(args json.RawMessage) (string, error) {
		var a ipArgs
		if err := decode(args, &a); err != nil {
			return "", err
		}
		ip := net.ParseIP(a.IP)
		if ip == nil {
			return "", errors.New("not an IP address: " + a.IP)
		}
		return fmt.Sprintf("nft delete element inet %s %s { %s }", nftTable, setFor(ip), ip), nil
	},
	Run: func(ctx context.Context, env *Env, args json.RawMessage) (any, error) {
		var a ipArgs
		if err := decode(args, &a); err != nil {
			return nil, err
		}
		ip := net.ParseIP(a.IP)
		if ip == nil {
			return nil, errors.New("not an IP address: " + a.IP)
		}
		if err := nft(ctx, "delete", "element", "inet", nftTable, setFor(ip), "{ "+ip.String()+" }"); err != nil {
			return nil, err
		}
		return map[string]any{"unblocked": ip.String()}, nil
	},
}

// checkBlock validates block_ip arguments, including the self-lockout guards.
func checkBlock(args json.RawMessage) (ipArgs, net.IP, time.Duration, error) {
	var a ipArgs
	if err := decode(args, &a); err != nil {
		return a, nil, 0, err
	}
	ip := net.ParseIP(strings.TrimSpace(a.IP))
	if ip == nil {
		return a, nil, 0, coded(BlockNotCanonical, errors.New("not a single IP address (ranges are not allowed): "+a.IP))
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
		return a, nil, 0, coded(BlockInternal, errors.New("refusing to block a loopback, unspecified, multicast or link-local address"))
	}
	if ownAddrs()[ip.String()] {
		return a, nil, 0, coded(BlockInternal, errors.New("refusing to block one of this server's own addresses"))
	}
	if infraAddrs()[ip.String()] {
		return a, nil, 0, coded(BlockLockout, errors.New("refusing to block this server's default gateway or DNS server"))
	}
	peers, err := SSHPeers()
	if err != nil {
		return a, nil, 0, coded(BlockStateError, errors.New("refusing to block: "+err.Error()+"; the IP may be the operator's"))
	}
	if peers[ip.String()] {
		return a, nil, 0, coded(BlockLockout, errors.New("refusing to block an IP with an active SSH session to this server (it may be the operator)"))
	}
	ttl := 24 * time.Hour
	if a.TTL != "" {
		d, err := time.ParseDuration(a.TTL)
		if err != nil || d <= 0 {
			return a, nil, 0, errors.New("invalid ttl: " + a.TTL)
		}
		ttl = d
	}
	if ttl > 720*time.Hour {
		ttl = 720 * time.Hour
	}
	return a, ip, ttl, nil
}

func setFor(ip net.IP) string {
	if ip.To4() != nil {
		return "block4"
	}
	return "block6"
}

func ownAddrs() map[string]bool {
	m := map[string]bool{}
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			m[normIP(n.IP)] = true
		}
	}
	return m
}

// infraAddrs returns the default gateways and DNS servers; blocking them would cut the server off.
func infraAddrs() map[string]bool {
	m := map[string]bool{}
	for _, f := range []string{"/etc/resolv.conf", "/run/systemd/resolve/resolv.conf"} {
		b, _ := os.ReadFile(f)
		for _, l := range strings.Split(string(b), "\n") {
			if f := strings.Fields(l); len(f) >= 2 && f[0] == "nameserver" {
				if ip := net.ParseIP(f[1]); ip != nil {
					m[normIP(ip)] = true
				}
			}
		}
	}
	// /proc/net/route: Iface Destination Gateway ..., hex in host (little-endian) byte order.
	b, _ := os.ReadFile("/proc/net/route")
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Fields(l)
		if len(f) > 2 && f[1] == "00000000" && len(f[2]) == 8 && f[2] != "00000000" {
			var v [4]byte
			if _, err := fmt.Sscanf(f[2], "%02x%02x%02x%02x", &v[3], &v[2], &v[1], &v[0]); err == nil {
				m[net.IP(v[:]).String()] = true
			}
		}
	}
	// /proc/net/ipv6_route: dest dest_len src src_len next_hop ...
	b, _ = os.ReadFile("/proc/net/ipv6_route")
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Fields(l)
		if len(f) > 4 && f[1] == "00" && f[4] != strings.Repeat("0", 32) {
			if ip := net.ParseIP(hexToIPv6(f[4])); ip != nil {
				m[normIP(ip)] = true
			}
		}
	}
	return m
}

func hexToIPv6(h string) string {
	if len(h) != 32 {
		return ""
	}
	var parts []string
	for i := 0; i < 32; i += 4 {
		parts = append(parts, h[i:i+4])
	}
	return strings.Join(parts, ":")
}

func ensureTable(ctx context.Context) error {
	if exec.CommandContext(ctx, "nft", "list", "table", "inet", nftTable).Run() == nil {
		return nil
	}
	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(nftSetup)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("creating nftables table: %v: %s", err, out)
	}
	return nil
}

func nft(ctx context.Context, args ...string) error {
	if out, err := exec.CommandContext(ctx, "nft", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("nft %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
