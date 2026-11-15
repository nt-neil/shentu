package tools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
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
}

var blockIP = Tool{
	Name:        "block_ip",
	Description: "Block all inbound traffic from one IP address with nftables, for a limited time. Requires the operator to confirm. Refuses loopback, this server's own addresses and the IPs of current SSH sessions.",
	Control:     true,
	Params: schema(`{"type":"object","required":["ip","reason"],"properties":{
		"ip":{"type":"string","description":"single IPv4 or IPv6 address"},
		"ttl":{"type":"string","description":"how long, e.g. 1h, 24h, 168h (default 24h, max 720h)"},
		"reason":{"type":"string","description":"why, shown to the operator"}}}`),
	Preview: func(args json.RawMessage) (string, error) {
		a, ip, ttl, err := checkBlock(args)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("nft add element inet %s %s { %s timeout %ds }   # %s", nftTable, setFor(ip), ip, int(ttl.Seconds()), a.Reason), nil
	},
	Run: func(ctx context.Context, env *Env, args json.RawMessage) (any, error) {
		_, ip, ttl, err := checkBlock(args)
		if err != nil {
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
		return a, nil, 0, errors.New("not a single IP address (ranges are not allowed): " + a.IP)
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
		return a, nil, 0, errors.New("refusing to block a loopback, unspecified, multicast or link-local address")
	}
	if ownAddrs()[ip.String()] {
		return a, nil, 0, errors.New("refusing to block one of this server's own addresses")
	}
	if infraAddrs()[ip.String()] {
		return a, nil, 0, errors.New("refusing to block this server's default gateway or DNS server")
	}
	peers, err := SSHPeers()
	if err != nil {
		return a, nil, 0, errors.New("refusing to block: " + err.Error() + "; the IP may be the operator's")
	}
	if peers[ip.String()] {
		return a, nil, 0, errors.New("refusing to block an IP with an active SSH session to this server (it may be the operator)")
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
