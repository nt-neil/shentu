package hostenv

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

// macOS 15's netstat -anv: after the four counters come pid and epid, no
// process name (B-055m-1). Hand-written in that layout, from the columns
// the v0.5.5 VM acceptance named; no machine's output.
const netstat15Head = "Active Internet connections (including servers)\n" +
	"Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)      rxbytes      txbytes  rhiwat  shiwat    pid   epid  state  options           gencnt    flags   flags1 usscnt rtncnt fltrs\n"

// B-055m-1: the macOS 15 layout is read, the pid from its column and the
// name from ps; a listener ps does not name makes the list partial.
func TestDarwinListenersMacOS15(t *testing.T) {
	tcp := netstat15Head +
		"tcp4       0      0  127.0.0.1.8021         *.*                    LISTEN             0            0  131072  131072    541      0 00100 00000006 00000000000004ab 00000000 00000800      1      0 000001\n" +
		"tcp6       0      0  *.22                   *.*                    LISTEN             0            0  131072  131072      1      0 00100 00000006 00000000000004ac 00000000 00000800      1      0 000001\n" +
		"tcp4       0      0  192.0.2.10.51000       198.51.100.7.443       ESTABLISHED     3476         6659  131072  131412    902      0 00102 00000008 00000000000004ad 00000080 04000900      2      0 000001\n"
	udp := netstat15Head +
		"udp4       0      0  *.5353                 *.*                                   0            0  786896    9216    384      0 00100 00000020 00000000000004ae 00008000 00000800      1      0 000001\n" +
		"udp4       0      0  192.0.2.10.52663       198.51.100.8.443                  14952         5623 1048576   29040    902      0 00102 00000000 00000000000004af 00000000 04200900      1      0 000002\n"
	ps := "  541     1     0 root               01:00 /usr/libexec/exampled\n" +
		"    1     0     0 root          3-00:00:00 /sbin/launchd\n" +
		"  384     1    65 _mdnsresponder      02:00 /usr/sbin/mDNSResponder\n" +
		"  902     1   501 user                03:00 /Applications/Example Browser.app/Contents/MacOS/Example Browser\n"
	src := fakeMac{cmds: map[string]string{key(netstatTCPArgv): tcp, key(netstatUDPArgv): udp, key(macPsArgv): ps}}
	got := DarwinCollector{}.Listeners(context.Background(), src)
	want := []Listener{
		{Proto: "tcp6", Addr: "::", Port: 22, PID: 1, Process: "launchd"},
		{Proto: "udp", Addr: "0.0.0.0", Port: 5353, PID: 384, Process: "mDNSResponder"},
		{Proto: "tcp", Addr: "127.0.0.1", Port: 8021, PID: 541, Process: "exampled"},
	}
	if got.Status != StatusOK || !reflect.DeepEqual(got.Value, want) {
		t.Errorf("macOS 15 netstat: %+v", got)
	}

	// ps unreadable: the listeners are all there, unnamed, and that is said.
	delete(src.cmds, key(macPsArgv))
	got = DarwinCollector{}.Listeners(context.Background(), src)
	if got.Status != StatusPartial || len(got.Value) != 3 || got.Value[0].PID != 1 || !strings.Contains(got.Detail, "without a process name") {
		t.Errorf("macOS 15 without ps: %+v", got)
	}
}

// B-055m-1, fail closed: a socket line in a layout netstat's parser does
// not read means the list may lack any listener; it is never returned as
// all there is. lsof's list (partial) comes instead, and without lsof the
// listeners are unknown.
func TestDarwinListenersUnreadLine(t *testing.T) {
	tcp := netstat15Head +
		"tcp4       0      0  127.0.0.1.8021         *.*                    LISTEN             0            0  131072  131072    541      0 00100 00000006 00000000000004ab 00000000 00000800      1      0 000001\n" +
		"tcp4       0      0  *.22                   *.*                    LISTEN      launchd 1 2 3 4 5\n"
	src := fakeMac{cmds: map[string]string{key(netstatTCPArgv): tcp, key(netstatUDPArgv): netstat15Head,
		key(macPsArgv):      "  541     1     0 root               01:00 /usr/libexec/exampled\n",
		key(lsofListenArgv): "p648\ncrapportd\nf11\ntIPv4\nPTCP\nn*:49154\n"}}
	got := DarwinCollector{}.Listeners(context.Background(), src)
	want := []Listener{{Proto: "tcp", Addr: "0.0.0.0", Port: 49154, PID: 648, Process: "rapportd"}}
	if got.Status != StatusPartial || !reflect.DeepEqual(got.Value, want) || !strings.Contains(got.Detail, "not understood") {
		t.Errorf("an unread line with lsof: %+v", got)
	}
	delete(src.cmds, key(lsofListenArgv))
	if got = (DarwinCollector{}).Listeners(context.Background(), src); got.Known() {
		t.Errorf("an unread line without lsof: %+v", got)
	}
}
