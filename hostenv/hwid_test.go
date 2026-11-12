package hostenv

import (
	"strings"
	"testing"
)

// N3: MAC addresses, DUIDs and IAIDs are masked; times are not.
func TestMaskHardwareIDs(t *testing.T) {
	m := &Masker{}
	m.init()
	mac := "00:0c:29:59:f3:3f"
	in := "Nov 12 14:06:33 vm dhcpcd[1]: eth0: IAID 29:59:f3:3f\n" +
		"eth0: DUID 00:04:9a:1b:2c:3d:4e:5f:60:71:82:93:a4:b5:c6:d7:e8:f9\n" +
		"link/ether " + strings.ToUpper(mac) + " brd ff:ff:ff:ff:ff:ff, again " + mac + ", win 00-0C-29-59-F3-3F\n"
	got := m.text(in, true, true)
	for _, leak := range []string{"29:59:f3:3f", "9a:1b:2c", "0c:29:59", "0C-29-59", "0C:29:59"} {
		if strings.Contains(got, leak) {
			t.Errorf("%q left in:\n%s", leak, got)
		}
	}
	if !strings.Contains(got, "Nov 12 14:06:33") {
		t.Errorf("a time was masked:\n%s", got)
	}
	// One MAC, one placeholder, whatever its case or separator.
	if ph := m.hwID(mac); strings.Count(got, ph) != 2 || !strings.Contains(got, strings.ReplaceAll(ph, ":", "-")) {
		t.Errorf("MAC placeholders differ:\n%s", got)
	}
	if again := m.text(got, true, true); again != got {
		t.Errorf("masking twice changed it:\n%s\nfirst:\n%s", again, got)
	}
}

// Other spellings of the same ids, and host names holding hex pairs.
func TestMaskHardwareIDForms(t *testing.T) {
	m := &Masker{Hosts: []string{"nas-00-11-22-33"}}
	m.init()
	padded := m.text("mac 00:0c:29:59:f3:3f", true, true)
	got := m.text("arp 0:c:29:59:f3:3f duid 00-01-00-01-2c-3d-4e-5f-00-0c-29-59-f3-3f cisco 000c.2959.f33f host nas-00-11-22-33", true, true)
	for _, leak := range []string{"c:29:59", "2c-3d-4e", "2959", "nas-", "11-22"} {
		if strings.Contains(got, leak) {
			t.Errorf("%q left in: %s", leak, got)
		}
	}
	if !strings.Contains(got, "host host1") {
		t.Errorf("host name not replaced whole: %s", got)
	}
	if want := strings.TrimPrefix(padded, "mac "); !strings.Contains(got, "arp "+want) {
		t.Errorf("unpadded MAC got another placeholder than %s: %s", want, got)
	}
}

// Mixed padding is taken whole, and a short name cannot split an id.
func TestMaskHardwareIDMixed(t *testing.T) {
	m := &Masker{Users: []string{"f3"}}
	m.init()
	got := m.text("a 00:0c:29:59:f:3f b 00:0c:29:59:f3:3f user f3 ver 1:2:3:4 iaid 29:59:f3:3f:1", true, true)
	for _, leak := range []string{"59:f", "0c:29", ":3f", "29:59"} {
		if strings.Contains(got, leak) {
			t.Errorf("%q left in: %s", leak, got)
		}
	}
	if !strings.Contains(got, "user user1") || !strings.Contains(got, "ver 1:2:3:4") {
		t.Errorf("%s", got)
	}
}

// Round-2 review: what only looks like a hardware id stays as it is.
func TestMaskHardwareIDLookalikes(t *testing.T) {
	m := &Masker{}
	m.init()
	for _, keep := range []string{
		"inet6 2001:db8:0:0:1:2:3:4/64",                           // IPv6 with 3- and 4-digit groups
		"via fe80::a:b:c:d dev eth0",                              // after ::
		"route 2001:db8::1:2:3:4",                                 // after ::
		"MD5:12:34:56:78:9a:bc:de:f0:12:34:56:78:9a:bc:de:f0 key", // fingerprint
		"12:34:56:78:9a:bc:de:f0:12:34:56:78:9a:bc:de:f0 (RSA)",   // bare MD5 fingerprint
		"Name=ip-10-20-30-40.ec2.internal",                        // a cloud host name
	} {
		if got := m.text(keep, false, true); got != keep {
			t.Errorf("%q masked as a hardware id: %q", keep, got)
		}
	}
	// Real ids are still masked.
	got := m.text("link/ether 00:0c:29:59:f3:3f iaid 29:59:f3:3f win 00-0C-29-59-F3-3F", false, true)
	for _, leak := range []string{"0c:29:59", "29:59:f3:3f", "0C-29-59"} {
		if strings.Contains(got, leak) {
			t.Errorf("%q left in %q", leak, got)
		}
	}
}
