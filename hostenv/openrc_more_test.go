package hostenv

import (
	"strings"
	"testing"
)

// N16: local scripts, custom and stacked runlevels, runlevel entries with
// no script, and /etc/inittab.
func TestOpenRCMore(t *testing.T) {
	h := newFake(true)
	h.files["/etc/init.d/sshd"] = "#!/sbin/openrc-run\n"
	h.files["/usr/local/etc/init.d/agent"] = "#!/sbin/openrc-run\n"
	h.links["/etc/runlevels/default/sshd"] = "/etc/init.d/sshd"
	h.links["/etc/runlevels/office/agent"] = "/usr/local/etc/init.d/agent" // a custom runlevel
	h.links["/etc/runlevels/office/default"] = "../default"                // stacked
	h.links["/etc/runlevels/boot/ghost"] = "/tmp/.x/ghost"                 // no script of that name
	h.files["/etc/inittab"] = "# comment\n::sysinit:/sbin/openrc sysinit\nttyS0::respawn:/sbin/getty -L 0 ttyS0 vt100\n::respawn:/tmp/.x/backdoor\n"
	h.denied["/etc/local.d"] = true
	svcs, items := LinuxCollector{}.OpenRCServices(h, nil)
	mode := map[string]string{}
	for _, s := range svcs.Value {
		mode[s.Name] = s.StartMode + " " + s.Exe
	}
	if mode["agent"] != "auto /usr/local/etc/init.d/agent" || mode["sshd"] != "auto /etc/init.d/sshd" {
		t.Errorf("services %v", mode)
	}
	if svcs.Status != StatusPartial || !strings.Contains(svcs.Detail, "/etc/local.d") {
		t.Errorf("unreadable /etc/local.d: %s %q", svcs.Status, svcs.Detail)
	}
	var got []string
	for _, it := range items {
		got = append(got, it.Kind+" "+it.Location+" "+it.Command+" "+it.Detail)
	}
	all := strings.Join(got, "\n")
	for _, want := range []string{
		"openrc /etc/runlevels/office/default  runlevel office stacks runlevel default",
		"openrc /etc/runlevels/boot/ghost  enabled in boot, but no script ghost in /etc/init.d or /usr/local/etc/init.d; links to /tmp/.x/ghost",
		"openrc /usr/local/etc/init.d/agent  enabled in office",
		"inittab /etc/inittab /tmp/.x/backdoor respawn",
		"inittab /etc/inittab /sbin/openrc sysinit sysinit",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("missing %q in:\n%s", want, all)
		}
	}
}

// N2-7: a script named like a runlevel, linked into one, is a script: it
// gets the "no package installed" mark, not a pass as a stacked runlevel.
func TestOpenRCScriptNamedLikeRunlevel(t *testing.T) {
	h := newFake(true)
	h.files["/etc/init.d/sshd"] = "#!/sbin/openrc-run\n"
	h.links["/etc/runlevels/default/sshd"] = "/etc/init.d/sshd"
	h.files["/etc/init.d/default"] = "#!/sbin/openrc-run\n"             // planted, named like a runlevel
	h.links["/etc/runlevels/boot/default"] = "/etc/init.d/default"      // enabled at boot
	h.links["/etc/runlevels/office/default"] = "/etc/runlevels/default" // a real stack
	_, items := LinuxCollector{}.OpenRCServices(h, map[string]bool{"/etc/init.d/sshd": true})
	var got []string
	for _, it := range items {
		got = append(got, it.Location+" "+it.Detail)
	}
	all := strings.Join(got, "\n")
	for _, want := range []string{
		"/etc/init.d/default enabled in boot; no package installed this script",
		"/etc/runlevels/office/default runlevel office stacks runlevel default",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("missing %q in:\n%s", want, all)
		}
	}
	if strings.Contains(all, "boot stacks") {
		t.Errorf("the script passed as a stack:\n%s", all)
	}
}
