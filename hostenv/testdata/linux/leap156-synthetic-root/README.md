# leap156-synthetic-root: SYNTHETIC, not recorded on a real host

This fixture is `rocky9-root` (recorded on a Rocky Linux 9.8 VM) with three
answers replaced by openSUSE Leap 15.6 values:

- `/etc/os-release`
- `/proc/sys/kernel/osrelease`
- `rpm -qa` (a short, hand-written Leap 15.6 package list)

Everything else (accounts, services, sshd, firewall, logs) is the Rocky host.
It exists to test the Leap paths that depend only on those three answers:
platform detection, the `openSUSE:Leap 15.6` OSV ecosystem, the `vr`
version format and the `zypper patch` upgrade command. `facts.golden.json`
beside it is generated from this synthetic input, not from a real Leap host.

Why synthetic: the Leap 15.6 Minimal-VM Cloud image booted on the test VM but
never sent a DHCP request (vmxnet3 and e1000e both tried), so no real
recording could be made. Replace it with a real recording when one is possible.

Built by: scratch script `mkleap.py rocky9-root leap156-synthetic-root`
(2026-11-12).
