# macos27-synthetic-user: SYNTHETIC, not recorded on a real host

An invented macOS 27.2 (arm64) host, run as the ordinary user `alice`, with nothing taken
from a real machine. A generator answers the darwin collector's reads and commands from
hand-written values; `hostenv.Recorder` saves them as for a real recording, and
`facts.golden.json` beside it is generated from this input.

The host: users root, daemon, nobody, _www, _sshd and alice (admin); launchd on *:22,
ExampleDB (/opt/example/bin/exampledb) on 127.0.0.1:7777 and mDNSResponder on *:5353; ExampleEditor 4.2.1, Safari and
Terminal; Homebrew openssl@3 3.4.0 and exampledb@2 2.1; one LaunchDaemon
(com.example.backup) and one user LaunchAgent (com.example.sync); application firewall on,
SIP on, Gatekeeper on, FileVault on; pfctl refused (not root).

Why synthetic: a recording of a real Mac carries its listening ports, installed software
and paths. Replace this with a recording of a clean, throwaway macOS host (for example a
CI runner) when one is made.
