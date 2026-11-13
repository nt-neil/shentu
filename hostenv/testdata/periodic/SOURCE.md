`defaults-periodic.conf` is the stock `/etc/defaults/periodic.conf` of macOS as published in Apple's
open source crontabs project: https://github.com/apple-oss-distributions/crontabs, tag
`crontabs-64.60.1`, file `files/periodic.conf` (unchanged; it is FreeBSD's
`src/etc/defaults/periodic.conf`, see its header). It is not from any machine.

`stockPeriodicDefaults` in darwin.go holds the sha256 (line ends normalized to `\n`) of every
version of that file in the project's tags: crontabs-63 to 64.60.1, 59.140.1, 52.80.1 to 59, and
46.1 to 52. Older tags have no such file.
