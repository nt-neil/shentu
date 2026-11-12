// Package hostenv is Shentu's host environment module: the core that sits
// beside the rules engine. The rules engine reads source code; hostenv reads
// the machine. It detects the platform, runs read-only commands, reads system
// files and APIs, and turns what it finds into normalized host facts
// (schema hostfacts/1). Checks in package checks consume only those facts and
// never touch the OS, so one check covers every platform that has a collector.
//
// Layers:
//
//	Source     how raw data is obtained: the live machine, a recording of it
//	           (Recorder), or a fixture played back (Replay). Only Source
//	           touches the OS.
//	parsers    pure functions in this package (ParseOSRelease, ParseProcNet,
//	           ...) from raw bytes to fact values. No build tags, so every
//	           platform's parsers are tested on every platform.
//	Collector  one per platform family (LinuxCollector, ...). It asks a
//	           Source for raw data and fills a Facts with parser output.
//
// Rules for anything that runs a command (see Runner):
//   - read-only, exact-argv allowlist, absolute paths, no shell
//   - timeout, stdout/stderr caps, fixed minimal environment, no stdin
//   - file contents reach parsers raw (masking them corrupted facts);
//     what leaves as text is masked where it leaves: command lines and
//     commands in facts, streamed log lines, fixtures
//   - a permission problem is reported as StatusUnknown with
//     ReasonPermission, never as "nothing found"
package hostenv
