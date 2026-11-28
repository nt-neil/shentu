package main

import (
	"fmt"
	"reflect"
	"strconv"
	"time"

	"github.com/nt-neil/shentu/rules/engine"
)

// Scan paths: how a release's files are scanned.
//
//   - product: as app_code_audit does (tools/codeaudit.go): each file on its own
//     first (Engine.ScanTimed), then what following calls across the files finds
//     (Project.ScanCallsPart, every rule at once), merged by rule, path and line.
//     A finding of the first pass stays when the calls across files show its
//     check: the report counts what a user is shown.
//   - project: Project.Scan, one pass that follows calls across the files and
//     decides each flow with them, so a check written in another file takes a
//     finding away. It is kept to compare with (the most a project-level
//     check could take away), not as the verdict.
//   - per-file: each file on its own (Engine.ScanFile), no calls across files.
const (
	pathProduct = "product"
	pathProject = "project"
	pathPerFile = "per-file"
)

// projectOptions are the project caps a cvebench run uses. app_code_audit sets
// MaxTime, MaxHeap and MaxTokens from the machine's budget and the audit's
// time left, and goes on in the next audit from where a cap stopped it; one
// cvebench pass stands for that audit gone to its end, so it takes the engine's
// defaults, written out here so the report can say them. MaxWork is the
// engine's default, as in app_code_audit.
var projectOptions = engine.ProjectOptions{
	MaxTime:   15 * time.Minute,
	MaxHeap:   1 << 30,
	MaxTokens: 3_000_000,
	MaxWork:   engine.DefaultProjectWork,
}

// scanPathNote is the report's line on how releases were scanned.
func scanPathNote(path string) string {
	switch path {
	case pathPerFile:
		return "scan path: per-file (each file on its own, no calls across files)"
	case pathProject:
		return fmt.Sprintf("scan path: project (Project.Scan; a check in another file takes the finding away, unlike app_code_audit); project caps MaxTime %s, MaxHeap %d MiB, MaxTokens %s, MaxWork %s",
			projectOptions.MaxTime, projectOptions.MaxHeap>>20, strconv.Itoa(projectOptions.MaxTokens), strconv.Itoa(projectOptions.MaxWork))
	}
	return fmt.Sprintf("scan path: product (as app_code_audit: each file on its own, then the calls across files, merged; no audit clock, no list cap); project caps MaxTime %s, MaxHeap %d MiB, MaxTokens %s, MaxWork %s",
		projectOptions.MaxTime, projectOptions.MaxHeap>>20, strconv.Itoa(projectOptions.MaxTokens), strconv.Itoa(projectOptions.MaxWork))
}

// scanned is one file's scan: its findings, the errors of each pass (for the
// unfinished and calls-cut counts) and whether a clock cut it short, which
// makes the result depend on how busy the machine was.
type scanned struct {
	found []engine.Finding
	errs  []error
	timed bool
}

// projectScanner returns the scan of one file for the path, following calls
// across the release's files when the engine can (Engine.NewProject); ok is
// false for an engine that only scans file by file. Methods are looked up by
// name, like the library mode, so that cvebench builds against either engine.
func projectScanner(eng *engine.Engine, files []string, read func(string) ([]byte, error), path string, opts engine.ProjectOptions) (func(string, []byte) scanned, func() bool, bool) {
	m := reflect.ValueOf(eng).MethodByName("NewProject")
	if !m.IsValid() || m.Type().NumIn() != 3 || m.Type().In(2) != reflect.TypeOf(opts) {
		return nil, nil, false
	}
	proj := m.Call([]reflect.Value{reflect.ValueOf(files), reflect.ValueOf(read), reflect.ValueOf(opts)})[0]
	// namesIncomplete: whether the receivers kept every method sink (an engine
	// without Project.NamesComplete has no receivers)
	namesIncomplete := func() bool {
		if nc := proj.MethodByName("NamesCompleteFor"); nc.IsValid() {
			return !nc.Call([]reflect.Value{reflect.ValueOf("php")})[0].Bool() // receivers are PHP rules'
		}
		nc := proj.MethodByName("NamesComplete")
		return nc.IsValid() && !nc.Call(nil)[0].Bool()
	}
	if path == pathProject {
		scan := proj.MethodByName("Scan")
		if !scan.IsValid() {
			return nil, nil, false
		}
		return func(rel string, src []byte) scanned {
			out := scan.Call([]reflect.Value{reflect.ValueOf(rel), reflect.ValueOf(src)})
			fs, _ := out[0].Interface().([]engine.Finding)
			err, _ := out[1].Interface().(error)
			return scanned{found: fs, errs: []error{err}}
		}, namesIncomplete, true
	}
	own := reflect.ValueOf(eng).MethodByName("ScanTimed")
	calls := proj.MethodByName("ScanCallsPart")
	if !own.IsValid() || !calls.IsValid() {
		return nil, nil, false
	}
	noSkip := reflect.Zero(calls.Type().In(2)) // every rule in this pass
	return productScan(func(rel string, src []byte) ([]engine.Finding, bool, error) {
		o := own.Call([]reflect.Value{reflect.ValueOf(engine.LangOf(rel)), reflect.ValueOf(rel), reflect.ValueOf(src)})
		fs, _ := o[0].Interface().([]engine.Finding)
		err, _ := o[2].Interface().(error)
		return fs, o[1].Bool(), err
	}, func(rel string, src []byte) (engine.CallsPart, error) {
		c := calls.Call([]reflect.Value{reflect.ValueOf(rel), reflect.ValueOf(src), noSkip})
		part, _ := c[0].Interface().(engine.CallsPart)
		err, _ := c[1].Interface().(error)
		return part, err
	}), namesIncomplete, true
}

// productScan is the product path's scan of one file: own is the file on its
// own (ScanTimed), calls what following calls across files finds
// (ScanCallsPart), merged as app_code_audit does.
func productScan(own func(string, []byte) ([]engine.Finding, bool, error), calls func(string, []byte) (engine.CallsPart, error)) func(string, []byte) scanned {
	return func(rel string, src []byte) scanned {
		var s scanned
		fs, timed, err := own(rel, src)
		s.timed = timed
		s.errs = append(s.errs, err)
		part, err := calls(rel, src)
		s.errs = append(s.errs, callsErr(part, err))
		s.timed = s.timed || part.Timed
		// merged as app_code_audit does: once per rule, path and line
		seen := map[string]bool{}
		for _, f := range append(fs, part.Found...) {
			k := f.RuleID + "\x00" + f.Path + "\x00" + strconv.Itoa(f.Line)
			if !seen[k] {
				seen[k] = true
				s.found = append(s.found, f)
			}
		}
		return s
	}
}

// callsErr is the error a calls pass counts as: a cap that cut a rule's calls
// short (part.Cut) counts as ErrCalls when the pass returned no error of its own.
func callsErr(part engine.CallsPart, err error) error {
	if err == nil && part.Cut {
		return engine.ErrCalls
	}
	return err
}
