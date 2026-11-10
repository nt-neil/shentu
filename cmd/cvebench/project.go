package main

import (
	"reflect"

	"github.com/nt-neil/shentu/rules/engine"
)

// projectScanner returns a scan that follows calls across the release's files,
// when the engine can (Engine.NewProject); ok is false for an engine that only
// scans file by file. It is looked up by name, like the library mode, so that
// cvebench builds against either engine.
func projectScanner(eng *engine.Engine, files []string, read func(string) ([]byte, error)) (func(string, []byte) ([]engine.Finding, error), bool) {
	m := reflect.ValueOf(eng).MethodByName("NewProject")
	if !m.IsValid() || m.Type().NumIn() != 3 {
		return nil, false
	}
	proj := m.Call([]reflect.Value{reflect.ValueOf(files), reflect.ValueOf(read), reflect.Zero(m.Type().In(2))})[0]
	scan := proj.MethodByName("Scan")
	if !scan.IsValid() {
		return nil, false
	}
	return func(rel string, src []byte) ([]engine.Finding, error) {
		out := scan.Call([]reflect.Value{reflect.ValueOf(rel), reflect.ValueOf(src)})
		fs, _ := out[0].Interface().([]engine.Finding)
		err, _ := out[1].Interface().(error)
		return fs, err
	}, true
}
