package main

import (
	"errors"
	"reflect"

	"github.com/nt-neil/shentu/rules/engine"
)

// setLibrary turns on the engine's library mode. It is looked up by name so
// that cvebench still builds against an engine that predates the mode, which is
// what comparing engine versions needs.
func setLibrary(e *engine.Engine) error {
	f := reflect.ValueOf(e).Elem().FieldByName("Library")
	if !f.IsValid() || f.Kind() != reflect.Bool {
		return errors.New("this engine has no library mode")
	}
	f.SetBool(true)
	return nil
}
