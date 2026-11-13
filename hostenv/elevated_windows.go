//go:build windows

package hostenv

// elevated is false until the Phase 2 Windows source checks the process
// token (TokenElevation). Reporting "not elevated" makes every
// permission-dependent fact come out unknown rather than falsely clean.
func elevated() bool { return false }
