//go:build windows

package hostenv

import "os"

// fixedEnv keeps only what Windows binaries need to start. Phase 2 avoids
// commands on Windows altogether (registry, SCM and WMI instead), so this is
// a floor, not an invitation.
func fixedEnv() []string {
	env := []string{"LANG=C"}
	for _, k := range []string{"SystemRoot", "windir", "SystemDrive"} {
		if v := os.Getenv(k); v != "" {
			env = append(env, k+"="+v)
		}
	}
	return env
}
