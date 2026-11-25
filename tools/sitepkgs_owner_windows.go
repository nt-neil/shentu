package tools

// rootOnlyFile: no Windows folder is the system package manager's (the
// prefixes osManagedPrefixes names are Unix ones).
func rootOnlyFile(string, bool) bool { return false }
