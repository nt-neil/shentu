//go:build windows

package hostenv

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// fileUID has no meaning on Windows: owners are SIDs (Phase 2).
func fileUID(os.FileInfo) int { return -1 }

// fileID cannot be had from a FileInfo on Windows: see openedFileID and
// pathFileID, which ask the file system ("" means unknown).
func fileID(os.FileInfo) string { return "" }

// openedFileID is "volume serial:file index" of an open file, as
// GetFileInformationByHandle reports it: what os.SameFile compares.
func openedFileID(f *os.File, _ os.FileInfo) string {
	return handleFileID(windows.Handle(f.Fd()))
}

// pathFileID is openedFileID for a path, following links as os.Stat does.
// The file is opened for its attributes only, shared with every other
// opener, so reading it locks nothing.
func pathFileID(p string, _ os.FileInfo) string {
	p16, err := windows.UTF16PtrFromString(p)
	if err != nil {
		return ""
	}
	h, err := windows.CreateFile(p16, windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)
	return handleFileID(h)
}

func handleFileID(h windows.Handle) string {
	var fi windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &fi); err != nil {
		return ""
	}
	return fmt.Sprintf("%d:%d", fi.VolumeSerialNumber, uint64(fi.FileIndexHigh)<<32|uint64(fi.FileIndexLow))
}
