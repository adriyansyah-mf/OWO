// Package proc reads process info from /proc for EDR enrichment (ppid, cmdline).
package proc

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// PpidFromStat reads /proc/<pid>/stat and returns parent pid (field 4). Best-effort; returns 0 on error.
func PpidFromStat(pid uint32) uint32 {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0
	}
	// Format: pid (comm) state ppid ...
	s := string(b)
	// Find last ')' to skip (comm) which may contain spaces
	end := strings.Index(s, ") ")
	if end < 0 {
		return 0
	}
	rest := s[end+2:]
	fields := strings.Fields(rest)
	if len(fields) < 2 {
		return 0
	}
	// stat: pid (comm) state ppid ... -> after ") " we have state, ppid, ...
	ppid, _ := strconv.ParseUint(fields[1], 10, 32)
	return uint32(ppid)
}

// Cmdline reads /proc/<pid>/cmdline (null-separated) and returns a single line with spaces.
func Cmdline(pid uint32) string {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return ""
	}
	// Replace \0 with space; trim
	return strings.TrimSpace(strings.ReplaceAll(string(b), "\x00", " "))
}

// Exe returns the resolved path of /proc/<pid>/exe (best-effort).
func Exe(pid uint32) string {
	p := fmt.Sprintf("/proc/%d/exe", pid)
	s, err := os.Readlink(p)
	if err != nil {
		return ""
	}
	return s
}
