// Package proc reads process info from /proc for EDR enrichment (ppid, cmdline).
package proc

import (
	"fmt"
	"os"
	"path/filepath"
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

// ProcInfo is a snapshot of one process (ps aux style).
type ProcInfo struct {
	Pid     int    `json:"pid"`
	Ppid    int    `json:"ppid"`
	Exe     string `json:"exe"`
	Cmdline string `json:"cmdline"`
	Uid     int    `json:"uid"`
	Gid     int    `json:"gid"`
	Comm    string `json:"comm"`
}

// ListAllProcesses reads /proc and returns current processes (like ps aux).
func ListAllProcesses() []ProcInfo {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var out []ProcInfo
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 0 {
			continue
		}
		ppid := int(PpidFromStat(uint32(pid)))
		exe := Exe(uint32(pid))
		cmdline := Cmdline(uint32(pid))
		if cmdline == "" && exe != "" {
			cmdline = filepath.Base(exe)
		}
		if cmdline == "" {
			cmdline = readComm(pid)
		}
		uid, gid := readUidGid(pid)
		comm := readComm(pid)
		out = append(out, ProcInfo{
			Pid:     pid,
			Ppid:    ppid,
			Exe:     exe,
			Cmdline: cmdline,
			Uid:     uid,
			Gid:     gid,
			Comm:    comm,
		})
	}
	return out
}

func readComm(pid int) string {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func readUidGid(pid int) (uid, gid int) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0, 0
	}
	s := string(b)
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				uid, _ = strconv.Atoi(fields[1])
			}
		}
		if strings.HasPrefix(line, "Gid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				gid, _ = strconv.Atoi(fields[1])
			}
			break
		}
	}
	return uid, gid
}
