// Package enrich adds EDR context to exec events: SHA256, inode, TTY, container.
package enrich

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const maxReadSize = 32 * 1024 * 1024 // 32MB max for hash

// ExecContext holds enriched fields for an exec event.
type ExecContext struct {
	SHA256       string // hex-encoded SHA256 of binary (empty if unreadable)
	Inode        uint64
	IsTTY        bool
	ContainerID  string // short id if in container (e.g. docker/k8s)
	LoadTime     int64  // unix nano when we observed (caller sets)
	SignedStatus string // "unknown" | "signed" | "unsigned" (stub)
}

// EnrichExec computes SHA256, inode, TTY, container for path (binary) and pid.
func EnrichExec(binaryPath string, pid uint32) ExecContext {
	ctx := ExecContext{SignedStatus: "unknown"}
	if binaryPath == "" || binaryPath == "-" {
		return ctx
	}
	path := binaryPath
	if !filepath.IsAbs(path) {
		path = filepath.Clean("/" + path)
	}
	// Inode
	if fi, err := os.Stat(path); err == nil {
		if stat, ok := fi.Sys().(*syscall.Stat_t); ok {
			ctx.Inode = stat.Ino
		}
	}
	// SHA256 of binary (read first N bytes to avoid huge files)
	if f, err := os.Open(path); err == nil {
		defer f.Close()
		buf := make([]byte, maxReadSize)
		n, _ := f.Read(buf)
		if n > 0 {
			sum := sha256.Sum256(buf[:n])
			ctx.SHA256 = hex.EncodeToString(sum[:])
		}
	}
	// TTY: check if stdin is a tty for this pid
	ctx.IsTTY = isTTY(pid)
	// Container: from cgroup
	ctx.ContainerID = containerID(pid)
	return ctx
}

func isTTY(pid uint32) bool {
	fd0 := fmt.Sprintf("/proc/%d/fd/0", pid)
	lnk, err := os.Readlink(fd0)
	if err != nil {
		return false
	}
	return strings.HasPrefix(lnk, "/dev/pts/") || strings.HasPrefix(lnk, "/dev/tty")
}

func containerID(pid uint32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, "docker") || strings.Contains(line, "kubepods") || strings.Contains(line, "containerd") {
			// e.g. 0::/docker/abc123 -> abc123
			parts := strings.Split(line, "/")
			for i, p := range parts {
				if (p == "docker" || p == "kubepods" || p == "containerd") && i+1 < len(parts) {
					id := parts[i+1]
					if len(id) > 12 {
						id = id[:12]
					}
					return id
				}
			}
		}
	}
	return ""
}
