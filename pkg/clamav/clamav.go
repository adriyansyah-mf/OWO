// Package clamav runs ClamAV scans and auto-installs if missing.
package clamav

import (
	"bufio"
	"bytes"
	"context"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// ScanResult is one infected file or scan summary.
type ScanResult struct {
	Path     string `json:"path"`
	Virus    string `json:"virus,omitempty"`
	Status   string `json:"status"` // "infected", "ok", "error"
	Scanned  int    `json:"scanned"`
	Infected int    `json:"infected"`
}

// EnsureInstalled tries to install ClamAV if clamscan is not found.
func EnsureInstalled() bool {
	if _, err := exec.LookPath("clamscan"); err == nil {
		return true
	}
	log.Println("clamav: clamscan not found, attempting auto-install...")
	// Try apt (Debian/Ubuntu)
	if _, err := exec.LookPath("apt-get"); err == nil {
		cmd := exec.Command("apt-get", "update")
		cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
		if err := cmd.Run(); err != nil {
			log.Printf("clamav: apt-get update: %v", err)
		}
		installCmd := exec.Command("apt-get", "install", "-y", "clamav", "clamav-daemon")
		installCmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
		if err := installCmd.Run(); err != nil {
			installCmd = exec.Command("sudo", "apt-get", "install", "-y", "clamav", "clamav-daemon")
			installCmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
			if err := installCmd.Run(); err != nil {
				log.Printf("clamav: install failed (run as root or: apt install clamav clamav-daemon)")
				return false
			}
		}
		log.Println("clamav: installed via apt")
		// Download virus DB (exit 2 = database missing)
		if fc, err := exec.LookPath("freshclam"); err == nil {
			log.Println("clamav: updating virus database (freshclam)...")
			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, fc)
			if out, err := cmd.CombinedOutput(); err != nil {
				log.Printf("clamav: freshclam: %v (output: %s)", err, string(out))
			} else {
				log.Println("clamav: virus database ready")
			}
		}
		return true
	}
	// Try dnf (Fedora/RHEL8+)
	if _, err := exec.LookPath("dnf"); err == nil {
		cmd := exec.Command("dnf", "install", "-y", "clamav", "clamav-update")
		if err := cmd.Run(); err != nil {
			log.Printf("clamav: dnf install: %v", err)
			return false
		}
		log.Println("clamav: installed via dnf")
		return true
	}
	// Try yum (RHEL7)
	if _, err := exec.LookPath("yum"); err == nil {
		cmd := exec.Command("yum", "install", "-y", "clamav", "clamav-update")
		if err := cmd.Run(); err != nil {
			log.Printf("clamav: yum install: %v", err)
			return false
		}
		log.Println("clamav: installed via yum")
		return true
	}
	log.Println("clamav: no supported package manager (apt/dnf/yum)")
	return false
}

// RunScan runs clamscan on paths. Returns results and any error.
func RunScan(paths []string) ([]ScanResult, error) {
	if len(paths) == 0 {
		paths = []string{"/tmp", "/var/tmp", "/home"}
	}
	// Ensure paths exist and are safe
	var safePaths []string
	for _, p := range paths {
		p = filepath.Clean(p)
		if p == "" || p == "." || strings.HasPrefix(p, "..") {
			continue
		}
		if _, err := os.Stat(p); err == nil {
			safePaths = append(safePaths, p)
		}
	}
	if len(safePaths) == 0 {
		return []ScanResult{{Status: "error", Path: "no valid paths"}}, nil
	}

	args := []string{"-r", "--no-summary"}
	args = append(args, safePaths...)
	cmd := exec.Command("clamscan", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	out := stdout.String() + stderr.String()

	// Exit 2 = database missing/corrupt, coba freshclam lalu retry
	if err != nil {
		serr := stderr.String()
		if strings.Contains(serr, "Can't open") || strings.Contains(serr, "database") || strings.Contains(serr, "ERROR") {
			if fc, lookErr := exec.LookPath("freshclam"); lookErr == nil {
				log.Println("clamav: database belum siap, menjalankan freshclam...")
				ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
				exec.CommandContext(ctx, fc).Run()
				cancel()
				cmd = exec.Command("clamscan", args...)
				stdout.Reset()
				stderr.Reset()
				cmd.Stdout = &stdout
				cmd.Stderr = &stderr
				err = cmd.Run()
				out = stdout.String() + stderr.String()
			}
		}
	}

	var results []ScanResult
	scanned, infected := 0, 0

	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "---") {
			continue
		}
		// Infected: /path/to/file: Virus.Name FOUND
		if strings.HasSuffix(line, " FOUND") {
			idx := strings.LastIndex(line, ": ")
			if idx > 0 {
				path := strings.TrimSpace(line[:idx])
				virus := strings.TrimSuffix(strings.TrimSpace(line[idx+2:]), " FOUND")
				results = append(results, ScanResult{
					Path:   path,
					Virus:  virus,
					Status: "infected",
				})
				infected++
			}
			continue
		}
		// OK: /path/to/file: OK
		if strings.HasSuffix(line, ": OK") {
			scanned++
		}
	}

	// Summary
	results = append([]ScanResult{{
		Status:   "summary",
		Scanned:  scanned + infected,
		Infected: infected,
	}}, results...)

	return results, err
}

// ScanFile scans a single file. Returns (infected, virusName, error).
func ScanFile(path string) (bool, string, error) {
	path = filepath.Clean(path)
	if path == "" || path == "." || strings.HasPrefix(path, "..") {
		return false, "", nil
	}
	if _, err := os.Stat(path); err != nil {
		return false, "", nil
	}
	cmd := exec.Command("clamscan", "--no-summary", path)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	_ = cmd.Run()
	out := stdout.String() + stderr.String()
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasSuffix(line, " FOUND") {
			idx := strings.LastIndex(line, ": ")
			if idx > 0 {
				virus := strings.TrimSuffix(strings.TrimSpace(line[idx+2:]), " FOUND")
				return true, virus, nil
			}
		}
	}
	return false, "", nil
}
