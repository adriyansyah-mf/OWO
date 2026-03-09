// Package ir handles incident response commands (isolate, kill, collect).
package ir

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/nats-io/nats.go"
)

// OnScanFunc is called when scan or deep_scan command is received.
type OnScanFunc func()

// OnAVScanFunc is called when av_scan command is received. Params may contain "paths" ([]interface{}).
type OnAVScanFunc func(params map[string]interface{})

// OnDLPScanFunc is called when dlp_scan command is received. Params may contain "paths" ([]interface{}).
type OnDLPScanFunc func(params map[string]interface{})

// Listener subscribes to IR commands and executes them.
type Listener struct {
	nc         *nats.Conn
	tenantID   string
	hostID     string
	sub        *nats.Subscription
	mu         sync.Mutex
	isolated   bool
	onScan     OnScanFunc    // optional: trigger process snapshot
	onDeepScan OnScanFunc    // optional: scan + triage
	onAVScan   OnAVScanFunc  // optional: ClamAV scan
	onDLPScan  OnDLPScanFunc // optional: DLP content scan
}

// NewListener creates an IR listener.
func NewListener(nc *nats.Conn, tenantID, hostID string) *Listener {
	return &Listener{nc: nc, tenantID: tenantID, hostID: hostID}
}

// SetOnScan sets callback for scan command (immediate process snapshot).
func (l *Listener) SetOnScan(f OnScanFunc) { l.onScan = f }

// SetOnDeepScan sets callback for deep_scan (scan + triage).
func (l *Listener) SetOnDeepScan(f OnScanFunc) { l.onDeepScan = f }

// SetOnAVScan sets callback for av_scan (ClamAV).
func (l *Listener) SetOnAVScan(f OnAVScanFunc) { l.onAVScan = f }

// SetOnDLPScan sets callback for dlp_scan (DLP).
func (l *Listener) SetOnDLPScan(f OnDLPScanFunc) { l.onDLPScan = f }

// Start subscribes to ir.{tenant}.{host} and handles commands.
func (l *Listener) Start() error {
	subj := "ir." + l.tenantID + "." + l.hostID
	sub, err := l.nc.Subscribe(subj, func(m *nats.Msg) {
		var cmd map[string]interface{}
		if json.Unmarshal(m.Data, &cmd) != nil {
			return
		}
		action, _ := cmd["action"].(string)
		params, _ := cmd["params"].(map[string]interface{})
		l.execute(action, params)
	})
	if err != nil {
		return err
	}
	l.sub = sub
	log.Printf("ir: listening on %s", subj)
	return nil
}

// Stop unsubscribes.
func (l *Listener) Stop() {
	if l.sub != nil {
		l.sub.Unsubscribe()
	}
}

func (l *Listener) execute(action string, params map[string]interface{}) {
	switch action {
	case "isolate":
		l.isolate()
	case "release":
		l.release()
	case "kill_process":
		l.killProcess(params)
	case "collect_triage":
		l.collectTriage(params)
	case "scan":
		if l.onScan != nil {
			l.onScan()
			log.Println("ir: scan completed (process snapshot sent)")
		} else {
			log.Println("ir: scan requested but no handler set")
		}
	case "deep_scan":
		if l.onDeepScan != nil {
			l.onDeepScan()
		} else if l.onScan != nil {
			l.onScan()
		}
		l.collectTriage(map[string]interface{}{"paths": []interface{}{"/tmp", "/var/log", "/etc"}, "artifact_name": "deep_scan"})
		log.Println("ir: deep_scan completed (snapshot + triage)")
	case "av_scan":
		if l.onAVScan != nil {
			l.onAVScan(params)
			log.Println("ir: av_scan completed")
		} else {
			log.Println("ir: av_scan requested but no handler set")
		}
	case "dlp_scan":
		if l.onDLPScan != nil {
			l.onDLPScan(params)
			log.Println("ir: dlp_scan completed")
		} else {
			log.Println("ir: dlp_scan requested but no handler set")
		}
	default:
		log.Printf("ir: unknown action %s", action)
	}
}

func (l *Listener) isolate() {
	l.mu.Lock()
	if l.isolated {
		l.mu.Unlock()
		return
	}
	l.isolated = true
	l.mu.Unlock()

	// iptables: DROP all except lo and established
	// Allow loopback, allow established, drop rest on OUTPUT and INPUT
	cmd := exec.Command("iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT")
	if err := cmd.Run(); err != nil {
		log.Printf("ir isolate: iptables lo: %v", err)
		return
	}
	cmd = exec.Command("iptables", "-A", "OUTPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT")
	if err := cmd.Run(); err != nil {
		log.Printf("ir isolate: iptables established: %v", err)
		return
	}
	cmd = exec.Command("iptables", "-A", "OUTPUT", "-j", "DROP")
	if err := cmd.Run(); err != nil {
		log.Printf("ir isolate: iptables drop: %v", err)
		return
	}
	cmd = exec.Command("iptables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT")
	if err := cmd.Run(); err != nil {
		log.Printf("ir isolate: iptables input lo: %v", err)
		return
	}
	cmd = exec.Command("iptables", "-A", "INPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT")
	if err := cmd.Run(); err != nil {
		log.Printf("ir isolate: iptables input established: %v", err)
		return
	}
	cmd = exec.Command("iptables", "-A", "INPUT", "-j", "DROP")
	if err := cmd.Run(); err != nil {
		log.Printf("ir isolate: iptables input drop: %v", err)
		return
	}
	log.Println("ir: host isolated")
}

func (l *Listener) release() {
	l.mu.Lock()
	if !l.isolated {
		l.mu.Unlock()
		return
	}
	l.isolated = false
	l.mu.Unlock()

	// Flush the rules we added (simplified: flush all - in prod would track rule numbers)
	exec.Command("iptables", "-F", "OUTPUT").Run()
	exec.Command("iptables", "-F", "INPUT").Run()
	log.Println("ir: host released")
}

func (l *Listener) killProcess(params map[string]interface{}) {
	pidVal, ok := params["pid"]
	if !ok {
		log.Printf("ir kill: no pid")
		return
	}
	var pid int
	switch v := pidVal.(type) {
	case float64:
		pid = int(v)
	case int:
		pid = v
	case string:
		pid, _ = strconv.Atoi(v)
	default:
		log.Printf("ir kill: invalid pid type")
		return
	}
	if pid <= 0 {
		return
	}
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		log.Printf("ir kill %d: %v", pid, err)
		return
	}
	log.Printf("ir: killed pid %d", pid)
}

// dumpProcessMemory writes forensic memory artifacts for pid into outDir.
// It tries gcore first (full ELF core); falls back to dumping readable anonymous
// segments from /proc/<pid>/mem (heap, stack, mmap'd regions).
func dumpProcessMemory(pid int, outDir string) {
	pidStr := strconv.Itoa(pid)

	// Always collect lightweight /proc pseudo-files — no extra tools needed.
	procFiles := []string{"maps", "smaps", "status", "environ", "cmdline", "comm", "stat", "limits"}
	for _, pf := range procFiles {
		src := fmt.Sprintf("/proc/%s/%s", pidStr, pf)
		data, err := os.ReadFile(src)
		if err != nil {
			continue
		}
		dst := filepath.Join(outDir, fmt.Sprintf("proc_%s_%s.txt", pidStr, pf))
		_ = os.WriteFile(dst, data, 0644)
	}

	// Try gcore (from gdb package) for a proper ELF core dump.
	corePath := filepath.Join(outDir, fmt.Sprintf("core_%s", pidStr))
	gcoreCmd := exec.Command("gcore", "-o", corePath, pidStr)
	if err := gcoreCmd.Run(); err == nil {
		log.Printf("ir memdump: gcore pid=%d -> %s", pid, corePath)
		return
	}

	// Fallback: read readable anonymous segments from /proc/<pid>/mem.
	mapsData, err := os.ReadFile(fmt.Sprintf("/proc/%s/maps", pidStr))
	if err != nil {
		log.Printf("ir memdump: pid=%d maps: %v", pid, err)
		return
	}
	memFile, err := os.Open(fmt.Sprintf("/proc/%s/mem", pidStr))
	if err != nil {
		log.Printf("ir memdump: pid=%d mem: %v", pid, err)
		return
	}
	defer memFile.Close()

	dumpPath := filepath.Join(outDir, fmt.Sprintf("mem_%s.dump", pidStr))
	dumpFile, err := os.Create(dumpPath)
	if err != nil {
		return
	}
	defer dumpFile.Close()

	total := int64(0)
	const maxDump = 256 * 1024 * 1024 // 256 MB cap per process
	for _, line := range strings.Split(string(mapsData), "\n") {
		if total >= maxDump {
			break
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		perms := fields[1]
		if !strings.Contains(perms, "r") {
			continue // skip non-readable segments
		}
		var start, end uint64
		if _, err := fmt.Sscanf(fields[0], "%x-%x", &start, &end); err != nil {
			continue
		}
		size := int64(end - start)
		if size <= 0 || size > 128*1024*1024 {
			continue // skip unreasonably large segments
		}
		buf := make([]byte, size)
		n, _ := memFile.ReadAt(buf, int64(start))
		if n > 0 {
			fmt.Fprintf(dumpFile, "# segment %x-%x perms=%s\n", start, end, perms)
			_, _ = io.Copy(dumpFile, strings.NewReader(string(buf[:n])))
			total += int64(n)
		}
	}
	log.Printf("ir memdump: pid=%d fallback dump %d bytes -> %s", pid, total, dumpPath)
}

func (l *Listener) collectTriage(params map[string]interface{}) {
	paths, _ := params["paths"].([]interface{})
	if len(paths) == 0 {
		paths = []interface{}{"/tmp", "/var/log"}
	}
	artifact, _ := params["artifact_name"].(string)
	if artifact == "" {
		artifact, _ = params["artifact"].(string)
	}
	if artifact == "" {
		artifact = "triage"
	}

	// Memory dump: if caller passes pids, dump each process's memory first.
	memDir := "/tmp/" + artifact + "_memdump"
	var memDumped bool
	if rawPids, ok := params["pids"]; ok {
		pids, _ := rawPids.([]interface{})
		if len(pids) > 0 {
			_ = os.MkdirAll(memDir, 0755)
			for _, p := range pids {
				var pid int
				switch v := p.(type) {
				case float64:
					pid = int(v)
				case int:
					pid = v
				case string:
					pid, _ = strconv.Atoi(v)
				}
				if pid > 0 {
					dumpProcessMemory(pid, memDir)
					memDumped = true
				}
			}
		}
	}

	outPath := "/tmp/" + artifact + ".tar.gz"
	// Only include paths that exist; skip virtual/proc files that confuse tar
	args := []string{"--ignore-failed-read", "-czf", outPath}
	included := 0
	if memDumped {
		args = append(args, memDir)
		included++
	}
	for _, p := range paths {
		s, ok := p.(string)
		if !ok || s == "" {
			continue
		}
		if _, err := os.Stat(s); err == nil {
			args = append(args, s)
			included++
		}
	}
	if included == 0 {
		log.Printf("ir collect: no valid paths to archive")
		return
	}
	cmd := exec.Command("tar", args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		// exit 1 = warnings (some files changed/skipped) — still usable
		if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() != 1 {
			log.Printf("ir collect: %v (output: %s)", err, string(out))
			return
		}
	}
	// Cleanup temp memdump dir after archiving
	if memDumped {
		_ = os.RemoveAll(memDir)
	}
	log.Printf("ir: triage saved to %s", outPath)

	// Deliver artifact via NATS (cap at 8 MB to stay within NATS limits)
	const maxBytes = 8 * 1024 * 1024
	data, err := os.ReadFile(outPath)
	if err != nil {
		log.Printf("ir: read artifact: %v", err)
		return
	}
	if len(data) > maxBytes {
		log.Printf("ir: artifact too large (%d bytes), skipping NATS delivery — use scp to retrieve", len(data))
		return
	}
	payload, _ := json.Marshal(map[string]interface{}{
		"artifact_name": artifact,
		"host_id":       l.hostID,
		"tenant_id":     l.tenantID,
		"size":          len(data),
		"timestamp":     time.Now().UTC().Format(time.RFC3339),
		"content_b64":   base64.StdEncoding.EncodeToString(data),
	})
	subj := "ir.artifacts." + l.tenantID + "." + l.hostID
	if err := l.nc.Publish(subj, payload); err != nil {
		log.Printf("ir: publish artifact: %v", err)
		return
	}
	log.Printf("ir: artifact published to %s (%d bytes)", subj, len(data))
}
