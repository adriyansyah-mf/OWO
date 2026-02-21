// Package ir handles incident response commands (isolate, kill, collect).
package ir

import (
	"encoding/json"
	"log"
	"os/exec"
	"strconv"
	"sync"
	"syscall"

	"github.com/nats-io/nats.go"
)

// Listener subscribes to IR commands and executes them.
type Listener struct {
	nc       *nats.Conn
	tenantID string
	hostID   string
	sub      *nats.Subscription
	mu       sync.Mutex
	isolated bool
}

// NewListener creates an IR listener.
func NewListener(nc *nats.Conn, tenantID, hostID string) *Listener {
	return &Listener{nc: nc, tenantID: tenantID, hostID: hostID}
}

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
	outPath := "/tmp/" + artifact + ".tar.gz"
	args := []string{"-czf", outPath}
	for _, p := range paths {
		if s, ok := p.(string); ok && s != "" {
			args = append(args, s)
		}
	}
	if err := exec.Command("tar", args...).Run(); err != nil {
		log.Printf("ir collect: %v", err)
		return
	}
	log.Printf("ir: triage saved to %s (scp from host to retrieve)", outPath)
}
