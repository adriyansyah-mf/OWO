// EDR client: execve + file + network hooks, enrichment (SHA256/inode/TTY/container), behavior engine. Matching/alerting di SIEM (e.g. Wazuh).
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"edr-linux/pkg/behavior"
	"edr-linux/pkg/config"
	"edr-linux/pkg/edr"
	"edr-linux/pkg/enrich"
	"edr-linux/pkg/monitor"
	"edr-linux/pkg/proc"
)

const (
	treeIndent    = "  "
	treeBranch    = "├─ "
	maxCmdlineLen = 240
)

var (
	configPath = flag.String("config", "", "Path to config YAML. Empty = defaults (Wazuh-style flexible).")
)

type procNode struct {
	Pid     uint32
	Ppid    uint32
	Tid     uint32
	Uid     uint32
	Gid     uint32
	Comm    string
	Path    string
	Cmdline string
	Exe     string
	Ts      time.Time
}

func main() {
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	cfg.Normalize()

	if !cfg.MonitorExecveEnabled() {
		log.Fatalf("no monitor enabled (monitor.execve=false). Enable at least one in config.")
	}

	// Buat direktori log jika path file output di-set (supaya /var/log/edr ada meski enabled: false)
	if cfg.Output.File.Path != "" {
		if err := os.MkdirAll(filepath.Dir(cfg.Output.File.Path), 0755); err != nil {
			log.Printf("warning: could not create log dir for %q: %v", cfg.Output.File.Path, err)
		}
	}

	opts := edr.ExporterOptions{
		Stderr:     cfg.OutputStderrEnabled(),
		AgentName:  cfg.Agent.Name,
		AgentHost:  cfg.Agent.Hostname,
		AgentGroup: cfg.Agent.Group,
	}
	if cfg.Output.File.Enabled && cfg.Output.File.Path != "" {
		opts.FilePath = cfg.Output.File.Path
	}
	if cfg.Output.Remote.Enabled && cfg.Output.Remote.Address != "" {
		opts.Remote = edr.NewRemoteOutput(
			cfg.Output.Remote.Address,
			cfg.Output.Remote.Protocol,
			cfg.Output.Remote.HTTPEndpoint,
			cfg.Output.Remote.MaxRetries,
			cfg.Output.Remote.RetryIntervalSeconds,
			cfg.Agent.Name,
			cfg.Agent.Hostname,
			cfg.Agent.Group,
		)
	}
	var exporter *edr.Exporter
	if opts.FilePath != "" || opts.Stderr || opts.Remote != nil {
		exporter, err = edr.NewExporter(opts)
		if err != nil {
			log.Fatalf("export: %v", err)
		}
		defer exporter.Close()
	}

	ebpfPath := cfg.Monitor.EbpfPath
	var m *monitor.Monitor
	if ebpfPath != "" {
		m, err = monitor.New(ebpfPath)
	} else {
		m, err = monitor.NewFromEmbed()
	}
	if err != nil {
		log.Fatalf("monitor: %v", err)
	}
	defer m.Close()

	var fileMon *monitor.FileMonitor
	if cfg.MonitorFileEventsEnabled() {
		watchAll := cfg.FileWatchAllPaths()
		fileMon, err = monitor.NewFileMonitorFromEmbed(watchAll)
		if err != nil {
			log.Printf("file_events: %v (disabled)", err)
			fileMon = nil
		} else {
			defer fileMon.Close()
			if watchAll {
				log.Printf("File events: openat/unlink/rename on ALL paths (total)")
			} else {
				log.Printf("File events: openat/unlink/rename on /etc,/usr/bin,/bin,/tmp,/dev/shm")
			}
		}
	}
	var netMon *monitor.NetworkMonitor
	if cfg.MonitorNetworkEventsEnabled() {
		netMon, err = monitor.NewNetworkMonitorFromEmbed()
		if err != nil {
			log.Printf("network_events: %v (disabled)", err)
			netMon = nil
		} else {
			defer netMon.Close()
			log.Printf("Network events: connect, sendto (for correlation)")
		}
	}

	beh := behavior.NewEngine()

	fmt.Printf("EDR agent [%s] – exec + file + network + behavior. Ctrl+C to stop.\n", cfg.Agent.Name)
	fmt.Println("Send SIGUSR1 to print full process tree.")
	if exporter != nil {
		fmt.Printf("Output: file=%v stderr=%v remote=%v\n",
			opts.FilePath != "", opts.Stderr, opts.Remote != nil)
	}
	fmt.Println("Columns: [tree] ts | pid | ppid | sha256 | inode | tty | container | path | cmdline")
	fmt.Println(strings.Repeat("-", 140))

	tree := make(map[uint32]*procNode)
	done := make(chan os.Signal, 1)
	treeDump := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGTERM)
	signal.Notify(treeDump, syscall.SIGUSR1)

	if fileMon != nil {
		go func() {
			for {
				ev, err := fileMon.ReadFileEvent()
				if err != nil {
					continue
				}
				beh.AddFile(ev.Pid, ev.Type, ev.Path)
				if alerts := beh.Check(); len(alerts) > 0 {
					for _, a := range alerts {
						log.Printf("[BEHAVIOR] %s pid=%d %s", a.Rule, a.Pid, a.Detail)
					}
				}
				fmt.Printf("  [FILE] %s pid=%d uid=%d %s %s → %s\n", ev.Type, ev.Pid, ev.Uid, ev.Comm, ev.Path, ev.Path2)
			}
		}()
	}
	if netMon != nil {
		go func() {
			for {
				ev, err := netMon.ReadNetworkEvent()
				if err != nil {
					continue
				}
				beh.AddNetwork(ev.Pid, ev.DAddr)
				if alerts := beh.Check(); len(alerts) > 0 {
					for _, a := range alerts {
						log.Printf("[BEHAVIOR] %s pid=%d %s", a.Rule, a.Pid, a.Detail)
					}
				}
				fmt.Printf("  [NET] %s pid=%d uid=%d %s → %s\n", ev.Type, ev.Pid, ev.Uid, ev.Comm, ev.DAddr)
			}
		}()
	}

	for {
		select {
		case <-done:
			return
		case <-treeDump:
			printProcessTree(tree)
			continue
		default:
			ev, err := m.ReadEvent()
			if err != nil {
				log.Printf("read event: %v", err)
				continue
			}

			ts := time.Now().UTC()
			comm := strings.TrimRight(string(ev.Comm[:]), "\x00")
			path := strings.TrimRight(string(ev.Filename[:]), "\x00")
			if path == "" {
				path = "-"
			}

			ppid := ev.Ppid
			if ppid == 0 {
				ppid = proc.PpidFromStat(ev.Pid)
			}
			cmdline := proc.Cmdline(ev.Pid)
			if cmdline == "" {
				cmdline = comm
			}
			exe := proc.Exe(ev.Pid)
			if exe == "" {
				exe = "-"
			}

			parentPath := "-"
			parentCmdline := ""
			if parent := tree[ppid]; parent != nil {
				parentPath = parent.Path
				parentCmdline = parent.Cmdline
			}

			node := &procNode{
				Pid: ev.Pid, Ppid: ppid, Tid: ev.Tid, Uid: ev.Uid, Gid: ev.Gid,
				Comm: comm, Path: path, Cmdline: cmdline, Exe: exe, Ts: ts,
			}
			tree[ev.Pid] = node

			// Untuk SHA256/inode: pakai path dari eBPF; kalau "-" atau kosong pakai exe dari /proc
			enrichPath := path
			if enrichPath == "" || enrichPath == "-" {
				enrichPath = exe
			}
			enrichCtx := enrich.EnrichExec(enrichPath, ev.Pid)
			enrichCtx.LoadTime = ts.UnixNano()
			beh.AddExec(ev.Pid, path)
			if alerts := beh.Check(); len(alerts) > 0 {
				for _, a := range alerts {
					log.Printf("[BEHAVIOR] %s pid=%d %s", a.Rule, a.Pid, a.Detail)
				}
			}

			if exporter != nil {
				eventJSON, _ := json.Marshal(map[string]interface{}{
					"timestamp": ts, "pid": ev.Pid, "ppid": ppid, "tid": ev.Tid,
					"uid": ev.Uid, "gid": ev.Gid, "comm": comm, "path": path,
					"exe": exe, "cmdline": cmdline,
					"parent_path": parentPath, "parent_cmdline": parentCmdline,
					"sha256": enrichCtx.SHA256, "inode": enrichCtx.Inode,
					"is_tty": enrichCtx.IsTTY, "container_id": enrichCtx.ContainerID,
					"load_time_ns": enrichCtx.LoadTime, "signed": enrichCtx.SignedStatus,
				})
				_ = exporter.WriteEvent(eventJSON)
			}
		}
	}
}

func printProcessTree(tree map[uint32]*procNode) {
	if len(tree) == 0 {
		fmt.Println("[tree] empty")
		return
	}
	children := make(map[uint32][]uint32)
	for pid, n := range tree {
		if n.Ppid == 0 || tree[n.Ppid] == nil {
			children[0] = append(children[0], pid)
		} else {
			children[n.Ppid] = append(children[n.Ppid], pid)
		}
	}
	fmt.Println("\n========== PROCESS TREE ==========")
	var walk func(pid uint32, depth int)
	walk = func(pid uint32, depth int) {
		if pid != 0 {
			n := tree[pid]
			if n == nil {
				return
			}
			prefix := strings.Repeat(treeIndent, depth) + treeBranch
			cmd := n.Cmdline
			if len(cmd) > 80 {
				cmd = cmd[:80] + "..."
			}
			fmt.Printf("%s[%d] ppid=%d uid=%d %s | %s\n", prefix, n.Pid, n.Ppid, n.Uid, n.Comm, cmd)
		}
		for _, c := range children[pid] {
			walk(c, depth+1)
		}
	}
	walk(0, 0)
	fmt.Println("===================================\n")
}
