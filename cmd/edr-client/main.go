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
	"unicode/utf8"

	"edr-linux/pkg/behavior"
	"edr-linux/pkg/config"
	"edr-linux/pkg/edr"
	"edr-linux/pkg/enrich"
	"edr-linux/pkg/gtfobins"
	"edr-linux/pkg/logger"
	"edr-linux/pkg/monitor"
	"edr-linux/pkg/proc"
)

const (
	treeIndent    = "  "
	treeBranch    = "├─ "
	maxCmdlineLen = 240
)

// sanitizePath returns "-" if path from eBPF looks invalid (garbage, non-UTF-8, or not absolute).
func sanitizePath(s string) string {
	s = strings.TrimRight(s, "\x00")
	if s == "" || s == "-" {
		return "-"
	}
	if !strings.HasPrefix(s, "/") {
		return "-"
	}
	if !utf8.ValidString(s) {
		return "-"
	}
	for _, r := range s {
		if r < 32 || r == utf8.RuneError {
			return "-"
		}
	}
	return s
}

var (
	configPath = flag.String("config", "", "Path to config YAML. Empty = defaults (Wazuh-style flexible).")
	showVersion = flag.Bool("version", false, "Print version and exit.")
)

// version is set at build time via -ldflags "-X main.version=..."
var version = "0.1.0"

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
	if *showVersion {
		fmt.Println("OWO (Open Workstation Observer)", version)
		os.Exit(0)
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	cfg.Normalize()
	if err := cfg.Validate(); err != nil {
		log.Fatalf("config: %v", err)
	}
	logger.SetLevel(cfg.Logging.Level)

	var gtfobinsDB *gtfobins.DB
	if cfg.Monitor.GTFOBinsPath != "" {
		var err error
		gtfobinsDB, err = gtfobins.Load(cfg.Monitor.GTFOBinsPath)
		if err != nil {
			logger.Warn("gtfobins: %v (disabled)", err)
		} else {
			logger.Info("GTFOBins: loaded from %s", cfg.Monitor.GTFOBinsPath)
		}
	}

	if !cfg.MonitorExecveEnabled() {
		log.Fatalf("no monitor enabled (monitor.execve=false). Enable at least one in config.")
	}

	// Buat direktori log jika path file output di-set (supaya /var/log/edr ada meski enabled: false)
	if cfg.Output.File.Path != "" {
		if err := os.MkdirAll(filepath.Dir(cfg.Output.File.Path), 0755); err != nil {
			logger.Warn("could not create log dir for %q: %v", cfg.Output.File.Path, err)
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
			logger.Warn("file_events: %v (disabled)", err)
			fileMon = nil
		} else {
			defer fileMon.Close()
			if watchAll {
				logger.Info("File events: openat/unlink/rename on ALL paths (total)")
			} else {
				logger.Info("File events: openat/unlink/rename on /etc,/usr/bin,/bin,/tmp,/dev/shm")
			}
		}
	}
	var netMon *monitor.NetworkMonitor
	if cfg.MonitorNetworkEventsEnabled() {
		netMon, err = monitor.NewNetworkMonitorFromEmbed()
		if err != nil {
			logger.Warn("network_events: %v (disabled)", err)
			netMon = nil
		} else {
			defer netMon.Close()
			logger.Info("Network events: connect, sendto, accept (DNS=port 53)")
		}
	}
	var privMon *monitor.PrivilegeMonitor
	if cfg.MonitorPrivilegeEventsEnabled() {
		privMon, err = monitor.NewPrivilegeMonitorFromEmbed()
		if err != nil {
			logger.Warn("privilege_events: %v (disabled)", err)
			privMon = nil
		} else {
			defer privMon.Close()
			logger.Info("Privilege events: setuid/setgid/setreuid/setregid")
		}
	}
	var exitMon *monitor.ExitMonitor
	if cfg.MonitorExitEventsEnabled() {
		exitMon, err = monitor.NewExitMonitorFromEmbed()
		if err != nil {
			logger.Warn("exit_events: %v (disabled)", err)
			exitMon = nil
		} else {
			defer exitMon.Close()
			logger.Info("Exit events: exit_group")
		}
	}
	var writeMon *monitor.WriteMonitor
	if cfg.MonitorWriteEventsEnabled() {
		writeMon, err = monitor.NewWriteMonitorFromEmbed()
		if err != nil {
			logger.Warn("write_events: %v (disabled)", err)
			writeMon = nil
		} else {
			defer writeMon.Close()
			logger.Info("Write events: write (path from /proc/pid/fd)")
		}
	}
	var modMon *monitor.ModuleMonitor
	if cfg.MonitorModuleEventsEnabled() {
		modMon, err = monitor.NewModuleMonitorFromEmbed()
		if err != nil {
			logger.Warn("module_events: %v (disabled)", err)
			modMon = nil
		} else {
			defer modMon.Close()
			logger.Info("Module events: init_module, finit_module")
		}
	}
	var processMon *monitor.ProcessMonitor
	if cfg.MonitorProcessEventsEnabled() {
		processMon, err = monitor.NewProcessMonitorFromEmbed()
		if err != nil {
			logger.Warn("process_events: %v (disabled)", err)
			processMon = nil
		} else {
			defer processMon.Close()
			logger.Info("Process events: fork, clone, clone3 (syscall level)")
		}
	}

	beh := behavior.NewEngine()

	fmt.Printf("OWO [%s] – exec, file, network, privilege, exit, write, module, process(fork/clone). Ctrl+C to stop.\n", cfg.Agent.Name)
	fmt.Println("Send SIGUSR1 to print full process tree.")
	if exporter != nil {
		fmt.Printf("Output: file=%v stderr=%v remote=%v\n",
			opts.FilePath != "", opts.Stderr, opts.Remote != nil)
	}

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
					logger.Warn("[FILE] reader: %v", err)
					return
				}
				beh.AddFile(ev.Pid, ev.Type, ev.Path)
				if alerts := beh.Check(); len(alerts) > 0 {
					for _, a := range alerts {
						logger.Warn("[BEHAVIOR] %s pid=%d %s", a.Rule, a.Pid, a.Detail)
					}
				}
				logger.Info("[FILE] %s pid=%d uid=%d %s %s → %s", ev.Type, ev.Pid, ev.Uid, ev.Comm, ev.Path, ev.Path2)
				if exporter != nil {
					eventJSON, _ := json.Marshal(map[string]interface{}{
						"event_type": "file", "timestamp": time.Now().UTC(),
						"type": ev.Type, "pid": ev.Pid, "tid": ev.Tid, "uid": ev.Uid,
						"comm": ev.Comm, "path": ev.Path, "path2": ev.Path2,
					})
					_ = exporter.WriteEvent(eventJSON)
				}
			}
		}()
	}
	if netMon != nil {
		go func() {
			for {
				ev, err := netMon.ReadNetworkEvent()
				if err != nil {
					logger.Warn("[NET] reader: %v", err)
					return
				}
				beh.AddNetwork(ev.Pid, ev.DAddr)
				if alerts := beh.Check(); len(alerts) > 0 {
					for _, a := range alerts {
						logger.Warn("[BEHAVIOR] %s pid=%d %s", a.Rule, a.Pid, a.Detail)
					}
				}
				logger.Info("[NET] %s pid=%d uid=%d %s → %s is_dns=%v", ev.Type, ev.Pid, ev.Uid, ev.Comm, ev.DAddr, ev.IsDNS)
				if exporter != nil {
					eventJSON, _ := json.Marshal(map[string]interface{}{
						"event_type": "network", "timestamp": time.Now().UTC(),
						"type": ev.Type, "pid": ev.Pid, "tid": ev.Tid, "uid": ev.Uid,
						"comm": ev.Comm, "daddr": ev.DAddr, "dport": ev.DPort, "is_dns": ev.IsDNS,
					})
					_ = exporter.WriteEvent(eventJSON)
				}
			}
		}()
	}
	if privMon != nil {
		go func() {
			for {
				ev, err := privMon.ReadPrivilegeEvent()
				if err != nil {
					logger.Warn("[PRIVILEGE] reader: %v", err)
					return
				}
				logger.Info("[PRIVILEGE] %s pid=%d uid=%d→%d gid=%d→%d %s", ev.Type, ev.Pid, ev.Uid, ev.NewUid, ev.Gid, ev.NewGid, ev.Comm)
				if exporter != nil {
					eventJSON, _ := json.Marshal(map[string]interface{}{
						"event_type": "privilege", "timestamp": time.Now().UTC(),
						"type": ev.Type, "pid": ev.Pid, "tid": ev.Tid, "uid": ev.Uid, "gid": ev.Gid,
						"new_uid": ev.NewUid, "new_gid": ev.NewGid, "comm": ev.Comm,
					})
					_ = exporter.WriteEvent(eventJSON)
				}
			}
		}()
	}
	if exitMon != nil {
		go func() {
			for {
				ev, err := exitMon.ReadExitEvent()
				if err != nil {
					logger.Warn("[EXIT] reader: %v", err)
					return
				}
				logger.Info("[EXIT] pid=%d uid=%d exit_code=%d %s", ev.Pid, ev.Uid, ev.ExitCode, ev.Comm)
				if exporter != nil {
					eventJSON, _ := json.Marshal(map[string]interface{}{
						"event_type": "exit", "timestamp": time.Now().UTC(),
						"pid": ev.Pid, "tid": ev.Tid, "uid": ev.Uid, "exit_code": ev.ExitCode, "comm": ev.Comm,
					})
					_ = exporter.WriteEvent(eventJSON)
				}
			}
		}()
	}
	if writeMon != nil {
		go func() {
			for {
				ev, err := writeMon.ReadWriteEvent()
				if err != nil {
					logger.Warn("[WRITE] reader: %v", err)
					return
				}
				logger.Info("[WRITE] pid=%d fd=%d count=%d path=%s %s", ev.Pid, ev.Fd, ev.Count, ev.Path, ev.Comm)
				if exporter != nil {
					eventJSON, _ := json.Marshal(map[string]interface{}{
						"event_type": "write", "timestamp": time.Now().UTC(),
						"pid": ev.Pid, "tid": ev.Tid, "uid": ev.Uid, "fd": ev.Fd, "count": ev.Count, "path": ev.Path, "comm": ev.Comm,
					})
					_ = exporter.WriteEvent(eventJSON)
				}
			}
		}()
	}
	if modMon != nil {
		go func() {
			for {
				ev, err := modMon.ReadModuleEvent()
				if err != nil {
					logger.Warn("[MODULE] reader: %v", err)
					return
				}
				logger.Info("[MODULE] %s pid=%d uid=%d %s", ev.Type, ev.Pid, ev.Uid, ev.Comm)
				if exporter != nil {
					eventJSON, _ := json.Marshal(map[string]interface{}{
						"event_type": "module", "timestamp": time.Now().UTC(),
						"type": ev.Type, "pid": ev.Pid, "uid": ev.Uid, "comm": ev.Comm,
					})
					_ = exporter.WriteEvent(eventJSON)
				}
			}
		}()
	}
	if processMon != nil {
		go func() {
			for {
				ev, err := processMon.ReadProcessEvent()
				if err != nil {
					logger.Warn("[PROCESS] reader: %v", err)
					return
				}
				logger.Info("[PROCESS] %s parent_pid=%d child_pid=%d uid=%d %s", ev.Type, ev.ParentPid, ev.ChildPid, ev.Uid, ev.Comm)
				if exporter != nil {
					eventJSON, _ := json.Marshal(map[string]interface{}{
						"event_type": "process", "timestamp": time.Now().UTC(),
						"type": ev.Type, "parent_pid": ev.ParentPid, "parent_tid": ev.ParentTid, "child_pid": ev.ChildPid, "uid": ev.Uid, "comm": ev.Comm,
					})
					_ = exporter.WriteEvent(eventJSON)
				}
			}
		}()
	}

	// Execve events via channel so main can respond to done/treeDump without blocking on ReadEvent.
	execChan := make(chan monitor.ExecveEvent, 256)
	go func() {
		defer close(execChan)
		for {
			ev, err := m.ReadEvent()
			if err != nil {
				logger.Warn("execve reader: %v", err)
				return
			}
			execChan <- ev
		}
	}()

	for {
		select {
		case <-done:
			return
		case <-treeDump:
			printProcessTree(tree)
			continue
		case ev, ok := <-execChan:
			if !ok {
				return
			}

			ts := time.Now().UTC()
			comm := strings.TrimRight(string(ev.Comm[:]), "\x00")
			path := sanitizePath(string(ev.Filename[:]))

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
				parentPath = sanitizePath(parent.Path)
				parentCmdline = parent.Cmdline
			}

			node := &procNode{
				Pid: ev.Pid, Ppid: ppid, Tid: ev.Tid, Uid: ev.Uid, Gid: ev.Gid,
				Comm: comm, Path: path, Cmdline: cmdline, Exe: exe, Ts: ts,
			}
			tree[ev.Pid] = node

			enrichPath := path
			if enrichPath == "" || enrichPath == "-" {
				enrichPath = exe
			}
			enrichCtx := enrich.EnrichExec(enrichPath, ev.Pid)
			enrichCtx.LoadTime = ts.UnixNano()
			beh.AddExec(ev.Pid, path)
			if alerts := beh.Check(); len(alerts) > 0 {
				for _, a := range alerts {
					logger.Warn("[BEHAVIOR] %s pid=%d %s", a.Rule, a.Pid, a.Detail)
				}
			}

			if exporter != nil {
				evMap := map[string]interface{}{
					"event_type": "execve", "timestamp": ts, "pid": ev.Pid, "ppid": ppid, "tid": ev.Tid,
					"uid": ev.Uid, "gid": ev.Gid, "comm": comm, "path": path,
					"exe": exe, "cmdline": cmdline,
					"parent_path": parentPath, "parent_cmdline": parentCmdline,
					"sha256": enrichCtx.SHA256, "inode": enrichCtx.Inode,
					"is_tty": enrichCtx.IsTTY, "container_id": enrichCtx.ContainerID,
					"load_time_ns": enrichCtx.LoadTime, "signed": enrichCtx.SignedStatus,
				}
				if gtfobinsDB != nil {
					binName := gtfobins.BinaryNameFromPath(exe)
					if binName == "" {
						binName = gtfobins.BinaryNameFromPath(path)
					}
					if fns := gtfobinsDB.Lookup(binName); len(fns) > 0 {
						evMap["gtfobins"] = fns
					}
					if mitre := gtfobinsDB.LookupMITRE(binName); len(mitre) > 0 {
						evMap["mitre_attck"] = mitre
					}
				}
				eventJSON, _ := json.Marshal(evMap)
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
