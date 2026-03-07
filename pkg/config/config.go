// Package config provides central EDR configuration (Wazuh-agent style flexibility).
package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config is the root EDR configuration.
type Config struct {
	Agent   AgentConfig   `yaml:"agent"`
	Monitor MonitorConfig `yaml:"monitor"`
	Output  OutputConfig  `yaml:"output"`
	Logging LoggingConfig `yaml:"logging"`
	// NDLP holds enterprise Data Loss Prevention configuration.
	// All fields have safe defaults and are optional — leaving this section
	// empty retains the existing behaviour (on-demand scan via IR command).
	NDLP NDLPConfig `yaml:"ndlp"`
}

// NDLPConfig contains enterprise DLP configuration for the agent.
type NDLPConfig struct {
	// PolicyCachePath is where DLP policies are persisted for offline operation.
	// The store reads this file on startup and writes it on every policy update.
	// Recommended: /var/lib/edr/dlp/policies.json
	PolicyCachePath string `yaml:"policy_cache_path"`

	// AuditLogPath is the JSON-lines audit file for all DLP events.
	// Suitable for direct ingestion by Elasticsearch, Splunk, or any SIEM.
	// Recommended: /var/log/edr/dlp-audit.jsonl
	AuditLogPath string `yaml:"audit_log_path"`

	// QuarantineDir is where quarantined files are moved.
	// Required when any active policy uses ActionQuarantine.
	// Default: /var/lib/edr/dlp/quarantine
	QuarantineDir string `yaml:"quarantine_dir"`

	// EscalationSubject overrides the NATS subject used for SOC/SOAR escalation.
	// Default: "dlp.escalation"
	EscalationSubject string `yaml:"escalation_subject"`

	// EnableBehavioral activates the behavioral DLP engine (mass file access,
	// USB bulk copy, archive creation, insider threat heuristics).
	// Default: false (opt-in to avoid false positives in development environments).
	EnableBehavioral bool `yaml:"enable_behavioral"`

	// BehavioralThresholds configures the behavioral detection thresholds.
	// All values apply per-process per 60-second sliding window.
	BehavioralThresholds BehavioralThresholdsConfig `yaml:"behavioral_thresholds"`

	// Channels lists which exfiltration channels to actively monitor.
	// Valid values: "usb", "cloud_storage", "email", "clipboard", "print",
	// "network_upload", "local_file", "all".
	// Default: ["usb", "local_file"] (safe defaults that match existing behaviour).
	Channels []string `yaml:"channels"`

	// FingerprintRegistryPath is the path to a JSON file containing known
	// sensitive document SHA256 fingerprints.
	// Format: [{"hash": "<sha256hex>", "name": "...", "label": "restricted", "notes": "..."}]
	FingerprintRegistryPath string `yaml:"fingerprint_registry_path"`

	// UseDefaultPolicies loads the built-in enterprise DLP policies when no
	// PolicyCachePath is configured or the cache is empty. Default: true.
	UseDefaultPolicies bool `yaml:"use_default_policies"`
}

// BehavioralThresholdsConfig tunes the behavioral DLP engine thresholds.
// All values are per-process per 60-second window. Zero means "use default."
type BehavioralThresholdsConfig struct {
	// MassAccessPerMinute: file accesses/min before RuleMassFileAccess fires.
	// Default: 100
	MassAccessPerMinute int `yaml:"mass_access_per_minute"`

	// BulkReadMB: megabytes read/min before RuleBulkRead fires.
	// Default: 50
	BulkReadMB int `yaml:"bulk_read_mb"`

	// USBCopyPerMinute: USB file writes/min before RuleUSBBulkCopy fires.
	// Default: 20
	USBCopyPerMinute int `yaml:"usb_copy_per_minute"`
}

type AgentConfig struct {
	// Name is the agent identifier (e.g. "edr-agent-01"). Default: hostname.
	Name string `yaml:"name"`
	// Hostname sent with events. Default: os.Hostname().
	Hostname string `yaml:"hostname"`
	// Group optional (e.g. "servers", "workstations").
	Group string `yaml:"group"`
}

type MonitorConfig struct {
	// Execve enables process execution (eBPF) monitoring. Default true.
	Execve bool `yaml:"execve"`
	// EbpfPath directory containing eBPF .o files. Default: auto-detect.
	EbpfPath string `yaml:"ebpf_path"`
	// FileEvents enables openat/unlink/rename. Default true.
	FileEvents bool `yaml:"file_events"`
	// FileWatchAllPaths if true, monitor all absolute paths; if false, only /etc,/usr/bin,/bin,/tmp,/dev/shm. Default false (noisier if true).
	FileWatchAllPaths bool `yaml:"file_watch_all_paths"`
	// NetworkEvents enables connect/sendto/accept for correlation. Default true.
	NetworkEvents bool `yaml:"network_events"`
	// PrivilegeEvents enables setuid/setgid/setreuid/setregid. Default true.
	PrivilegeEvents bool `yaml:"privilege_events"`
	// ExitEvents enables process exit (exit_group). Default true.
	ExitEvents bool `yaml:"exit_events"`
	// WriteEvents enables write syscall (noisy; path from /proc/pid/fd). Default false.
	WriteEvents bool `yaml:"write_events"`
	// ModuleEvents enables kernel module load (init_module/finit_module). Default true.
	ModuleEvents bool `yaml:"module_events"`
	// ProcessEvents enables fork/clone/clone3 (process creation). Default false (noisy).
	ProcessEvents bool `yaml:"process_events"`
	// GTFOBinsPath path to local gtfobins api.json (from contrib/scripts/fetch_gtfobins.sh). Empty = disabled.
	GTFOBinsPath string `yaml:"gtfobins_path"`
	// ProcessSnapshotIntervalSeconds: periodic process list (ps aux style) sent to server. 0 = disabled. Default 60.
	ProcessSnapshotIntervalSeconds int `yaml:"process_snapshot_interval"`
	// SigmaRulesPath: path to Sigma rules for stdout filter (only show execve that match). Empty = show all when stderr enabled.
	SigmaRulesPath string `yaml:"sigma_rules_path"`
	// ClamAVScanPaths: paths for av_scan (default: /tmp, /var/tmp, /home).
	ClamAVScanPaths []string `yaml:"clamav_scan_paths"`
	// RealtimeAVScan: scan executables on execve in real-time. Default false (adds latency).
	RealtimeAVScan bool `yaml:"realtime_av_scan"`
	// DLPScanPaths: paths for dlp_scan (default: /tmp, /var/tmp, /home).
	DLPScanPaths []string `yaml:"dlp_scan_paths"`
}

type OutputConfig struct {
	// File writes alerts to a local file (JSON lines).
	File FileOutputConfig `yaml:"file"`
	// Stderr prints alerts to stderr. Default true when no file/remote.
	Stderr *bool `yaml:"stderr"`
	// Remote sends alerts to a manager (Wazuh-style).
	Remote RemoteOutputConfig `yaml:"remote"`
	// NATS sends events to NATS for EDR backend pipeline.
	Nats NatsOutputConfig `yaml:"nats"`
}

type NatsOutputConfig struct {
	Enabled  bool   `yaml:"enabled"`
	URL      string `yaml:"url"`       // e.g. nats://localhost:4222
	Subject  string `yaml:"subject"`   // e.g. events.default
	TenantID string `yaml:"tenant_id"` // default: default
}

type FileOutputConfig struct {
	Enabled bool   `yaml:"enabled"`
	Path    string `yaml:"path"`
}

type RemoteOutputConfig struct {
	Enabled bool `yaml:"enabled"`
	// Address manager address (host:port), e.g. "192.168.1.10:1514".
	Address string `yaml:"address"`
	// Protocol "tcp" (plain) or "tls" or "http". Default tcp.
	Protocol string `yaml:"protocol"`
	// HTTPEndpoint used when protocol=http, e.g. "/alerts".
	HTTPEndpoint string `yaml:"http_endpoint"`
	// MaxRetries connection retries. Default 5.
	MaxRetries int `yaml:"max_retries"`
	// RetryIntervalSeconds between retries. Default 10.
	RetryIntervalSeconds int `yaml:"retry_interval"`
}

type LoggingConfig struct {
	Level string `yaml:"level"` // debug, info, warn, error. Default info.
}

// Load reads config from path. If path is empty, returns default config.
func Load(path string) (*Config, error) {
	c := Default()
	if path == "" {
		return c, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if err := yaml.Unmarshal(data, c); err != nil {
		return nil, fmt.Errorf("config yaml: %w", err)
	}
	return c, nil
}

// Default returns default configuration (flexible defaults like Wazuh).
func Default() *Config {
	return &Config{
		Agent: AgentConfig{
			Name:     "",
			Hostname: "",
			Group:    "",
		},
		Monitor: MonitorConfig{
			Execve:          true,
			FileEvents:      true,
			NetworkEvents:   true,
			PrivilegeEvents: true,
			ExitEvents:      true,
			ModuleEvents:    true,
			// WriteEvents:    false (default — noisy)
			// ProcessEvents:  false (default — noisy, fork/clone very frequent)
			// RealtimeAVScan: false (default — adds latency)
			ProcessSnapshotIntervalSeconds: 60,
		},
		Output: OutputConfig{
			File: FileOutputConfig{
				Enabled: false,
				Path:    "",
			},
			Stderr: func() *bool { v := true; return &v }(),
			Remote: RemoteOutputConfig{
				Enabled:             false,
				Address:             "",
				Protocol:            "tcp",
				HTTPEndpoint:        "/alerts",
				MaxRetries:          5,
				RetryIntervalSeconds: 10,
			},
			Nats: NatsOutputConfig{
				Enabled:  false,
				URL:      "nats://localhost:4222",
				Subject:  "events.default",
				TenantID: "default",
			},
		},
		Logging: LoggingConfig{Level: "info"},
		NDLP: NDLPConfig{
			PolicyCachePath:   "/var/lib/edr/dlp/policies.json",
			AuditLogPath:      "/var/log/edr/dlp-audit.jsonl",
			QuarantineDir:     "/var/lib/edr/dlp/quarantine",
			EscalationSubject: "dlp.escalation",
			EnableBehavioral:  false,
			Channels:          []string{"usb", "local_file"},
			UseDefaultPolicies: true,
			BehavioralThresholds: BehavioralThresholdsConfig{
				MassAccessPerMinute: 100,
				BulkReadMB:          50,
				USBCopyPerMinute:    20,
			},
		},
	}
}

// MonitorExecveEnabled returns whether execve monitoring is on.
func (c *Config) MonitorExecveEnabled() bool { return c.Monitor.Execve }

// MonitorFileEventsEnabled returns whether file (openat/unlink/rename) monitoring is on.
func (c *Config) MonitorFileEventsEnabled() bool { return c.Monitor.FileEvents }

// MonitorNetworkEventsEnabled returns whether network (connect/sendto) monitoring is on.
func (c *Config) MonitorNetworkEventsEnabled() bool { return c.Monitor.NetworkEvents }

// FileWatchAllPaths returns whether to monitor file ops on all paths (true) or only watched paths (false).
func (c *Config) FileWatchAllPaths() bool { return c.Monitor.FileWatchAllPaths }

// MonitorPrivilegeEventsEnabled returns whether privilege change monitoring is on.
func (c *Config) MonitorPrivilegeEventsEnabled() bool { return c.Monitor.PrivilegeEvents }

// MonitorExitEventsEnabled returns whether process exit monitoring is on.
func (c *Config) MonitorExitEventsEnabled() bool { return c.Monitor.ExitEvents }

// MonitorWriteEventsEnabled returns whether write syscall monitoring is on.
func (c *Config) MonitorWriteEventsEnabled() bool { return c.Monitor.WriteEvents }

// MonitorModuleEventsEnabled returns whether kernel module load monitoring is on.
func (c *Config) MonitorModuleEventsEnabled() bool { return c.Monitor.ModuleEvents }

// MonitorProcessEventsEnabled returns whether fork/clone/clone3 monitoring is on.
func (c *Config) MonitorProcessEventsEnabled() bool { return c.Monitor.ProcessEvents }

// MonitorRealtimeAVScanEnabled returns whether to scan executables on execve.
func (c *Config) MonitorRealtimeAVScanEnabled() bool { return c.Monitor.RealtimeAVScan }

// OutputStderrEnabled returns whether to log alerts to stderr.
func (c *Config) OutputStderrEnabled() bool {
	if c.Output.Stderr == nil {
		return true
	}
	return *c.Output.Stderr
}

// ResolveAgentName sets default agent name/hostname if not set.
func (c *Config) ResolveAgentName() {
	if c.Agent.Hostname == "" {
		c.Agent.Hostname, _ = os.Hostname()
	}
	if c.Agent.Name == "" {
		c.Agent.Name = c.Agent.Hostname
	}
}

// Validate returns an error if config is inconsistent (e.g. file enabled but path empty).
func (c *Config) Validate() error {
	if c.Output.File.Enabled && c.Output.File.Path == "" {
		return fmt.Errorf("output.file.enabled is true but output.file.path is empty")
	}
	if c.Output.Remote.Enabled && c.Output.Remote.Address == "" {
		return fmt.Errorf("output.remote.enabled is true but output.remote.address is empty")
	}
	return nil
}

// Normalize fills empty protocol/address defaults.
func (c *Config) Normalize() {
	c.ResolveAgentName()
	// When file or NATS is enabled, default stderr to false (no console spam)
	if (c.Output.File.Enabled && c.Output.File.Path != "") || c.Output.Nats.Enabled {
		if c.Output.Stderr == nil {
			falseVal := false
			c.Output.Stderr = &falseVal
		}
	}
	// Production: NATS_URL env overrides config (12-factor, Docker/k8s)
	if u := os.Getenv("NATS_URL"); u != "" && c.Output.Nats.Enabled {
		c.Output.Nats.URL = u
	}
	if c.Output.Remote.Protocol == "" {
		c.Output.Remote.Protocol = "tcp"
	}
	if c.Output.Remote.MaxRetries <= 0 {
		c.Output.Remote.MaxRetries = 5
	}
	if c.Output.Remote.RetryIntervalSeconds <= 0 {
		c.Output.Remote.RetryIntervalSeconds = 10
	}
	if c.Output.Remote.HTTPEndpoint == "" {
		c.Output.Remote.HTTPEndpoint = "/alerts"
	}
	c.Output.Remote.Protocol = strings.ToLower(c.Output.Remote.Protocol)
	if c.Logging.Level == "" {
		c.Logging.Level = "info"
	}
}
