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
	Execve *bool `yaml:"execve"`
	// EbpfPath path to execve.o. Default: auto-detect (bpf/execve.o).
	EbpfPath string `yaml:"ebpf_path"`
	// FileEvents enables openat/unlink/rename. Default true.
	FileEvents *bool `yaml:"file_events"`
	// FileWatchAllPaths if true, monitor all absolute paths; if false, only /etc,/usr/bin,/bin,/tmp,/dev/shm. Default false (noisier if true).
	FileWatchAllPaths *bool `yaml:"file_watch_all_paths"`
	// NetworkEvents enables connect/sendto/accept for correlation. Default true.
	NetworkEvents *bool `yaml:"network_events"`
	// PrivilegeEvents enables setuid/setgid/setreuid/setregid. Default true.
	PrivilegeEvents *bool `yaml:"privilege_events"`
	// ExitEvents enables process exit (exit_group). Default true.
	ExitEvents *bool `yaml:"exit_events"`
	// WriteEvents enables write syscall (noisy; path from /proc/pid/fd). Default false.
	WriteEvents *bool `yaml:"write_events"`
	// ModuleEvents enables kernel module load (init_module/finit_module). Default true.
	ModuleEvents *bool `yaml:"module_events"`
}

type OutputConfig struct {
	// File writes alerts to a local file (JSON lines).
	File FileOutputConfig `yaml:"file"`
	// Stderr prints alerts to stderr. Default true when no file/remote.
	Stderr *bool `yaml:"stderr"`
	// Remote sends alerts to a manager (Wazuh-style).
	Remote RemoteOutputConfig `yaml:"remote"`
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
	trueVal := true
	return &Config{
		Agent: AgentConfig{
			Name:     "",
			Hostname: "",
			Group:    "",
		},
		Monitor: MonitorConfig{
			Execve:            &trueVal,
			EbpfPath:          "",
			FileEvents:        &trueVal,
			FileWatchAllPaths: nil,
			NetworkEvents:     &trueVal,
			PrivilegeEvents:   &trueVal,
			ExitEvents:        &trueVal,
			WriteEvents:       nil, // false = noisy
			ModuleEvents:      &trueVal,
		},
		Output: OutputConfig{
			File: FileOutputConfig{
				Enabled: false,
				Path:    "",
			},
			Stderr: &trueVal,
			Remote: RemoteOutputConfig{
				Enabled:             false,
				Address:             "",
				Protocol:            "tcp",
				HTTPEndpoint:        "/alerts",
				MaxRetries:          5,
				RetryIntervalSeconds: 10,
			},
		},
		Logging: LoggingConfig{Level: "info"},
	}
}

// MonitorExecveEnabled returns whether execve monitoring is on.
func (c *Config) MonitorExecveEnabled() bool {
	if c.Monitor.Execve == nil {
		return true
	}
	return *c.Monitor.Execve
}

// MonitorFileEventsEnabled returns whether file (openat/unlink/rename) monitoring is on.
func (c *Config) MonitorFileEventsEnabled() bool {
	if c.Monitor.FileEvents == nil {
		return true
	}
	return *c.Monitor.FileEvents
}

// MonitorNetworkEventsEnabled returns whether network (connect/sendto) monitoring is on.
func (c *Config) MonitorNetworkEventsEnabled() bool {
	if c.Monitor.NetworkEvents == nil {
		return true
	}
	return *c.Monitor.NetworkEvents
}

// FileWatchAllPaths returns whether to monitor file ops on all paths (true) or only watched paths (false).
func (c *Config) FileWatchAllPaths() bool {
	return c.Monitor.FileWatchAllPaths != nil && *c.Monitor.FileWatchAllPaths
}

// MonitorPrivilegeEventsEnabled returns whether privilege change monitoring is on.
func (c *Config) MonitorPrivilegeEventsEnabled() bool {
	return c.Monitor.PrivilegeEvents == nil || *c.Monitor.PrivilegeEvents
}

// MonitorExitEventsEnabled returns whether process exit monitoring is on.
func (c *Config) MonitorExitEventsEnabled() bool {
	return c.Monitor.ExitEvents == nil || *c.Monitor.ExitEvents
}

// MonitorWriteEventsEnabled returns whether write syscall monitoring is on.
func (c *Config) MonitorWriteEventsEnabled() bool {
	return c.Monitor.WriteEvents != nil && *c.Monitor.WriteEvents
}

// MonitorModuleEventsEnabled returns whether kernel module load monitoring is on.
func (c *Config) MonitorModuleEventsEnabled() bool {
	return c.Monitor.ModuleEvents == nil || *c.Monitor.ModuleEvents
}

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

// Normalize fills empty protocol/address defaults.
func (c *Config) Normalize() {
	c.ResolveAgentName()
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
}
