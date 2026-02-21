// Package events provides ECS-like event schema for EDR platform.
package events

import "time"

// RawEvent is the raw event from agent (execve, file, network, etc.).
type RawEvent struct {
	EventType   string    `json:"event_type"`
	Timestamp   time.Time `json:"timestamp"`
	Pid         uint32    `json:"pid"`
	Ppid        uint32    `json:"ppid"`
	Tid         uint32    `json:"tid,omitempty"`
	Uid         uint32    `json:"uid"`
	Gid         uint32    `json:"gid"`
	Comm        string    `json:"comm"`
	Path        string    `json:"path"`
	Exe         string    `json:"exe"`
	Cmdline     string    `json:"cmdline"`
	ParentPath  string    `json:"parent_path,omitempty"`
	ParentCmd   string    `json:"parent_cmdline,omitempty"`
	SHA256      string    `json:"sha256,omitempty"`
	Inode       uint64    `json:"inode,omitempty"`
	IsTTY       bool      `json:"is_tty,omitempty"`
	ContainerID string    `json:"container_id,omitempty"`
	MitreAttck  []string  `json:"mitre_attck,omitempty"`
	GTFOBins    []string  `json:"gtfobins,omitempty"`
	// file events
	FilePath string `json:"file_path,omitempty"`
	Flags    uint32 `json:"flags,omitempty"`
	// network events
	RemoteAddr string `json:"remote_addr,omitempty"`
	RemotePort uint16 `json:"remote_port,omitempty"`
	LocalPort  uint16 `json:"local_port,omitempty"`
	Protocol   string `json:"protocol,omitempty"`
}

// AgentEnvelope wraps raw event with agent identity.
type AgentEnvelope struct {
	AgentName   string    `json:"agent_name"`
	AgentHost   string    `json:"agent_hostname"`
	AgentGroup  string    `json:"agent_group,omitempty"`
	TenantID    string    `json:"tenant_id,omitempty"`
	Timestamp   time.Time `json:"timestamp"`
	Event       RawEvent  `json:"event"`
}

// NormalizedEvent is ECS-like normalized event for detection/storage.
type NormalizedEvent struct {
	Timestamp  time.Time              `json:"@timestamp"`
	TenantID   string                 `json:"tenant_id"`
	HostID     string                 `json:"host_id"`
	EventID    string                 `json:"event_id"`
	EventType  string                 `json:"event_type"`
	Process    ProcessInfo            `json:"process"`
	User       UserInfo               `json:"user"`
	Host       HostInfo               `json:"host"`
	Threat     ThreatInfo             `json:"threat,omitempty"`
	File       *FileInfo              `json:"file,omitempty"`
	Network    *NetworkInfo           `json:"network,omitempty"`
	Raw        map[string]interface{} `json:"raw,omitempty"`
}

type ProcessInfo struct {
	Pid         uint32     `json:"pid"`
	Ppid        uint32     `json:"ppid"`
	Executable  string     `json:"executable"`
	CommandLine string     `json:"command_line"`
	Name        string     `json:"name"`
	Start       time.Time  `json:"start"`
	Hash        *HashInfo  `json:"hash,omitempty"`
	Parent      *ProcessInfo `json:"parent,omitempty"`
}

type HashInfo struct {
	SHA256 string `json:"sha256"`
}

type UserInfo struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
	GID  string `json:"group_id,omitempty"`
}

type HostInfo struct {
	Hostname string `json:"hostname"`
	OS      string `json:"os,omitempty"`
}

type ThreatInfo struct {
	Mitre   []string `json:"mitre,omitempty"`
	GTFOBins []string `json:"gtfobins,omitempty"`
}

type FileInfo struct {
	Path  string `json:"path"`
	Flags uint32 `json:"flags,omitempty"`
}

type NetworkInfo struct {
	RemoteAddr string `json:"remote_addr"`
	RemotePort uint16 `json:"remote_port"`
	LocalPort  uint16 `json:"local_port"`
	Protocol   string `json:"protocol"`
}
