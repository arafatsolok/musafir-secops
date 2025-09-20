//go:build windows

package main

import (
	"time"
)

// Common system information structures
type OSInfo struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	Build        string `json:"build"`
	Architecture string `json:"architecture"`
	Hostname     string `json:"hostname"`
	Domain       string `json:"domain"`
	Uptime       int64  `json:"uptime"`
	LastBoot     string `json:"last_boot"`
	TimeZone     string `json:"timezone"`
	Locale       string `json:"locale"`
}

type HardwareInfo struct {
	Manufacturer string               `json:"manufacturer"`
	Model        string               `json:"model"`
	SerialNumber string               `json:"serial_number"`
	CPU          CPUInfo              `json:"cpu"`
	Memory       MemoryInfo           `json:"memory"`
	Storage      []StorageInfo        `json:"storage"`
	Network      []NetworkAdapterInfo `json:"network"`
	BIOS         BIOSInfo             `json:"bios"`
}

type CPUInfo struct {
	Name         string  `json:"name"`
	Cores        int     `json:"cores"`
	Threads      int     `json:"threads"`
	Speed        float64 `json:"speed_ghz"`
	Architecture string  `json:"architecture"`
	Vendor       string  `json:"vendor"`
	Family       string  `json:"family"`
	Model        string  `json:"model"`
	Stepping     string  `json:"stepping"`
	Usage        float64 `json:"usage_percent"`
}

type MemoryInfo struct {
	Total     uint64       `json:"total_bytes"`
	Available uint64       `json:"available_bytes"`
	Used      uint64       `json:"used_bytes"`
	Usage     float64      `json:"usage_percent"`
	Slots     []MemorySlot `json:"slots"`
}

type MemorySlot struct {
	Size     uint64 `json:"size_bytes"`
	Type     string `json:"type"`
	Speed    int    `json:"speed_mhz"`
	Location string `json:"location"`
}

type StorageInfo struct {
	Device     string  `json:"device"`
	Type       string  `json:"type"`
	Size       uint64  `json:"size_bytes"`
	Used       uint64  `json:"used_bytes"`
	Available  uint64  `json:"available_bytes"`
	Usage      float64 `json:"usage_percent"`
	FileSystem string  `json:"filesystem"`
	MountPoint string  `json:"mount_point"`
	Health     string  `json:"health"`
}

type NetworkAdapterInfo struct {
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	MACAddress  string   `json:"mac_address"`
	IPAddresses []string `json:"ip_addresses"`
	Status      string   `json:"status"`
	Speed       uint64   `json:"speed_mbps"`
	Duplex      string   `json:"duplex"`
	MTU         int      `json:"mtu"`
}

type BIOSInfo struct {
	Vendor      string `json:"vendor"`
	Version     string `json:"version"`
	ReleaseDate string `json:"release_date"`
	Mode        string `json:"mode"`
}

type SoftwareInfo struct {
	Name            string    `json:"name"`
	Version         string    `json:"version"`
	Vendor          string    `json:"vendor"`
	InstallDate     time.Time `json:"install_date"`
	InstallLocation string    `json:"install_location"`
	Size            uint64    `json:"size_bytes"`
	Type            string    `json:"type"`
}

type ServiceInfo struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Status      string `json:"status"`
	StartType   string `json:"start_type"`
	Account     string `json:"account"`
	Path        string `json:"path"`
	PID         uint32 `json:"pid"`
	Description string `json:"description"`
}

type ProcessInfo struct {
	PID          uint32       `json:"pid"`
	PPID         uint32       `json:"ppid"`
	Name         string       `json:"name"`
	Path         string       `json:"path"`
	CommandLine  string       `json:"command_line"`
	User         string       `json:"user"`
	StartTime    time.Time    `json:"start_time"`
	CPUUsage     float64      `json:"cpu_usage"`
	MemoryUsage  uint64       `json:"memory_usage"`
	ThreadCount  int          `json:"thread_count"`
	HandleCount  int          `json:"handle_count"`
	Status       string       `json:"status"`
	Priority     int          `json:"priority"`
	Architecture string       `json:"architecture"`
	Modules      []ModuleInfo `json:"modules"`
}

type ModuleInfo struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	Size    uint64 `json:"size"`
	Version string `json:"version"`
	Hash    string `json:"hash"`
}

type NetworkConnection struct {
	LocalAddress  string `json:"local_address"`
	LocalPort     int    `json:"local_port"`
	RemoteAddress string `json:"remote_address"`
	RemotePort    int    `json:"remote_port"`
	Protocol      string `json:"protocol"`
	State         string `json:"state"`
	PID           uint32 `json:"pid"`
	ProcessName   string `json:"process_name"`
	Direction     string `json:"direction"`
	BytesSent     uint64 `json:"bytes_sent"`
	BytesReceived uint64 `json:"bytes_received"`
}

// Behavior analysis structures
type BehaviorRule struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Category    string                 `json:"category"`
	Severity    string                 `json:"severity"`
	Conditions  []BehaviorCondition    `json:"conditions"`
	Actions     []string               `json:"actions"`
	Enabled     bool                   `json:"enabled"`
	Metadata    map[string]interface{} `json:"metadata"`
}

type BehaviorCondition struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"`
	Value    interface{} `json:"value"`
	Logic    string      `json:"logic"` // AND, OR
}

// Event structures
type SecurityEvent struct {
	ID          string                 `json:"id"`
	Timestamp   time.Time              `json:"timestamp"`
	Type        string                 `json:"type"`
	Source      string                 `json:"source"`
	Severity    string                 `json:"severity"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Data        map[string]interface{} `json:"data"`
	Tags        []string               `json:"tags"`
	Hash        string                 `json:"hash"`
}

// Registry structures
type RegistryKey struct {
	Path         string            `json:"path"`
	Name         string            `json:"name"`
	Type         string            `json:"type"`
	Value        interface{}       `json:"value"`
	LastModified time.Time         `json:"last_modified"`
	Permissions  []string          `json:"permissions"`
	Owner        string            `json:"owner"`
	Metadata     map[string]string `json:"metadata"`
}

// File system structures
type FileInfo struct {
	Path        string            `json:"path"`
	Name        string            `json:"name"`
	Size        int64             `json:"size"`
	Mode        string            `json:"mode"`
	ModTime     time.Time         `json:"mod_time"`
	IsDir       bool              `json:"is_dir"`
	Hash        string            `json:"hash"`
	Owner       string            `json:"owner"`
	Permissions []string          `json:"permissions"`
	Attributes  []string          `json:"attributes"`
	Metadata    map[string]string `json:"metadata"`
}

// Event log structures
type EventLogEntry struct {
	ID        uint64                 `json:"id"`
	Source    string                 `json:"source"`
	Level     string                 `json:"level"`
	EventID   uint32                 `json:"event_id"`
	Timestamp time.Time              `json:"timestamp"`
	Message   string                 `json:"message"`
	Computer  string                 `json:"computer"`
	User      string                 `json:"user"`
	Category  string                 `json:"category"`
	Keywords  []string               `json:"keywords"`
	Data      map[string]interface{} `json:"data"`
}
