//go:build windows

package main

import (
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// TelemetryCollector gathers comprehensive system telemetry
type TelemetryCollector struct {
}

// SystemTelemetry represents comprehensive system information
type SystemTelemetry struct {
	Timestamp   time.Time           `json:"timestamp"`
	OS          OSInfo              `json:"os"`
	Hardware    HardwareInfo        `json:"hardware"`
	Network     []NetworkConnection `json:"network"`
	Processes   []ProcessInfo       `json:"processes"`
	Services    []ServiceInfo       `json:"services"`
	Software    []SoftwareInfo      `json:"software"`
	Performance PerformanceMetrics  `json:"performance"`
	Security    SecurityMetrics     `json:"security"`
}

type PerformanceMetrics struct {
	CPUUsage    float64 `json:"cpu_usage"`
	MemoryUsage float64 `json:"memory_usage"`
	DiskUsage   float64 `json:"disk_usage"`
	NetworkIO   struct {
		BytesSent     uint64 `json:"bytes_sent"`
		BytesReceived uint64 `json:"bytes_received"`
		PacketsSent   uint64 `json:"packets_sent"`
		PacketsRecv   uint64 `json:"packets_received"`
	} `json:"network_io"`
	DiskIO struct {
		ReadBytes  uint64 `json:"read_bytes"`
		WriteBytes uint64 `json:"write_bytes"`
		ReadOps    uint64 `json:"read_ops"`
		WriteOps   uint64 `json:"write_ops"`
	} `json:"disk_io"`
	Uptime int64 `json:"uptime_seconds"`
}

type SecurityMetrics struct {
	AntivirusStatus     string    `json:"antivirus_status"`
	FirewallStatus      string    `json:"firewall_status"`
	WindowsUpdateStatus string    `json:"windows_update_status"`
	LastSecurityScan    time.Time `json:"last_security_scan"`
	ThreatCount         int       `json:"threat_count"`
	QuarantineCount     int       `json:"quarantine_count"`
	DefenderStatus      string    `json:"defender_status"`
	UAC                 bool      `json:"uac_enabled"`
	BitLockerStatus     string    `json:"bitlocker_status"`
	EncryptionStatus    string    `json:"encryption_status"`
}

type UserSession struct {
	Username    string    `json:"username"`
	SessionID   uint32    `json:"session_id"`
	SessionType string    `json:"session_type"`
	State       string    `json:"state"`
	LoginTime   time.Time `json:"login_time"`
	IdleTime    int64     `json:"idle_time"`
	ClientName  string    `json:"client_name"`
	ClientIP    string    `json:"client_ip"`
}

type EventLogSummary struct {
	Source      string    `json:"source"`
	Level       string    `json:"level"`
	EventID     uint32    `json:"event_id"`
	Count       int       `json:"count"`
	LastOccured time.Time `json:"last_occurred"`
	Description string    `json:"description"`
}

type RegistryChange struct {
	KeyPath   string    `json:"key_path"`
	ValueName string    `json:"value_name"`
	OldValue  string    `json:"old_value"`
	NewValue  string    `json:"new_value"`
	Timestamp time.Time `json:"timestamp"`
	ProcessID uint32    `json:"process_id"`
	User      string    `json:"user"`
}

type FileSystemChange struct {
	Path      string    `json:"path"`
	Action    string    `json:"action"`
	Timestamp time.Time `json:"timestamp"`
	ProcessID uint32    `json:"process_id"`
	User      string    `json:"user"`
	Size      int64     `json:"size"`
	Hash      string    `json:"hash"`
}

type StartupProgram struct {
	Name     string `json:"name"`
	Command  string `json:"command"`
	Location string `json:"location"`
	Enabled  bool   `json:"enabled"`
	Impact   string `json:"impact"`
}

// Enhanced Windows telemetry structures for EDR/XDR/SIEM
type SystemInfo struct {
	Hostname          string            `json:"hostname"`
	Domain            string            `json:"domain"`
	OS                OSInfo            `json:"os"`
	Hardware          HardwareInfo      `json:"hardware"`
	Network           NetworkInfo       `json:"network"`
	Security          SecurityInfo      `json:"security"`
	Performance       PerformanceInfo   `json:"performance"`
	InstalledSoftware []SoftwareInfo    `json:"installed_software"`
	Services          []ServiceInfo     `json:"services"`
	Users             []UserInfo        `json:"users"`
	Environment       map[string]string `json:"environment"`
}

// DiskInfo represents disk information specific to telemetry
type DiskInfo struct {
	Drive        string  `json:"drive"`
	Type         string  `json:"type"`
	FileSystem   string  `json:"file_system"`
	TotalSize    uint64  `json:"total_size_gb"`
	FreeSpace    uint64  `json:"free_space_gb"`
	UsedSpace    uint64  `json:"used_space_gb"`
	UsagePercent float64 `json:"usage_percent"`
	Health       string  `json:"health"`
}

// NetworkCard represents network card information specific to telemetry
type NetworkCard struct {
	Name        string   `json:"name"`
	MACAddress  string   `json:"mac_address"`
	IPAddresses []string `json:"ip_addresses"`
	Status      string   `json:"status"`
	Speed       uint64   `json:"speed_mbps"`
}

type NetworkInfo struct {
	Interfaces     []TelemetryNetworkInterface `json:"interfaces"`
	Connections    []NetworkConnection         `json:"connections"`
	DNSServers     []string                    `json:"dns_servers"`
	DefaultGateway string                      `json:"default_gateway"`
	PublicIP       string                      `json:"public_ip"`
}

// TelemetryNetworkInterface represents network interface information for telemetry
type TelemetryNetworkInterface struct {
	Name          string   `json:"name"`
	Type          string   `json:"type"`
	Status        string   `json:"status"`
	MACAddress    string   `json:"mac_address"`
	IPAddresses   []string `json:"ip_addresses"`
	BytesSent     uint64   `json:"bytes_sent"`
	BytesReceived uint64   `json:"bytes_received"`
}

type SecurityInfo struct {
	AntivirusStatus   []AntivirusInfo `json:"antivirus_status"`
	FirewallStatus    FirewallInfo    `json:"firewall_status"`
	WindowsDefender   DefenderInfo    `json:"windows_defender"`
	UAC               UACInfo         `json:"uac"`
	BitLockerStatus   []BitLockerInfo `json:"bitlocker_status"`
	CertificateStores []CertInfo      `json:"certificate_stores"`
	SecurityPolicies  []PolicyInfo    `json:"security_policies"`
}

type AntivirusInfo struct {
	Name               string `json:"name"`
	Status             string `json:"status"`
	Version            string `json:"version"`
	LastUpdate         string `json:"last_update"`
	RealTimeProtection bool   `json:"real_time_protection"`
}

type FirewallInfo struct {
	DomainProfile  string         `json:"domain_profile"`
	PrivateProfile string         `json:"private_profile"`
	PublicProfile  string         `json:"public_profile"`
	Rules          []FirewallRule `json:"rules"`
}

type FirewallRule struct {
	Name      string `json:"name"`
	Direction string `json:"direction"`
	Action    string `json:"action"`
	Protocol  string `json:"protocol"`
	Port      string `json:"port"`
	Enabled   bool   `json:"enabled"`
}

type DefenderInfo struct {
	Enabled              bool   `json:"enabled"`
	RealTimeProtection   bool   `json:"real_time_protection"`
	Version              string `json:"version"`
	LastScan             string `json:"last_scan"`
	LastUpdate           string `json:"last_update"`
	ThreatDetectionCount int    `json:"threat_detection_count"`
}

type UACInfo struct {
	Enabled bool   `json:"enabled"`
	Level   string `json:"level"`
}

type BitLockerInfo struct {
	Drive          string `json:"drive"`
	Status         string `json:"status"`
	EncryptionType string `json:"encryption_type"`
	Percentage     int    `json:"encryption_percentage"`
}

type CertInfo struct {
	Store      string `json:"store"`
	Subject    string `json:"subject"`
	Issuer     string `json:"issuer"`
	Thumbprint string `json:"thumbprint"`
	NotBefore  string `json:"not_before"`
	NotAfter   string `json:"not_after"`
	KeyUsage   string `json:"key_usage"`
}

type PolicyInfo struct {
	Name        string `json:"name"`
	Value       string `json:"value"`
	Type        string `json:"type"`
	Description string `json:"description"`
}

type PerformanceInfo struct {
	CPUUsage     float64            `json:"cpu_usage_percent"`
	MemoryUsage  float64            `json:"memory_usage_percent"`
	DiskUsage    map[string]float64 `json:"disk_usage_percent"`
	NetworkIO    NetworkIOStats     `json:"network_io"`
	ProcessCount int                `json:"process_count"`
	ThreadCount  int                `json:"thread_count"`
	HandleCount  int                `json:"handle_count"`
	Uptime       int64              `json:"uptime_seconds"`
}

type NetworkIOStats struct {
	BytesSentPerSec       uint64 `json:"bytes_sent_per_sec"`
	BytesReceivedPerSec   uint64 `json:"bytes_received_per_sec"`
	PacketsSentPerSec     uint64 `json:"packets_sent_per_sec"`
	PacketsReceivedPerSec uint64 `json:"packets_received_per_sec"`
}

type UserInfo struct {
	Name        string   `json:"name"`
	FullName    string   `json:"full_name"`
	SID         string   `json:"sid"`
	AccountType string   `json:"account_type"`
	Enabled     bool     `json:"enabled"`
	LastLogon   string   `json:"last_logon"`
	Groups      []string `json:"groups"`
	Privileges  []string `json:"privileges"`
	ProfilePath string   `json:"profile_path"`
}

type ProcessIOCounters struct {
	ReadOperationCount  uint64 `json:"read_operation_count"`
	WriteOperationCount uint64 `json:"write_operation_count"`
	ReadTransferCount   uint64 `json:"read_transfer_count"`
	WriteTransferCount  uint64 `json:"write_transfer_count"`
}

type FileAccessInfo struct {
	Path      string `json:"path"`
	Operation string `json:"operation"`
	Timestamp string `json:"timestamp"`
	Result    string `json:"result"`
}

type RegistryAccessInfo struct {
	Key       string `json:"key"`
	Value     string `json:"value"`
	Operation string `json:"operation"`
	Timestamp string `json:"timestamp"`
	Result    string `json:"result"`
}

type ProcessSecurityContext struct {
	IntegrityLevel        string   `json:"integrity_level"`
	Privileges            []string `json:"privileges"`
	TokenType             string   `json:"token_type"`
	Elevated              bool     `json:"elevated"`
	VirtualizationEnabled bool     `json:"virtualization_enabled"`
}

// Collect comprehensive system information
func CollectSystemInfo() (*SystemInfo, error) {
	hostname, _ := os.Hostname()

	sysInfo := &SystemInfo{
		Hostname:    hostname,
		Environment: make(map[string]string),
	}

	// Collect OS information
	sysInfo.OS = collectOSInfo()

	// Collect hardware information
	sysInfo.Hardware = collectHardwareInfo()

	// Collect network information
	sysInfo.Network = collectNetworkInfo()

	// Collect security information
	sysInfo.Security = collectSecurityInfo()

	// Collect performance information
	sysInfo.Performance = collectPerformanceInfo()

	// Collect installed software
	sysInfo.InstalledSoftware = collectInstalledSoftware()

	// Collect services
	sysInfo.Services = collectServices()

	// Collect users
	sysInfo.Users = collectUsers()

	// Collect environment variables
	for _, env := range os.Environ() {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) == 2 {
			sysInfo.Environment[parts[0]] = parts[1]
		}
	}

	return sysInfo, nil
}

func collectOSInfo() OSInfo {
	osInfo := OSInfo{
		Name:         "Windows",
		Architecture: runtime.GOARCH,
		TimeZone:     getTimeZone(),
		Locale:       getLocale(),
	}

	// Get Windows version information
	if version := getWindowsVersion(); version != "" {
		osInfo.Version = version
	}

	if build := getWindowsBuild(); build != "" {
		osInfo.Build = build
	}

	if bootTime := getLastBootTime(); bootTime != "" {
		osInfo.LastBoot = bootTime
	}

	return osInfo
}

func collectHardwareInfo() HardwareInfo {
	hardware := HardwareInfo{
		CPU:     collectCPUInfo(),
		Memory:  collectMemoryInfo(),
		Storage: collectDiskInfo(),
		BIOS:    collectBIOSInfo(),
	}

	return hardware
}

func collectCPUInfo() CPUInfo {
	cpu := CPUInfo{
		Cores:        runtime.NumCPU(),
		Architecture: runtime.GOARCH,
	}

	// Get CPU name from registry
	if name := getCPUName(); name != "" {
		cpu.Name = name
	}

	return cpu
}

func collectMemoryInfo() MemoryInfo {
	// Define MEMORYSTATUSEX structure
	type MEMORYSTATUSEX struct {
		Length               uint32
		MemoryLoad           uint32
		TotalPhys            uint64
		AvailPhys            uint64
		TotalPageFile        uint64
		AvailPageFile        uint64
		TotalVirtual         uint64
		AvailVirtual         uint64
		AvailExtendedVirtual uint64
	}

	var memStatus MEMORYSTATUSEX
	memStatus.Length = uint32(unsafe.Sizeof(memStatus))

	// Use GlobalMemoryStatusEx from kernel32.dll
	kernel32 := windows.NewLazyDLL("kernel32.dll")
	globalMemoryStatusEx := kernel32.NewProc("GlobalMemoryStatusEx")

	ret, _, _ := globalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&memStatus)))

	if ret != 0 {
		return MemoryInfo{
			Total:     memStatus.TotalPhys,
			Available: memStatus.AvailPhys,
			Used:      memStatus.TotalPhys - memStatus.AvailPhys,
			Usage:     float64(memStatus.MemoryLoad),
		}
	}

	return MemoryInfo{}
}

func collectDiskInfo() []StorageInfo {
	var disks []StorageInfo

	drives := getDriveLetters()
	for _, drive := range drives {
		if diskInfo := getDiskInfo(drive); diskInfo != nil {
			disks = append(disks, *diskInfo)
		}
	}

	return disks
}

func collectBIOSInfo() BIOSInfo {
	return BIOSInfo{
		Vendor:  getBIOSVendor(),
		Version: getBIOSVersion(),
	}
}

func collectNetworkInfo() NetworkInfo {
	network := NetworkInfo{
		Interfaces:  collectNetworkInterfaces(),
		Connections: collectNetworkConnections(),
		DNSServers:  getDNSServers(),
	}

	return network
}

func collectNetworkInterfaces() []TelemetryNetworkInterface {
	var interfaces []TelemetryNetworkInterface

	ifaces, err := net.Interfaces()
	if err != nil {
		return interfaces
	}

	for _, iface := range ifaces {
		netIface := TelemetryNetworkInterface{
			Name:       iface.Name,
			MACAddress: iface.HardwareAddr.String(),
			Status:     getTelemetryInterfaceStatus(iface.Flags),
		}

		addrs, err := iface.Addrs()
		if err == nil {
			for _, addr := range addrs {
				netIface.IPAddresses = append(netIface.IPAddresses, addr.String())
			}
		}

		interfaces = append(interfaces, netIface)
	}

	return interfaces
}

func collectNetworkConnections() []NetworkConnection {
	// This would require more complex implementation using Windows APIs
	// For now, return empty slice
	return []NetworkConnection{}
}

func collectSecurityInfo() SecurityInfo {
	security := SecurityInfo{
		AntivirusStatus: collectAntivirusInfo(),
		FirewallStatus:  collectFirewallInfo(),
		WindowsDefender: collectDefenderInfo(),
		UAC:             collectUACInfo(),
	}

	return security
}

func collectAntivirusInfo() []AntivirusInfo {
	// This would require WMI queries to get antivirus information
	return []AntivirusInfo{}
}

func collectFirewallInfo() FirewallInfo {
	return FirewallInfo{}
}

func collectDefenderInfo() DefenderInfo {
	return DefenderInfo{}
}

func collectUACInfo() UACInfo {
	return UACInfo{}
}

func collectPerformanceInfo() PerformanceInfo {
	perf := PerformanceInfo{
		ProcessCount: getProcessCount(),
		Uptime:       getSystemUptime(),
	}

	return perf
}

func collectInstalledSoftware() []SoftwareInfo {
	var software []SoftwareInfo

	// Read from registry uninstall keys
	software = append(software, readUninstallRegistry(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`)...)
	software = append(software, readUninstallRegistry(registry.LOCAL_MACHINE, `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`)...)

	return software
}

func collectServices() []ServiceInfo {
	// This would require Windows service management APIs
	return []ServiceInfo{}
}

func collectUsers() []UserInfo {
	// This would require Windows user management APIs
	return []UserInfo{}
}

// Helper functions
func getTimeZone() string {
	zone, _ := time.Now().Zone()
	return zone
}

func getLocale() string {
	return os.Getenv("LANG")
}

func getWindowsVersion() string {
	cmd := exec.Command("cmd", "/c", "ver")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}

func getWindowsBuild() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()

	build, _, err := k.GetStringValue("CurrentBuild")
	if err != nil {
		return ""
	}
	return build
}

func getLastBootTime() string {
	// This would require Windows API calls
	return ""
}

func getCPUName() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `HARDWARE\DESCRIPTION\System\CentralProcessor\0`, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()

	name, _, err := k.GetStringValue("ProcessorNameString")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(name)
}

func getDriveLetters() []string {
	var drives []string
	for i := 'A'; i <= 'Z'; i++ {
		drive := string(i) + ":"
		driveType := windows.GetDriveType(windows.StringToUTF16Ptr(drive + "\\"))
		if driveType != windows.DRIVE_NO_ROOT_DIR {
			drives = append(drives, drive)
		}
	}
	return drives
}

func getDiskInfo(drive string) *StorageInfo {
	var freeBytesAvailable, totalNumberOfBytes, totalNumberOfFreeBytes uint64

	drivePtr := windows.StringToUTF16Ptr(drive + "\\")
	err := windows.GetDiskFreeSpaceEx(drivePtr, &freeBytesAvailable, &totalNumberOfBytes, &totalNumberOfFreeBytes)
	if err != nil {
		return nil
	}

	usagePercent := float64(totalNumberOfBytes-totalNumberOfFreeBytes) / float64(totalNumberOfBytes) * 100

	return &StorageInfo{
		Device:     drive,
		Type:       getDriveType(drive),
		Size:       totalNumberOfBytes,
		Used:       totalNumberOfBytes - totalNumberOfFreeBytes,
		Available:  totalNumberOfFreeBytes,
		Usage:      usagePercent,
		FileSystem: getFileSystem(drive),
		MountPoint: drive + "\\",
		Health:     "Unknown",
	}
}

func getFileSystem(drive string) string {
	var volumeName [256]uint16
	var fileSystemName [256]uint16
	var serialNumber, maxComponentLength, fileSystemFlags uint32

	drivePtr := windows.StringToUTF16Ptr(drive + "\\")
	err := windows.GetVolumeInformation(
		drivePtr,
		&volumeName[0], uint32(len(volumeName)),
		&serialNumber,
		&maxComponentLength,
		&fileSystemFlags,
		&fileSystemName[0], uint32(len(fileSystemName)))

	if err != nil {
		return "Unknown"
	}

	return windows.UTF16ToString(fileSystemName[:])
}

func getDriveType(drive string) string {
	driveType := windows.GetDriveType(windows.StringToUTF16Ptr(drive + "\\"))
	switch driveType {
	case windows.DRIVE_FIXED:
		return "Fixed"
	case windows.DRIVE_REMOVABLE:
		return "Removable"
	case windows.DRIVE_REMOTE:
		return "Network"
	case windows.DRIVE_CDROM:
		return "CD-ROM"
	case windows.DRIVE_RAMDISK:
		return "RAM Disk"
	default:
		return "Unknown"
	}
}

func getBIOSVendor() string {
	// This would require WMI queries
	return ""
}

func getBIOSVersion() string {
	// This would require WMI queries
	return ""
}

func getTelemetryInterfaceStatus(flags net.Flags) string {
	if flags&net.FlagUp != 0 {
		return "Up"
	}
	return "Down"
}

func getDNSServers() []string {
	// This would require Windows networking APIs
	return []string{}
}

func getProcessCount() int {
	// This would require Windows process enumeration APIs
	return 0
}

func getSystemUptime() int64 {
	// This would require Windows system APIs
	return 0
}

func readUninstallRegistry(hkey registry.Key, path string) []SoftwareInfo {
	var software []SoftwareInfo

	k, err := registry.OpenKey(hkey, path, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return software
	}
	defer k.Close()

	subkeys, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return software
	}

	for _, subkey := range subkeys {
		if sw := readSoftwareInfo(hkey, path+"\\"+subkey); sw != nil {
			software = append(software, *sw)
		}
	}

	return software
}

func readSoftwareInfo(hkey registry.Key, path string) *SoftwareInfo {
	k, err := registry.OpenKey(hkey, path, registry.QUERY_VALUE)
	if err != nil {
		return nil
	}
	defer k.Close()

	sw := &SoftwareInfo{}

	if name, _, err := k.GetStringValue("DisplayName"); err == nil {
		sw.Name = name
	} else {
		return nil // Skip entries without display name
	}

	if version, _, err := k.GetStringValue("DisplayVersion"); err == nil {
		sw.Version = version
	}

	if vendor, _, err := k.GetStringValue("Publisher"); err == nil {
		sw.Vendor = vendor
	}

	if installDateStr, _, err := k.GetStringValue("InstallDate"); err == nil {
		// Parse install date string to time.Time
		if installDate, err := time.Parse("20060102", installDateStr); err == nil {
			sw.InstallDate = installDate
		}
	}

	if installLocation, _, err := k.GetStringValue("InstallLocation"); err == nil {
		sw.InstallLocation = installLocation
	}

	// UninstallString field doesn't exist in SoftwareInfo struct, skip it

	if sizeStr, _, err := k.GetStringValue("EstimatedSize"); err == nil {
		if size, err := strconv.ParseUint(sizeStr, 10, 64); err == nil {
			sw.Size = size * 1024 // Convert KB to bytes
		}
	}

	return sw
}

func getDomain() string {
	// Get computer domain
	domain := os.Getenv("USERDOMAIN")
	if domain == "" {
		domain = "WORKGROUP"
	}
	return domain
}

func getEnvironmentVariables() map[string]string {
	env := make(map[string]string)
	for _, e := range os.Environ() {
		pair := strings.SplitN(e, "=", 2)
		if len(pair) == 2 {
			env[pair[0]] = pair[1]
		}
	}
	return env
}

// WindowsTelemetryCollector manages comprehensive Windows telemetry collection
type WindowsTelemetryCollector struct {
	// Add any state needed for telemetry collection
}

// NewWindowsTelemetryCollector creates a new Windows telemetry collector
func NewWindowsTelemetryCollector() *WindowsTelemetryCollector {
	return &WindowsTelemetryCollector{}
}

// CollectSystemInfo collects comprehensive system information
func (w *WindowsTelemetryCollector) CollectSystemInfo() (*SystemInfo, error) {
	systemInfo := &SystemInfo{
		Hostname:    getHostname(),
		Domain:      getDomain(),
		Environment: getEnvironmentVariables(),
	}

	// Collect system information
	systemInfo.OS = collectOSInfo()
	systemInfo.Hardware = collectHardwareInfo()
	systemInfo.Performance = collectPerformanceInfo()
	systemInfo.Network = collectNetworkInfo()
	systemInfo.Security = collectSecurityInfo()
	systemInfo.InstalledSoftware = collectInstalledSoftware()
	systemInfo.Services = collectServices()
	systemInfo.Users = collectUsers()

	return systemInfo, nil
}
