//go:build windows

package main

import (
	"log"
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// AssetInventory manages comprehensive asset discovery and inventory
type AssetInventory struct {
	assets      map[string]*Asset
	stopChannel chan bool
}

// Asset represents a discovered asset
type Asset struct {
	ID               string                 `json:"id"`
	Name             string                 `json:"name"`
	Type             string                 `json:"type"`
	IPAddresses      []string               `json:"ip_addresses"`
	MACAddresses     []string               `json:"mac_addresses"`
	OSInfo           OSInfo                 `json:"os_info"`
	HardwareInfo     HardwareInfo           `json:"hardware_info"`
	SoftwareInfo     []SoftwareInfo         `json:"software_info"`
	NetworkInfo      NetworkInfo            `json:"network_info"`
	SecurityInfo     SecurityInfo           `json:"security_info"`
	ComplianceStatus map[string]interface{} `json:"compliance_status"`
	RiskScore        float64                `json:"risk_score"`
	LastSeen         time.Time              `json:"last_seen"`
	FirstDiscovered  time.Time              `json:"first_discovered"`
	Tags             []string               `json:"tags"`
	Metadata         map[string]interface{} `json:"metadata"`
}

// PatchInfo contains patch information
type PatchInfo struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	InstallDate time.Time `json:"install_date"`
	Severity    string    `json:"severity"`
}

// VulnerabilityInfo contains vulnerability information
type VulnerabilityInfo struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Severity    string    `json:"severity"`
	CVSS        float64   `json:"cvss"`
	Description string    `json:"description"`
	Solution    string    `json:"solution"`
	References  []string  `json:"references"`
	Discovered  time.Time `json:"discovered"`
	Status      string    `json:"status"` // open, patched, mitigated
}

// ComplianceStatus contains compliance information
type ComplianceStatus struct {
	Frameworks []ComplianceFramework `json:"frameworks"`
	Score      float64               `json:"score"`
	LastCheck  time.Time             `json:"last_check"`
}

// ComplianceFramework represents compliance with a specific framework
type ComplianceFramework struct {
	Name     string              `json:"name"` // CIS, NIST, SOC2, etc.
	Version  string              `json:"version"`
	Score    float64             `json:"score"`
	Controls []ComplianceControl `json:"controls"`
}

// ComplianceControl represents a specific compliance control
type ComplianceControl struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Status      string `json:"status"` // compliant, non_compliant, not_applicable
	Severity    string `json:"severity"`
	Description string `json:"description"`
}

// NewAssetInventory creates a new asset inventory manager
func NewAssetInventory() *AssetInventory {
	return &AssetInventory{
		assets:      make(map[string]*Asset),
		stopChannel: make(chan bool),
	}
}

// DiscoverAssets performs comprehensive asset discovery
func (ai *AssetInventory) DiscoverAssets() error {
	log.Println("Starting comprehensive asset discovery...")

	// Discover local asset (this machine)
	localAsset, err := ai.discoverLocalAsset()
	if err != nil {
		log.Printf("Error discovering local asset: %v", err)
	} else {
		ai.assets[localAsset.ID] = &localAsset
	}

	// Discover network assets
	networkAssets, err := ai.discoverNetworkAssets()
	if err != nil {
		log.Printf("Error discovering network assets: %v", err)
	} else {
		for _, asset := range networkAssets {
			ai.assets[asset.ID] = &asset
		}
	}

	log.Printf("Asset discovery completed. Found %d assets", len(ai.assets))

	return nil
}

// discoverLocalAsset discovers information about the local machine
func (ai *AssetInventory) discoverLocalAsset() (Asset, error) {
	hostname, _ := os.Hostname()

	asset := Asset{
		ID:              hostname,
		Type:            "endpoint",
		Name:            hostname,
		FirstDiscovered: time.Now(),
		LastSeen:        time.Now(),
		Tags:            []string{"local", "agent_installed"},
		Metadata:        make(map[string]interface{}),
	}

	// Get IP addresses
	asset.IPAddresses = ai.getLocalIPAddresses()

	// Get MAC addresses
	asset.MACAddresses = ai.getLocalMACAddresses()

	// Get OS information
	asset.OSInfo = ai.getOSInfo()

	// Get hardware information
	asset.HardwareInfo = ai.getHardwareInfo()

	// Get installed software
	asset.SoftwareInfo = ai.getInstalledSoftware()

	// Get running services - add to software info since there's no Services field
	services := ai.getRunningServices()
	for _, service := range services {
		asset.SoftwareInfo = append(asset.SoftwareInfo, SoftwareInfo{
			Name:    service.Name,
			Version: service.Status,
			Type:    "service",
		})
	}

	// Assess compliance
	complianceStatus := ai.assessCompliance()
	// Convert ComplianceStatus struct to map[string]interface{}
	asset.ComplianceStatus = map[string]interface{}{
		"frameworks": complianceStatus.Frameworks,
		"score":      complianceStatus.Score,
		"last_check": complianceStatus.LastCheck,
	}

	// Calculate risk level
	asset.RiskScore = float64(len(ai.calculateRiskLevel(asset))) // Convert string to float64 based on length

	return asset, nil
}

// getLocalIPAddresses gets all local IP addresses
func (ai *AssetInventory) getLocalIPAddresses() []string {
	var ips []string

	interfaces, err := net.Interfaces()
	if err != nil {
		return ips
	}

	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipnet.IP.To4() != nil {
					ips = append(ips, ipnet.IP.String())
				}
			}
		}
	}

	return ips
}

// getLocalMACAddresses gets all local MAC addresses
func (ai *AssetInventory) getLocalMACAddresses() []string {
	var macs []string

	interfaces, err := net.Interfaces()
	if err != nil {
		return macs
	}

	for _, iface := range interfaces {
		if iface.HardwareAddr != nil {
			macs = append(macs, iface.HardwareAddr.String())
		}
	}

	return macs
}

// getOSInfo gets operating system information
func (ai *AssetInventory) getOSInfo() OSInfo {
	osInfo := OSInfo{
		Name:         runtime.GOOS,
		Architecture: runtime.GOARCH,
	}

	// Get Windows version information
	if runtime.GOOS == "windows" {
		cmd := exec.Command("wmic", "os", "get", "Caption,Version,BuildNumber", "/format:csv")
		output, err := cmd.Output()
		if err == nil {
			lines := strings.Split(string(output), "\n")
			for _, line := range lines {
				if strings.Contains(line, "Microsoft Windows") {
					parts := strings.Split(line, ",")
					if len(parts) >= 4 {
						osInfo.Build = strings.TrimSpace(parts[1])
						osInfo.Name = strings.TrimSpace(parts[2])
						osInfo.Version = strings.TrimSpace(parts[3])
					}
				}
			}
		}

		// Note: OSInfo struct doesn't have Patches field
		// Patches are handled separately through getInstalledPatches() method
	}

	return osInfo
}

// getHardwareInfo gets hardware information
func (ai *AssetInventory) getHardwareInfo() HardwareInfo {
	hwInfo := HardwareInfo{}

	if runtime.GOOS == "windows" {
		// Get system information
		cmd := exec.Command("wmic", "computersystem", "get", "Manufacturer,Model", "/format:csv")
		output, err := cmd.Output()
		if err == nil {
			lines := strings.Split(string(output), "\n")
			for _, line := range lines {
				if strings.Contains(line, ",") && !strings.Contains(line, "Manufacturer") {
					parts := strings.Split(line, ",")
					if len(parts) >= 3 {
						hwInfo.Manufacturer = strings.TrimSpace(parts[1])
						hwInfo.Model = strings.TrimSpace(parts[2])
					}
				}
			}
		}

		// Get CPU information
		hwInfo.CPU = ai.getCPUInfo()

		// Get memory information
		hwInfo.Memory = ai.getMemoryInfo()

		// Get storage information
		hwInfo.Storage = ai.getStorageInfo()

		// Get network adapter information
		hwInfo.Network = ai.getNetworkAdapterInfo()
	}

	return hwInfo
}

// getCPUInfo gets CPU information
func (ai *AssetInventory) getCPUInfo() CPUInfo {
	cpuInfo := CPUInfo{
		Cores: runtime.NumCPU(),
	}

	if runtime.GOOS == "windows" {
		cmd := exec.Command("wmic", "cpu", "get", "Name,NumberOfCores,NumberOfLogicalProcessors,MaxClockSpeed", "/format:csv")
		output, err := cmd.Output()
		if err == nil {
			lines := strings.Split(string(output), "\n")
			for _, line := range lines {
				if strings.Contains(line, ",") && !strings.Contains(line, "Name") {
					parts := strings.Split(line, ",")
					if len(parts) >= 5 {
						// Parse frequency and convert to GHz
						if freq, err := strconv.ParseFloat(strings.TrimSpace(parts[1]), 64); err == nil {
							cpuInfo.Speed = freq / 1000 // Convert MHz to GHz
						}
						cpuInfo.Name = strings.TrimSpace(parts[2])
						if cores, err := strconv.Atoi(strings.TrimSpace(parts[3])); err == nil {
							cpuInfo.Cores = cores
						}
						if threads, err := strconv.Atoi(strings.TrimSpace(parts[4])); err == nil {
							cpuInfo.Threads = threads
						}
					}
					break
				}
			}
		}
	}

	return cpuInfo
}

// getMemoryInfo gets memory information
func (ai *AssetInventory) getMemoryInfo() MemoryInfo {
	memInfo := MemoryInfo{}

	if runtime.GOOS == "windows" {
		// Get total physical memory
		cmd := exec.Command("wmic", "computersystem", "get", "TotalPhysicalMemory", "/format:csv")
		output, err := cmd.Output()
		if err == nil {
			re := regexp.MustCompile(`\d+`)
			matches := re.FindAllString(string(output), -1)
			if len(matches) > 0 {
				if totalBytes, parseErr := strconv.ParseInt(matches[0], 10, 64); parseErr == nil {
					memInfo.Total = uint64(totalBytes)
				}
			}
		}

		// Get available memory
		cmd = exec.Command("wmic", "OS", "get", "FreePhysicalMemory", "/format:csv")
		output, err = cmd.Output()
		if err == nil {
			re := regexp.MustCompile(`\d+`)
			matches := re.FindAllString(string(output), -1)
			if len(matches) > 0 {
				if freeKB, err := strconv.ParseInt(matches[0], 10, 64); err == nil {
					memInfo.Available = uint64(freeKB * 1024) // Convert KB to bytes
				}
			}
		}

		memInfo.Used = memInfo.Total - memInfo.Available
		if memInfo.Total > 0 {
			memInfo.Usage = float64(memInfo.Used) / float64(memInfo.Total) * 100
		}
	}

	return memInfo
}

// getStorageInfo gets storage information
func (ai *AssetInventory) getStorageInfo() []StorageInfo {
	var storageDevices []StorageInfo

	if runtime.GOOS == "windows" {
		cmd := exec.Command("wmic", "logicaldisk", "get", "DeviceID,Size,FreeSpace,FileSystem", "/format:csv")
		output, err := cmd.Output()
		if err == nil {
			lines := strings.Split(string(output), "\n")
			for _, line := range lines {
				if strings.Contains(line, ":") {
					parts := strings.Split(line, ",")
					if len(parts) >= 5 {
						device := strings.TrimSpace(parts[1])
						filesystem := strings.TrimSpace(parts[2])

						var totalGB, freeGB float64
						if freeBytes, err := strconv.ParseInt(strings.TrimSpace(parts[3]), 10, 64); err == nil {
							freeGB = float64(freeBytes) / (1024 * 1024 * 1024)
						}
						if totalBytes, err := strconv.ParseInt(strings.TrimSpace(parts[4]), 10, 64); err == nil {
							totalGB = float64(totalBytes) / (1024 * 1024 * 1024)
						}

						usedGB := totalGB - freeGB
						var usagePercent float64
						if totalGB > 0 {
							usagePercent = (usedGB / totalGB) * 100
						}

						storageDevices = append(storageDevices, StorageInfo{
							Device:     device,
							Type:       "Unknown",                            // Would need additional detection
							Size:       uint64(totalGB * 1024 * 1024 * 1024), // Convert GB to bytes
							Available:  uint64(freeGB * 1024 * 1024 * 1024),  // Convert GB to bytes
							Used:       uint64(usedGB * 1024 * 1024 * 1024),  // Convert GB to bytes
							Usage:      usagePercent,
							FileSystem: filesystem,
							MountPoint: device,    // Use device as mount point for now
							Health:     "Unknown", // Would need additional detection
						})
					}
				}
			}
		}
	}

	return storageDevices
}

// getNetworkAdapterInfo gets network adapter information
func (ai *AssetInventory) getNetworkAdapterInfo() []NetworkAdapterInfo {
	var adapters []NetworkAdapterInfo

	interfaces, err := net.Interfaces()
	if err != nil {
		return adapters
	}

	for _, iface := range interfaces {
		adapter := NetworkAdapterInfo{
			Name:       iface.Name,
			MACAddress: iface.HardwareAddr.String(),
			Status:     "up",
		}

		if iface.Flags&net.FlagUp == 0 {
			adapter.Status = "down"
		}

		// Get IP addresses for this interface
		addrs, err := iface.Addrs()
		if err == nil {
			for _, addr := range addrs {
				if ipnet, ok := addr.(*net.IPNet); ok {
					adapter.IPAddresses = append(adapter.IPAddresses, ipnet.IP.String())
				}
			}
		}

		adapters = append(adapters, adapter)
	}

	return adapters
}

// getInstalledSoftware gets list of installed software
func (ai *AssetInventory) getInstalledSoftware() []SoftwareInfo {
	var software []SoftwareInfo

	// This is a simplified implementation
	// In a real scenario, you would query the Windows registry or use WMI
	software = append(software, SoftwareInfo{
		Name:            "MUSAFIR Agent",
		Version:         "1.0.0-enhanced",
		Vendor:          "MUSAFIR Security",
		InstallDate:     time.Now().AddDate(0, 0, -1),
		Type:            "application",
		InstallLocation: "C:\\Program Files\\MUSAFIR\\Agent",
		Size:            0, // Size unknown
	})

	return software
}

// getRunningServices gets list of running services
func (ai *AssetInventory) getRunningServices() []ServiceInfo {
	var services []ServiceInfo

	if runtime.GOOS == "windows" {
		cmd := exec.Command("sc", "query", "state=", "all")
		output, err := cmd.Output()
		if err == nil {
			// Parse service output (simplified)
			lines := strings.Split(string(output), "\n")
			for i, line := range lines {
				if strings.Contains(line, "SERVICE_NAME:") {
					serviceName := strings.TrimSpace(strings.Split(line, ":")[1])

					// Get display name from next few lines
					displayName := serviceName
					status := "unknown"

					for j := i + 1; j < len(lines) && j < i+5; j++ {
						if strings.Contains(lines[j], "DISPLAY_NAME:") {
							displayName = strings.TrimSpace(strings.Split(lines[j], ":")[1])
						}
						if strings.Contains(lines[j], "STATE") {
							if strings.Contains(lines[j], "RUNNING") {
								status = "running"
							} else if strings.Contains(lines[j], "STOPPED") {
								status = "stopped"
							}
						}
					}

					services = append(services, ServiceInfo{
						Name:        serviceName,
						DisplayName: displayName,
						Status:      status,
					})
				}
			}
		}
	}

	return services
}

// discoverNetworkAssets discovers assets on the network
func (ai *AssetInventory) discoverNetworkAssets() ([]Asset, error) {
	var assets []Asset

	// This is a simplified network discovery
	// In a real implementation, you would use techniques like:
	// - ARP table scanning
	// - ICMP ping sweeps
	// - Port scanning
	// - SNMP discovery
	// - Active Directory queries

	log.Println("Network asset discovery not fully implemented in this demo")

	return assets, nil
}

// assessCompliance assesses compliance status
func (ai *AssetInventory) assessCompliance() ComplianceStatus {
	// Simplified compliance assessment
	cisControls := []ComplianceControl{
		{
			ID:          "CIS-1.1",
			Title:       "Ensure Windows Firewall is enabled",
			Status:      "compliant",
			Severity:    "high",
			Description: "Windows Firewall should be enabled for all profiles",
		},
		{
			ID:          "CIS-2.1",
			Title:       "Ensure password policy is configured",
			Status:      "non_compliant",
			Severity:    "medium",
			Description: "Password policy should meet minimum requirements",
		},
	}

	cisFramework := ComplianceFramework{
		Name:     "CIS",
		Version:  "1.0",
		Score:    75.0,
		Controls: cisControls,
	}

	return ComplianceStatus{
		Frameworks: []ComplianceFramework{cisFramework},
		Score:      75.0,
		LastCheck:  time.Now(),
	}
}

// calculateRiskLevel calculates the risk level for an asset
func (ai *AssetInventory) calculateRiskLevel(asset Asset) string {
	riskScore := 0

	// Factor in compliance score
	if complianceScore, ok := asset.ComplianceStatus["score"].(float64); ok {
		if complianceScore < 70 {
			riskScore += 2
		} else if complianceScore < 80 {
			riskScore += 1
		}
	}

	// Factor in vulnerabilities (placeholder - would need vulnerability scanning)
	// This would be populated by a vulnerability scanner
	vulnerabilityCount := 0 // Placeholder
	riskScore += vulnerabilityCount / 2

	// Factor in outdated software
	outdatedSoftware := 0
	for _, software := range asset.SoftwareInfo {
		if time.Since(software.InstallDate) > 365*24*time.Hour {
			outdatedSoftware++
		}
	}
	if outdatedSoftware > 5 {
		riskScore += 2
	}

	// Calculate final risk level
	switch {
	case riskScore >= 10:
		return "critical"
	case riskScore >= 7:
		return "high"
	case riskScore >= 4:
		return "medium"
	default:
		return "low"
	}
}

// GetAssets returns all discovered assets
func (ai *AssetInventory) GetAssets() []Asset {
	assets := make([]Asset, 0, len(ai.assets))
	for _, asset := range ai.assets {
		assets = append(assets, *asset)
	}
	return assets
}

// GetAssetByID returns a specific asset by ID
func (ai *AssetInventory) GetAssetByID(id string) (Asset, bool) {
	asset, exists := ai.assets[id]
	if exists {
		return *asset, true
	}
	return Asset{}, false
}

// UpdateAsset updates an existing asset
func (ai *AssetInventory) UpdateAsset(asset Asset) {
	asset.LastSeen = time.Now()
	ai.assets[asset.ID] = &asset
}

// GetAssetCount returns the number of discovered assets
func (ai *AssetInventory) GetAssetCount() int {
	return len(ai.assets)
}
