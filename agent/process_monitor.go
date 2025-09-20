//go:build windows

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Process monitoring structures
type ProcessEvent struct {
	EventType   string       `json:"event_type"`
	Timestamp   string       `json:"timestamp"`
	ProcessInfo ProcessInfo  `json:"process_info"`
	ParentInfo  *ProcessInfo `json:"parent_info,omitempty"`
	EventData   interface{}  `json:"event_data,omitempty"`
}

type ProcessCreateEvent struct {
	CommandLine      string            `json:"command_line"`
	CurrentDirectory string            `json:"current_directory"`
	Environment      map[string]string `json:"environment"`
	CreationFlags    uint32            `json:"creation_flags"`
}

type ProcessTerminateEvent struct {
	ExitCode uint32 `json:"exit_code"`
	Reason   string `json:"reason"`
	Duration int64  `json:"duration_seconds"`
}

type ProcessImageLoadEvent struct {
	ImagePath   string `json:"image_path"`
	BaseAddress string `json:"base_address"`
	ImageSize   uint64 `json:"image_size"`
	Signed      bool   `json:"signed"`
	SignerName  string `json:"signer_name"`
}

type ProcessNetworkEvent struct {
	EventType        string `json:"event_type"` // connect, listen, send, receive
	Protocol         string `json:"protocol"`
	LocalAddr        string `json:"local_address"`
	LocalPort        int    `json:"local_port"`
	RemoteAddr       string `json:"remote_address"`
	RemotePort       int    `json:"remote_port"`
	BytesTransferred uint64 `json:"bytes_transferred"`
}

type ProcessFileEvent struct {
	EventType  string `json:"event_type"` // create, read, write, delete, rename
	FilePath   string `json:"file_path"`
	OldPath    string `json:"old_path,omitempty"`
	FileSize   uint64 `json:"file_size"`
	Attributes uint32 `json:"attributes"`
	AccessMask uint32 `json:"access_mask"`
}

type ProcessRegistryEvent struct {
	EventType string `json:"event_type"` // create, read, write, delete
	KeyPath   string `json:"key_path"`
	ValueName string `json:"value_name,omitempty"`
	ValueType string `json:"value_type,omitempty"`
	ValueData string `json:"value_data,omitempty"`
}

// Process Monitor manages process monitoring
type ProcessMonitor struct {
	processes    map[uint32]*ProcessInfo
	eventChannel chan ProcessEvent
	stopChannel  chan bool
	running      bool
}

// NewProcessMonitor creates a new process monitor
func NewProcessMonitor() *ProcessMonitor {
	return &ProcessMonitor{
		processes:    make(map[uint32]*ProcessInfo),
		eventChannel: make(chan ProcessEvent, 1000),
		stopChannel:  make(chan bool),
		running:      false,
	}
}

// Start begins process monitoring
func (pm *ProcessMonitor) Start() error {
	if pm.running {
		return fmt.Errorf("process monitor already running")
	}

	pm.running = true

	// Start process enumeration goroutine
	go pm.enumerateProcesses()

	// Start event processing goroutine
	go pm.processEvents()

	log.Println("Process monitor started")
	return nil
}

// Stop stops process monitoring
func (pm *ProcessMonitor) Stop() {
	if !pm.running {
		return
	}

	pm.running = false
	close(pm.stopChannel)
	log.Println("Process monitor stopped")
}

// GetEventChannel returns the event channel
func (pm *ProcessMonitor) GetEventChannel() <-chan ProcessEvent {
	return pm.eventChannel
}

// enumerateProcesses continuously enumerates running processes
func (pm *ProcessMonitor) enumerateProcesses() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-pm.stopChannel:
			return
		case <-ticker.C:
			pm.scanProcesses()
		}
	}
}

// scanProcesses scans for new and terminated processes
func (pm *ProcessMonitor) scanProcesses() {
	currentProcesses := make(map[uint32]bool)

	// Get current process list
	processes, err := enumProcesses()
	if err != nil {
		log.Printf("Failed to enumerate processes: %v", err)
		return
	}

	for _, pid := range processes {
		currentProcesses[pid] = true

		// Check if this is a new process
		if _, exists := pm.processes[pid]; !exists {
			if processInfo := pm.getProcessInfo(pid); processInfo != nil {
				pm.processes[pid] = processInfo

				// Generate process create event
				event := ProcessEvent{
					EventType:   "process_create",
					Timestamp:   time.Now().UTC().Format(time.RFC3339),
					ProcessInfo: *processInfo,
				}

				// Get parent process info
				if processInfo.PPID != 0 {
					if parentInfo := pm.getProcessInfo(uint32(processInfo.PPID)); parentInfo != nil {
						event.ParentInfo = parentInfo
					}
				}

				pm.eventChannel <- event
			}
		}
	}

	// Check for terminated processes
	for pid, processInfo := range pm.processes {
		if !currentProcesses[pid] {
			// Process terminated
			event := ProcessEvent{
				EventType:   "process_terminate",
				Timestamp:   time.Now().UTC().Format(time.RFC3339),
				ProcessInfo: *processInfo,
			}

			pm.eventChannel <- event
			delete(pm.processes, pid)
		}
	}
}

// getProcessInfo retrieves detailed information about a process
func (pm *ProcessMonitor) getProcessInfo(pid uint32) *ProcessInfo {
	handle, err := windows.OpenProcess(
		windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ,
		false,
		pid,
	)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(handle)

	processInfo := &ProcessInfo{
		PID: uint32(pid),
	}

	// Get process name and path
	if name, path := getProcessNameAndPath(handle); name != "" {
		processInfo.Name = name
		processInfo.Path = path
	}

	// Get command line
	if cmdLine := getProcessCommandLine(); cmdLine != "" {
		processInfo.CommandLine = cmdLine
	}

	// Get process owner
	if user, _ := getProcessOwner(handle); user != "" {
		processInfo.User = user
		// Domain field not available in ProcessInfo struct
	}

	// Get parent process ID
	if ppid := getParentProcessID(); ppid != 0 {
		processInfo.PPID = uint32(ppid)
	}

	// Get creation time - using StartTime field instead of CreationTime
	if creationTime := getProcessCreationTime(handle); !creationTime.IsZero() {
		processInfo.StartTime = creationTime
	}

	// Get memory usage
	if memUsage := getProcessMemoryUsage(handle); memUsage > 0 {
		processInfo.MemoryUsage = memUsage / (1024 * 1024) // Convert to MB
	}

	// Get thread and handle counts
	processInfo.ThreadCount = getProcessThreadCount()
	processInfo.HandleCount = getProcessHandleCount()

	// Session ID, LoadedModules, and SecurityContext fields not available in ProcessInfo struct
	// These would need to be added to the struct or stored in a different way

	return processInfo
}

// processEvents processes and forwards events
func (pm *ProcessMonitor) processEvents() {
	for {
		select {
		case <-pm.stopChannel:
			return
		case event := <-pm.eventChannel:
			pm.handleProcessEvent(event)
		}
	}
}

// handleProcessEvent handles individual process events
func (pm *ProcessMonitor) handleProcessEvent(event ProcessEvent) {
	// Create envelope for the event
	envelope := Envelope{
		Ts:       event.Timestamp,
		TenantID: "t-aci",
		Asset: map[string]string{
			"id":   getHostname(),
			"type": "endpoint",
			"os":   "windows",
			"ip":   getLocalIP(),
		},
		User: map[string]string{
			"id":     event.ProcessInfo.User,
			"domain": "", // Domain field not available in ProcessInfo struct
		},
		Event: map[string]interface{}{
			"class":    "process",
			"name":     event.EventType,
			"severity": getEventSeverity(event.EventType),
			"attrs": map[string]interface{}{
				"pid":          event.ProcessInfo.PID,
				"ppid":         event.ProcessInfo.PPID,
				"name":         event.ProcessInfo.Name,
				"path":         event.ProcessInfo.Path,
				"command_line": event.ProcessInfo.CommandLine,
				"user":         event.ProcessInfo.User,
				// domain, session_id, creation_time, thread_count, handle_count fields not available in ProcessInfo struct
				"start_time":   event.ProcessInfo.StartTime,
				"memory_usage": event.ProcessInfo.MemoryUsage,
			},
		},
		Ingest: map[string]string{
			"agent_version": "0.0.2",
			"schema":        "ocsf:1.2",
			"platform":      "windows",
		},
	}

	// Add parent process info if available
	if event.ParentInfo != nil {
		envelope.Event["parent_process"] = map[string]interface{}{
			"pid":  event.ParentInfo.PID,
			"name": event.ParentInfo.Name,
			"path": event.ParentInfo.Path,
			"user": event.ParentInfo.User,
		}
	}

	// Send to gateway
	data, _ := json.Marshal(envelope)
	gatewayURL := os.Getenv("GATEWAY_URL")
	if gatewayURL == "" {
		gatewayURL = "http://localhost:8080"
	}

	go sendEventToGateway(gatewayURL, data)
}

// Helper functions for Windows API calls

func enumProcesses() ([]uint32, error) {
	var processes [1024]uint32
	var bytesReturned uint32

	err := windows.EnumProcesses(processes[:], &bytesReturned)
	if err != nil {
		return nil, err
	}

	numProcesses := bytesReturned / 4
	result := make([]uint32, numProcesses)
	copy(result, processes[:numProcesses])

	return result, nil
}

func getProcessNameAndPath(handle windows.Handle) (string, string) {
	var buffer [windows.MAX_PATH]uint16
	size := uint32(len(buffer))

	err := windows.QueryFullProcessImageName(handle, 0, &buffer[0], &size)
	if err != nil {
		return "", ""
	}

	fullPath := windows.UTF16ToString(buffer[:size])
	name := filepath.Base(fullPath)

	return name, fullPath
}

func getProcessCommandLine() string {
	// This requires more complex implementation using NtQueryInformationProcess
	// For now, return empty string
	return ""
}

func getProcessOwner(handle windows.Handle) (string, string) {
	var token windows.Token
	err := windows.OpenProcessToken(handle, windows.TOKEN_QUERY, &token)
	if err != nil {
		return "", ""
	}
	defer token.Close()

	tokenUser, err := token.GetTokenUser()
	if err != nil {
		return "", ""
	}

	account, domain, _, err := tokenUser.User.Sid.LookupAccount("")
	if err != nil {
		return "", ""
	}

	return account, domain
}

func getParentProcessID() uint32 {
	// This requires PROCESSENTRY32 structure and CreateToolhelp32Snapshot
	// For now, return 0
	return 0
}

func getProcessCreationTime(handle windows.Handle) time.Time {
	var creationTime, exitTime, kernelTime, userTime windows.Filetime
	err := windows.GetProcessTimes(handle, &creationTime, &exitTime, &kernelTime, &userTime)
	if err != nil {
		return time.Time{}
	}

	return time.Unix(0, creationTime.Nanoseconds())
}

func getProcessMemoryUsage(handle windows.Handle) uint64 {
	// Use PROCESS_MEMORY_COUNTERS instead of ProcessMemoryCountersEx
	type PROCESS_MEMORY_COUNTERS struct {
		Size                       uint32
		PageFaultCount             uint32
		PeakWorkingSetSize         uintptr
		WorkingSetSize             uintptr
		QuotaPeakPagedPoolUsage    uintptr
		QuotaPagedPoolUsage        uintptr
		QuotaPeakNonPagedPoolUsage uintptr
		QuotaNonPagedPoolUsage     uintptr
		PagefileUsage              uintptr
		PeakPagefileUsage          uintptr
	}

	var memCounters PROCESS_MEMORY_COUNTERS
	memCounters.Size = uint32(unsafe.Sizeof(memCounters))

	// Use GetProcessMemoryInfo from psapi.dll
	psapi := windows.NewLazyDLL("psapi.dll")
	getProcessMemoryInfo := psapi.NewProc("GetProcessMemoryInfo")

	ret, _, _ := getProcessMemoryInfo.Call(
		uintptr(handle),
		uintptr(unsafe.Pointer(&memCounters)),
		uintptr(memCounters.Size),
	)

	if ret == 0 {
		return 0
	}

	return uint64(memCounters.WorkingSetSize)
}

func getProcessThreadCount() int {
	// This requires more complex implementation
	return 0
}

func getProcessHandleCount() int {
	// This requires GetProcessHandleCount API
	return 0
}

// getProcessLocalIP gets the local IP address for process events
