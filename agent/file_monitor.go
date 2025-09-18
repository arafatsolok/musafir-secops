//go:build windows

package main

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// File monitoring structures
type FileEvent struct {
	EventType    string      `json:"event_type"`
	Timestamp    string      `json:"timestamp"`
	ProcessInfo  ProcessInfo `json:"process_info"`
	FileInfo     FileInfo    `json:"file_info"`
	OldFileInfo  *FileInfo   `json:"old_file_info,omitempty"`
	IntegrityInfo *IntegrityInfo `json:"integrity_info,omitempty"`
}

// FileInfo is defined in common_types.go

type IntegrityInfo struct {
	MD5Hash    string `json:"md5_hash"`
	SHA256Hash string `json:"sha256_hash"`
	Changed    bool   `json:"changed"`
	PreviousMD5 string `json:"previous_md5,omitempty"`
	PreviousSHA256 string `json:"previous_sha256,omitempty"`
}

type WatchedDirectory struct {
	Path      string
	Recursive bool
	Handle    windows.Handle
	Buffer    []byte
	Overlapped windows.Overlapped
}

// File Monitor manages file system monitoring
type FileMonitor struct {
	watchedDirs   map[string]*WatchedDirectory
	fileHashes    map[string]IntegrityInfo
	eventChannel  chan FileEvent
	stopChannel   chan bool
	running       bool
	criticalPaths []string
	suspiciousExts []string
}

// NewFileMonitor creates a new file monitor
func NewFileMonitor() *FileMonitor {
	return &FileMonitor{
		watchedDirs:  make(map[string]*WatchedDirectory),
		fileHashes:   make(map[string]IntegrityInfo),
		eventChannel: make(chan FileEvent, 1000),
		stopChannel:  make(chan bool),
		running:      false,
		criticalPaths: []string{
			"C:\\Windows\\System32",
			"C:\\Windows\\SysWOW64",
			"C:\\Program Files",
			"C:\\Program Files (x86)",
			"C:\\Users",
			"C:\\ProgramData",
		},
		suspiciousExts: []string{
			".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar",
			".scr", ".com", ".pif", ".msi", ".reg", ".lnk",
		},
	}
}

// Start begins file system monitoring
func (fm *FileMonitor) Start() error {
	if fm.running {
		return fmt.Errorf("file monitor already running")
	}

	fm.running = true
	
	// Start monitoring critical directories
	for _, path := range fm.criticalPaths {
		if err := fm.watchDirectory(path, true); err != nil {
			log.Printf("Failed to watch directory %s: %v", path, err)
		}
	}
	
	// Start integrity checking goroutine
	go fm.performIntegrityChecks()
	
	// Start event processing goroutine
	go fm.processEvents()
	
	// Start directory monitoring goroutine
	go fm.monitorDirectories()
	
	log.Println("File monitor started")
	return nil
}

// Stop stops file system monitoring
func (fm *FileMonitor) Stop() {
	if !fm.running {
		return
	}

	fm.running = false
	
	// Close all directory handles
	for _, watchedDir := range fm.watchedDirs {
		windows.CloseHandle(watchedDir.Handle)
	}
	
	close(fm.stopChannel)
	log.Println("File monitor stopped")
}

// GetEventChannel returns the event channel
func (fm *FileMonitor) GetEventChannel() <-chan FileEvent {
	return fm.eventChannel
}

// watchDirectory starts watching a directory for changes
func (fm *FileMonitor) watchDirectory(path string, recursive bool) error {
	// Convert path to UTF16
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}

	// Open directory handle
	handle, err := windows.CreateFile(
		pathPtr,
		windows.FILE_LIST_DIRECTORY,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OVERLAPPED,
		0,
	)
	if err != nil {
		return err
	}

	// Create watched directory structure
	watchedDir := &WatchedDirectory{
		Path:      path,
		Recursive: recursive,
		Handle:    handle,
		Buffer:    make([]byte, 64*1024), // 64KB buffer
	}

	fm.watchedDirs[path] = watchedDir
	
	// Start watching
	go fm.watchDirectoryChanges(watchedDir)
	
	return nil
}

// watchDirectoryChanges monitors changes in a directory
func (fm *FileMonitor) watchDirectoryChanges(watchedDir *WatchedDirectory) {
	for fm.running {
		var bytesReturned uint32
		
		err := windows.ReadDirectoryChanges(
			watchedDir.Handle,
			&watchedDir.Buffer[0],
			uint32(len(watchedDir.Buffer)),
			watchedDir.Recursive,
			windows.FILE_NOTIFY_CHANGE_FILE_NAME|
				windows.FILE_NOTIFY_CHANGE_DIR_NAME|
				windows.FILE_NOTIFY_CHANGE_ATTRIBUTES|
				windows.FILE_NOTIFY_CHANGE_SIZE|
				windows.FILE_NOTIFY_CHANGE_LAST_WRITE|
				windows.FILE_NOTIFY_CHANGE_CREATION,
			&bytesReturned,
			&watchedDir.Overlapped,
			0,
		)
		
		if err != nil {
			if err != windows.ERROR_IO_PENDING {
				log.Printf("ReadDirectoryChanges failed for %s: %v", watchedDir.Path, err)
				time.Sleep(5 * time.Second)
				continue
			}
		}

		// Wait for completion
		err = windows.GetOverlappedResult(watchedDir.Handle, &watchedDir.Overlapped, &bytesReturned, true)
		if err != nil {
			log.Printf("GetOverlappedResult failed for %s: %v", watchedDir.Path, err)
			time.Sleep(5 * time.Second)
			continue
		}

		// Process the changes
		fm.processDirectoryChanges(watchedDir, watchedDir.Buffer[:bytesReturned])
	}
}

// processDirectoryChanges processes directory change notifications
func (fm *FileMonitor) processDirectoryChanges(watchedDir *WatchedDirectory, buffer []byte) {
	offset := uint32(0)
	
	for offset < uint32(len(buffer)) {
		// Parse FILE_NOTIFY_INFORMATION structure
		info := (*windows.FileNotifyInformation)(unsafe.Pointer(&buffer[offset]))
		
		// Get filename
		nameBytes := (*[256]uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(info)) + unsafe.Sizeof(*info)))
		filename := windows.UTF16ToString(nameBytes[:info.FileNameLength/2])
		fullPath := filepath.Join(watchedDir.Path, filename)
		
		// Create file event
		event := fm.createFileEvent(info.Action, fullPath)
		if event != nil {
			fm.eventChannel <- *event
		}
		
		// Move to next entry
		if info.NextEntryOffset == 0 {
			break
		}
		offset += info.NextEntryOffset
	}
}

// createFileEvent creates a file event from Windows notification
func (fm *FileMonitor) createFileEvent(action uint32, filePath string) *FileEvent {
	var eventType string
	
	switch action {
	case windows.FILE_ACTION_ADDED:
		eventType = "file_created"
	case windows.FILE_ACTION_REMOVED:
		eventType = "file_deleted"
	case windows.FILE_ACTION_MODIFIED:
		eventType = "file_modified"
	case windows.FILE_ACTION_RENAMED_OLD_NAME:
		eventType = "file_renamed_old"
	case windows.FILE_ACTION_RENAMED_NEW_NAME:
		eventType = "file_renamed_new"
	default:
		return nil
	}

	// Get file information
	fileInfo := fm.getFileInfo(filePath)
	if fileInfo == nil {
		return nil
	}

	// Get process information (simplified - would need more complex tracking)
	processInfo := ProcessInfo{
		PID:  uint32(os.Getpid()),
		Name: "unknown",
		Path: "",
		User: "SYSTEM",
	}

	event := &FileEvent{
		EventType:   eventType,
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		ProcessInfo: processInfo,
		FileInfo:    *fileInfo,
	}

	// Add integrity information for suspicious files
	if fm.isSuspiciousFile(filePath) {
		if integrityInfo := fm.calculateFileIntegrity(filePath); integrityInfo != nil {
			event.IntegrityInfo = integrityInfo
		}
	}

	return event
}

// getFileInfo retrieves detailed file information
func (fm *FileMonitor) getFileInfo(filePath string) *FileInfo {
	stat, err := os.Stat(filePath)
	if err != nil {
		return nil
	}

	// Get Windows-specific attributes
	pathPtr, _ := windows.UTF16PtrFromString(filePath)
	attrs, err := windows.GetFileAttributes(pathPtr)
	if err != nil {
		attrs = 0
	}

	// Get file owner
	owner := fm.getFileOwner()

	fileInfo := &FileInfo{
		Path:         filePath,
		Name:        stat.Name(),
		Size:        stat.Size(),
		ModTime:     stat.ModTime(),
		Attributes:  convertAttributesToStrings(attrs),
		Owner:       owner,
		Permissions: []string{fm.getFilePermissions()},
		Metadata: map[string]string{
			"file_type":  fm.getFileType(filePath),
			"extension":  strings.ToLower(filepath.Ext(filePath)),
			"hidden":     fmt.Sprintf("%t", attrs&windows.FILE_ATTRIBUTE_HIDDEN != 0),
			"system":     fmt.Sprintf("%t", attrs&windows.FILE_ATTRIBUTE_SYSTEM != 0),
			"encrypted":  fmt.Sprintf("%t", attrs&windows.FILE_ATTRIBUTE_ENCRYPTED != 0),
			"compressed": fmt.Sprintf("%t", attrs&windows.FILE_ATTRIBUTE_COMPRESSED != 0),
		},
	}

	// Get creation and access times (Windows-specific)
	if times := fm.getFileTimes(filePath); times != nil {
		fileInfo.Metadata["creation_time"] = times["creation"]
		fileInfo.Metadata["access_time"] = times["access"]
	}

	// Get metadata for executable files
	if fm.isExecutableFile(filePath) {
		fileInfo.Metadata = fm.getExecutableMetadata()
	}

	return fileInfo
}

// performIntegrityChecks performs periodic integrity checks
func (fm *FileMonitor) performIntegrityChecks() {
	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-fm.stopChannel:
			return
		case <-ticker.C:
			fm.checkCriticalFileIntegrity()
		}
	}
}

// checkCriticalFileIntegrity checks integrity of critical system files
func (fm *FileMonitor) checkCriticalFileIntegrity() {
	criticalFiles := []string{
		"C:\\Windows\\System32\\kernel32.dll",
		"C:\\Windows\\System32\\ntdll.dll",
		"C:\\Windows\\System32\\user32.dll",
		"C:\\Windows\\System32\\advapi32.dll",
		"C:\\Windows\\System32\\wininet.dll",
	}

	for _, filePath := range criticalFiles {
		if _, err := os.Stat(filePath); err != nil {
			continue
		}

		currentIntegrity := fm.calculateFileIntegrity(filePath)
		if currentIntegrity == nil {
			continue
		}

		// Check if we have previous hash
		if previousIntegrity, exists := fm.fileHashes[filePath]; exists {
			if currentIntegrity.SHA256Hash != previousIntegrity.SHA256Hash {
				// File integrity changed!
				event := FileEvent{
					EventType:   "file_integrity_violation",
					Timestamp:   time.Now().UTC().Format(time.RFC3339),
					ProcessInfo: ProcessInfo{Name: "system", PID: 0},
					FileInfo:    *fm.getFileInfo(filePath),
					IntegrityInfo: &IntegrityInfo{
						MD5Hash:        currentIntegrity.MD5Hash,
						SHA256Hash:     currentIntegrity.SHA256Hash,
						Changed:        true,
						PreviousMD5:    previousIntegrity.MD5Hash,
						PreviousSHA256: previousIntegrity.SHA256Hash,
					},
				}
				
				fm.eventChannel <- event
			}
		}

		// Update stored hash
		fm.fileHashes[filePath] = *currentIntegrity
	}
}

// calculateFileIntegrity calculates file hashes
func (fm *FileMonitor) calculateFileIntegrity(filePath string) *IntegrityInfo {
	file, err := os.Open(filePath)
	if err != nil {
		return nil
	}
	defer file.Close()

	md5Hash := md5.New()
	sha256Hash := sha256.New()
	
	// Use MultiWriter to calculate both hashes in one pass
	multiWriter := io.MultiWriter(md5Hash, sha256Hash)
	
	if _, err := io.Copy(multiWriter, file); err != nil {
		return nil
	}

	return &IntegrityInfo{
		MD5Hash:    hex.EncodeToString(md5Hash.Sum(nil)),
		SHA256Hash: hex.EncodeToString(sha256Hash.Sum(nil)),
		Changed:    false,
	}
}

// processEvents processes and forwards events
func (fm *FileMonitor) processEvents() {
	for {
		select {
		case <-fm.stopChannel:
			return
		case event := <-fm.eventChannel:
			fm.handleFileEvent(event)
		}
	}
}

// handleFileEvent handles individual file events
func (fm *FileMonitor) handleFileEvent(event FileEvent) {
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
			"domain": "", // Domain not available in ProcessInfo struct
		},
		Event: map[string]interface{}{
			"class":    "file",
			"name":     event.EventType,
			"severity": getFileEventSeverity(event.EventType, event.FileInfo.Path),
			"attrs": map[string]interface{}{
				"process_id":     event.ProcessInfo.PID,
				"process_name":   event.ProcessInfo.Name,
				"file_path":      event.FileInfo.Path,
				"file_name":      event.FileInfo.Name,
				"file_size":      event.FileInfo.Size,
				"file_type":      event.FileInfo.Metadata["file_type"],
				"file_extension": event.FileInfo.Metadata["extension"],
				"creation_time":  event.FileInfo.Metadata["creation_time"],
				"modified_time":  event.FileInfo.ModTime.Format(time.RFC3339),
				"access_time":    event.FileInfo.Metadata["access_time"],
				"owner":          event.FileInfo.Owner,
				"hidden":         event.FileInfo.Metadata["hidden"],
				"system":         event.FileInfo.Metadata["system"],
				"encrypted":      event.FileInfo.Metadata["encrypted"],
				"compressed":     event.FileInfo.Metadata["compressed"],
			},
		},
		Ingest: map[string]string{
			"agent_version": "0.0.2",
			"schema":        "ocsf:1.2",
			"platform":      "windows",
		},
	}

	// Add integrity information if available
	if event.IntegrityInfo != nil {
		envelope.Event["integrity"] = map[string]interface{}{
			"md5_hash":         event.IntegrityInfo.MD5Hash,
			"sha256_hash":      event.IntegrityInfo.SHA256Hash,
			"changed":          event.IntegrityInfo.Changed,
			"previous_md5":     event.IntegrityInfo.PreviousMD5,
			"previous_sha256":  event.IntegrityInfo.PreviousSHA256,
		}
	}

	// Add metadata if available
	if event.FileInfo.Metadata != nil {
		envelope.Event["metadata"] = event.FileInfo.Metadata
	}

	// Send to gateway
	data, _ := json.Marshal(envelope)
	gatewayURL := os.Getenv("GATEWAY_URL")
	if gatewayURL == "" {
		gatewayURL = "http://localhost:8080"
	}
	
	go sendEventToGateway(gatewayURL, data)
}

// monitorDirectories monitors directory changes
func (fm *FileMonitor) monitorDirectories() {
	// This function handles the main directory monitoring loop
	for fm.running {
		time.Sleep(1 * time.Second)
		// Directory monitoring is handled by individual goroutines
		// This is just a keepalive loop
	}
}

// Helper functions

func (fm *FileMonitor) isSuspiciousFile(filePath string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))
	for _, suspiciousExt := range fm.suspiciousExts {
		if ext == suspiciousExt {
			return true
		}
	}
	return false
}

func (fm *FileMonitor) getFileOwner() string {
	// This would use GetFileSecurity and LookupAccountSid
	return "SYSTEM"
}

func (fm *FileMonitor) getFileType(filePath string) string {
	ext := strings.ToLower(filepath.Ext(filePath))
	switch ext {
	case ".exe", ".com", ".scr":
		return "executable"
	case ".dll", ".sys":
		return "library"
	case ".bat", ".cmd":
		return "batch"
	case ".ps1":
		return "powershell"
	case ".vbs", ".js":
		return "script"
	case ".doc", ".docx", ".pdf":
		return "document"
	case ".jpg", ".png", ".gif":
		return "image"
	default:
		return "file"
	}
}

func (fm *FileMonitor) getFileTimes(filePath string) map[string]string {
	pathPtr, _ := windows.UTF16PtrFromString(filePath)
	handle, err := windows.CreateFile(
		pathPtr,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ,
		nil,
		windows.OPEN_EXISTING,
		0,
		0,
	)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(handle)

	var creation, access, write windows.Filetime
	err = windows.GetFileTime(handle, &creation, &access, &write)
	if err != nil {
		return nil
	}

	return map[string]string{
		"creation": time.Unix(0, creation.Nanoseconds()).UTC().Format(time.RFC3339),
		"access":   time.Unix(0, access.Nanoseconds()).UTC().Format(time.RFC3339),
		"write":    time.Unix(0, write.Nanoseconds()).UTC().Format(time.RFC3339),
	}
}

func (fm *FileMonitor) getFilePermissions() string {
	// This would use GetFileSecurity to get detailed permissions
	return "unknown"
}

func (fm *FileMonitor) isExecutableFile(filePath string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))
	return ext == ".exe" || ext == ".dll" || ext == ".sys"
}

func (fm *FileMonitor) getExecutableMetadata() map[string]string {
	// This would use GetFileVersionInfo and VerQueryValue
	// For now, return basic metadata
	return map[string]string{
		"file_version":    "unknown",
		"product_version": "unknown",
		"company_name":    "unknown",
		"product_name":    "unknown",
		"description":     "unknown",
	}
}

func getFileEventSeverity(eventType, filePath string) int {
	// Higher severity for system files and executables
	if strings.Contains(strings.ToLower(filePath), "system32") ||
		strings.Contains(strings.ToLower(filePath), "syswow64") {
		switch eventType {
		case "file_created", "file_modified":
			return 4 // High
		case "file_deleted":
			return 5 // Critical
		case "file_integrity_violation":
			return 5 // Critical
		}
	}

	// Check for suspicious extensions
	ext := strings.ToLower(filepath.Ext(filePath))
	suspiciousExts := []string{".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js"}
	for _, suspExt := range suspiciousExts {
		if ext == suspExt {
			return 3 // Medium
		}
	}

	switch eventType {
	case "file_created", "file_modified":
		return 2 // Informational
	case "file_deleted":
		return 2 // Informational
	case "file_integrity_violation":
		return 4 // High
	default:
		return 1 // Low
	}
}

// convertAttributesToStrings converts Windows file attributes to a slice of strings
func convertAttributesToStrings(attrs uint32) []string {
	var attributes []string
	
	if attrs&windows.FILE_ATTRIBUTE_READONLY != 0 {
		attributes = append(attributes, "readonly")
	}
	if attrs&windows.FILE_ATTRIBUTE_HIDDEN != 0 {
		attributes = append(attributes, "hidden")
	}
	if attrs&windows.FILE_ATTRIBUTE_SYSTEM != 0 {
		attributes = append(attributes, "system")
	}
	if attrs&windows.FILE_ATTRIBUTE_DIRECTORY != 0 {
		attributes = append(attributes, "directory")
	}
	if attrs&windows.FILE_ATTRIBUTE_ARCHIVE != 0 {
		attributes = append(attributes, "archive")
	}
	if attrs&windows.FILE_ATTRIBUTE_ENCRYPTED != 0 {
		attributes = append(attributes, "encrypted")
	}
	if attrs&windows.FILE_ATTRIBUTE_COMPRESSED != 0 {
		attributes = append(attributes, "compressed")
	}
	
	return attributes
}