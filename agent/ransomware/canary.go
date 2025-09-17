package ransomware

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// CanaryFile represents a honeypot file for ransomware detection
type CanaryFile struct {
	Path         string    `json:"path"`
	Hash         string    `json:"hash"`
	Size         int64     `json:"size"`
	CreatedAt    time.Time `json:"created_at"`
	LastModified time.Time `json:"last_modified"`
	Content      []byte    `json:"content"`
	IsActive     bool      `json:"is_active"`
}

// CanaryManager handles ransomware canary files
type CanaryManager struct {
	baseDir     string
	canaryFiles []CanaryFile
	monitorChan chan CanaryFile
}

func NewCanaryManager(baseDir string) *CanaryManager {
	return &CanaryManager{
		baseDir:     baseDir,
		canaryFiles: []CanaryFile{},
		monitorChan: make(chan CanaryFile, 100),
	}
}

func (cm *CanaryManager) Start() error {
	// Create base directory
	if err := os.MkdirAll(cm.baseDir, 0755); err != nil {
		return err
	}

	// Deploy canary files
	if err := cm.deployCanaryFiles(); err != nil {
		return err
	}

	// Start monitoring
	go cm.monitorCanaryFiles()

	return nil
}

func (cm *CanaryManager) deployCanaryFiles() error {
	// Common file extensions targeted by ransomware
	extensions := []string{
		".docx", ".xlsx", ".pptx", ".pdf", ".txt", ".rtf",
		".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff",
		".mp4", ".avi", ".mov", ".wmv", ".flv",
		".mp3", ".wav", ".flac", ".aac",
		".zip", ".rar", ".7z", ".tar", ".gz",
		".db", ".sqlite", ".mdb", ".accdb",
		".psd", ".ai", ".indd", ".sketch",
		".dwg", ".dxf", ".cad",
		".backup", ".bak", ".old",
	}

	// Common directories to place canaries
	directories := []string{
		"Documents",
		"Desktop",
		"Downloads",
		"Pictures",
		"Videos",
		"Music",
		"Projects",
		"Backups",
		"Shared",
		"Public",
	}

	// Create canary files in each directory
	for _, dir := range directories {
		dirPath := filepath.Join(cm.baseDir, dir)
		if err := os.MkdirAll(dirPath, 0755); err != nil {
			log.Printf("Failed to create directory %s: %v", dirPath, err)
			continue
		}

		// Create multiple canary files per directory
		for i := 0; i < 3; i++ {
			ext := extensions[i%len(extensions)]
			filename := fmt.Sprintf("important_document_%d%s", i+1, ext)
			filePath := filepath.Join(dirPath, filename)

			canary, err := cm.createCanaryFile(filePath, ext)
			if err != nil {
				log.Printf("Failed to create canary file %s: %v", filePath, err)
				continue
			}

			cm.canaryFiles = append(cm.canaryFiles, *canary)
		}
	}

	log.Printf("Deployed %d canary files across %d directories", len(cm.canaryFiles), len(directories))
	return nil
}

func (cm *CanaryManager) createCanaryFile(filePath, ext string) (*CanaryFile, error) {
	// Generate realistic content based on file extension
	content := cm.generateRealisticContent(ext)

	// Add canary markers
	content = cm.addCanaryMarkers(content, filePath)

	// Write file
	if err := os.WriteFile(filePath, content, 0644); err != nil {
		return nil, err
	}

	// Get file info
	info, err := os.Stat(filePath)
	if err != nil {
		return nil, err
	}

	// Calculate hash
	hash := cm.calculateHash(content)

	canary := &CanaryFile{
		Path:         filePath,
		Hash:         hash,
		Size:         info.Size(),
		CreatedAt:    time.Now(),
		LastModified: info.ModTime(),
		Content:      content,
		IsActive:     true,
	}

	return canary, nil
}

func (cm *CanaryManager) generateRealisticContent(ext string) []byte {
	switch strings.ToLower(ext) {
	case ".docx", ".txt", ".rtf":
		return []byte(`Important Business Document

This document contains confidential information about our company's operations, financial data, and strategic plans. 

Please keep this information secure and do not share with unauthorized personnel.

Contact: john.doe@company.com
Phone: +1-555-0123
Date: ` + time.Now().Format("2006-01-02") + `

Confidential - Internal Use Only`)

	case ".xlsx", ".csv":
		return []byte(`Name,Department,Salary,Start Date
John Doe,Engineering,75000,2023-01-15
Jane Smith,Marketing,65000,2023-02-01
Bob Johnson,Sales,70000,2023-01-30
Alice Brown,HR,60000,2023-03-01`)

	case ".pdf":
		// Simple PDF header (simplified)
		return []byte(`%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [3 0 R]
/Count 1
>>
endobj
3 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
/Contents 4 0 R
>>
endobj
4 0 obj
<<
/Length 44
>>
stream
BT
/F1 12 Tf
100 700 Td
(Important Document) Tj
ET
endstream
endobj
xref
0 5
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
0000000204 00000 n 
trailer
<<
/Size 5
/Root 1 0 R
>>
startxref
297
%%EOF`)

	case ".jpg", ".jpeg", ".png", ".gif":
		// Minimal image file header
		if strings.ToLower(ext) == ".jpg" || strings.ToLower(ext) == ".jpeg" {
			return []byte{0xFF, 0xD8, 0xFF, 0xE0} // JPEG header
		} else if strings.ToLower(ext) == ".png" {
			return []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A} // PNG header
		}
		return []byte("fake image content")

	case ".zip", ".rar", ".7z":
		// Minimal archive header
		if strings.ToLower(ext) == ".zip" {
			return []byte{0x50, 0x4B, 0x03, 0x04} // ZIP header
		}
		return []byte("fake archive content")

	default:
		// Generic content
		return []byte(fmt.Sprintf(`Important Document - %s

This file contains important business information.

Created: %s
Modified: %s

Please do not delete or modify this file.

Confidential - Internal Use Only`, ext, time.Now().Format("2006-01-02 15:04:05"), time.Now().Format("2006-01-02 15:04:05")))
	}
}

func (cm *CanaryManager) addCanaryMarkers(content []byte, filePath string) []byte {
	// Add invisible markers that can be detected
	markers := []string{
		"MUSAFIR_CANARY_FILE",
		"RANSOMWARE_DETECTION_MARKER",
		"SECURITY_HONEYPOT_FILE",
	}

	// Append markers as comments or in metadata
	markerText := "\n<!-- " + filePath + " " + strings.Join(markers, " ") + " -->\n"
	return append(content, []byte(markerText)...)
}

func (cm *CanaryManager) calculateHash(content []byte) string {
	// Calculate SHA-256 hash of content
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

func (cm *CanaryManager) monitorCanaryFiles() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		cm.checkCanaryFiles()
	}
}

func (cm *CanaryManager) checkCanaryFiles() {
	for i, canary := range cm.canaryFiles {
		if !canary.IsActive {
			continue
		}

		// Check if file still exists
		info, err := os.Stat(canary.Path)
		if err != nil {
			// File was deleted or modified
			cm.handleCanaryCompromise(canary, "file_deleted")
			cm.canaryFiles[i].IsActive = false
			continue
		}

		// Check if file was modified
		if info.ModTime().After(canary.LastModified) {
			cm.handleCanaryCompromise(canary, "file_modified")
			cm.canaryFiles[i].LastModified = info.ModTime()
		}

		// Check if file size changed
		if info.Size() != canary.Size {
			cm.handleCanaryCompromise(canary, "file_size_changed")
			cm.canaryFiles[i].Size = info.Size()
		}

		// Check file content for encryption
		content, err := os.ReadFile(canary.Path)
		if err != nil {
			cm.handleCanaryCompromise(canary, "file_read_error")
			continue
		}

		// Check for high entropy (encryption indicator)
		if cm.calculateEntropy(content) > 7.5 {
			cm.handleCanaryCompromise(canary, "high_entropy_detected")
		}

		// Check if canary markers are still present
		if !strings.Contains(string(content), "MUSAFIR_CANARY_FILE") {
			cm.handleCanaryCompromise(canary, "canary_markers_removed")
		}
	}
}

func (cm *CanaryManager) calculateEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}

	// Calculate byte frequency
	freq := make(map[byte]int)
	for _, b := range data {
		freq[b]++
	}

	// Calculate entropy
	entropy := 0.0
	for _, count := range freq {
		p := float64(count) / float64(len(data))
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

func (cm *CanaryManager) handleCanaryCompromise(canary CanaryFile, reason string) {
	log.Printf("CANARY COMPROMISED: %s - %s", canary.Path, reason)

	// Send alert
	cm.monitorChan <- canary

	// In production, this would:
	// 1. Send alert to correlation engine
	// 2. Trigger incident response
	// 3. Isolate affected systems
	// 4. Collect forensic evidence
}

func (cm *CanaryManager) GetMonitorChannel() <-chan CanaryFile {
	return cm.monitorChan
}

// Start canary monitoring (call this from agent)
func StartCanaryMonitoring() {
	canaryDir := os.Getenv("CANARY_DIR")
	if canaryDir == "" {
		canaryDir = "/tmp/musafir_canaries"
	}

	manager := NewCanaryManager(canaryDir)
	if err := manager.Start(); err != nil {
		log.Printf("Failed to start canary monitoring: %v", err)
		return
	}

	log.Println("Ransomware canary monitoring started")

	// Monitor for compromises
	go func() {
		for canary := range manager.GetMonitorChannel() {
			// Process canary compromise
			log.Printf("Processing canary compromise: %s", canary.Path)
		}
	}()
}
