//go:build windows

package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// ComplianceMonitor manages compliance monitoring and reporting
type ComplianceMonitor struct {
	frameworks       map[string]ComplianceFrameworkConfig
	lastCheck        time.Time
	checkInterval    time.Duration
	complianceReport ComplianceReport
}

// ComplianceFrameworkConfig defines a compliance framework configuration
type ComplianceFrameworkConfig struct {
	Name        string                    `json:"name"`
	Version     string                    `json:"version"`
	Description string                    `json:"description"`
	Controls    []ComplianceControlConfig `json:"controls"`
}

// ComplianceControlConfig defines a compliance control configuration
type ComplianceControlConfig struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`
	Category    string    `json:"category"`
	CheckType   string    `json:"check_type"` // registry, file, service, policy, wmi
	CheckData   CheckData `json:"check_data"`
	Remediation string    `json:"remediation"`
}

// CheckData contains the data needed to perform a compliance check
type CheckData struct {
	Registry RegistryCheck `json:"registry,omitempty"`
	File     FileCheck     `json:"file,omitempty"`
	Service  ServiceCheck  `json:"service,omitempty"`
	Policy   PolicyCheck   `json:"policy,omitempty"`
	WMI      WMICheck      `json:"wmi,omitempty"`
}

// RegistryCheck defines a registry-based compliance check
type RegistryCheck struct {
	Key           string      `json:"key"`
	Value         string      `json:"value"`
	ExpectedValue interface{} `json:"expected_value"`
	Operator      string      `json:"operator"` // equals, not_equals, greater_than, less_than, exists, not_exists
}

// FileCheck defines a file-based compliance check
type FileCheck struct {
	Path        string            `json:"path"`
	CheckType   string            `json:"check_type"` // exists, not_exists, permissions, content
	Permissions string            `json:"permissions,omitempty"`
	Content     string            `json:"content,omitempty"`
	Attributes  map[string]string `json:"attributes,omitempty"`
}

// ServiceCheck defines a service-based compliance check
type ServiceCheck struct {
	Name          string `json:"name"`
	ExpectedState string `json:"expected_state"`         // running, stopped, disabled
	StartupType   string `json:"startup_type,omitempty"` // automatic, manual, disabled
}

// PolicyCheck defines a policy-based compliance check
type PolicyCheck struct {
	PolicyType string `json:"policy_type"` // local_policy, group_policy, audit_policy
	Setting    string `json:"setting"`
	Value      string `json:"value"`
}

// WMICheck defines a WMI-based compliance check
type WMICheck struct {
	Class    string `json:"class"`
	Property string `json:"property"`
	Filter   string `json:"filter,omitempty"`
	Expected string `json:"expected"`
	Operator string `json:"operator"`
}

// ComplianceReport represents a compliance assessment report
type ComplianceReport struct {
	Timestamp       time.Time                   `json:"timestamp"`
	OverallScore    float64                     `json:"overall_score"`
	TotalControls   int                         `json:"total_controls"`
	PassedControls  int                         `json:"passed_controls"`
	FailedControls  int                         `json:"failed_controls"`
	Frameworks      []ComplianceFrameworkResult `json:"frameworks"`
	Summary         ComplianceSummary           `json:"summary"`
	Recommendations []ComplianceRecommendation  `json:"recommendations"`
}

// ComplianceFrameworkResult represents results for a specific framework
type ComplianceFrameworkResult struct {
	Name           string                    `json:"name"`
	Version        string                    `json:"version"`
	Score          float64                   `json:"score"`
	TotalControls  int                       `json:"total_controls"`
	PassedControls int                       `json:"passed_controls"`
	FailedControls int                       `json:"failed_controls"`
	Controls       []ComplianceControlResult `json:"controls"`
}

// ComplianceControlResult represents the result of a compliance control check
type ComplianceControlResult struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Status      string    `json:"status"` // compliant, non_compliant, not_applicable, error
	Severity    string    `json:"severity"`
	Category    string    `json:"category"`
	Message     string    `json:"message"`
	Evidence    string    `json:"evidence"`
	Remediation string    `json:"remediation"`
	CheckTime   time.Time `json:"check_time"`
}

// ComplianceSummary provides a high-level summary of compliance status
type ComplianceSummary struct {
	CriticalFindings int                        `json:"critical_findings"`
	HighFindings     int                        `json:"high_findings"`
	MediumFindings   int                        `json:"medium_findings"`
	LowFindings      int                        `json:"low_findings"`
	Categories       map[string]CategorySummary `json:"categories"`
}

// CategorySummary provides summary for a compliance category
type CategorySummary struct {
	TotalControls  int     `json:"total_controls"`
	PassedControls int     `json:"passed_controls"`
	FailedControls int     `json:"failed_controls"`
	Score          float64 `json:"score"`
}

// ComplianceRecommendation provides remediation recommendations
type ComplianceRecommendation struct {
	Priority    string   `json:"priority"`
	Category    string   `json:"category"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Impact      string   `json:"impact"`
	Effort      string   `json:"effort"`
	Steps       []string `json:"steps"`
}

// NewComplianceMonitor creates a new compliance monitor
func NewComplianceMonitor() *ComplianceMonitor {
	cm := &ComplianceMonitor{
		frameworks:    make(map[string]ComplianceFrameworkConfig),
		checkInterval: 24 * time.Hour, // Daily compliance checks
	}

	// Initialize with default frameworks
	cm.initializeDefaultFrameworks()

	return cm
}

// initializeDefaultFrameworks initializes default compliance frameworks
func (cm *ComplianceMonitor) initializeDefaultFrameworks() {
	// CIS Windows 10 Benchmark
	cisFramework := ComplianceFrameworkConfig{
		Name:        "CIS",
		Version:     "1.12.0",
		Description: "CIS Microsoft Windows 10 Enterprise Benchmark",
		Controls:    cm.getCISControls(),
	}
	cm.frameworks["CIS"] = cisFramework

	// NIST Cybersecurity Framework
	nistFramework := ComplianceFrameworkConfig{
		Name:        "NIST",
		Version:     "1.1",
		Description: "NIST Cybersecurity Framework",
		Controls:    cm.getNISTControls(),
	}
	cm.frameworks["NIST"] = nistFramework

	// SOC 2 Type II
	soc2Framework := ComplianceFrameworkConfig{
		Name:        "SOC2",
		Version:     "2017",
		Description: "SOC 2 Type II Security Controls",
		Controls:    cm.getSOC2Controls(),
	}
	cm.frameworks["SOC2"] = soc2Framework
}

// getCISControls returns CIS benchmark controls
func (cm *ComplianceMonitor) getCISControls() []ComplianceControlConfig {
	return []ComplianceControlConfig{
		{
			ID:          "CIS-1.1.1",
			Title:       "Ensure 'Enforce password history' is set to '24 or more password(s)'",
			Description: "This policy setting determines the number of renewed, unique passwords that have to be associated with a user account before you can reuse an old password.",
			Severity:    "medium",
			Category:    "Account Policies",
			CheckType:   "registry",
			CheckData: CheckData{
				Registry: RegistryCheck{
					Key:           "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters",
					Value:         "PasswordHistoryLength",
					ExpectedValue: 24,
					Operator:      "greater_than_or_equal",
				},
			},
			Remediation: "Configure password history to remember at least 24 passwords",
		},
		{
			ID:          "CIS-1.1.2",
			Title:       "Ensure 'Maximum password age' is set to '365 or fewer days, but not 0'",
			Description: "This policy setting defines how long a user can use their password before it expires.",
			Severity:    "medium",
			Category:    "Account Policies",
			CheckType:   "registry",
			CheckData: CheckData{
				Registry: RegistryCheck{
					Key:           "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters",
					Value:         "MaximumPasswordAge",
					ExpectedValue: 365,
					Operator:      "less_than_or_equal",
				},
			},
			Remediation: "Set maximum password age to 365 days or less",
		},
		{
			ID:          "CIS-2.2.1",
			Title:       "Ensure 'Access Credential Manager as a trusted caller' is set to 'No One'",
			Description: "This security setting allows a process to call into Credential Manager.",
			Severity:    "high",
			Category:    "User Rights Assignment",
			CheckType:   "policy",
			CheckData: CheckData{
				Policy: PolicyCheck{
					PolicyType: "local_policy",
					Setting:    "SeTrustedCredManAccessPrivilege",
					Value:      "",
				},
			},
			Remediation: "Remove all users from 'Access Credential Manager as a trusted caller' user right",
		},
		{
			ID:          "CIS-5.1",
			Title:       "Ensure 'Print Spooler (Spooler)' is set to 'Disabled'",
			Description: "This service spools print jobs and handles interaction with the printer.",
			Severity:    "medium",
			Category:    "System Services",
			CheckType:   "service",
			CheckData: CheckData{
				Service: ServiceCheck{
					Name:          "Spooler",
					ExpectedState: "stopped",
					StartupType:   "disabled",
				},
			},
			Remediation: "Disable the Print Spooler service if not required",
		},
		{
			ID:          "CIS-9.1.1",
			Title:       "Ensure 'Windows Firewall: Domain: Firewall state' is set to 'On'",
			Description: "This setting determines whether Windows Firewall with Advanced Security is on or off.",
			Severity:    "high",
			Category:    "Windows Firewall",
			CheckType:   "registry",
			CheckData: CheckData{
				Registry: RegistryCheck{
					Key:           "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile",
					Value:         "EnableFirewall",
					ExpectedValue: 1,
					Operator:      "equals",
				},
			},
			Remediation: "Enable Windows Firewall for Domain profile",
		},
	}
}

// getNISTControls returns NIST framework controls
func (cm *ComplianceMonitor) getNISTControls() []ComplianceControlConfig {
	return []ComplianceControlConfig{
		{
			ID:          "NIST-AC-2",
			Title:       "Account Management",
			Description: "Manages information system accounts, group memberships, privileges, workflow, notifications, deactivations, and authorizations.",
			Severity:    "high",
			Category:    "Access Control",
			CheckType:   "policy",
			CheckData: CheckData{
				Policy: PolicyCheck{
					PolicyType: "local_policy",
					Setting:    "Account lockout threshold",
					Value:      "5",
				},
			},
			Remediation: "Implement proper account management procedures",
		},
		{
			ID:          "NIST-AU-2",
			Title:       "Audit Events",
			Description: "Determines that the information system is capable of auditing events and defines auditable events.",
			Severity:    "medium",
			Category:    "Audit and Accountability",
			CheckType:   "registry",
			CheckData: CheckData{
				Registry: RegistryCheck{
					Key:           "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\Security",
					Value:         "MaxSize",
					ExpectedValue: 196608,
					Operator:      "greater_than_or_equal",
				},
			},
			Remediation: "Configure audit log size and retention policies",
		},
	}
}

// getSOC2Controls returns SOC 2 controls
func (cm *ComplianceMonitor) getSOC2Controls() []ComplianceControlConfig {
	return []ComplianceControlConfig{
		{
			ID:          "SOC2-CC6.1",
			Title:       "Logical and Physical Access Controls",
			Description: "The entity implements logical and physical access controls to protect against threats from sources outside its system boundaries.",
			Severity:    "high",
			Category:    "Common Criteria",
			CheckType:   "service",
			CheckData: CheckData{
				Service: ServiceCheck{
					Name:          "Windows Defender Antivirus Service",
					ExpectedState: "running",
					StartupType:   "automatic",
				},
			},
			Remediation: "Ensure antivirus service is running and configured properly",
		},
		{
			ID:          "SOC2-CC6.7",
			Title:       "Data Transmission Controls",
			Description: "The entity restricts the transmission of data to authorized internal and external users and processes.",
			Severity:    "medium",
			Category:    "Common Criteria",
			CheckType:   "registry",
			CheckData: CheckData{
				Registry: RegistryCheck{
					Key:           "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile",
					Value:         "EnableFirewall",
					ExpectedValue: 1,
					Operator:      "equals",
				},
			},
			Remediation: "Enable Windows Firewall for Public profile",
		},
	}
}

// RunComplianceCheck performs a comprehensive compliance check
func (cm *ComplianceMonitor) RunComplianceCheck() error {
	log.Println("Starting comprehensive compliance check...")

	report := ComplianceReport{
		Timestamp:  time.Now(),
		Frameworks: make([]ComplianceFrameworkResult, 0),
		Summary: ComplianceSummary{
			Categories: make(map[string]CategorySummary),
		},
	}

	totalControls := 0
	passedControls := 0

	// Check each framework
	for _, framework := range cm.frameworks {
		frameworkResult := cm.checkFramework(framework)
		report.Frameworks = append(report.Frameworks, frameworkResult)

		totalControls += frameworkResult.TotalControls
		passedControls += frameworkResult.PassedControls

		// Update category summaries
		for _, control := range frameworkResult.Controls {
			category := control.Category
			if _, exists := report.Summary.Categories[category]; !exists {
				report.Summary.Categories[category] = CategorySummary{}
			}

			catSummary := report.Summary.Categories[category]
			catSummary.TotalControls++

			switch control.Status {
			case "compliant":
				catSummary.PassedControls++
			case "non_compliant":
				catSummary.FailedControls++

				// Count findings by severity
				switch control.Severity {
				case "critical":
					report.Summary.CriticalFindings++
				case "high":
					report.Summary.HighFindings++
				case "medium":
					report.Summary.MediumFindings++
				case "low":
					report.Summary.LowFindings++
				}
			}

			if catSummary.TotalControls > 0 {
				catSummary.Score = float64(catSummary.PassedControls) / float64(catSummary.TotalControls) * 100
			}

			report.Summary.Categories[category] = catSummary
		}
	}

	// Calculate overall score
	if totalControls > 0 {
		report.OverallScore = float64(passedControls) / float64(totalControls) * 100
	}

	report.TotalControls = totalControls
	report.PassedControls = passedControls
	report.FailedControls = totalControls - passedControls

	// Generate recommendations
	report.Recommendations = cm.generateRecommendations(report)

	cm.complianceReport = report
	cm.lastCheck = time.Now()

	log.Printf("Compliance check completed. Overall score: %.2f%% (%d/%d controls passed)",
		report.OverallScore, passedControls, totalControls)

	return nil
}

// checkFramework checks all controls in a compliance framework
func (cm *ComplianceMonitor) checkFramework(framework ComplianceFrameworkConfig) ComplianceFrameworkResult {
	result := ComplianceFrameworkResult{
		Name:     framework.Name,
		Version:  framework.Version,
		Controls: make([]ComplianceControlResult, 0),
	}

	for _, control := range framework.Controls {
		controlResult := cm.checkControl(control)
		result.Controls = append(result.Controls, controlResult)

		result.TotalControls++
		switch controlResult.Status {
		case "compliant":
			result.PassedControls++
		case "non_compliant":
			result.FailedControls++
		}
	}

	// Calculate framework score
	if result.TotalControls > 0 {
		result.Score = float64(result.PassedControls) / float64(result.TotalControls) * 100
	}

	return result
}

// checkControl performs a specific compliance control check
func (cm *ComplianceMonitor) checkControl(control ComplianceControlConfig) ComplianceControlResult {
	result := ComplianceControlResult{
		ID:          control.ID,
		Title:       control.Title,
		Severity:    control.Severity,
		Category:    control.Category,
		Remediation: control.Remediation,
		CheckTime:   time.Now(),
	}

	switch control.CheckType {
	case "registry":
		result = cm.checkRegistryControl(control, result)
	case "file":
		result = cm.checkFileControl(control, result)
	case "service":
		result = cm.checkServiceControl(control, result)
	case "policy":
		result = cm.checkPolicyControl(control, result)
	case "wmi":
		result = cm.checkWMIControl(control, result)
	default:
		result.Status = "error"
		result.Message = "Unknown check type: " + control.CheckType
	}

	return result
}

// checkRegistryControl performs a registry-based compliance check
func (cm *ComplianceMonitor) checkRegistryControl(control ComplianceControlConfig, result ComplianceControlResult) ComplianceControlResult {
	regCheck := control.CheckData.Registry

	// Use reg query command to check registry value
	cmd := exec.Command("reg", "query", regCheck.Key, "/v", regCheck.Value)
	output, err := cmd.Output()

	if err != nil {
		if regCheck.Operator == "not_exists" {
			result.Status = "compliant"
			result.Message = "Registry value does not exist as expected"
		} else {
			result.Status = "non_compliant"
			result.Message = "Registry key or value not found"
		}
		return result
	}

	// Parse registry output
	outputStr := string(output)
	result.Evidence = outputStr

	// Extract value from output
	lines := strings.Split(outputStr, "\n")
	var actualValue string
	for _, line := range lines {
		if strings.Contains(line, regCheck.Value) {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				actualValue = parts[len(parts)-1]
			}
			break
		}
	}

	// Compare values based on operator
	compliant := cm.compareValues(actualValue, regCheck.ExpectedValue, regCheck.Operator)

	if compliant {
		result.Status = "compliant"
		result.Message = fmt.Sprintf("Registry value '%s' is compliant (actual: %s)", regCheck.Value, actualValue)
	} else {
		result.Status = "non_compliant"
		result.Message = fmt.Sprintf("Registry value '%s' is non-compliant (actual: %s, expected: %v)",
			regCheck.Value, actualValue, regCheck.ExpectedValue)
	}

	return result
}

// checkServiceControl performs a service-based compliance check
func (cm *ComplianceMonitor) checkServiceControl(control ComplianceControlConfig, result ComplianceControlResult) ComplianceControlResult {
	serviceCheck := control.CheckData.Service

	// Query service status
	cmd := exec.Command("sc", "query", serviceCheck.Name)
	output, err := cmd.Output()

	if err != nil {
		result.Status = "error"
		result.Message = "Service not found: " + serviceCheck.Name
		return result
	}

	outputStr := string(output)
	result.Evidence = outputStr

	// Check service state
	var actualState string
	if strings.Contains(outputStr, "RUNNING") {
		actualState = "running"
	} else if strings.Contains(outputStr, "STOPPED") {
		actualState = "stopped"
	} else {
		actualState = "unknown"
	}

	// Check startup type if specified
	startupCompliant := true
	if serviceCheck.StartupType != "" {
		cmd = exec.Command("sc", "qc", serviceCheck.Name)
		configOutput, err := cmd.Output()
		if err == nil {
			configStr := string(configOutput)
			result.Evidence += "\n" + configStr

			var actualStartupType string
			if strings.Contains(configStr, "AUTO_START") {
				actualStartupType = "automatic"
			} else if strings.Contains(configStr, "DEMAND_START") {
				actualStartupType = "manual"
			} else if strings.Contains(configStr, "DISABLED") {
				actualStartupType = "disabled"
			}

			startupCompliant = (actualStartupType == serviceCheck.StartupType)
		}
	}

	stateCompliant := (actualState == serviceCheck.ExpectedState)

	if stateCompliant && startupCompliant {
		result.Status = "compliant"
		result.Message = fmt.Sprintf("Service '%s' is in expected state: %s", serviceCheck.Name, actualState)
	} else {
		result.Status = "non_compliant"
		result.Message = fmt.Sprintf("Service '%s' is not compliant (actual state: %s, expected: %s)",
			serviceCheck.Name, actualState, serviceCheck.ExpectedState)
	}

	return result
}

// checkFileControl performs a file-based compliance check
func (cm *ComplianceMonitor) checkFileControl(control ComplianceControlConfig, result ComplianceControlResult) ComplianceControlResult {
	fileCheck := control.CheckData.File

	// Check if file exists
	_, err := os.Stat(fileCheck.Path)
	fileExists := err == nil

	switch fileCheck.CheckType {
	case "exists":
		if fileExists {
			result.Status = "compliant"
			result.Message = "File exists as expected"
		} else {
			result.Status = "non_compliant"
			result.Message = "File does not exist"
		}
	case "not_exists":
		if !fileExists {
			result.Status = "compliant"
			result.Message = "File does not exist as expected"
		} else {
			result.Status = "non_compliant"
			result.Message = "File exists but should not"
		}
	default:
		result.Status = "error"
		result.Message = "Unsupported file check type: " + fileCheck.CheckType
	}

	result.Evidence = fmt.Sprintf("File path: %s, Exists: %t", fileCheck.Path, fileExists)

	return result
}

// checkPolicyControl performs a policy-based compliance check
func (cm *ComplianceMonitor) checkPolicyControl(_ ComplianceControlConfig, result ComplianceControlResult) ComplianceControlResult {
	// This is a simplified implementation
	// In a real scenario, you would use tools like secedit or PowerShell to query policies

	result.Status = "not_applicable"
	result.Message = "Policy checks not fully implemented in this demo"
	result.Evidence = "Policy check would require additional Windows API calls or PowerShell integration"

	return result
}

// checkWMIControl performs a WMI-based compliance check
func (cm *ComplianceMonitor) checkWMIControl(_ ComplianceControlConfig, result ComplianceControlResult) ComplianceControlResult {
	// This is a simplified implementation
	// In a real scenario, you would use WMI queries

	result.Status = "not_applicable"
	result.Message = "WMI checks not fully implemented in this demo"
	result.Evidence = "WMI check would require WMI integration"

	return result
}

// compareValues compares actual and expected values based on operator
func (cm *ComplianceMonitor) compareValues(actual string, expected interface{}, operator string) bool {
	switch operator {
	case "equals":
		return fmt.Sprintf("%v", expected) == actual
	case "not_equals":
		return fmt.Sprintf("%v", expected) != actual
	case "greater_than":
		actualNum, err1 := strconv.ParseFloat(actual, 64)
		expectedNum, err2 := strconv.ParseFloat(fmt.Sprintf("%v", expected), 64)
		if err1 != nil || err2 != nil {
			return false
		}
		return actualNum > expectedNum
	case "less_than":
		actualNum, err1 := strconv.ParseFloat(actual, 64)
		expectedNum, err2 := strconv.ParseFloat(fmt.Sprintf("%v", expected), 64)
		if err1 != nil || err2 != nil {
			return false
		}
		return actualNum < expectedNum
	case "greater_than_or_equal":
		actualNum, err1 := strconv.ParseFloat(actual, 64)
		expectedNum, err2 := strconv.ParseFloat(fmt.Sprintf("%v", expected), 64)
		if err1 != nil || err2 != nil {
			return false
		}
		return actualNum >= expectedNum
	case "less_than_or_equal":
		actualNum, err1 := strconv.ParseFloat(actual, 64)
		expectedNum, err2 := strconv.ParseFloat(fmt.Sprintf("%v", expected), 64)
		if err1 != nil || err2 != nil {
			return false
		}
		return actualNum <= expectedNum
	default:
		return false
	}
}

// generateRecommendations generates compliance recommendations based on findings
func (cm *ComplianceMonitor) generateRecommendations(report ComplianceReport) []ComplianceRecommendation {
	var recommendations []ComplianceRecommendation

	// High-priority recommendations for critical and high severity findings
	if report.Summary.CriticalFindings > 0 {
		recommendations = append(recommendations, ComplianceRecommendation{
			Priority:    "critical",
			Category:    "Security",
			Title:       "Address Critical Security Findings",
			Description: fmt.Sprintf("You have %d critical security findings that require immediate attention", report.Summary.CriticalFindings),
			Impact:      "High risk of security breach",
			Effort:      "High",
			Steps: []string{
				"Review all critical findings in the compliance report",
				"Prioritize fixes based on business impact",
				"Implement remediation steps for each critical finding",
				"Verify fixes through re-testing",
			},
		})
	}

	if report.Summary.HighFindings > 0 {
		recommendations = append(recommendations, ComplianceRecommendation{
			Priority:    "high",
			Category:    "Security",
			Title:       "Address High Severity Findings",
			Description: fmt.Sprintf("You have %d high severity findings that should be addressed soon", report.Summary.HighFindings),
			Impact:      "Moderate risk of security issues",
			Effort:      "Medium",
			Steps: []string{
				"Review high severity findings",
				"Create remediation plan with timelines",
				"Implement fixes in order of priority",
				"Document changes and verify compliance",
			},
		})
	}

	// Framework-specific recommendations
	for _, framework := range report.Frameworks {
		if framework.Score < 80 {
			recommendations = append(recommendations, ComplianceRecommendation{
				Priority:    "medium",
				Category:    "Compliance",
				Title:       fmt.Sprintf("Improve %s Compliance Score", framework.Name),
				Description: fmt.Sprintf("Your %s compliance score is %.1f%%, which is below the recommended 80%% threshold", framework.Name, framework.Score),
				Impact:      "Regulatory and audit risks",
				Effort:      "Medium",
				Steps: []string{
					fmt.Sprintf("Review failed %s controls", framework.Name),
					"Prioritize controls based on business requirements",
					"Implement necessary configuration changes",
					"Establish ongoing monitoring and maintenance",
				},
			})
		}
	}

	return recommendations
}

// GetComplianceReport returns the latest compliance report
func (cm *ComplianceMonitor) GetComplianceReport() ComplianceReport {
	return cm.complianceReport
}

// GetFrameworkScore returns the compliance score for a specific framework
func (cm *ComplianceMonitor) GetFrameworkScore(frameworkName string) float64 {
	for _, framework := range cm.complianceReport.Frameworks {
		if framework.Name == frameworkName {
			return framework.Score
		}
	}
	return 0.0
}

// GetComplianceSummary returns a summary of compliance status
func (cm *ComplianceMonitor) GetComplianceSummary() ComplianceSummary {
	return cm.complianceReport.Summary
}
