package types

import "time"

// VulnerabilitySeverity représente le niveau de sévérité d'une vulnérabilité
type VulnerabilitySeverity string

const (
	SeverityCritical VulnerabilitySeverity = "CRITICAL"
	SeverityHigh     VulnerabilitySeverity = "HIGH"
	SeverityMedium   VulnerabilitySeverity = "MEDIUM"
	SeverityLow      VulnerabilitySeverity = "LOW"
	SeverityInfo     VulnerabilitySeverity = "INFO"
)

// VulnerabilityFinding représente un résultat de scan détecté
type VulnerabilityFinding struct {
	ID                string                 `json:"id"`
	Title             string                 `json:"title"`
	Description       string                 `json:"description"`
	Severity          VulnerabilitySeverity  `json:"severity"`
	AffectedComponent string                 `json:"affectedComponent"`
	ResourceID        string                 `json:"resourceId"`
	ResourceType      string                 `json:"resourceType"`
	Namespace         string                 `json:"namespace"`
	WorkloadName      string                 `json:"workloadName"`
	ScannerName       string                 `json:"scannerName"`
	References        []string               `json:"references"`
	DetectedAt        time.Time              `json:"detectedAt"`
	ExploitAvailable  bool                   `json:"exploitAvailable"`
	Metadata          map[string]interface{} `json:"metadata,omitempty"`
}

// ScanOptions contient les options de configuration pour un scan
type ScanOptions struct {
	IncludeNamespaces []string
	IncludeWorkloads  []string
	MinimumSeverity   VulnerabilitySeverity
	MaxFindings       int
}

// ScanResult contient le résultat global d'un scan
type ScanResult struct {
	ScannerName string                 `json:"scannerName"`
	StartTime   time.Time              `json:"startTime"`
	EndTime     time.Time              `json:"endTime"`
	Success     bool                   `json:"success"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	Findings    []VulnerabilityFinding `json:"findings"`
}
