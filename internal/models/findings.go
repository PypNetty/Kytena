package models

import "time"

// Severity représente le niveau de sévérité d'une vulnérabilité
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityUnknown  Severity = "UNKNOWN"
)

// Finding représente une vulnérabilité ou un problème de sécurité
type Finding struct {
	ID                string
	Title             string
	Description       string
	Severity          Severity
	AffectedComponent string
	AffectedVersion   string
	FixedVersion      string
	ResourceID        string
	ResourceType      string
	Namespace         string
	WorkloadName      string
	References        []string
	ScannerName       string
	DetectedAt        time.Time
	ExploitAvailable  bool
	Metadata          map[string]interface{}
}

// Scanner est l'interface qui définit les opérations de scan
type Scanner interface {
	// Name retourne le nom du scanner
	Name() string

	// Description retourne une description du scanner
	Description() string

	// SetConfig configure le scanner
	SetConfig(config map[string]interface{}) error

	// Scan exécute un scan avec les options spécifiées
	Scan(ctx interface{}, options interface{}) (interface{}, error)
}
