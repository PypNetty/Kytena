package scanner

import (
	"context"
	"time"
)

// VulnerabilitySeverity représente le niveau de sévérité d'une vulnérabilité
type VulnerabilitySeverity string

const (
	// SeverityCritical indique une vulnérabilité critique
	SeverityCritical VulnerabilitySeverity = "Critical"

	// SeverityHigh indique une vulnérabilité à haut risque
	SeverityHigh VulnerabilitySeverity = "High"

	// SeverityMedium indique une vulnérabilité à risque moyen
	SeverityMedium VulnerabilitySeverity = "Medium"

	// SeverityLow indique une vulnérabilité à faible risque
	SeverityLow VulnerabilitySeverity = "Low"

	// SeverityUnknown indique une vulnérabilité dont la sévérité est inconnue
	SeverityUnknown VulnerabilitySeverity = "Unknown"
)

// VulnerabilityFinding représente une vulnérabilité détectée par un scanner
type VulnerabilityFinding struct {
	// ID est l'identifiant de la vulnérabilité (ex: CVE-2023-12345)
	ID string

	// Title est le titre de la vulnérabilité
	Title string

	// Description décrit la vulnérabilité
	Description string

	// Severity indique la sévérité de la vulnérabilité
	Severity VulnerabilitySeverity

	// AffectedComponent est le composant affecté (ex: image, package)
	AffectedComponent string

	// AffectedVersion est la version affectée
	AffectedVersion string

	// FixedVersion est la version qui corrige la vulnérabilité
	FixedVersion string

	// ResourceID identifie la ressource où la vulnérabilité a été détectée
	ResourceID string

	// ResourceType est le type de ressource (pod, deployment, etc.)
	ResourceType string

	// Namespace est le namespace Kubernetes où la vulnérabilité a été détectée
	Namespace string

	// WorkloadName est le nom du workload concerné
	WorkloadName string

	// References contient des liens vers des informations supplémentaires
	References []string

	// Tags contient des tags associés à la vulnérabilité
	Tags []string

	// ScannerName indique quel scanner a détecté cette vulnérabilité
	ScannerName string

	// DetectedAt indique quand la vulnérabilité a été détectée
	DetectedAt time.Time

	// ExploitAvailable indique si un exploit est publiquement disponible
	ExploitAvailable bool

	// Metadata contient des informations supplémentaires spécifiques au scanner
	Metadata map[string]interface{}
}

// ScanResult contient les résultats d'un scan
type ScanResult struct {
	// ScannerName est le nom du scanner utilisé
	ScannerName string

	// Findings contient les vulnérabilités détectées
	Findings []VulnerabilityFinding

	// StartTime indique quand le scan a commencé
	StartTime time.Time

	// EndTime indique quand le scan s'est terminé
	EndTime time.Time

	// Success indique si le scan s'est terminé avec succès
	Success bool

	// Error contient l'erreur si le scan a échoué
	Error error

	// Metadata contient des informations supplémentaires sur le scan
	Metadata map[string]interface{}
}

// ScanOptions contient les options pour un scan
type ScanOptions struct {
	// IncludeNamespaces limite le scan à certains namespaces
	IncludeNamespaces []string

	// ExcludeNamespaces exclut certains namespaces du scan
	ExcludeNamespaces []string

	// IncludeWorkloads limite le scan à certains workloads
	IncludeWorkloads []string

	// ExcludeWorkloads exclut certains workloads du scan
	ExcludeWorkloads []string

	// MinimumSeverity indique la sévérité minimale à rapporter
	MinimumSeverity VulnerabilitySeverity

	// MaxFindings limite le nombre de résultats
	MaxFindings int

	// Timeout définit un timeout pour le scan
	Timeout time.Duration

	// ScannerSpecific contient des options spécifiques au scanner
	ScannerSpecific map[string]interface{}
}

// VulnerabilityScanner définit l'interface pour les scanners de vulnérabilités
type VulnerabilityScanner interface {
	// Name retourne le nom du scanner
	Name() string

	// Description retourne une description du scanner
	Description() string

	// Scan lance un scan avec les options spécifiées
	Scan(ctx context.Context, options ScanOptions) (*ScanResult, error)

	// SetConfig configure le scanner
	SetConfig(config map[string]interface{}) error
}

// VulnerabilityScannerRegistry est un registre de scanners disponibles
type VulnerabilityScannerRegistry struct {
	scanners map[string]VulnerabilityScanner
}

// NewVulnerabilityScannerRegistry crée un nouveau registre de scanners
func NewVulnerabilityScannerRegistry() *VulnerabilityScannerRegistry {
	return &VulnerabilityScannerRegistry{
		scanners: make(map[string]VulnerabilityScanner),
	}
}

// RegisterScanner enregistre un scanner dans le registre
func (r *VulnerabilityScannerRegistry) RegisterScanner(scanner VulnerabilityScanner) {
	r.scanners[scanner.Name()] = scanner
}

// GetScanner récupère un scanner par son nom
func (r *VulnerabilityScannerRegistry) GetScanner(name string) (VulnerabilityScanner, bool) {
	scanner, exists := r.scanners[name]
	return scanner, exists
}

// ListScanners liste tous les scanners enregistrés
func (r *VulnerabilityScannerRegistry) ListScanners() []VulnerabilityScanner {
	result := make([]VulnerabilityScanner, 0, len(r.scanners))
	for _, scanner := range r.scanners {
		result = append(result, scanner)
	}
	return result
}

// MapSeverity mappe une sévérité de scanner externe vers une VulnerabilitySeverity
func MapSeverity(severity string) VulnerabilitySeverity {
	switch severity {
	case "CRITICAL", "critical", "Critical":
		return SeverityCritical
	case "HIGH", "high", "High":
		return SeverityHigh
	case "MEDIUM", "medium", "Medium":
		return SeverityMedium
	case "LOW", "low", "Low":
		return SeverityLow
	default:
		return SeverityUnknown
	}
}
