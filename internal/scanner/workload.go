package scanner

// Container représente un conteneur dans un workload
type Container struct {
	Name  string
	Image string
}

// Workload représente un workload Kubernetes
type Workload struct {
	Name       string
	Namespace  string
	Type       string
	Containers []Container
}

// VulnerabilitySeverity représente le niveau de sévérité d'une vulnérabilité
type VulnerabilitySeverity string

const (
	SeverityCritical VulnerabilitySeverity = "CRITICAL"
	SeverityHigh     VulnerabilitySeverity = "HIGH"
	SeverityMedium   VulnerabilitySeverity = "MEDIUM"
	SeverityLow      VulnerabilitySeverity = "LOW"
	SeverityUnknown  VulnerabilitySeverity = "UNKNOWN"
)

// MapSeverity mappe une chaîne de sévérité à un type VulnerabilitySeverity
func MapSeverity(severity string) VulnerabilitySeverity {
	switch severity {
	case "CRITICAL", "Critical", "critical":
		return SeverityCritical
	case "HIGH", "High", "high":
		return SeverityHigh
	case "MEDIUM", "Medium", "medium":
		return SeverityMedium
	case "LOW", "Low", "low":
		return SeverityLow
	default:
		return SeverityUnknown
	}
}

// WorkloadScanOptions contient les options pour exécuter un scan
type WorkloadScanOptions struct {
	MinimumSeverity   VulnerabilitySeverity
	MaxFindings       int
	IncludeNamespaces []string
	ExcludeNamespaces []string
	IncludeWorkloads  []string
	ExcludeWorkloads  []string
	Timeout           interface{}
	ScannerSpecific   map[string]interface{}
}
