package scanner

import (
	"strings"

	types "github.com/PypNetty/Kytena/pkg/scanner/types"
)

// MapSeverity convertit une chaîne de sévérité en type VulnerabilitySeverity
func MapSeverity(severity string) types.VulnerabilitySeverity {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return types.SeverityCritical
	case "HIGH":
		return types.SeverityHigh
	case "MEDIUM":
		return types.SeverityMedium
	case "LOW":
		return types.SeverityLow
	default:
		return types.SeverityLow // Using SeverityLow as fallback instead of undefined SeverityUnknown
	}
}
