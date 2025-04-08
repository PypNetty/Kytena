package scanner

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/PypNetty/Kytena/pkg/scanner/types"
	"github.com/sirupsen/logrus"
)

// Alertes communes de comportements suspects dans Kubernetes
var commonRuntimeAlerts = []struct {
	ID          string
	Title       string
	Description string
	Severity    types.VulnerabilitySeverity
	Rule        string
	References  []string
}{
	{
		ID:          "FALCO-01-001",
		Title:       "Suspicious Shell in Container",
		Description: "A shell was spawned in a container with an attached terminal, which may indicate an interactive compromise.",
		Severity:    types.SeverityHigh,
		Rule:        "Terminal Shell in Container",
		References:  []string{"https://falco.org/docs/rules/default-rules/#shell-in-container"},
	},
	{
		ID:          "FALCO-01-002",
		Title:       "Sensitive File Access",
		Description: "A process in a container accessed a sensitive file like /etc/shadow, which is unusual behavior.",
		Severity:    types.SeverityHigh,
		Rule:        "Read Sensitive File",
		References:  []string{"https://falco.org/docs/rules/default-rules/#read-sensitive-file-untrusted"},
	},
	{
		ID:          "FALCO-01-003",
		Title:       "Outbound Network Connection from Database Container",
		Description: "A database container is making an unexpected outbound network connection, potentially exfiltrating data.",
		Severity:    types.SeverityCritical,
		Rule:        "Unexpected Outbound Connection",
		References:  []string{"https://falco.org/docs/rules/default-rules/#unexpected-outbound-connection"},
	},
	{
		ID:          "FALCO-01-004",
		Title:       "Package Management Execution",
		Description: "A package management tool (apt, yum, etc.) was executed in a container, which may indicate an attacker installing tools.",
		Severity:    types.SeverityMedium,
		Rule:        "Package Management Executed",
		References:  []string{"https://falco.org/docs/rules/default-rules/#detect-apt-get-package-management"},
	},
	{
		ID:          "FALCO-01-005",
		Title:       "Crypto Miner Execution",
		Description: "A process with a command line matching known crypto miners was executed.",
		Severity:    types.SeverityCritical,
		Rule:        "Crypto Miner Execution",
		References:  []string{"https://falco.org/docs/rules/default-rules/#detect-crypto-miners"},
	},
	{
		ID:          "FALCO-01-006",
		Title:       "Container Privilege Escalation",
		Description: "A container process attempted a privilege escalation by modifying capabilities.",
		Severity:    types.SeverityCritical,
		Rule:        "Container Capability Change",
		References:  []string{"https://falco.org/docs/rules/default-rules/#container-capability-change"},
	},
	{
		ID:          "FALCO-01-007",
		Title:       "Container Namespace Change",
		Description: "A container process attempted to modify namespaces, possibly trying to escape container isolation.",
		Severity:    types.SeverityCritical,
		Rule:        "Container Namespace Change",
		References:  []string{"https://falco.org/docs/rules/default-rules/#container-namespace-change"},
	},
	{
		ID:          "FALCO-01-008",
		Title:       "File Created in /tmp with Binary Signature",
		Description: "A process created a file in /tmp with binary signatures, potentially dropping malware.",
		Severity:    types.SeverityHigh,
		Rule:        "Binary Created in Temp Directory",
		References:  []string{"https://falco.org/docs/rules/default-rules/#write-binary-to-tmp"},
	},
	{
		ID:          "FALCO-01-009",
		Title:       "Kernel Module Loading",
		Description: "An attempt to load a kernel module from a container was detected.",
		Severity:    types.SeverityCritical,
		Rule:        "Load Kernel Module",
		References:  []string{"https://falco.org/docs/rules/default-rules/#load-kernel-module"},
	},
	{
		ID:          "FALCO-01-010",
		Title:       "Execution in Unusual Directory",
		Description: "A process was started in an unusual directory, which might indicate unauthorized software execution.",
		Severity:    types.SeverityMedium,
		Rule:        "Execution in Unusual Directory",
		References:  []string{"https://falco.org/docs/rules/default-rules/#execution-in-unusual-dir"},
	},
}

// BaseScanner provides common scanner functionality
type BaseScanner struct {
	name        string
	description string
	logger      *logrus.Logger
}

// FalcoScanner simule un scanner Falco
type FalcoScanner struct {
	*BaseScanner
	random *rand.Rand
}

// NewFalcoScanner crée un nouveau scanner Falco simulé
func NewFalcoScanner(logger *logrus.Logger) *FalcoScanner {
	return &FalcoScanner{
		BaseScanner: NewBaseScanner("Falco", "Runtime behavior analysis using Falco", logger),
		random:      rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

func NewBaseScanner(name, description string, logger *logrus.Logger) *BaseScanner {
	return &BaseScanner{
		name:        name,
		description: description,
		logger:      logger,
	}
}

// Name returns the scanner name
func (s *BaseScanner) Name() string {
	return s.name
}

// Description returns the scanner description
func (s *BaseScanner) Description() string {
	return s.description
}

// FilterFindings filters findings by minimum severity
func (s *BaseScanner) FilterFindings(findings []types.VulnerabilityFinding, minSeverity types.VulnerabilitySeverity) []types.VulnerabilityFinding {
	if minSeverity == "" {
		return findings
	}

	var filtered []types.VulnerabilityFinding
	for _, f := range findings {
		if f.Severity >= minSeverity {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

// Scan simule un scan Falco
func (s *FalcoScanner) Scan(ctx context.Context, options types.ScanOptions) (*types.ScanResult, error) {
	start := time.Now()
	s.logger.Info("Starting Falco scan...")

	// Simulation d'exécution
	select {
	case <-time.After(time.Duration(300+s.random.Intn(500)) * time.Millisecond):
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	result := &types.ScanResult{
		ScannerName: s.Name(),
		StartTime:   start,
		EndTime:     time.Now(),
		Success:     true,
		Metadata:    map[string]interface{}{"falcoVersion": "0.34.1"},
	}

	// Génération simulée
	for _, wl := range s.getWorkloadsToScan(options) {
		alerts := s.simulateRuntimeAlerts(wl.Name, wl.Namespace, wl.Type, wl.Image, options)
		result.Findings = append(result.Findings, alerts...)
	}

	// Filtrage
	result.Findings = s.FilterFindings(result.Findings, options.MinimumSeverity)
	result.Findings = s.LimitFindings(result.Findings, options.MaxFindings)

	s.logger.Infof("Falco scan completed in %s, %d findings", result.EndTime.Sub(result.StartTime), len(result.Findings))
	return result, nil
}

func (s *FalcoScanner) LimitFindings(findings []types.VulnerabilityFinding, max int) []types.VulnerabilityFinding {
	if max <= 0 || len(findings) <= max {
		return findings
	}
	return findings[:max]
}

// simulateRuntimeAlerts génère des alertes runtime simulées
func (s *FalcoScanner) simulateRuntimeAlerts(name, ns, kind, image string, options types.ScanOptions) []types.VulnerabilityFinding {
	var findings []types.VulnerabilityFinding

	alertProbability := 0.1
	if containsAny(image, []string{"mysql", "postgres", "redis", "mongo"}) {
		alertProbability += 0.1
	}
	if containsAny(image, []string{"ubuntu:16.04", "debian:9", "alpine:3.7"}) {
		alertProbability += 0.15
	}

	for _, alert := range commonRuntimeAlerts {
		proba := alertProbability

		if alert.ID == "FALCO-01-003" && containsAny(image, []string{"mysql", "postgres"}) {
			proba += 0.2
		}
		if alert.ID == "FALCO-01-001" && containsAny(name, []string{"api", "web"}) {
			proba += 0.15
		}
		if alert.ID == "FALCO-01-005" {
			proba -= 0.05
		}

		if s.random.Float64() < proba {
			findings = append(findings, types.VulnerabilityFinding{
				ID:                alert.ID,
				Title:             alert.Title,
				Description:       alert.Description,
				Severity:          alert.Severity,
				AffectedComponent: "Container Runtime",
				ResourceID:        fmt.Sprintf("%s/%s", ns, name),
				ResourceType:      kind,
				Namespace:         ns,
				WorkloadName:      name,
				ScannerName:       s.Name(),
				References:        alert.References,
				DetectedAt:        time.Now(),
				ExploitAvailable:  alert.Severity == types.SeverityCritical || alert.Severity == types.SeverityHigh,
				Metadata: map[string]interface{}{
					"imageId":     image,
					"ruleName":    alert.Rule,
					"detectedPID": 1000 + s.random.Intn(5000),
				},
			})
		}
	}

	return findings
}

// getWorkloadsToScan simule la récupération de workloads
func (s *FalcoScanner) getWorkloadsToScan(options types.ScanOptions) []struct {
	Name, Namespace, Type, Image string
} {
	all := []struct {
		Name, Namespace, Type, Image string
	}{
		{"frontend", "default", "Deployment", "nginx:1.21.6"},
		{"api", "default", "Deployment", "node:16.19.1"},
		{"database", "default", "StatefulSet", "mysql:8.0.31"},
		{"redis", "default", "Deployment", "redis:6.2.6"},
		{"logging", "monitoring", "DaemonSet", "fluent/fluentd:v1.14"},
		{"metrics", "monitoring", "Deployment", "prom/prometheus:v2.36.0"},
	}

	if len(options.IncludeNamespaces) > 0 {
		var filtered []struct {
			Name, Namespace, Type, Image string
		}
		for _, w := range all {
			for _, ns := range options.IncludeNamespaces {
				if w.Namespace == ns {
					filtered = append(filtered, w)
					break
				}
			}
		}
		all = filtered
	}

	if len(options.IncludeWorkloads) > 0 {
		var filtered []struct {
			Name, Namespace, Type, Image string
		}
		for _, w := range all {
			for _, name := range options.IncludeWorkloads {
				if w.Name == name {
					filtered = append(filtered, w)
					break
				}
			}
		}
		all = filtered
	}

	return all
}

// containsAny vérifie si une chaîne contient un des substrings
func containsAny(s string, list []string) bool {
	for _, sub := range list {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
