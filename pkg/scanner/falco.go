// pkg/scanner/falco.go
package scanner

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// Alertes communes de comportements suspects dans Kubernetes
var commonRuntimeAlerts = []struct {
	ID          strin
	Title       string
	Description string
	Severity    VulnerabilitySeverity
	Rule        string
	References  []string
}{
	{
		ID:          "FALCO-01-001",
		Title:       "Suspicious Shell in Container",
		Description: "A shell was spawned in a container with an attached terminal, which may indicate an interactive compromise.",
		Severity:    SeverityHigh,
		Rule:        "Terminal Shell in Container",
		References:  []string{"https://falco.org/docs/rules/default-rules/#shell-in-container"},
	},
	{
		ID:          "FALCO-01-002",
		Title:       "Sensitive File Access",
		Description: "A process in a container accessed a sensitive file like /etc/shadow, which is unusual behavior.",
		Severity:    SeverityHigh,
		Rule:        "Read Sensitive File",
		References:  []string{"https://falco.org/docs/rules/default-rules/#read-sensitive-file-untrusted"},
	},
	{
		ID:          "FALCO-01-003",
		Title:       "Outbound Network Connection from Database Container",
		Description: "A database container is making an unexpected outbound network connection, potentially exfiltrating data.",
		Severity:    SeverityCritical,
		Rule:        "Unexpected Outbound Connection",
		References:  []string{"https://falco.org/docs/rules/default-rules/#unexpected-outbound-connection"},
	},
	{
		ID:          "FALCO-01-004",
		Title:       "Package Management Execution",
		Description: "A package management tool (apt, yum, etc.) was executed in a container, which may indicate an attacker installing tools.",
		Severity:    SeverityMedium,
		Rule:        "Package Management Executed",
		References:  []string{"https://falco.org/docs/rules/default-rules/#detect-apt-get-package-management"},
	},
	{
		ID:          "FALCO-01-005",
		Title:       "Crypto Miner Execution",
		Description: "A process with a command line matching known crypto miners was executed.",
		Severity:    SeverityCritical,
		Rule:        "Crypto Miner Execution",
		References:  []string{"https://falco.org/docs/rules/default-rules/#detect-crypto-miners"},
	},
	{
		ID:          "FALCO-01-006",
		Title:       "Container Privilege Escalation",
		Description: "A container process attempted a privilege escalation by modifying capabilities.",
		Severity:    SeverityCritical,
		Rule:        "Container Capability Change",
		References:  []string{"https://falco.org/docs/rules/default-rules/#container-capability-change"},
	},
	{
		ID:          "FALCO-01-007",
		Title:       "Container Namespace Change",
		Description: "A container process attempted to modify namespaces, possibly trying to escape container isolation.",
		Severity:    SeverityCritical,
		Rule:        "Container Namespace Change",
		References:  []string{"https://falco.org/docs/rules/default-rules/#container-namespace-change"},
	},
	{
		ID:          "FALCO-01-008",
		Title:       "File Created in /tmp with Binary Signature",
		Description: "A process created a file in /tmp with binary signatures, potentially dropping malware.",
		Severity:    SeverityHigh,
		Rule:        "Binary Created in Temp Directory",
		References:  []string{"https://falco.org/docs/rules/default-rules/#write-binary-to-tmp"},
	},
	{
		ID:          "FALCO-01-009",
		Title:       "Kernel Module Loading",
		Description: "An attempt to load a kernel module from a container was detected.",
		Severity:    SeverityCritical,
		Rule:        "Load Kernel Module",
		References:  []string{"https://falco.org/docs/rules/default-rules/#load-kernel-module"},
	},
	{
		ID:          "FALCO-01-010",
		Title:       "Execution in Unusual Directory",
		Description: "A process was started in an unusual directory, which might indicate unauthorized software execution.",
		Severity:    SeverityMedium,
		Rule:        "Execution in Unusual Directory",
		References:  []string{"https://falco.org/docs/rules/default-rules/#execution-in-unusual-dir"},
	},
}

// FalcoScanner simule un scanner Falco
type FalcoScanner struct {
	*BaseScanner
	random *rand.Rand
}

// NewFalcoScanner crée un nouveau scanner Falco simulé
func NewFalcoScanner(logger *logrus.Logger) *FalcoScanner {
	base := NewBaseScanner("Falco", "Runtime security scanner for Kubernetes", logger)

	return &FalcoScanner{
		BaseScanner: base,
		random:      rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// Scan simule un scan Falco
func (s *FalcoScanner) Scan(ctx context.Context, options ScanOptions) (*ScanResult, error) {
	startTime := time.Now()

	s.logger.Info("Starting Falco scan")

	// Simuler un délai d'exécution réaliste
	scanDuration := time.Duration(300+s.random.Intn(500)) * time.Millisecond

	select {
	case <-time.After(scanDuration):
		// Continue
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	// Préparer le résultat du scan
	result := &ScanResult{
		ScannerName: s.Name(),
		StartTime:   startTime,
		EndTime:     time.Now(),
		Success:     true,
		Metadata: map[string]interface{}{
			"falcoVersion": "0.34.1",
		},
	}

	// Simuler les workloads à scanner
	workloads := s.getWorkloadsToScan(options)

	// Générer des résultats pour chaque workload
	for _, workload := range workloads {
		// Simuler les alertes runtime pour ce workload
		runtimeFindings := s.simulateRuntimeAlerts(workload.Name, workload.Namespace, workload.Type, workload.Image, options)

		result.Findings = append(result.Findings, runtimeFindings...)
	}

	// Filtrer selon la sévérité minimale si spécifiée
	result.Findings = s.FilterFindings(result.Findings, options.MinimumSeverity)

	// Limiter le nombre de résultats si demandé
	result.Findings = s.LimitFindings(result.Findings, options.MaxFindings)

	s.logger.Infof("Falco scan completed in %s, found %d runtime alerts", result.EndTime.Sub(result.StartTime), len(result.Findings))

	return result, nil
}

// simulateRuntimeAlerts génère des alertes runtime simulées pour un workload
func (s *FalcoScanner) simulateRuntimeAlerts(workloadName, namespace, resourceType, image string, options ScanOptions) []VulnerabilityFinding {
	var findings []VulnerabilityFinding

	// Déterminer la probabilité d'alertes basée sur l'image et le type de workload
	alertProbability := 0.1 // 10% de base

	// Augmenter la probabilité pour certains types d'images
	if containsAny(image, []string{"mysql", "postgres", "redis", "mongo"}) {
		alertProbability += 0.1 // +10% pour les bases de données
	}

	// Augmenter pour les images anciennes ou potentiellement vulnérables
	if containsAny(image, []string{"ubuntu:16.04", "debian:9", "alpine:3.7"}) {
		alertProbability += 0.15 // +15% pour les OS anciens
	}

	// Pour chaque alerte possible, déterminer si elle s'applique
	for _, alert := range commonRuntimeAlerts {
		// Certaines alertes sont plus probables pour certains types de workloads
		alertSpecificProbability := alertProbability

		// Personnaliser les probabilités selon le contexte
		switch {
		case alert.ID == "FALCO-01-003" && containsAny(image, []string{"mysql", "postgres", "redis", "mongo"}):
			// Alerte de connexion sortante sur un conteneur de base de données
			alertSpecificProbability += 0.2
		case alert.ID == "FALCO-01-001" && containsAny(workloadName, []string{"api", "web", "app"}):
			// Shell dans un conteneur pour les applications web/API
			alertSpecificProbability += 0.15
		case alert.ID == "FALCO-01-005":
			// Crypto miners sont rares mais très graves
			alertSpecificProbability -= 0.05
		}

		// Décider si l'alerte s'applique à ce workload
		if s.random.Float64() < alertSpecificProbability {
			finding := VulnerabilityFinding{
				ID:                alert.ID,
				Title:             alert.Title,
				Description:       alert.Description,
				Severity:          alert.Severity,
				AffectedComponent: "Container Runtime",
				ResourceID:        fmt.Sprintf("%s/%s", namespace, workloadName),
				ResourceType:      resourceType,
				Namespace:         namespace,
				WorkloadName:      workloadName,
				References:        alert.References,
				ScannerName:       s.Name(),
				DetectedAt:        time.Now(),
				ExploitAvailable:  alert.Severity == SeverityCritical || alert.Severity == SeverityHigh,
				Metadata: map[string]interface{}{
					"imageId":     image,
					"ruleName":    alert.Rule,
					"detectedPID": 1000 + s.random.Intn(5000),
				},
			}

			findings = append(findings, finding)
		}
	}

	return findings
}

// getWorkloadsToScan simule la récupération des workloads à scanner
func (s *FalcoScanner) getWorkloadsToScan(options ScanOptions) []struct {
	Name      string
	Namespace string
	Type      string
	Image     string
} {
	// Simuler une liste de workloads
	workloads := []struct {
		Name      string
		Namespace string
		Type      string
		Image     string
	}{
		{Name: "frontend", Namespace: "default", Type: "Deployment", Image: "nginx:1.21.6"},
		{Name: "api", Namespace: "default", Type: "Deployment", Image: "node:16.19.1"},
		{Name: "database", Namespace: "default", Type: "StatefulSet", Image: "mysql:8.0.31"},
		{Name: "redis", Namespace: "default", Type: "Deployment", Image: "redis:6.2.6"},
		{Name: "logging", Namespace: "monitoring", Type: "DaemonSet", Image: "fluent/fluentd:v1.14"},
		{Name: "metrics", Namespace: "monitoring", Type: "Deployment", Image: "prom/prometheus:v2.36.0"},
	}

	// Filtrer par namespace si spécifié
	if len(options.IncludeNamespaces) > 0 {
		var filtered []struct {
			Name      string
			Namespace string
			Type      string
			Image     string
		}

		for _, w := range workloads {
			for _, ns := range options.IncludeNamespaces {
				if w.Namespace == ns {
					filtered = append(filtered, w)
					break
				}
			}
		}

		workloads = filtered
	}

	// Filtrer par workload si spécifié
	if len(options.IncludeWorkloads) > 0 {
		var filtered []struct {
			Name      string
			Namespace string
			Type      string
			Image     string
		}

		for _, w := range workloads {
			for _, name := range options.IncludeWorkloads {
				if w.Name == name {
					filtered = append(filtered, w)
					break
				}
			}
		}

		workloads = filtered
	}

	return workloads
}

// containsAny vérifie si une chaîne contient l'un des éléments d'une liste
func containsAny(s string, substrings []string) bool {
	for _, substr := range substrings {
		if strings.Contains(s, substr) {
			return true
		}
	}
	return false
}
