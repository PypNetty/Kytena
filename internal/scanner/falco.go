package scanner

import (
	"context"
	"fmt"
	"math/rand"
	"time"
)

// Alertes communes de comportements suspects dans Kubernetes
var commonRuntimeAlerts = []struct {
	ID          string
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
	config map[string]interface{}
	random *rand.Rand
}

// NewFalcoScanner crée un nouveau scanner Falco simulé
func NewFalcoScanner() *FalcoScanner {
	return &FalcoScanner{
		config: make(map[string]interface{}),
		random: rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// Name retourne le nom du scanner
func (s *FalcoScanner) Name() string {
	return "Falco"
}

// Description retourne une description du scanner
func (s *FalcoScanner) Description() string {
	return "Simulated Falco runtime security scanner for Kubernetes"
}

// SetConfig configure le scanner
func (s *FalcoScanner) SetConfig(config map[string]interface{}) error {
	s.config = config
	return nil
}

// Scan simule un scan Falco
func (s *FalcoScanner) Scan(ctx context.Context, options ScanOptions) (*ScanResult, error) {
	startTime := time.Now()

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
	workloads := simulateWorkloads(options)

	// Générer des résultats pour chaque workload
	for _, workload := range workloads {
		// Simuler les alertes runtime pour ce workload
		runtimeFindings := s.simulateRuntimeAlerts(workload.Name, workload.Namespace, workload.Type, workload.Image, options)
		result.Findings = append(result.Findings, runtimeFindings...)
	}

	// Filtrer selon la sévérité minimale si spécifiée
	if options.MinimumSeverity != "" {
		var filteredFindings []VulnerabilityFinding
		for _, finding := range result.Findings {
			if isSeverityAtLeast(finding.Severity, options.MinimumSeverity) {
				filteredFindings = append(filteredFindings, finding)
			}
		}
		result.Findings = filteredFindings
	}

	// Limiter le nombre de résultats si demandé
	if options.MaxFindings > 0 && len(result.Findings) > options.MaxFindings {
		result.Findings = result.Findings[:options.MaxFindings]
	}

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

// containsAny vérifie si une chaîne contient l'un des éléments d'une liste
func containsAny(s string, substrings []string) bool {
	for _, substr := range substrings {
		if contains(s, substr) {
			return true
		}
	}
	return false
}

// contains vérifie si une chaîne en contient une autre
func contains(s, substr string) bool {
	return s == substr || fmt.Sprintf("%s", s) == fmt.Sprintf("%s", substr)
}
