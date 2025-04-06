package scanner

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"time"
)

// Vulnérabilités communes dans les images de conteneurs
var commonContainerVulnerabilities = []struct {
	ID          string
	Title       string
	Description string
	Severity    VulnerabilitySeverity
	Component   string
	FixedIn     string
	References  []string
}{
	{
		ID:          "CVE-2023-23916",
		Title:       "libcurl URL Credential Exposure",
		Description: "When sending HTTP requests with credentials in the URL, libcurl would send those credentials again in the Location: following request as well.",
		Severity:    SeverityHigh,
		Component:   "curl",
		FixedIn:     "8.0.0",
		References:  []string{"https://curl.se/docs/CVE-2023-23916.html"},
	},
	{
		ID:          "CVE-2023-28840",
		Title:       "nginx HTTP/2 Memory Corruption",
		Description: "A crafted HTTP/2 request can cause memory corruption in the NGINX process, potentially leading to remote code execution.",
		Severity:    SeverityCritical,
		Component:   "nginx",
		FixedIn:     "1.22.1",
		References:  []string{"https://nginx.org/en/security_advisories.html"},
	},
	{
		ID:          "CVE-2023-24329",
		Title:       "Node.js Path Traversal",
		Description: "Path traversal vulnerability exists in Node.js when handling certain URL patterns.",
		Severity:    SeverityHigh,
		Component:   "node",
		FixedIn:     "18.15.0",
		References:  []string{"https://nodejs.org/en/blog/vulnerability/feb-2023-security-releases/"},
	},
	{
		ID:          "CVE-2023-25809",
		Title:       "Python Request Smuggling",
		Description: "A malicious client can manipulate HTTP requests to the urllib.request module to make it send different data than intended.",
		Severity:    SeverityMedium,
		Component:   "python",
		FixedIn:     "3.11.3",
		References:  []string{"https://python.org/security"},
	},
	{
		ID:          "CVE-2023-27533",
		Title:       "OpenSSL TLS Padding Oracle Vulnerability",
		Description: "A padding oracle vulnerability in OpenSSL's TLS implementation could lead to information disclosure or MITM attacks.",
		Severity:    SeverityHigh,
		Component:   "openssl",
		FixedIn:     "3.0.8",
		References:  []string{"https://www.openssl.org/news/secadv/20230322.txt"},
	},
	{
		ID:          "CVE-2023-25690",
		Title:       "Apache HTTP Server mod_proxy DoS",
		Description: "A flaw in mod_proxy_uwsgi of Apache HTTP Server allows an attacker to cause a Denial of Service.",
		Severity:    SeverityMedium,
		Component:   "httpd",
		FixedIn:     "2.4.56",
		References:  []string{"https://httpd.apache.org/security/vulnerabilities_24.html"},
	},
	{
		ID:          "CVE-2023-28466",
		Title:       "Redis Command Injection",
		Description: "Redis is vulnerable to command injection via specially crafted Lua scripts.",
		Severity:    SeverityCritical,
		Component:   "redis",
		FixedIn:     "7.0.10",
		References:  []string{"https://redis.io/security"},
	},
	{
		ID:          "CVE-2023-21892",
		Title:       "MySQL Authentication Bypass",
		Description: "A vulnerability in MySQL authentication mechanism could allow authentication bypass.",
		Severity:    SeverityCritical,
		Component:   "mysql",
		FixedIn:     "8.0.32",
		References:  []string{"https://www.oracle.com/security-alerts/"},
	},
	{
		ID:          "CVE-2023-24807",
		Title:       "Golang crypto/tls Timing Side-Channel",
		Description: "A timing side-channel in the Go TLS implementation could reveal information about session tickets.",
		Severity:    SeverityLow,
		Component:   "golang",
		FixedIn:     "1.20.2",
		References:  []string{"https://groups.google.com/g/golang-announce"},
	},
	{
		ID:          "CVE-2023-29402",
		Title:       "Java JRE Deserialization Vulnerability",
		Description: "A deserialization vulnerability in the Java Runtime Environment could allow remote code execution.",
		Severity:    SeverityHigh,
		Component:   "openjdk",
		FixedIn:     "17.0.6",
		References:  []string{"https://www.oracle.com/security-alerts/"},
	},
}

// Images communes avec leurs composants
var commonImages = map[string][]string{
	"nginx:1.21.6":   {"nginx/1.21.6", "openssl/1.1.1n", "curl/7.81.0"},
	"nginx:1.22.0":   {"nginx/1.22.0", "openssl/1.1.1q", "curl/7.83.1"},
	"node:16.19.1":   {"node/16.19.1", "npm/8.19.3", "openssl/1.1.1t"},
	"node:18.12.0":   {"node/18.12.0", "npm/8.19.2", "openssl/3.0.5"},
	"python:3.9.16":  {"python/3.9.16", "openssl/1.1.1t", "pip/22.3.1"},
	"python:3.10.10": {"python/3.10.10", "openssl/1.1.1t", "pip/23.0.1"},
	"redis:6.2.10":   {"redis/6.2.10", "openssl/1.1.1t"},
	"redis:7.0.9":    {"redis/7.0.9", "openssl/3.0.8"},
	"mysql:8.0.31":   {"mysql/8.0.31", "openssl/1.1.1n"},
	"mysql:8.0.32":   {"mysql/8.0.32", "openssl/1.1.1t"},
	"openjdk:17.0.5": {"openjdk/17.0.5", "openssl/1.1.1s"},
	"openjdk:17.0.6": {"openjdk/17.0.6", "openssl/1.1.1t"},
	"golang:1.20.1":  {"golang/1.20.1", "openssl/3.0.7"},
	"golang:1.20.2":  {"golang/1.20.2", "openssl/3.0.8"},
	"httpd:2.4.55":   {"httpd/2.4.55", "openssl/1.1.1t"},
	"httpd:2.4.56":   {"httpd/2.4.56", "openssl/1.1.1t"},
}

// TrivyScanner simule un scanner Trivy
type TrivyScanner struct {
	config map[string]interface{}
	random *rand.Rand
}

// NewTrivyScanner crée un nouveau scanner Trivy simulé
func NewTrivyScanner() *TrivyScanner {
	return &TrivyScanner{
		config: make(map[string]interface{}),
		random: rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// Name retourne le nom du scanner
func (s *TrivyScanner) Name() string {
	return "Trivy"
}

// Description retourne une description du scanner
func (s *TrivyScanner) Description() string {
	return "Simulated Trivy vulnerability scanner for container images"
}

// SetConfig configure le scanner
func (s *TrivyScanner) SetConfig(config map[string]interface{}) error {
	s.config = config
	return nil
}

// Scan simule un scan Trivy
func (s *TrivyScanner) Scan(ctx context.Context, options ScanOptions) (*ScanResult, error) {
	startTime := time.Now()

	// Simuler un délai d'exécution réaliste
	scanDuration := time.Duration(500+s.random.Intn(1000)) * time.Millisecond
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
			"trivyVersion": "0.38.2",
		},
	}

	// Simuler les workloads à scanner (dans un vrai scénario, nous récupérerions cela de Kubernetes)
	workloads := simulateWorkloads(options)

	// Générer des résultats pour chaque workload
	for _, workload := range workloads {
		// Simuler les vulnérabilités pour cette image
		imageFindings := s.simulateImageVulnerabilities(workload.Image, workload.Name, workload.Namespace, workload.Type, options)
		result.Findings = append(result.Findings, imageFindings...)
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

// simulateImageVulnerabilities génère des vulnérabilités simulées pour une image
func (s *TrivyScanner) simulateImageVulnerabilities(image, workloadName, namespace, resourceType string, options ScanOptions) []VulnerabilityFinding {
	var findings []VulnerabilityFinding

	// Déterminer les composants dans cette image
	var components []string
	if knownComponents, ok := commonImages[image]; ok {
		components = knownComponents
	} else {
		// Pour les images inconnues, deviner les composants potentiels
		baseImage := strings.Split(image, ":")[0]
		version := "latest"
		if parts := strings.Split(image, ":"); len(parts) > 1 {
			version = parts[1]
		}

		// Ajouter le composant principal basé sur le nom de l'image
		components = append(components, fmt.Sprintf("%s/%s", baseImage, version))

		// Ajouter quelques composants communs
		components = append(components, "openssl/1.1.1t", "curl/7.81.0")
	}

	// Pour chaque composant, déterminer s'il est vulnérable
	for _, component := range components {
		parts := strings.Split(component, "/")
		if len(parts) != 2 {
			continue
		}

		componentName := parts[0]
		componentVersion := parts[1]

		// Chercher des vulnérabilités connues pour ce composant
		for _, vuln := range commonContainerVulnerabilities {
			if vuln.Component == componentName {
				// Déterminer si cette version est vulnérable (simulation simplifiée)
				isVulnerable := s.isVersionVulnerable(componentVersion, vuln.FixedIn)

				// Inclure un élément aléatoire pour la diversité
				if isVulnerable && s.random.Float32() < 0.7 { // 70% de chance d'inclure la vulnérabilité
					finding := VulnerabilityFinding{
						ID:                vuln.ID,
						Title:             vuln.Title,
						Description:       vuln.Description,
						Severity:          vuln.Severity,
						AffectedComponent: componentName,
						AffectedVersion:   componentVersion,
						FixedVersion:      vuln.FixedIn,
						ResourceID:        fmt.Sprintf("%s/%s", namespace, workloadName),
						ResourceType:      resourceType,
						Namespace:         namespace,
						WorkloadName:      workloadName,
						References:        vuln.References,
						ScannerName:       s.Name(),
						DetectedAt:        time.Now(),
						ExploitAvailable:  s.random.Float32() < 0.3, // 30% de chance d'avoir un exploit disponible
						Metadata: map[string]interface{}{
							"imageId": image,
						},
					}
					findings = append(findings, finding)
				}
			}
		}
	}

	return findings
}

// isVersionVulnerable détermine si une version est vulnérable en la comparant à la version fixée
func (s *TrivyScanner) isVersionVulnerable(currentVersion, fixedVersion string) bool {
	// Implémentation simplifiée pour la simulation
	// En réalité, nous utiliserions une comparaison sémantique de versions

	// Si les versions sont identiques, considérer comme non vulnérable
	if currentVersion == fixedVersion {
		return false
	}

	// Extraire les composants numériques des versions
	currentParts := strings.Split(currentVersion, ".")
	fixedParts := strings.Split(fixedVersion, ".")

	// Comparer les composants disponibles
	minLength := len(currentParts)
	if len(fixedParts) < minLength {
		minLength = len(fixedParts)
	}

	for i := 0; i < minLength; i++ {
		// Comparaison simpliste, ne gère pas les cas comme "1.10" vs "1.9"
		if currentParts[i] < fixedParts[i] {
			return true // Vulnérable si version actuelle < version fixée
		} else if currentParts[i] > fixedParts[i] {
			return false // Non vulnérable si version actuelle > version fixée
		}
	}

	// Si toutes les parties comparées sont égales, la vulnérabilité dépend de la longueur
	return len(currentParts) < len(fixedParts)
}

// Structure pour représenter un workload simulé
type simulatedWorkload struct {
	Name      string
	Namespace string
	Type      string
	Image     string
}

// simulateWorkloads génère une liste de workloads simulés
func simulateWorkloads(options ScanOptions) []simulatedWorkload {
	// Dans un vrai scénario, nous récupérerions cette information de Kubernetes
	defaultWorkloads := []simulatedWorkload{
		{Name: "frontend", Namespace: "default", Type: "Deployment", Image: "nginx:1.21.6"},
		{Name: "api", Namespace: "default", Type: "Deployment", Image: "node:16.19.1"},
		{Name: "database", Namespace: "default", Type: "StatefulSet", Image: "mysql:8.0.31"},
		{Name: "cache", Namespace: "default", Type: "Deployment", Image: "redis:6.2.10"},
		{Name: "auth", Namespace: "security", Type: "Deployment", Image: "openjdk:17.0.5"},
		{Name: "logger", Namespace: "monitoring", Type: "DaemonSet", Image: "golang:1.20.1"},
		{Name: "proxy", Namespace: "ingress", Type: "Deployment", Image: "httpd:2.4.55"},
		{Name: "analytics", Namespace: "data", Type: "Deployment", Image: "python:3.9.16"},
	}

	// Filtrer selon les options
	var filteredWorkloads []simulatedWorkload
	for _, w := range defaultWorkloads {
		// Filtrer par namespace inclus
		if len(options.IncludeNamespaces) > 0 {
			included := false
			for _, ns := range options.IncludeNamespaces {
				if w.Namespace == ns {
					included = true
					break
				}
			}
			if !included {
				continue
			}
		}

		// Filtrer par namespace exclus
		if len(options.ExcludeNamespaces) > 0 {
			excluded := false
			for _, ns := range options.ExcludeNamespaces {
				if w.Namespace == ns {
					excluded = true
					break
				}
			}
			if excluded {
				continue
			}
		}

		// Filtrer par workload inclus
		if len(options.IncludeWorkloads) > 0 {
			included := false
			for _, name := range options.IncludeWorkloads {
				if w.Name == name {
					included = true
					break
				}
			}
			if !included {
				continue
			}
		}

		// Filtrer par workload exclus
		if len(options.ExcludeWorkloads) > 0 {
			excluded := false
			for _, name := range options.ExcludeWorkloads {
				if w.Name == name {
					excluded = true
					break
				}
			}
			if excluded {
				continue
			}
		}

		filteredWorkloads = append(filteredWorkloads, w)
	}

	return filteredWorkloads
}

// isSeverityAtLeast vérifie si une sévérité est au moins aussi élevée qu'une autre
func isSeverityAtLeast(actual, minimum VulnerabilitySeverity) bool {
	severityRank := map[VulnerabilitySeverity]int{
		SeverityCritical: 4,
		SeverityHigh:     3,
		SeverityMedium:   2,
		SeverityLow:      1,
		SeverityUnknown:  0,
	}

	return severityRank[actual] >= severityRank[minimum]
}
