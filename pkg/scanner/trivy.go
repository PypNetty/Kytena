// pkg/scanner/trivy.go
package scanner

import (
	"context"
	"fmt"
	"math/rand"
	"os/exec"
	"strings"
	"time"

	"github.com/PypNetty/kytena/pkg/loggers"
	types "github.com/PypNetty/kytena/pkg/scanner/types"
)

// TrivyScanner est un scanner de vulnérabilités utilisant Trivy
type TrivyScanner struct {
	*BaseScanner
	binaryPath     string
	minSeverity    string
	cacheEnabled   bool
	cachePath      string
	timeoutSeconds int
}

func (s *TrivyScanner) Configure(m map[string]interface{}) error {
	return s.SetConfig(m)
}

// NewTrivyScanner crée un nouveau scanner Trivy
func NewTrivyScanner(logger loggers.Logger) *TrivyScanner {
	base := NewBaseScanner("Trivy", "Container vulnerability scanner", logger)

	return &TrivyScanner{
		BaseScanner:    base,
		binaryPath:     "trivy",
		minSeverity:    "MEDIUM",
		cacheEnabled:   true,
		cachePath:      ".trivy-cache",
		timeoutSeconds: 300,
	}
}

// SetConfig configure le scanner Trivy
func (s *TrivyScanner) SetConfig(config map[string]interface{}) error {
	// Extraire les configurations spécifiques à Trivy
	if path, ok := config["binaryPath"].(string); ok && path != "" {
		s.binaryPath = path
	}

	if severity, ok := config["minSeverity"].(string); ok && severity != "" {
		s.minSeverity = severity
	}

	if cacheEnabled, ok := config["cacheEnabled"].(bool); ok {
		s.cacheEnabled = cacheEnabled
	}

	if cachePath, ok := config["cachePath"].(string); ok && cachePath != "" {
		s.cachePath = cachePath
	}

	if timeout, ok := config["timeoutSeconds"].(int); ok && timeout > 0 {
		s.timeoutSeconds = timeout
	}

	if timeout, ok := config["timeout"].(time.Duration); ok && timeout > 0 {
		s.timeoutSeconds = int(timeout.Seconds())
	}

	// Vérifier que le binaire Trivy est accessible
	_, err := exec.LookPath(s.binaryPath)
	if err != nil {
		return fmt.Errorf("trivy binary not found at path %s: %w", s.binaryPath, err)
	}

	return nil
}

// Scan lance un scan Trivy
func (s *TrivyScanner) Scan(ctx context.Context, options types.ScanOptions) (*types.ScanResult, error) {
	startTime := time.Now()

	s.logger.Info("Starting Trivy scan")

	// Préparer le résultat du scan
	result := &types.ScanResult{
		ScannerName: s.Name(),
		StartTime:   startTime,
		Success:     false,
		Metadata: map[string]interface{}{
			"trivyVersion": s.getTrivyVersion(),
		},
	}

	// Récupérer les workloads à scanner
	workloads := s.getWorkloadsToScan(ctx, options)

	s.logger.Debugf("Found %d workloads to scan", len(workloads))

	// Exécuter un scan pour chaque workload
	for _, workload := range workloads {
		s.logger.Debugf("Scanning workload: %s/%s (%s)", workload.Namespace, workload.Name, workload.Type)

		// Récupérer le premier conteneur qui a une image
		var imageToScan string
		for _, container := range workload.Containers {
			if container.Image != "" {
				imageToScan = container.Image
				break
			}
		}

		// Si aucune image n'est trouvée, passer au workload suivant
		if imageToScan == "" {
			s.logger.Warnf("No image found for workload: %s/%s", workload.Namespace, workload.Name)
			continue
		}

		// Exécuter le scan sur l'image
		findings, err := s.scanImage(ctx, imageToScan, options)
		if err != nil {
			s.logger.Warnf("Error scanning image %s: %v", imageToScan, err)
			continue
		}

		// Ajouter les informations du workload aux findings
		for i := range findings {
			findings[i].ResourceType = string(workload.Type)
			findings[i].Namespace = workload.Namespace
			findings[i].WorkloadName = workload.Name
			findings[i].ResourceID = fmt.Sprintf("%s/%s", workload.Namespace, workload.Name)
		}

		result.Findings = append(result.Findings, findings...)
	}

	// Filtrer les findings selon la sévérité minimale
	result.Findings = s.FilterFindings(result.Findings, options.MinimumSeverity)

	// Limiter le nombre de findings
	result.Findings = s.LimitFindings(result.Findings, options.MaxFindings)

	result.Success = true
	result.EndTime = time.Now()

	s.logger.Info("Trivy scan completed in %s, found %d vulnerabilities", result.EndTime.Sub(result.StartTime), len(result.Findings))

	return result, nil
}

// getTrivyVersion récupère la version de Trivy
func (s *TrivyScanner) getTrivyVersion() string {
	cmd := exec.Command(s.binaryPath, "--version")
	out, err := cmd.Output()
	if err != nil {
		s.logger.Warnf("Failed to get Trivy version: %v", err)
		return "unknown"
	}

	version := strings.TrimSpace(string(out))
	if i := strings.Index(version, "Version:"); i >= 0 {
		version = strings.TrimSpace(version[i+8:])
		if j := strings.Index(version, "\n"); j >= 0 {
			version = version[:j]
		}
	}

	return version
}

// getWorkloadsToScan récupère les workloads à scanner
func (s *TrivyScanner) getWorkloadsToScan(ctx context.Context, options types.ScanOptions) []struct {
	Name       string
	Namespace  string
	Type       string
	Containers []struct {
		Name  string
		Image string
	}
} {
	// Dans une implémentation réelle, cette méthode récupérerait les workloads depuis Kubernetes
	// Pour cet exemple, nous simulons des workloads

	// Utiliser une liste de workloads de test pour la simulation
	return []struct {
		Name       string
		Namespace  string
		Type       string
		Containers []struct {
			Name  string
			Image string
		}
	}{
		{
			Name:      "frontend",
			Namespace: "default",
			Type:      "Deployment",
			Containers: []struct {
				Name  string
				Image string
			}{
				{
					Name:  "web",
					Image: "nginx:1.21.6",
				},
			},
		},
		{
			Name:      "api",
			Namespace: "default",
			Type:      "Deployment",
			Containers: []struct {
				Name  string
				Image string
			}{
				{
					Name:  "api",
					Image: "node:16.19.1",
				},
			},
		},
		{
			Name:      "database",
			Namespace: "default",
			Type:      "StatefulSet",
			Containers: []struct {
				Name  string
				Image string
			}{
				{
					Name:  "db",
					Image: "mysql:8.0.31",
				},
			},
		},
	}
}

// scanImage simule un scan Trivy sur une image
func (s *TrivyScanner) scanImage(ctx context.Context, image string, options types.ScanOptions) ([]types.VulnerabilityFinding, error) {
	// Pour cet exemple, nous simulons les résultats du scan
	// Dans une implémentation réelle, cette méthode exécuterait Trivy sur l'image

	// Simuler un délai pour le scan
	select {
	case <-time.After(time.Duration(200+rand.Intn(500)) * time.Millisecond):
		// Continuer l'exécution
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	// Simuler les résultats du scan
	var findings []types.VulnerabilityFinding

	// Adapter le nombre de vulnérabilités simulées en fonction de l'image
	numVulnerabilities := 2 + rand.Intn(8)

	// Images connues comme ayant des vulnérabilités
	if strings.Contains(image, "nginx:1.18") || strings.Contains(image, "node:14") || strings.Contains(image, "mysql:5.7") {
		numVulnerabilities += 5
	}

	// Générer des vulnérabilités simulées
	for i := 0; i < numVulnerabilities; i++ {
		severity := types.SeverityMedium

		// Distribuer les sévérités de manière aléatoire mais réaliste
		r := rand.Float64()
		if r < 0.1 {
			severity = types.SeverityCritical
		} else if r < 0.3 {
			severity = types.SeverityHigh
		} else if r < 0.7 {
			severity = types.SeverityMedium
		} else {
			severity = types.SeverityLow
		}

		// Construire un identifiant de vulnérabilité
		year := 2020 + rand.Intn(5)
		id := fmt.Sprintf("CVE-%d-%04d", year, 1000+rand.Intn(9000))

		// Construire un titre de vulnérabilité
		titles := []string{
			"Buffer overflow in %s",
			"Information disclosure in %s",
			"Privilege escalation in %s",
			"SQL injection in %s",
			"Cross-site scripting in %s",
			"Path traversal in %s",
			"Remote code execution in %s",
			"Denial of service in %s",
		}
		components := []string{
			"libssl",
			"openssl",
			"glibc",
			"libxml2",
			"zlib",
			"curl",
			"bash",
			"nginx",
			"nodejs",
			"mysql",
			"openldap",
		}
		title := fmt.Sprintf(titles[rand.Intn(len(titles))], components[rand.Intn(len(components))])

		// Créer la vulnérabilité
		finding := types.VulnerabilityFinding{
			ID:                id,
			Title:             title,
			Description:       fmt.Sprintf("This is a simulated vulnerability for %s", id),
			Severity:          severity,
			AffectedComponent: components[rand.Intn(len(components))],
			ScannerName:       s.Name(),
			DetectedAt:        time.Now(),
			ExploitAvailable:  rand.Float64() < 0.2, // 20% de chance d'avoir un exploit disponible
			References:        []string{fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", id)},
			Metadata: map[string]interface{}{
				"image":           image,
				"affectedVersion": fmt.Sprintf("%d.%d.%d", rand.Intn(10), rand.Intn(10), rand.Intn(10)),
				"fixedVersion":    fmt.Sprintf("%d.%d.%d", rand.Intn(10)+1, rand.Intn(10), rand.Intn(10)),
				"cvssScore":       2.0 + rand.Float64()*8.0, // Score CVSS entre 2 et 10
			},
		}

		findings = append(findings, finding)
	}

	return findings, nil
}
