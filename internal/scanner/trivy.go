package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

// TrivyScanner implémente VulnerabilityScanner pour l'outil Trivy
type TrivyScanner struct {
	binaryPath   string
	timeout      time.Duration
	minSeverity  string
	cacheEnabled bool
	cachePath    string
	extraArgs    []string
}

// TrivyResult représente les résultats d'un scan Trivy
type TrivyResult struct {
	SchemaVersion int    `json:"SchemaVersion"`
	ArtifactName  string `json:"ArtifactName"`
	ArtifactType  string `json:"ArtifactType"`
	Metadata      struct {
		OS struct {
			Family string `json:"Family"`
			Name   string `json:"Name"`
		} `json:"OS"`
		ImageID     string   `json:"ImageID"`
		DiffIDs     []string `json:"DiffIDs"`
		RepoTags    []string `json:"RepoTags"`
		RepoDigests []string `json:"RepoDigests"`
	} `json:"Metadata"`
	Results []struct {
		Target          string `json:"Target"`
		Class           string `json:"Class"`
		Type            string `json:"Type"`
		Vulnerabilities []struct {
			VulnerabilityID  string   `json:"VulnerabilityID"`
			PkgName          string   `json:"PkgName"`
			InstalledVersion string   `json:"InstalledVersion"`
			FixedVersion     string   `json:"FixedVersion"`
			Title            string   `json:"Title"`
			Description      string   `json:"Description"`
			Severity         string   `json:"Severity"`
			References       []string `json:"References"`
			CVSS             struct {
				V3Vector string  `json:"V3Vector"`
				V3Score  float64 `json:"V3Score"`
			} `json:"CVSS"`
			CweIDs           []string `json:"CweIDs"`
			PublishedDate    string   `json:"PublishedDate,omitempty"`
			LastModifiedDate string   `json:"LastModifiedDate,omitempty"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

// NewTrivyScanner crée une nouvelle instance du scanner Trivy
func NewTrivyScanner() *TrivyScanner {
	return &TrivyScanner{
		binaryPath:   "trivy", // Chemin par défaut, peut être modifié par SetConfig
		timeout:      5 * time.Minute,
		minSeverity:  "MEDIUM",
		cacheEnabled: true,
		cachePath:    ".trivy-cache",
	}
}

// Name retourne le nom du scanner
func (s *TrivyScanner) Name() string {
	return "Trivy"
}

// Description retourne une description du scanner
func (s *TrivyScanner) Description() string {
	return "Trivy vulnerability scanner for container images"
}

// SetConfig configure le scanner
func (s *TrivyScanner) SetConfig(config map[string]interface{}) error {
	// Mettre à jour la configuration avec les valeurs fournies
	if path, ok := config["binaryPath"].(string); ok && path != "" {
		s.binaryPath = path
	}

	if timeout, ok := config["timeout"].(time.Duration); ok {
		s.timeout = timeout
	} else if timeoutSec, ok := config["timeoutSeconds"].(int); ok {
		s.timeout = time.Duration(timeoutSec) * time.Second
	}

	if severity, ok := config["minSeverity"].(string); ok {
		s.minSeverity = severity
	}

	if cache, ok := config["cacheEnabled"].(bool); ok {
		s.cacheEnabled = cache
	}

	if path, ok := config["cachePath"].(string); ok && path != "" {
		s.cachePath = path
	}

	if args, ok := config["extraArgs"].([]string); ok {
		s.extraArgs = args
	}

	// Vérifier que le binaire existe
	_, err := exec.LookPath(s.binaryPath)
	if err != nil {
		return fmt.Errorf("trivy binary not found at %s: %w", s.binaryPath, err)
	}

	return nil
}

// Scan exécute un scan avec Trivy
func (s *TrivyScanner) Scan(ctx context.Context, options ScanOptions) (*ScanResult, error) {
	startTime := time.Now()

	// Préparer le résultat
	result := &ScanResult{
		ScannerName: s.Name(),
		StartTime:   startTime,
		Findings:    []VulnerabilityFinding{},
		Success:     true,
		Metadata:    map[string]interface{}{},
	}

	// Vérifier la version de Trivy
	trivyVersion, err := s.checkTrivyVersion()
	if err != nil {
		log.Warnf("Failed to check Trivy version: %v", err)
		// Continuer quand même, ce n'est pas critique
	} else {
		log.Infof("Using Trivy version: %s", trivyVersion)
		result.Metadata["trivyVersion"] = trivyVersion
	}

	// Mettre à jour la base de données Trivy si demandé
	if updateDB, ok := options.ScannerSpecific["updateDB"].(bool); ok && updateDB {
		if err := s.updateTrivyDB(ctx); err != nil {
			log.Warnf("Failed to update Trivy database: %v", err)
			// Continuer quand même, utilisera la base de données existante
		}
	}

	// Pour l'instant, nous utilisons encore la fonction simulée
	// À remplacer par une vraie récupération des workloads depuis Kubernetes
	workloads := simulateWorkloads(options)

	log.Infof("Found %d workloads to scan", len(workloads))

	// Scanner chaque workload
	for _, workload := range workloads {
		log.Infof("Scanning workload %s/%s (%s)", workload.Namespace, workload.Name, workload.Type)

		// Vérifier si l'image est scanneable
		if workload.Image == "" {
			log.Warnf("Workload %s/%s has no image specified, skipping", workload.Namespace, workload.Name)
			continue
		}

		// Scanner l'image
		imageFindings, err := s.scanImage(ctx, workload.Image, workload, options)
		if err != nil {
			log.Warnf("Error scanning image %s for workload %s/%s: %v",
				workload.Image, workload.Namespace, workload.Name, err)
			continue
		}

		result.Findings = append(result.Findings, imageFindings...)
	}

	// Filtrer les résultats selon les options
	if len(result.Findings) > 0 {
		// Filtrer par sévérité minimale
		if options.MinimumSeverity != "" {
			var filteredFindings []VulnerabilityFinding
			for _, finding := range result.Findings {
				if isSeverityAtLeast(finding.Severity, options.MinimumSeverity) {
					filteredFindings = append(filteredFindings, finding)
				}
			}

			log.Infof("Filtered %d/%d findings by minimum severity %s",
				len(filteredFindings), len(result.Findings), options.MinimumSeverity)
			result.Findings = filteredFindings
		}

		// Limiter le nombre de résultats
		if options.MaxFindings > 0 && len(result.Findings) > options.MaxFindings {
			log.Infof("Limiting results to %d (from %d total findings)",
				options.MaxFindings, len(result.Findings))
			result.Findings = result.Findings[:options.MaxFindings]
		}
	}

	result.EndTime = time.Now()
	scanDuration := result.EndTime.Sub(result.StartTime)
	log.Infof("Trivy scan completed in %s, found %d vulnerabilities",
		scanDuration, len(result.Findings))

	return result, nil
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

	actualRank, ok1 := severityRank[actual]
	minimumRank, ok2 := severityRank[minimum]

	if !ok1 || !ok2 {
		// Si une des sévérités n'est pas reconnue, considérer qu'elle est inférieure
		return false
	}

	return actualRank >= minimumRank
}

// simulateWorkloads génère une liste de workloads simulés pour les tests
func simulateWorkloads(options ScanOptions) []simulatedWorkload {
	// Liste de workloads par défaut pour les tests
	defaultWorkloads := []simulatedWorkload{
		{Name: "frontend", Namespace: "default", Type: "Deployment", Image: "nginx:1.21.6"},
		{Name: "api", Namespace: "default", Type: "Deployment", Image: "node:16.19.1"},
		{Name: "database", Namespace: "default", Type: "StatefulSet", Image: "mysql:8.0.31"},
		{Name: "cache", Namespace: "default", Type: "Deployment", Image: "redis:6.2.10"},
		{Name: "auth", Namespace: "security", Type: "Deployment", Image: "openjdk:17.0.5"},
	}

	// Si une image de test est spécifiée dans les options, l'utiliser
	if testImage, ok := options.ScannerSpecific["testImage"].(string); ok && testImage != "" {
		return []simulatedWorkload{
			{Name: "test-workload", Namespace: "test", Type: "Deployment", Image: testImage},
		}
	}

	// Filtrer les workloads selon les options
	var result []simulatedWorkload
	for _, wl := range defaultWorkloads {
		// Filtrer par namespace si spécifié
		if len(options.IncludeNamespaces) > 0 {
			included := false
			for _, ns := range options.IncludeNamespaces {
				if wl.Namespace == ns {
					included = true
					break
				}
			}
			if !included {
				continue
			}
		}

		// Filtrer par namespace exclu
		if len(options.ExcludeNamespaces) > 0 {
			excluded := false
			for _, ns := range options.ExcludeNamespaces {
				if wl.Namespace == ns {
					excluded = true
					break
				}
			}
			if excluded {
				continue
			}
		}

		// Filtrer par workload si spécifié
		if len(options.IncludeWorkloads) > 0 {
			included := false
			for _, name := range options.IncludeWorkloads {
				if wl.Name == name {
					included = true
					break
				}
			}
			if !included {
				continue
			}
		}

		// Filtrer par workload exclu
		if len(options.ExcludeWorkloads) > 0 {
			excluded := false
			for _, name := range options.ExcludeWorkloads {
				if wl.Name == name {
					excluded = true
					break
				}
			}
			if excluded {
				continue
			}
		}

		result = append(result, wl)
	}

	return result
}

type simulatedWorkload struct {
	Name      string
	Namespace string
	Type      string
	Image     string
}

func (s *TrivyScanner) scanImage(ctx context.Context, image string, workload simulatedWorkload, _ ScanOptions) ([]VulnerabilityFinding, error) {
	log.Infof("Scanning image %s with Trivy", image)

	// Créer un contexte avec timeout
	ctxWithTimeout, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	// Préparer les arguments pour Trivy
	args := []string{
		"image",
		"--format", "json",
		"--quiet",
	}

	// Ajouter la sévérité minimale si spécifiée
	if s.minSeverity != "" {
		args = append(args, "--severity", s.minSeverity)
	}

	// Configurer le cache
	if s.cacheEnabled {
		args = append(args, "--cache-dir", s.cachePath)
	} else {
		args = append(args, "--no-cache")
	}

	// Ajouter les arguments supplémentaires
	if len(s.extraArgs) > 0 {
		args = append(args, s.extraArgs...)
	}

	// Ajouter l'image à scanner
	args = append(args, image)

	log.Debugf("Running Trivy command: %s %s", s.binaryPath, strings.Join(args, " "))

	// Exécuter la commande Trivy
	cmd := exec.CommandContext(ctxWithTimeout, s.binaryPath, args...)

	// Récupérer la sortie
	output, err := cmd.Output()
	if err != nil {
		// Vérifier si le contexte a expiré
		if ctxWithTimeout.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("trivy scan timed out for image %s", image)
		}

		// Si l'erreur est due à des vulnérabilités trouvées (code de sortie 1),
		// nous voulons quand même traiter la sortie
		if strings.Contains(err.Error(), "exit status 1") {
			// C'est normal, Trivy retourne 1 quand des vulnérabilités sont trouvées
			log.Debugf("Trivy found vulnerabilities in image %s", image)
		} else if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("trivy scan failed: %v, stderr: %s", err, string(exitErr.Stderr))
		} else {
			return nil, fmt.Errorf("trivy scan failed: %v", err)
		}
	}

	// Vérifier si la sortie est vide
	if len(output) == 0 {
		log.Warnf("Trivy returned empty output for image %s", image)
		return nil, nil
	}

	// Parser la sortie JSON
	var trivyResult TrivyResult
	err = json.Unmarshal(output, &trivyResult)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Trivy output: %w", err)
	}

	// Convertir les résultats Trivy en VulnerabilityFindings
	var findings []VulnerabilityFinding

	for _, result := range trivyResult.Results {
		if result.Vulnerabilities == nil {
			continue
		}

		for _, vuln := range result.Vulnerabilities {
			// Mapper la sévérité
			severity := MapSeverity(vuln.Severity)

			// Créer un VulnerabilityFinding
			finding := VulnerabilityFinding{
				ID:                vuln.VulnerabilityID,
				Title:             vuln.Title,
				Description:       vuln.Description,
				Severity:          severity,
				AffectedComponent: fmt.Sprintf("%s:%s", vuln.PkgName, vuln.InstalledVersion),
				AffectedVersion:   vuln.InstalledVersion,
				FixedVersion:      vuln.FixedVersion,
				ResourceID:        fmt.Sprintf("%s/%s", workload.Namespace, workload.Name),
				ResourceType:      workload.Type,
				Namespace:         workload.Namespace,
				WorkloadName:      workload.Name,
				References:        vuln.References,
				ScannerName:       s.Name(),
				DetectedAt:        time.Now(),
				// Supposer qu'un exploit est disponible pour les vulnérabilités critiques
				// Dans une implémentation réelle, cela devrait être déterminé par d'autres moyens
				ExploitAvailable: severity == SeverityCritical,
				Metadata: map[string]interface{}{
					"imageId":    image,
					"cvssScore":  vuln.CVSS.V3Score,
					"cvssVector": vuln.CVSS.V3Vector,
					"target":     result.Target,
					"cweIDs":     vuln.CweIDs,
				},
			}

			if vuln.PublishedDate != "" {
				finding.Metadata["publishedDate"] = vuln.PublishedDate
			}

			if vuln.LastModifiedDate != "" {
				finding.Metadata["lastModifiedDate"] = vuln.LastModifiedDate
			}

			findings = append(findings, finding)
		}
	}

	log.Infof("Trivy found %d vulnerabilities in image %s", len(findings), image)
	return findings, nil
}

// checkTrivyVersion vérifie la version de Trivy installée
func (s *TrivyScanner) checkTrivyVersion() (string, error) {
	cmd := exec.Command(s.binaryPath, "--version")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get Trivy version: %w", err)
	}

	// Extraire la version de la sortie
	versionOutput := string(output)
	// La sortie est généralement de la forme "Version: X.Y.Z"
	versionParts := strings.Split(versionOutput, "Version: ")
	if len(versionParts) < 2 {
		return "", fmt.Errorf("unexpected Trivy version output format")
	}

	version := strings.TrimSpace(versionParts[1])
	return version, nil
}

// updateTrivyDB met à jour la base de données de vulnérabilités Trivy
func (s *TrivyScanner) updateTrivyDB(ctx context.Context) error {
	log.Info("Updating Trivy vulnerability database...")

	cmd := exec.CommandContext(ctx, s.binaryPath, "image", "--download-db-only")
	if s.cacheEnabled && s.cachePath != "" {
		cmd.Args = append(cmd.Args, "--cache-dir", s.cachePath)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to update Trivy DB: %w, output: %s", err, string(output))
	}

	log.Info("Trivy vulnerability database updated successfully")
	return nil
}
