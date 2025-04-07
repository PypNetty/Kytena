// internal/scanner/trivy_test.go
package scanner

import (
	"context"
	"os/exec"
	"testing"
	"time"
)

// TestTrivyScanner teste l'intégration basique avec Trivy
func TestTrivyScanner(t *testing.T) {
	// Vérifier si Trivy est installé
	trivyPath := "trivy"
	_, err := exec.LookPath(trivyPath)
	if err != nil {
		t.Skip("Trivy not found in PATH, skipping integration test")
	}

	// Créer un scanner Trivy
	trivyScanner := NewTrivyScanner()

	// Vérifier que le scanner respecte l'interface VulnerabilityScanner
	var _ VulnerabilityScanner = trivyScanner

	// Vérifier les valeurs par défaut
	if trivyScanner.binaryPath != "trivy" {
		t.Errorf("Expected default binary path to be 'trivy', got '%s'", trivyScanner.binaryPath)
	}

	if trivyScanner.minSeverity != "MEDIUM" {
		t.Errorf("Expected default min severity to be 'MEDIUM', got '%s'", trivyScanner.minSeverity)
	}

	if !trivyScanner.cacheEnabled {
		t.Errorf("Expected cache to be enabled by default")
	}
}

// Le test utilise le type simulatedWorkload défini dans trivy.go

// TestTrivyIntegration teste l'intégration complète avec Trivy
func TestTrivyIntegration(t *testing.T) {
	// Ignorer ce test dans les exécutions courtes
	if testing.Short() {
		t.Skip("Skipping Trivy integration test in short mode")
	}

	// Vérifier si Trivy est installé
	trivyPath := "trivy"
	_, err := exec.LookPath(trivyPath)
	if err != nil {
		t.Skip("Trivy not found in PATH, skipping integration test")
	}

	// Créer et configurer scanner Trivy
	trivyScanner := NewTrivyScanner()
	err = trivyScanner.SetConfig(map[string]interface{}{
		"binaryPath":     trivyPath,
		"minSeverity":    "HIGH",
		"cacheEnabled":   true,
		"cachePath":      ".trivy-test-cache",
		"timeoutSeconds": 60,
	})

	if err != nil {
		t.Fatalf("Failed to configure Trivy scanner: %v", err)
	}

	// Définir les options de scan pour tester avec une image vulnérable connue
	options := ScanOptions{
		MinimumSeverity: SeverityHigh,
		Timeout:         2 * time.Minute,
		ScannerSpecific: map[string]interface{}{
			"testImage": "nginx:1.18", // Une version avec des vulnérabilités connues
		},
	}

	// Créer une liste de workloads de test qui inclut l'image vulnérable
	testWorkloads := []simulatedWorkload{
		{
			Name:      "test-nginx",
			Namespace: "default",
			Type:      "Deployment",
			Image:     "nginx:1.18",
		},
	}

	// Sauvegarder la fonction originale si elle existe déjà
	oldSimulateWorkloads := testSimulateWorkloads

	// Remplacer temporairement la fonction testSimulateWorkloads
	testSimulateWorkloads = func(opts ScanOptions) []simulatedWorkload {
		return testWorkloads
	}

	// Restaurer la fonction originale à la fin du test
	defer func() {
		testSimulateWorkloads = oldSimulateWorkloads
	}()

	// Exécuter le scan
	ctx := context.Background()
	result, err := trivyScanner.Scan(ctx, options)
	if err != nil {
		t.Fatalf("Trivy scan failed: %v", err)
	}

	// Vérifier que le scan a réussi
	if !result.Success {
		t.Errorf("Expected scan to succeed")
	}

	// Vérifier que des résultats ont été trouvés
	if len(result.Findings) == 0 {
		t.Logf("No vulnerabilities found in nginx:1.18, which is unexpected")
		t.Logf("This could indicate an issue with the Trivy integration or the test image")
	} else {
		t.Logf("Found %d vulnerabilities in nginx:1.18", len(result.Findings))

		// Vérifier quelques propriétés des résultats
		for i, finding := range result.Findings[:min(5, len(result.Findings))] {
			t.Logf("Vulnerability %d: %s (%s)", i+1, finding.ID, finding.Severity)

			// Vérifier que les champs essentiels sont présents
			if finding.ID == "" {
				t.Errorf("Finding %d has empty ID", i+1)
			}
			if finding.Title == "" {
				t.Errorf("Finding %d has empty Title", i+1)
			}
			if finding.Severity == "" {
				t.Errorf("Finding %d has empty Severity", i+1)
			}
			if finding.WorkloadName != "test-nginx" {
				t.Errorf("Finding %d has incorrect WorkloadName: expected 'test-nginx', got '%s'",
					i+1, finding.WorkloadName)
			}
		}
	}
}

// min retourne le minimum de deux entiers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// testSimulateWorkloads est la version par défaut qui sera remplacée dans le test
var testSimulateWorkloads = func(options ScanOptions) []simulatedWorkload {
	return []simulatedWorkload{
		{Name: "frontend", Namespace: "default", Type: "Deployment", Image: "nginx:1.21.6"},
		{Name: "api", Namespace: "default", Type: "Deployment", Image: "node:16.19.1"},
		{Name: "database", Namespace: "default", Type: "StatefulSet", Image: "mysql:8.0.31"},
	}
}
