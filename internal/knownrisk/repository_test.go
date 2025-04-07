package knownrisk

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/PypNetty/Kytena/internal/workload"
)

// createTestRepository crée un repository temporaire pour les tests
func createTestRepository(t *testing.T) (*FileRepository, func()) {
	// Créer un répertoire temporaire
	tempDir := filepath.Join(os.TempDir(), "kyra-test-"+time.Now().Format("20060102150405"))

	repo, err := NewFileRepository(tempDir)
	if err != nil {
		t.Fatalf("Failed to create test repository: %v", err)
	}

	// Fonction de nettoyage
	cleanup := func() {
		os.RemoveAll(tempDir)
	}

	return repo, cleanup
}

// createTestKnownRisk crée un KnownRisk pour les tests
func createTestKnownRisk() *KnownRisk {
	w := workload.NewWorkload(
		"test-app",
		"default",
		workload.TypeDeployment,
		"nginx:1.19.0",
		5,
		map[string]string{},
		map[string]string{},
	)

	return NewKnownRisk(
		"CVE-2023-12345",
		*w,
		"Test justification",
		"security-team@example.com",
		time.Now(),                   // createdAt
		time.Now().Add(24*time.Hour), // expiresAt
		SeverityHigh,
	)
}

func TestFileRepositorySave(t *testing.T) {
	repo, cleanup := createTestRepository(t)
	defer cleanup()

	kr := createTestKnownRisk()

	// Sauvegarder le KnownRisk
	err := repo.Save(kr)
	if err != nil {
		t.Fatalf("Failed to save KnownRisk: %v", err)
	}

	// Vérifier que le fichier a été créé
	filePath := repo.getFilePath(kr.ID)
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		t.Errorf("Expected file %s to exist", filePath)
	}
}

func TestFileRepositoryGet(t *testing.T) {
	repo, cleanup := createTestRepository(t)
	defer cleanup()

	kr := createTestKnownRisk()

	// Sauvegarder le KnownRisk
	err := repo.Save(kr)
	if err != nil {
		t.Fatalf("Failed to save KnownRisk: %v", err)
	}

	// Récupérer le KnownRisk
	retrievedKR, err := repo.Get(kr.ID)
	if err != nil {
		t.Fatalf("Failed to get KnownRisk: %v", err)
	}

	// Vérifier les propriétés
	if retrievedKR.ID != kr.ID {
		t.Errorf("Expected ID to be %s, got %s", kr.ID, retrievedKR.ID)
	}

	if retrievedKR.VulnerabilityID != kr.VulnerabilityID {
		t.Errorf("Expected VulnerabilityID to be %s, got %s", kr.VulnerabilityID, retrievedKR.VulnerabilityID)
	}

	if retrievedKR.Justification != kr.Justification {
		t.Errorf("Expected Justification to be %s, got %s", kr.Justification, retrievedKR.Justification)
	}
}

func TestFileRepositoryList(t *testing.T) {
	repo, cleanup := createTestRepository(t)
	defer cleanup()

	// Créer et sauvegarder plusieurs KnownRisks
	kr1 := createTestKnownRisk()
	kr2 := createTestKnownRisk()

	if err := repo.Save(kr1); err != nil {
		t.Fatalf("Failed to save first KnownRisk: %v", err)
	}

	if err := repo.Save(kr2); err != nil {
		t.Fatalf("Failed to save second KnownRisk: %v", err)
	}

	// Récupérer la liste
	knownRisks, err := repo.List()
	if err != nil {
		t.Fatalf("Failed to list KnownRisks: %v", err)
	}

	// Vérifier qu'il y a bien 2 KnownRisks
	if len(knownRisks) != 2 {
		t.Errorf("Expected 2 KnownRisks, got %d", len(knownRisks))
	}
}

func TestFileRepositoryUpdate(t *testing.T) {
	repo, cleanup := createTestRepository(t)
	defer cleanup()

	kr := createTestKnownRisk()

	// Sauvegarder le KnownRisk
	if err := repo.Save(kr); err != nil {
		t.Fatalf("Failed to save KnownRisk: %v", err)
	}

	// Modifier le KnownRisk
	newJustification := "Updated justification"
	kr.Justification = newJustification

	// Mettre à jour
	if err := repo.Update(kr); err != nil {
		t.Fatalf("Failed to update KnownRisk: %v", err)
	}

	// Récupérer le KnownRisk mis à jour
	updatedKR, err := repo.Get(kr.ID)
	if err != nil {
		t.Fatalf("Failed to get updated KnownRisk: %v", err)
	}

	// Vérifier que la justification a été mise à jour
	if updatedKR.Justification != newJustification {
		t.Errorf("Expected Justification to be %s, got %s", newJustification, updatedKR.Justification)
	}
}

func TestFileRepositoryDelete(t *testing.T) {
	repo, cleanup := createTestRepository(t)
	defer cleanup()

	kr := createTestKnownRisk()

	// Sauvegarder le KnownRisk
	if err := repo.Save(kr); err != nil {
		t.Fatalf("Failed to save KnownRisk: %v", err)
	}

	// Supprimer le KnownRisk
	if err := repo.Delete(kr.ID); err != nil {
		t.Fatalf("Failed to delete KnownRisk: %v", err)
	}

	// Vérifier que le fichier n'existe plus
	filePath := repo.getFilePath(kr.ID)
	if _, err := os.Stat(filePath); !os.IsNotExist(err) {
		t.Errorf("Expected file %s to be deleted", filePath)
	}

	// Vérifier qu'une erreur est retournée lors de la récupération
	_, err := repo.Get(kr.ID)
	if err == nil {
		t.Errorf("Expected error when getting deleted KnownRisk, got none")
	}
}
