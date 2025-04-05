package knownrisk

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Repository définit l'interface pour les opérations de persistance des KnownRisks
type Repository interface {
	// Save persiste un KnownRisk
	Save(kr *KnownRisk) error

	// Get récupère un KnownRisk par son ID
	Get(id string) (*KnownRisk, error)

	// List récupère tous les KnownRisks
	List() ([]*KnownRisk, error)

	// Update met à jour un KnownRisk existant
	Update(kr *KnownRisk) error

	// Delete supprime un KnownRisk
	Delete(id string) error
}

// FileRepository implémente Repository en utilisant des fichiers YAML
type FileRepository struct {
	// BasePath est le chemin de base où les fichiers seront stockés
	BasePath string
}

// NewFileRepository crée une nouvelle instance de FileRepository
func NewFileRepository(basePath string) (*FileRepository, error) {
	// Créer le répertoire s'il n'existe pas
	if err := os.MkdirAll(basePath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create directory %s: %w", basePath, err)
	}

	return &FileRepository{
		BasePath: basePath,
	}, nil
}

// getFilePath retourne le chemin complet du fichier pour un KnownRisk
func (r *FileRepository) getFilePath(id string) string {
	return filepath.Join(r.BasePath, fmt.Sprintf("%s.yaml", id))
}

// Save persiste un KnownRisk dans un fichier YAML
func (r *FileRepository) Save(kr *KnownRisk) error {
	// Valider le KnownRisk
	if err := kr.Validate(); err != nil {
		return fmt.Errorf("invalid KnownRisk: %w", err)
	}

	// Mettre à jour le statut avant de sauvegarder
	kr.UpdateStatus()

	// Sérialiser en YAML
	data, err := yaml.Marshal(kr)
	if err != nil {
		return fmt.Errorf("failed to marshal KnownRisk: %w", err)
	}

	// Écrire dans le fichier
	filePath := r.getFilePath(kr.ID)
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write file %s: %w", filePath, err)
	}

	return nil
}

// Get récupère un KnownRisk par son ID
func (r *FileRepository) Get(id string) (*KnownRisk, error) {
	filePath := r.getFilePath(id)

	// Vérifier si le fichier existe
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("KnownRisk with ID %s not found", id)
	}

	// Lire le contenu du fichier
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", filePath, err)
	}

	// Désérialiser le YAML
	var kr KnownRisk
	if err := yaml.Unmarshal(data, &kr); err != nil {
		return nil, fmt.Errorf("failed to unmarshal KnownRisk: %w", err)
	}

	// Mettre à jour le statut après chargement
	kr.UpdateStatus()

	return &kr, nil
}

// List récupère tous les KnownRisks
func (r *FileRepository) List() ([]*KnownRisk, error) {
	var knownRisks []*KnownRisk

	// Parcourir tous les fichiers YAML dans le répertoire
	entries, err := os.ReadDir(r.BasePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory %s: %w", r.BasePath, err)
	}

	for _, entry := range entries {
		// Ignorer les répertoires et les fichiers non-YAML
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}

		// Extraire l'ID du nom de fichier
		id := strings.TrimSuffix(entry.Name(), ".yaml")

		// Récupérer le KnownRisk
		kr, err := r.Get(id)
		if err != nil {
			// Log l'erreur mais continuer
			fmt.Printf("Warning: Failed to load KnownRisk %s: %v\n", id, err)
			continue
		}

		knownRisks = append(knownRisks, kr)
	}

	return knownRisks, nil
}

// Update met à jour un KnownRisk existant
func (r *FileRepository) Update(kr *KnownRisk) error {
	// Vérifier si le KnownRisk existe
	filePath := r.getFilePath(kr.ID)
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return fmt.Errorf("KnownRisk with ID %s not found", kr.ID)
	}

	// Sauvegarder le KnownRisk mis à jour
	return r.Save(kr)
}

// Delete supprime un KnownRisk
func (r *FileRepository) Delete(id string) error {
	filePath := r.getFilePath(id)

	// Vérifier si le fichier existe
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return fmt.Errorf("KnownRisk with ID %s not found", id)
	}

	// Supprimer le fichier
	if err := os.Remove(filePath); err != nil {
		return fmt.Errorf("failed to delete file %s: %w", filePath, err)
	}

	return nil
}
