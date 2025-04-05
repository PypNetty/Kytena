package knownrisk

import (
	"fmt"

	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type Repository interface {
	Save(kr *KnownRisk) error
	Get(id string) (*KnownRisk, error)
	List() ([]*KnownRisk, error)
	Update(kr *KnownRisk) error
	Delete(id string) error
}

type FileRepository struct {
	BasePath string
}

// NewFileRepository creates a new FileRepository with the specified base path
func NewFileRepository(basePath string) (*FileRepository, error) {
	if err := os.MkdirAll(basePath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create directory %s: %w", basePath, err)
	}

	return &FileRepository{
		BasePath: basePath,
	}, nil
}

// gelFIlePath return complete file for KnownRisk
func (r *FileRepository) getFilePath(id string) string {
	return filepath.Join(r.BasePath, fmt.Sprintf("%s.yaml", id))
}

// Save saves a KnownRisk to a file YAML
func (r *FileRepository) Save(kr *KnownRisk) error {
	if err := kr.Validate(); err != nil {
		return fmt.Errorf("invalid KnownRisk: %w", err)
	}

	kr.UpdateStatus()

	data, err := yaml.Marshal(kr)
	if err != nil {
		return fmt.Errorf("failed to marshal KnownRisk: %w", err)
	}

	filePath := r.getFilePath(kr.ID)
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write file %s: %w", filePath, err)
	}
	return nil
}

// Get retrieves a KnownRisk by its ID
func (r *FileRepository) Get(id string) (*KnownRisk, error) {
	filePath := r.getFilePath(id)

	// Verify if the file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("KnownRisk with ID %s not found", id)
	}

	// Read the file
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", filePath, err)
	}

	//Deserialize the YAML data
	var kr KnownRisk
	if err := yaml.Unmarshal(data, &kr); err != nil {
		return nil, fmt.Errorf("failed to unmasharl KnownRisk: %w", err)
	}

	// Update the status of the KnownRisk
	kr.UpdateStatus()
	return &kr, nil
}

// List retrieves all KnownRisks
func (r *FileRepository) List() ([]*KnownRisk, error) {
	var knownRisks []*KnownRisk

	// Browse always the yaml files in directory
	entries, err := os.ReadDir(r.BasePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory %s: %w", r.BasePath, err)
	}

	for _, entry := range entries {
		// Ignore non-YAML files and directories
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}

		//Extract the ID from the file name
		id := strings.TrimSuffix(entry.Name(), ".yaml")

		// Retrieve the KnownRisk
		kr, err := r.Get(id)
		if err != nil {
			fmt.Printf("Warning: Failed to load KnownRisk %s: %v\n", id, err)
			continue
		}

		knownRisks = append(knownRisks, kr)
	}

	return knownRisks, nil
}

// Update updates an existing KnownRisk
func (r *FileRepository) Update(kr *KnownRisk) error {
	// verify if the KnownRisk exists
	filePath := r.getFilePath(kr.ID)
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return fmt.Errorf("KnownRisk with ID %s not found", kr.ID)
	}

	// Save the updated KnownRisk
	return r.Save(kr)
}

// Delete deletes a KnownRisk by its ID
func (r *FileRepository) Delete(id string) error {
	filePath := r.getFilePath(id)

	// Verify if the file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return fmt.Errorf("KnownRisk with ID %s not found", id)
	}

	// Delete the file
	if err := os.Remove(filePath); err != nil {
		return fmt.Errorf("failed to delete file %s: %w", filePath, err)
	}
	return nil
}
