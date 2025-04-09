package common

import (
	"context"
	"fmt"

	"github.com/PypNetty/Kytena/pkg/models"
	"github.com/PypNetty/Kytena/pkg/storage"
)

// RepositoryWrapper provides a common interface for repository operations
type RepositoryWrapper struct {
	repo   storage.Repository
	logger Logger
}

// NewRepositoryWrapper creates a new repository wrapper
func NewRepositoryWrapper(dataDir string, logger Logger) (*RepositoryWrapper, error) {
	repo, err := storage.NewFileRepository(dataDir)
	if err != nil {
		return nil, fmt.Errorf("failed to create repository: %w", err)
	}

	return &RepositoryWrapper{
		repo:   repo,
		logger: logger,
	}, nil
}

// CreateKnownRisk creates a new KnownRisk
func (r *RepositoryWrapper) CreateKnownRisk(ctx context.Context, kr *models.KnownRisk) error {
	r.logger.Debug("Creating new KnownRisk: %s", kr.ID)
	return r.repo.CreateKnownRisk(ctx, kr)
}

// Get retrieves a KnownRisk by ID
func (r *RepositoryWrapper) Get(ctx context.Context, id string) (*models.KnownRisk, error) {
	r.logger.Debug("Retrieving KnownRisk: %s", id)
	return r.repo.Get(ctx, id)
}

// List retrieves all KnownRisks matching the given options
func (r *RepositoryWrapper) List(ctx context.Context, opts storage.ListOptions) ([]*models.KnownRisk, error) {
	r.logger.Debug("Listing KnownRisks with options: %+v", opts)
	return r.repo.List(ctx, opts)
}

// Update updates an existing KnownRisk
func (r *RepositoryWrapper) Update(ctx context.Context, kr *models.KnownRisk) error {
	r.logger.Debug("Updating KnownRisk: %s", kr.ID)
	return r.repo.Update(ctx, kr)
}

// Delete removes a KnownRisk by ID
func (r *RepositoryWrapper) Delete(ctx context.Context, id string) error {
	r.logger.Debug("Deleting KnownRisk: %s", id)
	return r.repo.Delete(ctx, id)
}

// GetByVulnerabilityID retrieves KnownRisks by vulnerability ID
func (r *RepositoryWrapper) GetByVulnerabilityID(ctx context.Context, vulnID string) ([]*models.KnownRisk, error) {
	r.logger.Debug("Retrieving KnownRisks for vulnerability: %s", vulnID)
	return r.repo.GetByVulnerabilityID(ctx, vulnID)
}

// GetByWorkload retrieves KnownRisks for a specific workload
func (r *RepositoryWrapper) GetByWorkload(ctx context.Context, namespace, name string) ([]*models.KnownRisk, error) {
	r.logger.Debug("Retrieving KnownRisks for workload: %s/%s", namespace, name)
	return r.repo.GetByWorkload(ctx, namespace, name)
}

// CountBySeverity counts KnownRisks by severity
func (r *RepositoryWrapper) CountBySeverity(ctx context.Context) (map[models.Severity]int, error) {
	r.logger.Debug("Counting KnownRisks by severity")
	return r.repo.CountBySeverity(ctx)
}

// CountByStatus counts KnownRisks by status
func (r *RepositoryWrapper) CountByStatus(ctx context.Context) (map[models.Status]int, error) {
	r.logger.Debug("Counting KnownRisks by status")
	return r.repo.CountByStatus(ctx)
}
