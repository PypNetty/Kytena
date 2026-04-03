// pkg/storage/repository.go
package storage

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/PypNetty/kytena/pkg/models"
)

// Filter définit les options de filtrage pour les recherches
type Filter struct {
	Status       string
	Severity     string
	Workload     string
	Namespace    string
	Tags         []string
	ExpiryBefore *time.Time
	ExpiryAfter  *time.Time
}

// SortOptions définit les options de tri pour les résultats
type SortOptions struct {
	Field     string
	Direction string // "asc" ou "desc"
}

// ListOptions définit les options pour lister les éléments
type ListOptions struct {
	Filter Filter
	Sort   SortOptions
	Limit  int
	Offset int
}

// Repository définit l'interface pour les opérations de persistance des KnownRisks
type Repository interface {
	// Save persiste un KnownRisk
	Save(ctx context.Context, kr *models.KnownRisk) error

	// Get récupère un KnownRisk par son ID
	Get(ctx context.Context, id string) (*models.KnownRisk, error)

	// List récupère tous les KnownRisks avec des options de filtrage et de tri
	List(ctx context.Context, options ListOptions) ([]*models.KnownRisk, error)

	// Update met à jour un KnownRisk existant
	Update(ctx context.Context, kr *models.KnownRisk) error

	// Delete supprime un KnownRisk
	Delete(ctx context.Context, id string) error

	// GetByVulnerabilityID recherche les KnownRisks par ID de vulnérabilité
	GetByVulnerabilityID(ctx context.Context, vulnerabilityID string) ([]*models.KnownRisk, error)

	// GetByWorkload recherche les KnownRisks par workload
	GetByWorkload(ctx context.Context, namespace, name string) ([]*models.KnownRisk, error)

	// CountByStatus compte les KnownRisks par statut
	CountByStatus(ctx context.Context) (map[models.Status]int, error)

	// CountBySeverity compte les KnownRisks par sévérité
	CountBySeverity(ctx context.Context) (map[models.Severity]int, error)
}

// FileRepository implémente Repository en utilisant des fichiers YAML
type FileRepository struct {
	// BasePath est le chemin de base où les fichiers seront stockés
	BasePath string
	// CacheEnabled indique si le cache est activé
	CacheEnabled bool
	// Cache est un cache en mémoire des KnownRisks
	cache map[string]*models.KnownRisk
	// lastUpdate est la dernière mise à jour du cache
	lastUpdate time.Time
	// cacheTTL est la durée de vie du cache
	cacheTTL time.Duration
}

func (f *FileRepository) storageFilePath() string {
	return filepath.Join(f.BasePath, "knownrisks.json")
}

func (f *FileRepository) ensureLoaded() error {
	if f.cache == nil {
		f.cache = make(map[string]*models.KnownRisk)
	}

	if len(f.cache) > 0 {
		return nil
	}

	if err := os.MkdirAll(f.BasePath, 0755); err != nil {
		return err
	}

	data, err := os.ReadFile(f.storageFilePath())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}

	if len(data) == 0 {
		return nil
	}

	var risks []*models.KnownRisk
	if err := json.Unmarshal(data, &risks); err != nil {
		return err
	}

	for _, kr := range risks {
		if kr != nil {
			f.cache[kr.ID] = kr
		}
	}

	return nil
}

func (f *FileRepository) persist() error {
	if err := os.MkdirAll(f.BasePath, 0755); err != nil {
		return err
	}

	risks := make([]*models.KnownRisk, 0, len(f.cache))
	for _, kr := range f.cache {
		risks = append(risks, kr)
	}

	data, err := json.MarshalIndent(risks, "", "  ")
	if err != nil {
		return err
	}

	tmp := f.storageFilePath() + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}

	return os.Rename(tmp, f.storageFilePath())
}

func (f *FileRepository) List(ctx context.Context, options ListOptions) ([]*models.KnownRisk, error) {
	if err := f.ensureLoaded(); err != nil {
		return nil, err
	}

	result := make([]*models.KnownRisk, 0, len(f.cache))
	for _, kr := range f.cache {
		if options.Filter.Status != "" && !strings.EqualFold(string(kr.Status), options.Filter.Status) {
			continue
		}
		if options.Filter.Severity != "" && !strings.EqualFold(string(kr.Severity), options.Filter.Severity) {
			continue
		}
		if options.Filter.Namespace != "" && !strings.EqualFold(kr.WorkloadInfo.Namespace, options.Filter.Namespace) {
			continue
		}
		if options.Filter.Workload != "" && !strings.Contains(strings.ToLower(kr.WorkloadInfo.Name), strings.ToLower(options.Filter.Workload)) {
			continue
		}

		if options.Filter.ExpiryBefore != nil && !kr.ExpiresAt.Before(*options.Filter.ExpiryBefore) {
			continue
		}
		if options.Filter.ExpiryAfter != nil && !kr.ExpiresAt.After(*options.Filter.ExpiryAfter) {
			continue
		}

		if len(options.Filter.Tags) > 0 {
			hasAllTags := true
			for _, want := range options.Filter.Tags {
				found := false
				for _, tag := range kr.Tags {
					if strings.EqualFold(tag, want) {
						found = true
						break
					}
				}
				if !found {
					hasAllTags = false
					break
				}
			}
			if !hasAllTags {
				continue
			}
		}

		result = append(result, kr)
	}

	sort.Slice(result, func(i, j int) bool {
		desc := strings.EqualFold(options.Sort.Direction, "desc")
		switch strings.ToLower(options.Sort.Field) {
		case "severity":
			li := models.GetSeverityPriority(result[i].Severity)
			lj := models.GetSeverityPriority(result[j].Severity)
			if desc {
				return li > lj
			}
			return li < lj
		case "workload":
			li := result[i].WorkloadInfo.FormattedName()
			lj := result[j].WorkloadInfo.FormattedName()
			if desc {
				return li > lj
			}
			return li < lj
		case "expiry":
			fallthrough
		default:
			if desc {
				return result[i].ExpiresAt.After(result[j].ExpiresAt)
			}
			return result[i].ExpiresAt.Before(result[j].ExpiresAt)
		}
	})

	if options.Offset > 0 {
		if options.Offset >= len(result) {
			result = []*models.KnownRisk{}
		} else {
			result = result[options.Offset:]
		}
	}

	if options.Limit > 0 && len(result) > options.Limit {
		result = result[:options.Limit]
	}

	_ = ctx
	return result, nil
}

// NewFileRepository crée une nouvelle instance de FileRepository
func NewFileRepository(basePath string, options ...FileRepositoryOption) (*FileRepository, error) {
	repo := &FileRepository{
		BasePath:     basePath,
		CacheEnabled: false,
		cache:        make(map[string]*models.KnownRisk),
		cacheTTL:     5 * time.Minute,
	}

	// Appliquer les options
	for _, option := range options {
		option(repo)
	}

	return repo, nil
}

// FileRepositoryOption définit une option pour la configuration du FileRepository
type FileRepositoryOption func(*FileRepository)

// WithCache active le cache avec une durée de vie spécifiée
func WithCache(ttl time.Duration) FileRepositoryOption {
	return func(r *FileRepository) {
		r.CacheEnabled = true
		r.cacheTTL = ttl
	}
}

// Save persiste un KnownRisk
func (f *FileRepository) Save(ctx context.Context, kr *models.KnownRisk) error {
	if err := f.ensureLoaded(); err != nil {
		return err
	}

	if err := kr.Validate(); err != nil {
		return err
	}
	f.cache[kr.ID] = kr
	f.lastUpdate = time.Now()
	if err := f.persist(); err != nil {
		return err
	}
	_ = ctx
	return nil
}

// Get récupère un KnownRisk par son ID
func (f *FileRepository) Get(ctx context.Context, id string) (*models.KnownRisk, error) {
	if err := f.ensureLoaded(); err != nil {
		return nil, err
	}

	kr, exists := f.cache[id]
	if !exists {
		return nil, ErrNotFound
	}
	_ = ctx
	return kr, nil
}

// Update met à jour un KnownRisk existant
func (f *FileRepository) Update(ctx context.Context, kr *models.KnownRisk) error {
	if err := f.ensureLoaded(); err != nil {
		return err
	}

	if _, exists := f.cache[kr.ID]; !exists {
		return ErrNotFound
	}
	f.cache[kr.ID] = kr
	f.lastUpdate = time.Now()
	if err := f.persist(); err != nil {
		return err
	}
	_ = ctx
	return nil
}

// Delete supprime un KnownRisk
func (f *FileRepository) Delete(ctx context.Context, id string) error {
	if err := f.ensureLoaded(); err != nil {
		return err
	}

	if _, exists := f.cache[id]; !exists {
		return ErrNotFound
	}
	delete(f.cache, id)
	f.lastUpdate = time.Now()
	if err := f.persist(); err != nil {
		return err
	}
	_ = ctx
	return nil
}

// GetByVulnerabilityID recherche les KnownRisks par ID de vulnérabilité
func (f *FileRepository) GetByVulnerabilityID(ctx context.Context, vulnerabilityID string) ([]*models.KnownRisk, error) {
	if err := f.ensureLoaded(); err != nil {
		return nil, err
	}

	var result []*models.KnownRisk
	for _, kr := range f.cache {
		if kr.VulnerabilityID == vulnerabilityID {
			result = append(result, kr)
		}
	}
	_ = ctx
	return result, nil
}

// GetByWorkload recherche les KnownRisks par workload
func (f *FileRepository) GetByWorkload(ctx context.Context, namespace, name string) ([]*models.KnownRisk, error) {
	if err := f.ensureLoaded(); err != nil {
		return nil, err
	}

	var result []*models.KnownRisk
	for _, kr := range f.cache {
		if kr.WorkloadInfo.Namespace == namespace && kr.WorkloadInfo.Name == name {
			result = append(result, kr)
		}
	}
	_ = ctx
	return result, nil
}

// CountByStatus compte les KnownRisks par statut
func (f *FileRepository) CountByStatus(ctx context.Context) (map[models.Status]int, error) {
	if err := f.ensureLoaded(); err != nil {
		return nil, err
	}

	counts := make(map[models.Status]int)
	for _, kr := range f.cache {
		counts[kr.Status]++
	}
	_ = ctx
	return counts, nil
}

// CountBySeverity compte les KnownRisks par sévérité
func (f *FileRepository) CountBySeverity(ctx context.Context) (map[models.Severity]int, error) {
	if err := f.ensureLoaded(); err != nil {
		return nil, err
	}

	counts := make(map[models.Severity]int)
	for _, kr := range f.cache {
		counts[kr.Severity]++
	}
	_ = ctx
	return counts, nil
}

// InMemoryRepository implémente Repository avec un stockage en mémoire (utile pour les tests)
type InMemoryRepository struct {
	data map[string]*models.KnownRisk
}

// NewInMemoryRepository crée un nouveau repository en mémoire
func NewInMemoryRepository() *InMemoryRepository {
	return &InMemoryRepository{
		data: make(map[string]*models.KnownRisk),
	}
}

// Save enregistre un KnownRisk en mémoire
func (r *InMemoryRepository) Save(ctx context.Context, kr *models.KnownRisk) error {
	if err := kr.Validate(); err != nil {
		return err
	}
	r.data[kr.ID] = kr
	return nil
}

// Get récupère un KnownRisk par son ID
func (r *InMemoryRepository) Get(ctx context.Context, id string) (*models.KnownRisk, error) {
	kr, exists := r.data[id]
	if !exists {
		return nil, ErrNotFound
	}
	return kr, nil
}

// List retourne tous les KnownRisks
func (r *InMemoryRepository) List(ctx context.Context, options ListOptions) ([]*models.KnownRisk, error) {
	result := make([]*models.KnownRisk, 0, len(r.data))

	// Appliquer les filtres et tri ici
	// Pour simplifier, je retourne simplement tous les éléments
	for _, kr := range r.data {
		result = append(result, kr)
	}

	return result, nil
}

// Update met à jour un KnownRisk existant
func (r *InMemoryRepository) Update(ctx context.Context, kr *models.KnownRisk) error {
	if _, exists := r.data[kr.ID]; !exists {
		return ErrNotFound
	}
	r.data[kr.ID] = kr
	return nil
}

// Delete supprime un KnownRisk
func (r *InMemoryRepository) Delete(ctx context.Context, id string) error {
	if _, exists := r.data[id]; !exists {
		return ErrNotFound
	}
	delete(r.data, id)
	return nil
}

// GetByVulnerabilityID recherche les KnownRisks par ID de vulnérabilité
func (r *InMemoryRepository) GetByVulnerabilityID(ctx context.Context, vulnerabilityID string) ([]*models.KnownRisk, error) {
	var result []*models.KnownRisk
	for _, kr := range r.data {
		if kr.VulnerabilityID == vulnerabilityID {
			result = append(result, kr)
		}
	}
	return result, nil
}

// GetByWorkload recherche les KnownRisks par workload
func (r *InMemoryRepository) GetByWorkload(ctx context.Context, namespace, name string) ([]*models.KnownRisk, error) {
	var result []*models.KnownRisk
	for _, kr := range r.data {
		if kr.WorkloadInfo.Namespace == namespace && kr.WorkloadInfo.Name == name {
			result = append(result, kr)
		}
	}
	return result, nil
}

// CountByStatus compte les KnownRisks par statut
func (r *InMemoryRepository) CountByStatus(ctx context.Context) (map[models.Status]int, error) {
	counts := make(map[models.Status]int)
	for _, kr := range r.data {
		counts[kr.Status]++
	}
	return counts, nil
}

// CountBySeverity compte les KnownRisks par sévérité
func (r *InMemoryRepository) CountBySeverity(ctx context.Context) (map[models.Severity]int, error) {
	counts := make(map[models.Severity]int)
	for _, kr := range r.data {
		counts[kr.Severity]++
	}
	return counts, nil
}

// Erreurs standard
var (
	ErrNotFound = errors.New("item not found")
)
