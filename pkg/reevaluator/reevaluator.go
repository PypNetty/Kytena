// pkg/reevaluator/reevaluator.go
package reevaluator

import (
	"context"
	"fmt"
	"time"

	"github.com/PypNetty/Kytena/pkg/models"
	"github.com/PypNetty/Kytena/pkg/storage"
	"github.com/sirupsen/logrus"
)

// NotificationType représente le type de notification
type NotificationType string

const (
	// NotificationExpired indique un KnownRisk qui a expiré
	NotificationExpired NotificationType = "Expired"
	// NotificationExpiringSoon indique un KnownRisk qui va bientôt expirer
	NotificationExpiringSoon NotificationType = "ExpiringSoon"
)

// Notification représente une notification pour un KnownRisk
type Notification struct {
	// Type est le type de notification
	Type NotificationType
	// KnownRiskID est l'ID du KnownRisk concerné
	KnownRiskID string
	// Message est le message de notification
	Message string
	// Timestamp est l'horodatage de la notification
	Timestamp time.Time
}

// NotificationHandler est une fonction qui gère une notification
type NotificationHandler func(notification Notification)

// ReevaluationResult contient les résultats d'une réévaluation
type ReevaluationResult struct {
	// ProcessedCount est le nombre de KnownRisks traités
	ProcessedCount int
	// UpdatedCount est le nombre de KnownRisks mis à jour
	UpdatedCount int
	// Notifications est la liste des notifications générées
	Notifications []Notification
	// StartTime est l'heure de début de la réévaluation
	StartTime time.Time
	// EndTime est l'heure de fin de la réévaluation
	EndTime time.Time
}

// Reevaluator est l'interface pour les réévaluateurs
type Reevaluator interface {
	// Start démarre le réévaluateur
	Start(ctx context.Context) error
	// Stop arrête le réévaluateur
	Stop() error
	// RegisterNotificationHandler enregistre un gestionnaire de notifications
	RegisterNotificationHandler(handler NotificationHandler)
	// RunOnce exécute une réévaluation unique
	RunOnce(ctx context.Context) ([]Notification, error)
}

// PeriodicReevaluator réévalue périodiquement les KnownRisks
type PeriodicReevaluator struct {
	repository           storage.Repository
	interval             time.Duration
	warningThreshold     time.Duration
	notificationHandlers []NotificationHandler
	ticker               *time.Ticker
	done                 chan bool
	running              bool
	logger               *logrus.Logger
	lastResult           *ReevaluationResult
}

// NewPeriodicReevaluator crée un nouveau réévaluateur périodique
func NewPeriodicReevaluator(repo storage.Repository, interval time.Duration, logger *logrus.Logger) *PeriodicReevaluator {
	if logger == nil {
		logger = logrus.New()
		logger.SetLevel(logrus.InfoLevel)
	}

	return &PeriodicReevaluator{
		repository:           repo,
		interval:             interval,
		warningThreshold:     72 * time.Hour, // Par défaut: 3 jours
		notificationHandlers: []NotificationHandler{},
		done:                 make(chan bool),
		running:              false,
		logger:               logger,
	}
}

// SetRepository définit le repository à utiliser
func (r *PeriodicReevaluator) SetRepository(repo storage.Repository) {
	r.repository = repo
}

// SetWarningThreshold définit le seuil d'avertissement
func (r *PeriodicReevaluator) SetWarningThreshold(threshold time.Duration) {
	r.warningThreshold = threshold
}

// RegisterNotificationHandler enregistre un gestionnaire de notifications
func (r *PeriodicReevaluator) RegisterNotificationHandler(handler NotificationHandler) {
	r.notificationHandlers = append(r.notificationHandlers, handler)
}

// Start démarre le réévaluateur périodique
func (r *PeriodicReevaluator) Start(ctx context.Context) error {
	if r.running {
		return fmt.Errorf("reevaluator is already running")
	}

	if r.repository == nil {
		return fmt.Errorf("repository is not set")
	}

	r.ticker = time.NewTicker(r.interval)
	r.done = make(chan bool)
	r.running = true

	r.logger.Info("Starting periodic reevaluator")

	go func() {
		defer func() {
			r.running = false
			r.logger.Info("Periodic reevaluator stopped")
		}()

		// Exécuter une réévaluation immédiatement
		r.processReevaluation(ctx)

		for {
			select {
			case <-r.ticker.C:
				r.processReevaluation(ctx)
			case <-ctx.Done():
				r.logger.Debug("Context cancelled, stopping reevaluator")
				return
			case <-r.done:
				r.logger.Debug("Stop signal received")
				return
			}
		}
	}()

	return nil
}

// Stop arrête le réévaluateur périodique
func (r *PeriodicReevaluator) Stop() error {
	if !r.running {
		return nil
	}

	if r.ticker != nil {
		r.ticker.Stop()
	}

	r.done <- true
	r.running = false

	return nil
}

// RunOnce exécute une réévaluation unique
func (r *PeriodicReevaluator) RunOnce(ctx context.Context) ([]Notification, error) {
	if r.repository == nil {
		return nil, fmt.Errorf("repository is not set")
	}

	result, err := r.reevaluate(ctx)
	if err != nil {
		return nil, err
	}

	r.lastResult = result

	return result.Notifications, nil
}

// GetLastResult retourne le dernier résultat de réévaluation
func (r *PeriodicReevaluator) GetLastResult() *ReevaluationResult {
	return r.lastResult
}

// processReevaluation exécute une réévaluation et traite les notifications
func (r *PeriodicReevaluator) processReevaluation(ctx context.Context) {
	result, err := r.reevaluate(ctx)
	if err != nil {
		r.logger.Errorf("Error during reevaluation: %v", err)
		return
	}

	r.lastResult = result

	for _, notification := range result.Notifications {
		for _, handler := range r.notificationHandlers {
			handler(notification)
		}
	}
}

// reevaluate réévalue tous les KnownRisks
func (r *PeriodicReevaluator) reevaluate(ctx context.Context) (*ReevaluationResult, error) {
	start := time.Now()

	r.logger.Debug("Starting reevaluation of KnownRisks")

	// Récupérer tous les KnownRisks
	knownRisks, err := r.repository.List(ctx, storage.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list KnownRisks: %w", err)
	}

	r.logger.Debugf("Found %d KnownRisks to evaluate", len(knownRisks))

	result := &ReevaluationResult{
		ProcessedCount: len(knownRisks),
		UpdatedCount:   0,
		Notifications:  []Notification{},
		StartTime:      start,
	}

	for _, kr := range knownRisks {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		oldStatus := kr.Status

		// Mettre à jour le statut
		kr.UpdateStatus()

		// Si le statut a changé, mettre à jour le KnownRisk
		if oldStatus != kr.Status {
			if err := r.repository.Update(ctx, kr); err != nil {
				return nil, fmt.Errorf("failed to update KnownRisk %s: %w", kr.ID, err)
			}

			result.UpdatedCount++

			// Générer une notification si le statut est devenu expiré
			if kr.Status == models.StatusExpired {
				notification := Notification{
					Type:        NotificationExpired,
					KnownRiskID: kr.ID,
					Message:     fmt.Sprintf("KnownRisk for %s in workload %s has expired", kr.VulnerabilityID, kr.WorkloadInfo.FormattedName()),
					Timestamp:   time.Now(),
				}

				result.Notifications = append(result.Notifications, notification)
			}
		}

		// Pour les risques actifs, vérifier s'ils vont bientôt expirer
		if kr.Status == models.StatusActive {
			timeUntilExpiry := kr.ExpiresAt.Sub(time.Now())

			if timeUntilExpiry > 0 && timeUntilExpiry <= r.warningThreshold {
				notification := Notification{
					Type:        NotificationExpiringSoon,
					KnownRiskID: kr.ID,
					Message:     fmt.Sprintf("KnownRisk for %s in workload %s will expire in %.1f days", kr.VulnerabilityID, kr.WorkloadInfo.FormattedName(), timeUntilExpiry.Hours()/24),
					Timestamp:   time.Now(),
				}

				result.Notifications = append(result.Notifications, notification)
			}
		}
	}

	result.EndTime = time.Now()

	r.logger.Infof("Reevaluation completed in %s, %d KnownRisks updated, %d notifications generated",
		result.EndTime.Sub(result.StartTime),
		result.UpdatedCount,
		len(result.Notifications))

	return result, nil
}
