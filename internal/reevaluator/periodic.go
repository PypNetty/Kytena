package reevaluator

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/PypNetty/Kyra/internal/knownrisk"
)

// PeriodicReevaluator implémente un réévaluateur qui s'exécute à intervalles réguliers
type PeriodicReevaluator struct {
	// repository est utilisé pour accéder aux KnownRisks
	repository knownrisk.Repository

	// interval définit la durée entre deux réévaluations
	interval time.Duration

	// warningThreshold définit combien de temps avant l'expiration émettre un avertissement
	warningThreshold time.Duration

	// notificationHandlers contient les gestionnaires de notifications
	notificationHandlers []NotificationHandler

	// ticker est utilisé pour déclencher des réévaluations périodiques
	ticker *time.Ticker

	// done est utilisé pour signaler l'arrêt du ticker
	done chan bool

	// running indique si le réévaluateur est en cours d'exécution
	running bool

	// mu protège l'accès concurrent aux champs
	mu sync.Mutex

	// lastResult contient les résultats de la dernière réévaluation
	lastResult *ReevaluationResult
}

// NewPeriodicReevaluator crée un nouveau réévaluateur périodique
func NewPeriodicReevaluator(repo knownrisk.Repository, interval time.Duration) *PeriodicReevaluator {
	return &PeriodicReevaluator{
		repository:           repo,
		interval:             interval,
		warningThreshold:     72 * time.Hour, // Par défaut: avertir 3 jours avant l'expiration
		notificationHandlers: []NotificationHandler{},
		done:                 make(chan bool),
		running:              false,
	}
}

// SetRepository configure le repository à utiliser
func (r *PeriodicReevaluator) SetRepository(repo knownrisk.Repository) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.repository = repo
}

// SetWarningThreshold configure le seuil d'avertissement avant expiration
func (r *PeriodicReevaluator) SetWarningThreshold(threshold time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.warningThreshold = threshold
}

// RegisterNotificationHandler enregistre un gestionnaire de notifications
func (r *PeriodicReevaluator) RegisterNotificationHandler(handler NotificationHandler) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.notificationHandlers = append(r.notificationHandlers, handler)
}

// Start lance le processus de réévaluation périodique
func (r *PeriodicReevaluator) Start(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.running {
		return fmt.Errorf("reevaluator is already running")
	}

	if r.repository == nil {
		return fmt.Errorf("repository is not set")
	}

	r.ticker = time.NewTicker(r.interval)
	r.running = true

	// Exécuter une première réévaluation immédiatement
	go func() {
		r.processReevaluation(ctx)

		// Puis exécuter périodiquement
		for {
			select {
			case <-r.ticker.C:
				r.processReevaluation(ctx)
			case <-r.done:
				return
			case <-ctx.Done():
				r.Stop()
				return
			}
		}
	}()

	return nil
}

// Stop arrête le processus de réévaluation
func (r *PeriodicReevaluator) Stop() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.running {
		return nil
	}

	r.ticker.Stop()
	r.done <- true
	r.running = false

	return nil
}

// RunOnce exécute une réévaluation immédiate
func (r *PeriodicReevaluator) RunOnce(ctx context.Context) ([]Notification, error) {
	r.mu.Lock()
	if r.repository == nil {
		r.mu.Unlock()
		return nil, fmt.Errorf("repository is not set")
	}
	r.mu.Unlock()

	result, err := r.reevaluate(ctx)
	if err != nil {
		return nil, err
	}

	r.mu.Lock()
	r.lastResult = result
	r.mu.Unlock()

	return result.Notifications, nil
}

// GetLastResult retourne les résultats de la dernière réévaluation
func (r *PeriodicReevaluator) GetLastResult() *ReevaluationResult {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lastResult
}

// processReevaluation exécute une réévaluation et dispatche les notifications
func (r *PeriodicReevaluator) processReevaluation(ctx context.Context) {
	result, err := r.reevaluate(ctx)
	if err != nil {
		// Log l'erreur mais continuer
		fmt.Printf("Error during reevaluation: %v\n", err)
		return
	}

	r.mu.Lock()
	r.lastResult = result
	handlers := r.notificationHandlers
	r.mu.Unlock()

	// Dispatcher les notifications
	for _, notification := range result.Notifications {
		for _, handler := range handlers {
			handler(notification)
		}
	}
}

// reevaluate effectue la réévaluation des KnownRisks
func (r *PeriodicReevaluator) reevaluate(ctx context.Context) (*ReevaluationResult, error) {
	start := time.Now()

	// Récupérer tous les KnownRisks
	knownRisks, err := r.repository.List()
	if err != nil {
		return nil, fmt.Errorf("failed to list KnownRisks: %w", err)
	}

	result := &ReevaluationResult{
		ProcessedCount: len(knownRisks),
		UpdatedCount:   0,
		Notifications:  []Notification{},
		StartTime:      start,
	}

	// Traiter chaque KnownRisk
	for _, kr := range knownRisks {
		// Vérifier si le contexte est annulé
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
			// Continuer
		}

		// Sauvegarder l'ancien statut
		oldStatus := kr.Status

		// Mettre à jour le statut
		kr.UpdateStatus()

		// Si le statut a changé, mettre à jour le KnownRisk
		if oldStatus != kr.Status {
			if err := r.repository.Update(kr); err != nil {
				return nil, fmt.Errorf("failed to update KnownRisk %s: %w", kr.ID, err)
			}
			result.UpdatedCount++

			// Si le KnownRisk est expiré, créer une notification
			if kr.Status == knownrisk.StatusExpired {
				notification := Notification{
					Type:        NotificationExpired,
					KnownRiskID: kr.ID,
					Message:     fmt.Sprintf("KnownRisk for %s in workload %s has expired", kr.VulnerabilityID, kr.WorkloadInfo.FormattedName()),
					Timestamp:   time.Now(),
				}
				result.Notifications = append(result.Notifications, notification)
			}
		}

		// Si le KnownRisk va bientôt expirer, créer une notification
		if kr.Status == knownrisk.StatusActive {
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
	return result, nil
}
