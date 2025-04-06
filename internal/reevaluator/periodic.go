package reevaluator

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/PypNetty/Kytena/internal/knownrisk"
)

type PeriodicReevaluator struct {
	repository           knownrisk.Repository
	interval             time.Duration
	warningThreshold     time.Duration
	notificationHandlers []NotificationHandler
	ticker               *time.Ticker
	done                 chan bool
	running              bool
	mu                   sync.Mutex
	lastResult           *ReevaluationResult
}

func NewPeriodicReevaluator(repo knownrisk.Repository, interval time.Duration) *PeriodicReevaluator {
	return &PeriodicReevaluator{
		repository:           repo,
		interval:             interval,
		warningThreshold:     72 * time.Hour,
		notificationHandlers: []NotificationHandler{},
		done:                 make(chan bool),
		running:              false,
	}
}

func (r *PeriodicReevaluator) SetRepository(repo knownrisk.Repository) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.repository = repo
}

func (r *PeriodicReevaluator) SetWarningThreshold(threshold time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.warningThreshold = threshold
}

func (r *PeriodicReevaluator) RegisterNotificationHandler(handler NotificationHandler) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.notificationHandlers = append(r.notificationHandlers, handler)
}

func (r *PeriodicReevaluator) Start(ctx context.Context) error {
	r.mu.Lock()
	if r.running {
		r.mu.Unlock()
		return fmt.Errorf("reevaluator is already running")
	}
	if r.repository == nil {
		r.mu.Unlock()
		return fmt.Errorf("repository is not set")
	}
	r.ticker = time.NewTicker(r.interval)
	r.done = make(chan bool)
	r.running = true
	r.mu.Unlock()

	go func() {
		defer func() {
			r.mu.Lock()
			r.running = false
			r.mu.Unlock()
		}()

		r.processReevaluation(ctx)
		for {
			select {
			case <-r.ticker.C:
				r.processReevaluation(ctx)
			case <-ctx.Done():
				fmt.Println("Received context cancellation. Stopping...")
				r.Stop(ctx)
				return
			case <-r.done:
				fmt.Println("Stop signal received.")
				return
			}
		}
	}()

	return nil
}

func (r *PeriodicReevaluator) Stop(_ context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.running {
		return nil
	}

	if r.ticker != nil {
		r.ticker.Stop()
	}

	select {
	case r.done <- true:
	default:
	}

	r.running = false
	return nil
}

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

func (r *PeriodicReevaluator) GetLastResult() *ReevaluationResult {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lastResult
}

func (r *PeriodicReevaluator) processReevaluation(ctx context.Context) {
	result, err := r.reevaluate(ctx)
	if err != nil {
		fmt.Printf("Error during reevaluation: %v\n", err)
		return
	}

	r.mu.Lock()
	r.lastResult = result
	handlers := r.notificationHandlers
	r.mu.Unlock()

	for _, notification := range result.Notifications {
		for _, handler := range handlers {
			handler(notification)
		}
	}
}

func (r *PeriodicReevaluator) reevaluate(ctx context.Context) (*ReevaluationResult, error) {
	start := time.Now()

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

	for _, kr := range knownRisks {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		oldStatus := kr.Status
		kr.UpdateStatus()

		if oldStatus != kr.Status {
			if err := r.repository.Update(kr); err != nil {
				return nil, fmt.Errorf("failed to update KnownRisk %s: %w", kr.ID, err)
			}
			result.UpdatedCount++

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

		if kr.Status == knownrisk.StatusActive {
			timeUntilExpiry := time.Until(kr.ExpiresAt)
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
