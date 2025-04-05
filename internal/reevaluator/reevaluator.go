package reevaluator

import (
	"context"
	"time"
)

type NotificationType string

const (
	NotificationExpired NotificationType = "Expired"

	NotificationExpiringSoon NotificationType = "ExpiringSoon"
)

type Notification struct {
	Type NotificationType

	KnownRiskID string

	Message string

	Timestamp time.Time
}

type NotificationHandler func(notification Notification)

type Reevaluator interface {
	// Start starts the reevaluation process
	Start(ctx context.Context) error
	// Stop stops the reevaluation process
	Stop(ctx context.Context) error
	// RegisterNotificationHandler registers a notification handler
	RegisterNotificationHandler(handler NotificationHandler)

	// RunOnce performs an immediate re-evaluation (useful for testing or manual execution).
	RunOnce(ctx context.Context) ([]Notification, error)
}

type ReevaluationResult struct {
	ProcessedCount int

	UpdatedCount int

	Notifications []Notification

	StartTime time.Time

	EndTime time.Time
}
