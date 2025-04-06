package reevaluator

import (
	"context"
	"time"
)

type NotificationType string

const (
	NotificationExpired      NotificationType = "Expired"
	NotificationExpiringSoon NotificationType = "ExpiringSoon"
)

type Notification struct {
	Type        NotificationType
	KnownRiskID string
	Message     string
	Timestamp   time.Time
}

type NotificationHandler func(notification Notification)

type Reevaluator interface {
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	RegisterNotificationHandler(handler NotificationHandler)
	RunOnce(ctx context.Context) ([]Notification, error)
}

type ReevaluationResult struct {
	ProcessedCount int
	UpdatedCount   int
	Notifications  []Notification
	StartTime      time.Time
	EndTime        time.Time
}
