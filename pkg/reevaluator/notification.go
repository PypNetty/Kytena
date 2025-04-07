// pkg/reevaluator/notification.go
package reevaluator

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

// LoggingNotificationHandler crée un gestionnaire de notifications qui écrit dans un fichier de log
func LoggingNotificationHandler(logDir string) (NotificationHandler, error) {
	// Créer le répertoire si nécessaire
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}

	// Créer ou ouvrir le fichier de log
	logPath := filepath.Join(logDir, "reevaluations.log")
	logFile, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %w", err)
	}

	// Créer le logger
	logger := log.New(logFile, "", log.LstdFlags)

	// Retourner le gestionnaire de notifications
	return func(notification Notification) {
		var severity string
		switch notification.Type {
		case NotificationExpired:
			severity = "ALERT"
		case NotificationExpiringSoon:
			severity = "WARNING"
		default:
			severity = "INFO"
		}

		logger.Printf("[%s] %s: %s", severity, notification.Type, notification.Message)
	}, nil
}

// ConsoleNotificationHandler crée un gestionnaire de notifications qui affiche dans la console
func ConsoleNotificationHandler() NotificationHandler {
	return func(notification Notification) {
		var severity string
		switch notification.Type {
		case NotificationExpired:
			severity = "ALERT"
		case NotificationExpiringSoon:
			severity = "WARNING"
		default:
			severity = "INFO"
		}

		timestamp := notification.Timestamp.Format(time.RFC3339)
		fmt.Printf("[%s] [%s] %s: %s\n", timestamp, severity, notification.Type, notification.Message)
	}
}
