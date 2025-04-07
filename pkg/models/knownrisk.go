// pkg/models/knownrisk.go
package models

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Status représente l'état actuel d'un KnownRisk
type Status string

const (
	// StatusActive indique un risque actuellement accepté et dans sa période de validité
	StatusActive Status = "Active"
	// StatusExpired indique un risque dont la période d'acceptation est dépassée
	StatusExpired Status = "Expired"
	// StatusResolved indique un risque qui a été corrigé
	StatusResolved Status = "Resolved"
)

// Severity représente le niveau de gravité d'un risque
type Severity string

const (
	// SeverityCritical indique une vulnérabilité critique
	SeverityCritical Severity = "Critical"
	// SeverityHigh indique une vulnérabilité à haut risque
	SeverityHigh Severity = "High"
	// SeverityMedium indique une vulnérabilité à risque moyen
	SeverityMedium Severity = "Medium"
	// SeverityLow indique une vulnérabilité à faible risque
	SeverityLow Severity = "Low"
)

// KnownRisk représente une vulnérabilité ou un écart de sécurité accepté et documenté
type KnownRisk struct {
	// ID est l'identifiant unique du KnownRisk
	ID string `json:"id" yaml:"id"`
	// VulnerabilityID est l'identifiant de la vulnérabilité (ex: CVE-2023-XXXXX)
	VulnerabilityID string `json:"vulnerabilityId" yaml:"vulnerabilityId"`
	// WorkloadInfo contient les informations sur le workload affecté
	WorkloadInfo Workload `json:"workload" yaml:"workload"`
	// Justification explique pourquoi ce risque est accepté
	Justification string `json:"justification" yaml:"justification"`
	// AcceptedBy indique qui a accepté ce risque
	AcceptedBy string `json:"acceptedBy" yaml:"acceptedBy"`
	// AcceptedAt indique quand le risque a été accepté
	AcceptedAt time.Time `json:"acceptedAt" yaml:"acceptedAt"`
	// ExpiresAt indique quand l'acceptation du risque expire
	ExpiresAt time.Time `json:"expiresAt" yaml:"expiresAt"`
	// Severity indique le niveau de gravité du risque
	Severity Severity `json:"severity" yaml:"severity"`
	// Status indique l'état actuel du risque
	Status Status `json:"status" yaml:"status"`
	// LastReviewedAt indique la dernière fois que ce risque a été réévalué
	LastReviewedAt time.Time `json:"lastReviewedAt,omitempty" yaml:"lastReviewedAt,omitempty"`
	// Tags permet de catégoriser et rechercher les risques
	Tags []string `json:"tags,omitempty" yaml:"tags,omitempty"`
	// RelatedTickets contient des références à des tickets externes
	RelatedTickets []string `json:"relatedTickets,omitempty" yaml:"relatedTickets,omitempty"`
}

// NewKnownRisk crée une nouvelle instance de KnownRisk avec un ID généré
func NewKnownRisk(
	vulnerabilityID string,
	workloadInfo Workload,
	justification string,
	acceptedBy string,
	acceptedAt time.Time,
	expiresAt time.Time,
	severity Severity,
) *KnownRisk {
	now := time.Now()

	return &KnownRisk{
		ID:              uuid.New().String(),
		VulnerabilityID: vulnerabilityID,
		WorkloadInfo:    workloadInfo,
		Justification:   justification,
		AcceptedBy:      acceptedBy,
		AcceptedAt:      acceptedAt,
		ExpiresAt:       expiresAt,
		Severity:        severity,
		Status:          StatusActive,
		LastReviewedAt:  now,
		Tags:            []string{},
		RelatedTickets:  []string{},
	}
}

// Validate vérifie si le KnownRisk est valide
func (kr *KnownRisk) Validate() error {
	if kr.ID == "" {
		return errors.New("ID cannot be empty")
	}
	if kr.VulnerabilityID == "" {
		return errors.New("VulnerabilityID cannot be empty")
	}
	if err := kr.WorkloadInfo.Validate(); err != nil {
		return fmt.Errorf("invalid workload information: %w", err)
	}
	if kr.Justification == "" {
		return errors.New("justification cannot be empty")
	}
	if kr.AcceptedBy == "" {
		return errors.New("acceptedBy cannot be empty")
	}
	if kr.AcceptedAt.IsZero() {
		return errors.New("acceptedAt cannot be zero time")
	}
	if kr.ExpiresAt.IsZero() {
		return errors.New("expiresAt cannot be zero time")
	}
	if kr.ExpiresAt.Before(kr.AcceptedAt) {
		return errors.New("expiresAt cannot be before acceptedAt")
	}
	return nil
}

// IsExpired vérifie si le KnownRisk est expiré
func (kr *KnownRisk) IsExpired() bool {
	return time.Now().After(kr.ExpiresAt)
}

// UpdateStatus met à jour le statut du KnownRisk en fonction de son état actuel
func (kr *KnownRisk) UpdateStatus() {
	if kr.Status == StatusResolved {
		return // Si déjà résolu, ne pas changer le statut
	}

	if kr.IsExpired() {
		kr.Status = StatusExpired
	} else {
		kr.Status = StatusActive
	}
}

// MarkAsReviewed marque le KnownRisk comme revu à l'heure actuelle
func (kr *KnownRisk) MarkAsReviewed() {
	kr.LastReviewedAt = time.Now()
}

// MarkAsResolved marque le KnownRisk comme résolu
func (kr *KnownRisk) MarkAsResolved() {
	kr.Status = StatusResolved
	kr.MarkAsReviewed()
}

// ExtendExpiration prolonge la date d'expiration du KnownRisk
func (kr *KnownRisk) ExtendExpiration(newExpiresAt time.Time) error {
	if newExpiresAt.Before(time.Now()) {
		return errors.New("new expiration date cannot be in the past")
	}

	kr.ExpiresAt = newExpiresAt
	kr.UpdateStatus()
	kr.MarkAsReviewed()
	return nil
}

// AddTag ajoute un tag au KnownRisk s'il n'existe pas déjà
func (kr *KnownRisk) AddTag(tag string) {
	for _, existingTag := range kr.Tags {
		if existingTag == tag {
			return
		}
	}
	kr.Tags = append(kr.Tags, tag)
}

// AddRelatedTicket ajoute une référence à un ticket externe
func (kr *KnownRisk) AddRelatedTicket(ticketID string) {
	for _, existingTicket := range kr.RelatedTickets {
		if existingTicket == ticketID {
			return
		}
	}
	kr.RelatedTickets = append(kr.RelatedTickets, ticketID)
}

// GetStatusPriority retourne une priorité numérique pour le tri des statuts
func GetStatusPriority(status Status) int {
	switch status {
	case StatusExpired:
		return 3 // Highest priority
	case StatusActive:
		return 2
	case StatusResolved:
		return 1 // Lowest priority
	default:
		return 0
	}
}

// GetSeverityPriority retourne une priorité numérique pour le tri des sévérités
func GetSeverityPriority(severity Severity) int {
	switch severity {
	case SeverityCritical:
		return 4 // Highest priority
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1 // Lowest priority
	default:
		return 0
	}
}
