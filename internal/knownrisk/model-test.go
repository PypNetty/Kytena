package knownrisk

import (
	"testing"
	"time"

	"github.com/PypNetty/Kyra/internal/workload"
)

func TestNewKnownRisk(t *testing.T) {
	// Créer un workload pour le test
	w := workload.NewWorkload(
		"test-app",
		"default",
		workload.TypeDeployment,
		"nginx:1.19.0",
		5,
		map[string]string{},
		map[string]string{},
	)

	// Créer un nouveau KnownRisk
	vulnerabilityID := "CVE-2023-12345"
	justification := "Required for business continuity until next release"
	acceptedBy := "security-team@example.com"
	expiresAt := time.Now().Add(30 * 24 * time.Hour) // 30 jours
	severity := SeverityHigh

	kr := NewKnownRisk(
		vulnerabilityID,
		*w,
		justification,
		acceptedBy,
		expiresAt,
		severity,
	)

	// Vérifications
	if kr.ID == "" {
		t.Error("Expected non-empty ID")
	}

	if kr.VulnerabilityID != vulnerabilityID {
		t.Errorf("Expected VulnerabilityID to be %s, got %s", vulnerabilityID, kr.VulnerabilityID)
	}

	if kr.Justification != justification {
		t.Errorf("Expected Justification to be %s, got %s", justification, kr.Justification)
	}

	if kr.AcceptedBy != acceptedBy {
		t.Errorf("Expected AcceptedBy to be %s, got %s", acceptedBy, kr.AcceptedBy)
	}

	if !kr.ExpiresAt.Equal(expiresAt) {
		t.Errorf("Expected ExpiresAt to be %v, got %v", expiresAt, kr.ExpiresAt)
	}

	if kr.Severity != severity {
		t.Errorf("Expected Severity to be %s, got %s", severity, kr.Severity)
	}

	if kr.Status != StatusActive {
		t.Errorf("Expected Status to be %s, got %s", StatusActive, kr.Status)
	}
}

func TestKnownRiskValidate(t *testing.T) {
	// Créer un workload valide
	w := workload.NewWorkload(
		"test-app",
		"default",
		workload.TypeDeployment,
		"nginx:1.19.0",
		5,
		map[string]string{},
		map[string]string{},
	)

	// Test cas valide
	kr := NewKnownRisk(
		"CVE-2023-12345",
		*w,
		"Valid justification",
		"security-team@example.com",
		time.Now().Add(24*time.Hour),
		SeverityHigh,
	)

	if err := kr.Validate(); err != nil {
		t.Errorf("Expected no validation error, got: %v", err)
	}

	// Test ID vide
	invalidKR := *kr
	invalidKR.ID = ""
	if err := invalidKR.Validate(); err == nil {
		t.Error("Expected validation error for empty ID, got none")
	}

	// Test VulnerabilityID vide
	invalidKR = *kr
	invalidKR.VulnerabilityID = ""
	if err := invalidKR.Validate(); err == nil {
		t.Error("Expected validation error for empty VulnerabilityID, got none")
	}

	// Test Justification vide
	invalidKR = *kr
	invalidKR.Justification = ""
	if err := invalidKR.Validate(); err == nil {
		t.Error("Expected validation error for empty Justification, got none")
	}

	// Test AcceptedBy vide
	invalidKR = *kr
	invalidKR.AcceptedBy = ""
	if err := invalidKR.Validate(); err == nil {
		t.Error("Expected validation error for empty AcceptedBy, got none")
	}

	// Test ExpiresAt avant AcceptedAt
	invalidKR = *kr
	invalidKR.ExpiresAt = invalidKR.AcceptedAt.Add(-1 * time.Hour)
	if err := invalidKR.Validate(); err == nil {
		t.Error("Expected validation error for ExpiresAt before AcceptedAt, got none")
	}
}

func TestKnownRiskIsExpired(t *testing.T) {
	// Créer un workload pour le test
	w := workload.NewWorkload(
		"test-app",
		"default",
		workload.TypeDeployment,
		"nginx:1.19.0",
		5,
		map[string]string{},
		map[string]string{},
	)

	// Test KnownRisk non expiré
	futureTime := time.Now().Add(24 * time.Hour)
	kr := NewKnownRisk(
		"CVE-2023-12345",
		*w,
		"Test justification",
		"security-team@example.com",
		futureTime,
		SeverityHigh,
	)

	if kr.IsExpired() {
		t.Error("Expected KnownRisk to not be expired")
	}

	// Test KnownRisk expiré
	pastTime := time.Now().Add(-24 * time.Hour)
	expiredKR := NewKnownRisk(
		"CVE-2023-12345",
		*w,
		"Test justification",
		"security-team@example.com",
		pastTime,
		SeverityHigh,
	)

	if !expiredKR.IsExpired() {
		t.Error("Expected KnownRisk to be expired")
	}
}

func TestKnownRiskUpdateStatus(t *testing.T) {
	// Créer un workload pour le test
	w := workload.NewWorkload(
		"test-app",
		"default",
		workload.TypeDeployment,
		"nginx:1.19.0",
		5,
		map[string]string{},
		map[string]string{},
	)

	// Test mise à jour vers expiré
	pastTime := time.Now().Add(-24 * time.Hour)
	kr := NewKnownRisk(
		"CVE-2023-12345",
		*w,
		"Test justification",
		"security-team@example.com",
		pastTime,
		SeverityHigh,
	)

	kr.Status = StatusActive // Forcer le statut à actif
	kr.UpdateStatus()
	if kr.Status != StatusExpired {
		t.Errorf("Expected Status to be %s, got %s", StatusExpired, kr.Status)
	}

	// Test maintien du statut résolu
	kr.Status = StatusResolved
	kr.UpdateStatus()
	if kr.Status != StatusResolved {
		t.Errorf("Expected Status to remain %s, got %s", StatusResolved, kr.Status)
	}
}
