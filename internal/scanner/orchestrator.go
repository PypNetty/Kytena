package scanner

import (
	"context"
	"fmt"
	"time"

	"github.com/PypNetty/Kytena/internal/knownrisk"
	"github.com/PypNetty/Kytena/internal/workload"
)

// ScanOrchestrator coordonne les scans de différents scanners et génère des propositions de KnownRisks
type ScanOrchestrator struct {
	registry  *VulnerabilityScannerRegistry
	kRegistry knownrisk.Repository
}

// ProposedKnownRisk représente un KnownRisk suggéré basé sur une vulnérabilité détectée
type ProposedKnownRisk struct {
	// Finding est la vulnérabilité détectée
	Finding VulnerabilityFinding

	// KnownRisk est la proposition de KnownRisk
	KnownRisk *knownrisk.KnownRisk

	// Justification est la justification suggérée
	Justification string

	// ExpiryDays est le nombre de jours suggéré pour l'expiration
	ExpiryDays int

	// BusinessImpact est l'impact business suggéré (0-10)
	BusinessImpact int

	// CriticalityScore est un score calculé représentant l'importance de traiter cette vulnérabilité
	CriticalityScore float64
}

// OrchestratedScanResult contient les résultats agrégés de plusieurs scanners
type OrchestratedScanResult struct {
	// Results contient les résultats individuels par scanner
	Results map[string]*ScanResult

	// AllFindings contient toutes les vulnérabilités détectées
	AllFindings []VulnerabilityFinding

	// ProposedActions contient les propositions de KnownRisks
	ProposedActions []ProposedKnownRisk

	// StartTime indique quand le scan orchestré a commencé
	StartTime time.Time

	// EndTime indique quand le scan orchestré s'est terminé
	EndTime time.Time

	// Summary contient des statistiques sur les résultats
	Summary ScanSummary
}

// ScanSummary contient des statistiques sur les résultats d'un scan
type ScanSummary struct {
	// TotalFindings est le nombre total de vulnérabilités détectées
	TotalFindings int

	// FindingsBySeverity est le nombre de vulnérabilités par sévérité
	FindingsBySeverity map[VulnerabilitySeverity]int

	// FindingsByWorkload est le nombre de vulnérabilités par workload
	FindingsByWorkload map[string]int

	// FindingsByNamespace est le nombre de vulnérabilités par namespace
	FindingsByNamespace map[string]int

	// FindingsByScanner est le nombre de vulnérabilités par scanner
	FindingsByScanner map[string]int
}

// NewScanOrchestrator crée un nouveau ScanOrchestrator
func NewScanOrchestrator(registry *VulnerabilityScannerRegistry, kRegistry knownrisk.Repository) *ScanOrchestrator {
	return &ScanOrchestrator{
		registry:  registry,
		kRegistry: kRegistry,
	}
}

// Scan lance un scan avec tous les scanners enregistrés
func (o *ScanOrchestrator) Scan(ctx context.Context, options ScanOptions) (*OrchestratedScanResult, error) {
	startTime := time.Now()

	// Préparer le résultat
	result := &OrchestratedScanResult{
		Results:   make(map[string]*ScanResult),
		StartTime: startTime,
		Summary: ScanSummary{
			FindingsBySeverity:  make(map[VulnerabilitySeverity]int),
			FindingsByWorkload:  make(map[string]int),
			FindingsByNamespace: make(map[string]int),
			FindingsByScanner:   make(map[string]int),
		},
	}

	// Récupérer les scanners disponibles
	scanners := o.registry.ListScanners()
	if len(scanners) == 0 {
		return nil, fmt.Errorf("no scanners registered")
	}

	// Lancer un scan pour chaque scanner
	for _, scanner := range scanners {
		scanResult, err := scanner.Scan(ctx, options)
		if err != nil {
			// Enregistrer l'erreur mais continuer avec les autres scanners
			result.Results[scanner.Name()] = &ScanResult{
				ScannerName: scanner.Name(),
				Success:     false,
				Error:       err,
				StartTime:   startTime,
				EndTime:     time.Now(),
			}
			continue
		}

		result.Results[scanner.Name()] = scanResult
		result.AllFindings = append(result.AllFindings, scanResult.Findings...)

		// Mettre à jour les statistiques
		result.Summary.TotalFindings += len(scanResult.Findings)
		result.Summary.FindingsByScanner[scanner.Name()] = len(scanResult.Findings)

		for _, finding := range scanResult.Findings {
			result.Summary.FindingsBySeverity[finding.Severity]++
			result.Summary.FindingsByWorkload[finding.WorkloadName]++
			result.Summary.FindingsByNamespace[finding.Namespace]++
		}
	}

	// Générer des propositions de KnownRisks
	result.ProposedActions = o.generateProposedActions(result.AllFindings)

	result.EndTime = time.Now()
	return result, nil
}

// generateProposedActions génère des propositions de KnownRisks basées sur les vulnérabilités détectées
func (o *ScanOrchestrator) generateProposedActions(findings []VulnerabilityFinding) []ProposedKnownRisk {
	var proposals []ProposedKnownRisk

	// Vérifier les KnownRisks existants pour éviter les doublons
	existingKnownRisks, err := o.kRegistry.List()
	if err != nil {
		// En cas d'erreur, continuer avec une liste vide
		existingKnownRisks = []*knownrisk.KnownRisk{}
	}

	for _, finding := range findings {
		// Vérifier si cette vulnérabilité est déjà couverte par un KnownRisk existant
		isAlreadyCovered := false
		for _, kr := range existingKnownRisks {
			if kr.VulnerabilityID == finding.ID &&
				kr.WorkloadInfo.Name == finding.WorkloadName &&
				kr.WorkloadInfo.Namespace == finding.Namespace {
				isAlreadyCovered = true
				break
			}
		}

		if isAlreadyCovered {
			continue
		}

		// Déterminer l'impact business et les jours d'expiration en fonction de la sévérité
		businessImpact := 5 // Valeur par défaut moyenne
		expiryDays := 30    // Par défaut 30 jours

		switch finding.Severity {
		case SeverityCritical:
			businessImpact = 9
			expiryDays = 7 // Les vulnérabilités critiques devraient être corrigées rapidement
		case SeverityHigh:
			businessImpact = 7
			expiryDays = 14
		case SeverityMedium:
			businessImpact = 5
			expiryDays = 30
		case SeverityLow:
			businessImpact = 3
			expiryDays = 90
		}

		// Calculer un score de criticité
		criticalityScore := calculateCriticalityScore(finding, businessImpact)

		// Générer une justification
		justification := generateJustification(finding)

		// Créer un workload
		w := workload.NewWorkload(
			finding.WorkloadName,
			finding.Namespace,
			convertResourceType(finding.ResourceType),
			finding.AffectedComponent,
			businessImpact,
			map[string]string{}, // Pas de labels pour la simulation
			map[string]string{}, // Pas d'annotations pour la simulation
		)

		// Créer un KnownRisk proposé
		kr := knownrisk.NewKnownRisk(
			finding.ID,
			*w,
			justification,
			"security-team@example.com", // Contact par défaut
			time.Now(),
			time.Now().Add(time.Duration(expiryDays)*24*time.Hour),
			convertSeverity(finding.Severity),
		)

		// Ajouter des tags basés sur le scanner
		kr.AddTag(finding.ScannerName)

		if finding.ScannerName == "Trivy" {
			kr.AddTag("container-vulnerability")
		} else if finding.ScannerName == "Falco" {
			kr.AddTag("runtime-security")
		}

		// Créer la proposition
		proposal := ProposedKnownRisk{
			Finding:          finding,
			KnownRisk:        kr,
			Justification:    justification,
			ExpiryDays:       expiryDays,
			BusinessImpact:   businessImpact,
			CriticalityScore: criticalityScore,
		}

		proposals = append(proposals, proposal)
	}

	return proposals
}

// calculateCriticalityScore calcule un score de criticité pour une vulnérabilité
func calculateCriticalityScore(finding VulnerabilityFinding, businessImpact int) float64 {
	// Base score selon la sévérité
	severityScore := 0.0
	switch finding.Severity {
	case SeverityCritical:
		severityScore = 1.0
	case SeverityHigh:
		severityScore = 0.8
	case SeverityMedium:
		severityScore = 0.5
	case SeverityLow:
		severityScore = 0.2
	default:
		severityScore = 0.1
	}

	// Modificateurs
	exploitModifier := 1.0
	if finding.ExploitAvailable {
		exploitModifier = 1.5
	}

	// Impact business (normalisé de 0 à 1)
	businessModifier := float64(businessImpact) / 10.0

	// Score final
	return severityScore * exploitModifier * (0.5 + 0.5*businessModifier)
}

// generateJustification génère une justification pour un KnownRisk
func generateJustification(finding VulnerabilityFinding) string {
	// Base de la justification
	base := fmt.Sprintf("%s detected in %s. ", finding.Title, finding.AffectedComponent)

	// Ajouter des détails selon le scanner
	if finding.ScannerName == "Trivy" {
		if finding.FixedVersion != "" {
			base += fmt.Sprintf("This vulnerability is fixed in version %s. ", finding.FixedVersion)
		}
	} else if finding.ScannerName == "Falco" {
		base += "This runtime behavior may indicate a security issue. "
	}

	// Ajouter des conseils selon la sévérité
	switch finding.Severity {
	case SeverityCritical:
		base += "This is a critical vulnerability that should be addressed as soon as possible."
	case SeverityHigh:
		base += "This high severity issue should be prioritized for remediation."
	case SeverityMedium:
		base += "This medium severity issue should be scheduled for remediation in the normal update cycle."
	case SeverityLow:
		base += "This low severity issue can be addressed in a future update."
	}

	return base
}

// convertResourceType convertit un type de ressource en WorkloadType
func convertResourceType(resourceType string) workload.WorkloadType {
	switch resourceType {
	case "Deployment":
		return workload.TypeDeployment
	case "StatefulSet":
		return workload.TypeStatefulSet
	case "DaemonSet":
		return workload.TypeDaemonSet
	case "CronJob":
		return workload.TypeCronJob
	case "Job":
		return workload.TypeJob
	case "Pod":
		return workload.TypePod
	default:
		return workload.TypeDeployment // Par défaut
	}
}

// convertSeverity convertit une VulnerabilitySeverity en knownrisk.Severity
func convertSeverity(severity VulnerabilitySeverity) knownrisk.Severity {
	switch severity {
	case SeverityCritical:
		return knownrisk.SeverityCritical
	case SeverityHigh:
		return knownrisk.SeverityHigh
	case SeverityMedium:
		return knownrisk.SeverityMedium
	case SeverityLow:
		return knownrisk.SeverityLow
	default:
		return knownrisk.SeverityMedium
	}
}
