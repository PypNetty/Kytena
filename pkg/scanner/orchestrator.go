package scanner

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/PypNetty/kytena/pkg/loggers"
	"github.com/PypNetty/kytena/pkg/models"
	types "github.com/PypNetty/kytena/pkg/scanner/types"
	"github.com/PypNetty/kytena/pkg/storage"
)

// VulnerabilityScanner interface represents a scanner that can scan for vulnerabilities
type VulnerabilityScanner interface {
	Name() string
	Scan(ctx context.Context, options types.ScanOptions) (*types.ScanResult, error)
}

// VulnerabilityScannerRegistry manages the registration of vulnerability scanners
type VulnerabilityScannerRegistry struct {
	scanners []VulnerabilityScanner
}

func (r *VulnerabilityScannerRegistry) GetScanner(name string) (VulnerabilityScanner, bool) {
	for _, scanner := range r.scanners {
		if scanner.Name() == name {
			return scanner, true
		}
	}
	return nil, false
}

// NewVulnerabilityScannerRegistry creates a new registry for vulnerability scanners
func NewVulnerabilityScannerRegistry() *VulnerabilityScannerRegistry {
	return &VulnerabilityScannerRegistry{
		scanners: []VulnerabilityScanner{},
	}
}

// RegisterScanner adds a scanner to the registry
func (r *VulnerabilityScannerRegistry) RegisterScanner(scanner VulnerabilityScanner) {
	r.scanners = append(r.scanners, scanner)
}

// ListScanners returns all registered scanners
func (r *VulnerabilityScannerRegistry) ListScanners() []VulnerabilityScanner {
	return r.scanners
}

// ProposedKnownRisk représente un KnownRisk suggéré basé sur une vulnérabilité détectée
type ProposedKnownRisk struct {
	Finding          types.VulnerabilityFinding
	KnownRisk        *models.KnownRisk
	Justification    string
	ExpiryDays       int
	BusinessImpact   int
	CriticalityScore float64
}

// OrchestratedScanResult contient les résultats agrégés de plusieurs scanners
type OrchestratedScanResult struct {
	Results         map[string]*types.ScanResult
	AllFindings     []types.VulnerabilityFinding
	ProposedActions []ProposedKnownRisk
	StartTime       time.Time
	EndTime         time.Time
	Summary         ScanSummary
}

type ScanSummary struct {
	TotalFindings       int
	FindingsBySeverity  map[types.VulnerabilitySeverity]int
	FindingsByWorkload  map[string]int
	FindingsByNamespace map[string]int
	FindingsByScanner   map[string]int
}

// ScanOrchestrator coordonne les scans de différents scanners
// et génère des propositions de KnownRisks
type ScanOrchestrator struct {
	registry   *VulnerabilityScannerRegistry
	repository storage.Repository
	logger     loggers.Logger
}

func NewScanOrchestrator(registry *VulnerabilityScannerRegistry, repository storage.Repository, logger loggers.Logger) *ScanOrchestrator {
	return &ScanOrchestrator{
		registry:   registry,
		repository: repository,
		logger:     logger,
	}
}

func (o *ScanOrchestrator) Scan(ctx context.Context, options types.ScanOptions) (*OrchestratedScanResult, error) {
	startTime := time.Now()
	o.logger.Info("Starting orchestrated scan")

	result := &OrchestratedScanResult{
		Results:   make(map[string]*types.ScanResult),
		StartTime: startTime,
		Summary: ScanSummary{
			FindingsBySeverity:  make(map[types.VulnerabilitySeverity]int),
			FindingsByWorkload:  make(map[string]int),
			FindingsByNamespace: make(map[string]int),
			FindingsByScanner:   make(map[string]int),
		},
	}

	scanners := o.registry.ListScanners()
	if len(scanners) == 0 {
		return nil, fmt.Errorf("no scanners registered")
	}

	for _, scanner := range scanners {
		o.logger.Infof("Starting scan with %s scanner", scanner.Name())
		scanResult, err := scanner.Scan(ctx, options)

		if err != nil {
			o.logger.Warnf("Error running %s scanner: %v", scanner.Name(), err)
			result.Results[scanner.Name()] = &types.ScanResult{
				ScannerName: scanner.Name(),
				Success:     false,
				StartTime:   startTime,
				EndTime:     time.Now(),
				Metadata: map[string]interface{}{
					"error": err.Error(),
				},
			}
			continue
		}
		result.Results[scanner.Name()] = scanResult
		result.AllFindings = append(result.AllFindings, scanResult.Findings...)
		result.Summary.TotalFindings += len(scanResult.Findings)
		result.Summary.FindingsByScanner[scanner.Name()] = len(scanResult.Findings)

		for _, finding := range scanResult.Findings {
			result.Summary.FindingsBySeverity[finding.Severity]++
			result.Summary.FindingsByWorkload[finding.WorkloadName]++
			result.Summary.FindingsByNamespace[finding.Namespace]++
		}
	}

	result.ProposedActions = o.generateProposedActions(ctx, result.AllFindings)
	result.EndTime = time.Now()
	o.logger.Infof("Orchestrated scan completed in %s, total findings: %d",
		result.EndTime.Sub(result.StartTime), result.Summary.TotalFindings)
	return result, nil
}

func (o *ScanOrchestrator) generateProposedActions(ctx context.Context, findings []types.VulnerabilityFinding) []ProposedKnownRisk {
	var proposals []ProposedKnownRisk
	existing, err := o.repository.List(ctx, storage.ListOptions{})
	if err != nil {
		o.logger.Warnf("Error retrieving existing KnownRisks: %v", err)
		existing = []*models.KnownRisk{}
	}

	for _, f := range findings {
		if alreadyCovered(f, existing) {
			continue
		}

		impact := 5
		days := 30
		switch f.Severity {
		case types.SeverityCritical:
			impact, days = 9, 7
		case types.SeverityHigh:
			impact, days = 7, 14
		case types.SeverityMedium:
			impact, days = 5, 30
		case types.SeverityLow:
			impact, days = 3, 90
		}

		score := o.calculateCriticalityScore(f, impact)
		justif := o.generateJustification(f)

		w := models.Workload{
			Name:                f.WorkloadName,
			Namespace:           f.Namespace,
			Type:                models.WorkloadType(f.ResourceType),
			ImageID:             f.AffectedComponent,
			BusinessCriticality: impact,
			Labels:              map[string]string{},
			Annotations:         map[string]string{},
		}

		kr := models.NewKnownRisk(
			f.ID, w, justif, "security-team@example.com",
			time.Now(), time.Now().Add(time.Duration(days)*24*time.Hour),
			MapToKnownRiskSeverity(f.Severity),
		)
		kr.AddTag(f.ScannerName)
		if f.ScannerName == "Trivy" {
			kr.AddTag("container-vulnerability")
		} else if f.ScannerName == "Falco" {
			kr.AddTag("runtime-security")
		}

		proposals = append(proposals, ProposedKnownRisk{
			Finding:          f,
			KnownRisk:        kr,
			Justification:    justif,
			ExpiryDays:       days,
			BusinessImpact:   impact,
			CriticalityScore: score,
		})
	}

	sort.Slice(proposals, func(i, j int) bool {
		return proposals[i].CriticalityScore > proposals[j].CriticalityScore
	})

	return proposals
}

func MapToKnownRiskSeverity(vulnerabilitySeverity types.VulnerabilitySeverity) models.Severity {
	switch vulnerabilitySeverity {
	case types.SeverityCritical:
		return models.SeverityCritical
	case types.SeverityHigh:
		return models.SeverityHigh
	case types.SeverityMedium:
		return models.SeverityMedium
	case types.SeverityLow:
		return models.SeverityLow
	default:
		return models.SeverityLow // Using a defined severity as fallback
	}
}

func alreadyCovered(f types.VulnerabilityFinding, existing []*models.KnownRisk) bool {
	for _, kr := range existing {
		if kr.VulnerabilityID == f.ID &&
			kr.WorkloadInfo.Name == f.WorkloadName &&
			kr.WorkloadInfo.Namespace == f.Namespace {
			return true
		}
	}
	return false
}

func (o *ScanOrchestrator) calculateCriticalityScore(f types.VulnerabilityFinding, impact int) float64 {
	sev := map[types.VulnerabilitySeverity]float64{
		types.SeverityCritical: 1.0,
		types.SeverityHigh:     0.8,
		types.SeverityMedium:   0.5,
		types.SeverityLow:      0.2,
		"":                     0.1,
	}[f.Severity]

	exploit := 1.0
	if f.ExploitAvailable {
		exploit = 1.5
	}
	return sev * exploit * (0.5 + 0.5*float64(impact)/10)
}

func (o *ScanOrchestrator) generateJustification(f types.VulnerabilityFinding) string {
	base := fmt.Sprintf("%s detected in %s. ", f.Title, f.AffectedComponent)
	if f.ScannerName == "Trivy" {
		base += "This vulnerability may have a fix available in a newer version. "
	} else if f.ScannerName == "Falco" {
		base += "This runtime behavior may indicate a security issue. "
	}

	switch f.Severity {
	case types.SeverityCritical:
		base += "This is a critical vulnerability that should be addressed as soon as possible."
	case types.SeverityHigh:
		base += "This high severity issue should be prioritized for remediation."
	case types.SeverityMedium:
		base += "This medium severity issue should be scheduled for remediation in the normal update cycle."
	case types.SeverityLow:
		base += "This low severity issue can be addressed in a future update."
	}
	return base
}
