package commands

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/PypNetty/Kytena/pkg/cli"
	"github.com/PypNetty/Kytena/pkg/models"
	"github.com/PypNetty/Kytena/pkg/scanner"
	"github.com/PypNetty/Kytena/pkg/scanner/types"
	"github.com/PypNetty/Kytena/pkg/storage"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

type ScanOptions struct {
	MinSeverity     string
	Namespace       string
	Workload        string
	MaxResults      int
	IgnoreExisting  bool
	AcceptProposed  bool
	Timeout         int
	UseRealK8s      bool
	TrivyPath       string
	TrivyNoCache    bool
	TrivyCachePath  string
	TrivyUpdateDB   bool
	TrivySkipFS     bool
	TrivyCustomArgs string
}

func NewScanCommand(globalOpts *cli.GlobalOptions) *cobra.Command {
	options := &ScanOptions{
		MinSeverity:    "Low",
		MaxResults:     100,
		Timeout:        300,
		TrivyPath:      "trivy",
		TrivyCachePath: ".trivy-cache",
	}

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Run security scans on Kubernetes workloads",
		Long: `Run security scans on your Kubernetes workloads using various scanners.
This command will scan your workloads for vulnerabilities and runtime issues,
and will provide recommendations for KnownRisks based on the findings.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runScan(cmd.Context(), options, globalOpts)
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&options.MinSeverity, "min-severity", options.MinSeverity, "Minimum severity (Critical, High, Medium, Low)")
	flags.StringVar(&options.Namespace, "namespace", "", "Filter by namespace (comma-separated)")
	flags.StringVar(&options.Workload, "workload", "", "Filter by workload name (comma-separated)")
	flags.IntVar(&options.MaxResults, "max-results", options.MaxResults, "Maximum number of findings to display")
	flags.BoolVar(&options.IgnoreExisting, "ignore-existing", false, "Ignore findings covered by existing KnownRisks")
	flags.BoolVar(&options.AcceptProposed, "accept-proposed", false, "Automatically accept proposed KnownRisks")
	flags.IntVar(&options.Timeout, "timeout", options.Timeout, "Scan timeout in seconds")
	flags.BoolVar(&options.UseRealK8s, "use-real-k8s", false, "Use real Kubernetes cluster")
	flags.StringVar(&options.TrivyPath, "trivy-path", options.TrivyPath, "Path to Trivy executable")
	flags.BoolVar(&options.TrivyNoCache, "trivy-no-cache", false, "Disable Trivy cache")
	flags.StringVar(&options.TrivyCachePath, "trivy-cache-path", options.TrivyCachePath, "Path for Trivy cache")
	flags.BoolVar(&options.TrivyUpdateDB, "trivy-update-db", false, "Update Trivy vulnerability database")
	flags.BoolVar(&options.TrivySkipFS, "trivy-skip-fs", false, "Skip filesystem scanning")
	flags.StringVar(&options.TrivyCustomArgs, "trivy-args", "", "Custom arguments for Trivy (comma-separated)")

	return cmd
}

// Wrapper pour implémenter storage.Repository
type repositoryAdapter struct {
	repo   *storage.FileRepository
	logger *logrus.Logger
}

// Delete implements storage.Repository.
func (r *repositoryAdapter) Delete(ctx context.Context, id string) error {
	panic("unimplemented")
}

// Get implements storage.Repository.
func (r *repositoryAdapter) Get(ctx context.Context, id string) (*models.KnownRisk, error) {
	panic("unimplemented")
}

// GetByVulnerabilityID implements storage.Repository.
func (r *repositoryAdapter) GetByVulnerabilityID(ctx context.Context, vulnerabilityID string) ([]*models.KnownRisk, error) {
	panic("unimplemented")
}

// GetByWorkload implements storage.Repository.
func (r *repositoryAdapter) GetByWorkload(ctx context.Context, namespace string, name string) ([]*models.KnownRisk, error) {
	panic("unimplemented")
}

// Save implements storage.Repository.
func (r *repositoryAdapter) Save(ctx context.Context, kr *models.KnownRisk) error {
	panic("unimplemented")
}

// Update implements storage.Repository.
func (r *repositoryAdapter) Update(ctx context.Context, kr *models.KnownRisk) error {
	panic("unimplemented")
}

// Implémentation de storage.Repository
func (r *repositoryAdapter) CreateKnownRisk(ctx context.Context, knownRisk *models.KnownRisk) error {
	// Implémenter cette méthode en appelant la méthode appropriée de FileRepository
	return r.repo.Create(ctx, knownRisk)
}

func (r *repositoryAdapter) List(ctx context.Context, options storage.ListOptions) ([]*models.KnownRisk, error) {
	// Implémenter cette méthode en appelant la méthode appropriée de FileRepository
	result, err := r.repo.List(ctx, options)
	if err != nil {
		return nil, err
	}

	// Conversion du résultat au type attendu
	var knownRisks []*models.KnownRisk
	for _, item := range result.([]*models.KnownRisk) {
		knownRisks = append(knownRisks, item)
	}

	return knownRisks, nil
}

func (r *repositoryAdapter) CountBySeverity(ctx context.Context) (map[models.Severity]int, error) {
	// Implémentation pour compter par sévérité
	return make(map[models.Severity]int), nil
}

func (r *repositoryAdapter) CountByStatus(ctx context.Context) (map[models.Status]int, error) {
	// Implémentation pour compter par statut
	return make(map[models.Status]int), nil
}

// Implémenter d'autres méthodes requises par l'interface storage.Repository

func runScan(ctx context.Context, options *ScanOptions, globalOpts *cli.GlobalOptions) error {
	// Créer le repository avec les options globales
	repo, err := storage.NewFileRepository(globalOpts.DataDir)
	if err != nil {
		return fmt.Errorf("failed to create repository: %w", err)
	}

	// Ajout de l'adaptateur pour que FileRepository implémente storage.Repository
	repoAdapter := &repositoryAdapter{
		repo:   repo,
		logger: globalOpts.Logger,
	}

	// Créer le registry de scanners
	registry := scanner.NewVulnerabilityScannerRegistry()

	// Création du scanner Trivy avec le logger
	trivyScanner := scanner.NewTrivyScanner(globalOpts.Logger)

	// Configure les options pour Trivy via une fonction ou un setter
	// Si le scanner expose une méthode de configuration
	trivyScanner.Configure(map[string]interface{}{
		"binaryPath": options.TrivyPath,
		"cachePath":  options.TrivyCachePath,
		"noCache":    options.TrivyNoCache,
		"updateDB":   options.TrivyUpdateDB,
		"skipFS":     options.TrivySkipFS,
		"extraArgs":  strings.Split(options.TrivyCustomArgs, ","),
		"timeout":    time.Duration(options.Timeout) * time.Second,
	})

	registry.RegisterScanner(trivyScanner)

	// Créer l'orchestrateur de scan
	orchestrator := scanner.NewScanOrchestrator(registry, repoAdapter, globalOpts.Logger)

	// Configurer les options de scan
	scanOptions := types.ScanOptions{
		MinimumSeverity: types.VulnerabilitySeverity(strings.ToUpper(options.MinSeverity)),
		MaxFindings:     options.MaxResults,
	}

	if options.Namespace != "" {
		scanOptions.IncludeNamespaces = strings.Split(options.Namespace, ",")
	}
	if options.Workload != "" {
		scanOptions.IncludeWorkloads = strings.Split(options.Workload, ",")
	}

	// Exécuter le scan
	globalOpts.Logger.Info("Starting security scan...")
	result, err := orchestrator.Scan(ctx, scanOptions)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	// Afficher les résultats
	displayScanSummary(result)

	if result.Summary.TotalFindings > 0 {
		displayFindings(result, options.IgnoreExisting, options.MaxResults)

		if len(result.ProposedActions) > 0 {
			displayProposedActions(result.ProposedActions)

			if options.AcceptProposed {
				if err := acceptProposedKnownRisks(ctx, result.ProposedActions, repoAdapter); err != nil {
					globalOpts.Logger.Errorf("Failed to accept proposed KnownRisks: %v", err)
				}
			}
		}
	}

	return nil
}

func displayScanSummary(result *scanner.OrchestratedScanResult) {
	fmt.Printf("\nScan completed in %.2f seconds\n", result.EndTime.Sub(result.StartTime).Seconds())
	fmt.Printf("Total findings: %d\n\n", result.Summary.TotalFindings)

	if result.Summary.TotalFindings > 0 {
		fmt.Println("Findings by severity:")
		for _, sev := range []types.VulnerabilitySeverity{
			types.SeverityCritical,
			types.SeverityHigh,
			types.SeverityMedium,
			types.SeverityLow,
		} {
			if count := result.Summary.FindingsBySeverity[sev]; count > 0 {
				fmt.Printf("  %s: %d\n", sev, count)
			}
		}
	}
}

func displayFindings(result *scanner.OrchestratedScanResult, ignoreExisting bool, maxResults int) {
	displayed := 0
	for _, finding := range result.AllFindings {
		// Vérification si on doit ignorer ce finding
		if ignoreExisting {
			// Si le finding doit être ignoré, vérifier si une des propositions d'action
			// est basée sur un KnownRisk existant
			shouldIgnore := false
			for _, prop := range result.ProposedActions {
				if prop.Finding.ID == finding.ID {
					// Vérifier si c'est déjà couvert
					// Noter que nous devons adapter cette logique selon la structure réelle
					shouldIgnore = true
					break
				}
			}

			if shouldIgnore {
				continue
			}
		}

		if maxResults > 0 && displayed >= maxResults {
			break
		}

		fmt.Printf("\nFinding: %s\n", finding.Title)
		fmt.Printf("Severity: %s\n", finding.Severity)
		fmt.Printf("Location: %s/%s\n", finding.Namespace, finding.ResourceID)
		fmt.Printf("Description: %s\n", finding.Description)

		displayed++
	}
}

func displayProposedActions(proposals []scanner.ProposedKnownRisk) {
	fmt.Printf("\nProposed actions (%d):\n", len(proposals))
	for i, prop := range proposals {
		fmt.Printf("\n%d. %s\n", i+1, prop.Finding.Title)
		fmt.Printf("   Severity: %s\n", prop.Finding.Severity)
		fmt.Printf("   Impact Score: %.2f\n", prop.CriticalityScore)
		fmt.Printf("   Expires in: %d days\n", prop.ExpiryDays)
		fmt.Printf("   Justification: %s\n", prop.Justification)
	}
}

func acceptProposedKnownRisks(ctx context.Context, proposals []scanner.ProposedKnownRisk, repo storage.Repository) error {
	for _, prop := range proposals {
		// Utiliser la méthode Save pour enregistrer les KnownRisks
		if err := repo.Save(ctx, prop.KnownRisk); err != nil {
			return fmt.Errorf("failed to create KnownRisk for %s: %w", prop.Finding.Title, err)
		}
	}
	return nil
}
