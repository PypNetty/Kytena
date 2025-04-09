package commands

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/PypNetty/Kytena/pkg/cli/common"
	"github.com/PypNetty/Kytena/pkg/scanner"
	"github.com/PypNetty/Kytena/pkg/scanner/types"
	"github.com/PypNetty/Kytena/pkg/storage"
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

func NewScanCommand() *cobra.Command {
	options := &ScanOptions{
		MinSeverity:    "Low",
		MaxResults:     100,
		Timeout:        300,
		TrivyPath:      "trivy",
		TrivyCachePath: ".trivy-cache",
	}
	baseCmd := common.CreateBaseCommand("scan", "Run security scans on Kubernetes workloads",
		`Run security scans on your Kubernetes workloads using various scanners.
This command will scan your workloads for vulnerabilities and runtime issues,
and will provide recommendations for KnownRisks based on the findings.`,
		func(cmd *cobra.Command, args []string, globalOptions common.GlobalOptions) error {
			return runScan(cmd.Context(), options, &globalOptions)
		},
	)
	cmd := baseCmd.Setup()

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

func runScan(ctx context.Context, options *ScanOptions, globalOpts *common.GlobalOptions) error {
	// Créer le repository avec les options globales
	repo, err := storage.NewFileRepository(globalOpts.DataDir)
	if err != nil {
		return fmt.Errorf("failed to create repository: %w", err)
	}

	// Adapter le repository au format attendu
	repoAdapter := &scanner.RepositoryAdapter{
		Repository: repo,
		Logger:     globalOpts.Logger,
	}

	// Créer le registry de scanners
	registry := scanner.NewVulnerabilityScannerRegistry()

	// Création du scanner Trivy avec le logger
	trivyScanner := scanner.NewTrivyScanner(globalOpts.Logger)

	// Configure les options pour Trivy via une fonction ou un setter
	trivyConfig := map[string]interface{}{
		"binaryPath": options.TrivyPath,
		"cachePath":  options.TrivyCachePath,
		"noCache":    options.TrivyNoCache,
		"updateDB":   options.TrivyUpdateDB,
		"skipFS":     options.TrivySkipFS,
		"extraArgs":  strings.Split(options.TrivyCustomArgs, ","),
		"timeout":    time.Duration(options.Timeout) * time.Second,
	}

	// Configurer le scanner - supposons que cette méthode existe
	trivyScanner.Configure(trivyConfig)

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
	common.PrintInfo("Starting security scan...")
	result, err := orchestrator.Scan(ctx, scanOptions)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	// Afficher les résultats
	displayScanResults(result, options.IgnoreExisting, options.MaxResults)

	// Accepter les actions proposées si demandé
	if options.AcceptProposed && len(result.ProposedActions) > 0 {
		if err := acceptProposedKnownRisks(ctx, result.ProposedActions, repoAdapter); err != nil {
			common.PrintError("Failed to accept proposed KnownRisks: %v", err)
		}
	}

	return nil
}

// displayScanResults affiche tous les résultats du scan
func displayScanResults(result *scanner.OrchestratedScanResult, ignoreExisting bool, maxResults int) {
	duration := result.EndTime.Sub(result.StartTime)

	common.PrintInfo("Scan completed in %s", common.FormatDuration(duration))
	common.PrintInfo("Total findings: %d", result.Summary.TotalFindings)

	if result.Summary.TotalFindings > 0 {
		displayScanSummary(result.Summary)

		if len(result.AllFindings) > 0 {
			displayFindings(result.AllFindings, result.ProposedActions, ignoreExisting, maxResults)
		}

		if len(result.ProposedActions) > 0 {
			displayProposedActions(result.ProposedActions)
		}
	} else {
		common.PrintInfo("No vulnerabilities found matching the criteria")
	}
}

// displayScanSummary affiche le résumé des résultats du scan
func displayScanSummary(summary scanner.ScanSummary) {
	// Afficher par sévérité
	severityRows := [][]string{}
	for _, sev := range []types.VulnerabilitySeverity{
		types.SeverityCritical,
		types.SeverityHigh,
		types.SeverityMedium,
		types.SeverityLow,
	} {
		if count := summary.FindingsBySeverity[sev]; count > 0 {
			severityRows = append(severityRows, []string{string(sev), fmt.Sprintf("%d", count)})
		}
	}

	if len(severityRows) > 0 {
		common.PrintInfo("Findings by severity:")
		common.PrintTable([]string{"SEVERITY", "COUNT"}, severityRows)
	}

	// Afficher par namespace si disponible
	if len(summary.FindingsByNamespace) > 0 {
		namespaceRows := [][]string{}
		for ns, count := range summary.FindingsByNamespace {
			namespaceRows = append(namespaceRows, []string{ns, fmt.Sprintf("%d", count)})
		}

		common.PrintInfo("Findings by namespace:")
		common.PrintTable([]string{"NAMESPACE", "COUNT"}, namespaceRows)
	}
}

// displayFindings affiche les vulnérabilités trouvées
func displayFindings(findings []types.VulnerabilityFinding, proposals []scanner.ProposedKnownRisk, ignoreExisting bool, maxResults int) {
	// Filtrer les findings
	var filtered []types.VulnerabilityFinding

	for _, finding := range findings {
		if ignoreExisting && isProposed(finding, proposals) {
			continue
		}

		filtered = append(filtered, finding)

		if maxResults > 0 && len(filtered) >= maxResults {
			break
		}
	}

	if len(filtered) == 0 {
		common.PrintInfo("No findings to display after filtering")
		return
	}

	// Préparer les données pour l'affichage
	rows := make([][]string, len(filtered))
	for i, f := range filtered {
		rows[i] = []string{
			string(f.Severity),
			f.Title,
			f.AffectedComponent,
			fmt.Sprintf("%s/%s", f.Namespace, f.ResourceID),
		}
	}

	common.PrintInfo("Vulnerability findings:")
	common.PrintTable([]string{"SEVERITY", "TITLE", "COMPONENT", "LOCATION"}, rows)
}

// isProposed vérifie si une vulnérabilité fait partie des propositions
func isProposed(finding types.VulnerabilityFinding, proposals []scanner.ProposedKnownRisk) bool {
	for _, prop := range proposals {
		if prop.Finding.ID == finding.ID {
			return true
		}
	}
	return false
}

// displayProposedActions affiche les KnownRisks proposés
func displayProposedActions(proposals []scanner.ProposedKnownRisk) {
	rows := make([][]string, len(proposals))
	for i, prop := range proposals {
		rows[i] = []string{
			string(prop.Finding.Severity),
			prop.Finding.Title,
			fmt.Sprintf("%.2f", prop.CriticalityScore),
			fmt.Sprintf("%d days", prop.ExpiryDays),
			truncateString(prop.Justification, 50),
		}
	}

	common.PrintInfo("Proposed KnownRisks (%d):", len(proposals))
	common.PrintTable([]string{"SEVERITY", "TITLE", "IMPACT", "EXPIRES IN", "JUSTIFICATION"}, rows)
}

// truncateString limite la longueur d'une chaîne et ajoute "..." si nécessaire
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// acceptProposedKnownRisks enregistre les KnownRisks proposés
func acceptProposedKnownRisks(ctx context.Context, proposals []scanner.ProposedKnownRisk, repo scanner.Repository) error {
	common.PrintInfo("Accepting proposed KnownRisks...")

	var errors []string
	accepted := 0

	for i, prop := range proposals {
		common.PrintInfo("Processing %d/%d: %s", i+1, len(proposals), prop.Finding.Title)

		if err := repo.Save(ctx, prop.KnownRisk); err != nil {
			errors = append(errors, fmt.Sprintf("Failed to save '%s': %v", prop.Finding.Title, err))
		} else {
			accepted++
		}
	}

	common.PrintInfo("Successfully accepted %d/%d KnownRisks", accepted, len(proposals))

	if len(errors) > 0 {
		return fmt.Errorf("errors occurred while accepting KnownRisks: %s", strings.Join(errors, "; "))
	}

	return nil
}
