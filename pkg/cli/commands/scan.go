// pkg/cli/commands/scan.go
package commands

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/PypNetty/Kytena/pkg/cli"
	"github.com/PypNetty/Kytena/pkg/scanner"
	"github.com/spf13/cobra"
)

// ScanOptions contient les options spécifiques à la commande scan
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

// NewScanCommand crée une nouvelle commande de scan
func NewScanCommand() *cobra.Command {
	options := ScanOptions{
		MinSeverity:    "Low",
		MaxResults:     100,
		Timeout:        300,
		TrivyPath:      "trivy",
		TrivyCachePath: ".trivy-cache",
	}

	cmd := cli.NewBaseCommand(
		"scan",
		"Run security scans on Kubernetes workloads",
		`Run security scans on your Kubernetes workloads using various scanners.
This command will scan your workloads for vulnerabilities and runtime issues,
and will provide recommendations for KnownRisks based on the findings.

Examples:
  # Scan all workloads with default settings
  kytena scan
  
  # Scan workloads in a specific namespace
  kytena scan --namespace production
  
  # Only show critical and high severity vulnerabilities
  kytena scan --min-severity High
  
  # Update Trivy database before scanning
  kytena scan --trivy-update-db
  
  # Use a custom path for Trivy
  kytena scan --trivy-path /usr/local/bin/trivy`,
		func(cmd *cobra.Command, args []string, globalOptions cli.GlobalOptions) error {
			return runScan(cmd, args, globalOptions, options)
		},
	)

	baseCmd := cmd.Setup()

	// Ajouter les flags spécifiques à la commande scan
	baseCmd.Flags().StringVar(&options.MinSeverity, "min-severity", options.MinSeverity, "Minimum severity (Critical, High, Medium, Low)")
	baseCmd.Flags().StringVar(&options.Namespace, "namespace", options.Namespace, "Filter by namespace (comma-separated)")
	baseCmd.Flags().StringVar(&options.Workload, "workload", options.Workload, "Filter by workload name (comma-separated)")
	baseCmd.Flags().IntVar(&options.MaxResults, "max-results", options.MaxResults, "Maximum number of findings to display")
	baseCmd.Flags().BoolVar(&options.IgnoreExisting, "ignore-existing", options.IgnoreExisting, "Ignore findings that are already covered by existing KnownRisks")
	baseCmd.Flags().BoolVar(&options.AcceptProposed, "accept-proposed", options.AcceptProposed, "Automatically accept proposed KnownRisks")
	baseCmd.Flags().IntVar(&options.Timeout, "timeout", options.Timeout, "Scan timeout in seconds")

	// Ajouter les flags spécifiques à Trivy
	baseCmd.Flags().StringVar(&options.TrivyPath, "trivy-path", options.TrivyPath, "Path to Trivy executable")
	baseCmd.Flags().BoolVar(&options.TrivyNoCache, "trivy-no-cache", options.TrivyNoCache, "Disable Trivy cache")
	baseCmd.Flags().StringVar(&options.TrivyCachePath, "trivy-cache-path", options.TrivyCachePath, "Path for Trivy cache directory")
	baseCmd.Flags().BoolVar(&options.TrivyUpdateDB, "trivy-update-db", options.TrivyUpdateDB, "Update Trivy vulnerability database before scanning")
	baseCmd.Flags().BoolVar(&options.TrivySkipFS, "trivy-skip-fs", options.TrivySkipFS, "Skip filesystem scanning and only scan container images")
	baseCmd.Flags().StringVar(&options.TrivyCustomArgs, "trivy-args", options.TrivyCustomArgs, "Custom arguments passed to Trivy (comma-separated)")

	// Ajouter les flags pour Kubernetes
	baseCmd.Flags().BoolVar(&options.UseRealK8s, "use-real-k8s", options.UseRealK8s, "Use real Kubernetes workloads instead of simulated ones")

	return baseCmd
}

// runScan exécute la commande de scan
func runScan(_ *cobra.Command, _ []string, globalOptions cli.GlobalOptions, options ScanOptions) error {
	// Créer le repository
	repo, err := cli.CreateRepository(globalOptions)
	if err != nil {
		cli.Fatal("Failed to create repository: %v", err)
	}

	// Créer le registre de scanners
	registry := cli.CreateScannerRegistry(globalOptions)

	// Configurer le scanner Trivy
	trivyScanner, found := registry.GetScanner("Trivy")
	if found {
		trivyConfig := map[string]interface{}{
			"binaryPath":     options.TrivyPath,
			"minSeverity":    options.MinSeverity,
			"cacheEnabled":   !options.TrivyNoCache,
			"cachePath":      options.TrivyCachePath,
			"timeoutSeconds": options.Timeout,
		}

		// Ajouter les arguments personnalisés si fournis
		if options.TrivyCustomArgs != "" {
			trivyConfig["extraArgs"] = strings.Split(options.TrivyCustomArgs, ",")
		}

		// Configurer le scanner
		if err := trivyScanner.SetConfig(trivyConfig); err != nil {
			globalOptions.Logger.Warnf("Error configuring Trivy scanner: %v", err)
			globalOptions.Logger.Warn("Will use default configuration")
		}
	}

	// Créer l'orchestrateur de scan
	orchestrator := scanner.NewScanOrchestrator(registry, repo, globalOptions.Logger)

	// Préparer les options de scan
	scanOptions := scanner.ScanOptions{
		MinimumSeverity: scanner.MapSeverity(options.MinSeverity),
		MaxFindings:     options.MaxResults,
		Timeout:         time.Duration(options.Timeout) * time.Second,
		ScannerSpecific: map[string]interface{}{
			"updateDB":       options.TrivyUpdateDB,
			"skipFileSystem": options.TrivySkipFS,
			"useRealK8s":     options.UseRealK8s,
		},
	}

	// Ajouter le kubeconfig si spécifié
	if globalOptions.KubeConfig != "" {
		scanOptions.ScannerSpecific["kubeconfig"] = globalOptions.KubeConfig
	}

	// Ajouter le filtre de namespace si spécifié
	if options.Namespace != "" {
		scanOptions.IncludeNamespaces = strings.Split(options.Namespace, ",")
	}

	// Ajouter le filtre de workload si spécifié
	if options.Workload != "" {
		scanOptions.IncludeWorkloads = strings.Split(options.Workload, ",")
	}

	// Exécuter le scan
	cli.PrintInfo("Running security scans...")

	result, err := orchestrator.Scan(globalOptions.Context, scanOptions)
	if err != nil {
		cli.Fatal("Scan failed: %v", err)
	}

	// Afficher le résumé du scan
	displayScanSummary(result)

	// Afficher les résultats
	if result.Summary.TotalFindings > 0 {
		displayFindings(result, options.IgnoreExisting, options.MaxResults)
	}

	// Afficher les actions proposées
	if len(result.ProposedActions) > 0 {
		displayProposedActions(result.ProposedActions)

		// Accepter les actions proposées si demandé
		if options.AcceptProposed {
			acceptProposedKnownRisks(result.ProposedActions, repo, globalOptions.Context)
		}
	}

	return nil
}

// displayScanSummary affiche un résumé des résultats du scan
func displayScanSummary(result *scanner.OrchestratedScanResult) {
	fmt.Println("\n=== Scan Summary ===")
	fmt.Printf("Scan completed in %.2f seconds\n", result.EndTime.Sub(result.StartTime).Seconds())
	fmt.Printf("Total findings: %d\n", result.Summary.TotalFindings)

	// Afficher les résultats par sévérité
	fmt.Println("\nFindings by severity:")
	for _, severity := range []scanner.VulnerabilitySeverity{
		scanner.SeverityCritical, scanner.SeverityHigh,
		scanner.SeverityMedium, scanner.SeverityLow, scanner.SeverityUnknown} {
		count := result.Summary.FindingsBySeverity[severity]
		if count > 0 {
			fmt.Printf(" %s: %d\n", severity, count)
		}
	}

	// Afficher les résultats par scanner
	fmt.Println("\nFindings by scanner:")
	for scanner, count := range result.Summary.FindingsByScanner {
		fmt.Printf(" %s: %d\n", scanner, count)
	}

	// Afficher les résultats par namespace
	fmt.Println("\nFindings by namespace:")
	var namespaces []string
	for namespace := range result.Summary.FindingsByNamespace {
		namespaces = append(namespaces, namespace)
	}
	sort.Strings(namespaces)
	for _, namespace := range namespaces {
		fmt.Printf(" %s: %d\n", namespace, result.Summary.FindingsByNamespace[namespace])
	}

	// Afficher le nombre d'actions proposées
	fmt.Printf("\nProposed KnownRisks: %d\n", len(result.ProposedActions))
}

// displayFindings affiche les résultats des vulnérabilités
func displayFindings(result *scanner.OrchestratedScanResult, ignoreExisting bool, maxResults int) {
	fmt.Println("\n=== Vulnerability Findings ===")

	// Code pour afficher les résultats
	// ...
}

// displayProposedActions affiche les KnownRisks proposés
func displayProposedActions(proposals []scanner.ProposedKnownRisk) {
	fmt.Println("\n=== Proposed KnownRisks ===")

	// Code pour afficher les propositions
	// ...
}

// acceptProposedKnownRisks enregistre les KnownRisks proposés dans le repository
func acceptProposedKnownRisks(proposals []scanner.ProposedKnownRisk, repo storage.Repository, ctx context.Context) {
	fmt.Println("\n=== Accepting Proposed KnownRisks ===")

	// Code pour accepter les propositions
	// ...
}
