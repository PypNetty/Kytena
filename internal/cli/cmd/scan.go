package cmd

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/PypNetty/Kytena/internal/knownrisk"
	"github.com/PypNetty/Kytena/internal/scanner"
	"github.com/spf13/cobra"
)

var (
	// Scan command flags
	scanMinSeverity    string
	scanNamespace      string
	scanWorkload       string
	scanMaxResults     int
	scanIgnoreExisting bool
	scanAcceptProposed bool
	scanTimeout        int
)

// scanCmd represents the scan command
var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Run security scans using simulated scanners",
	Long: `Run security scans on your Kubernetes workloads using simulated scanners. 
This command will simulate scanning your workloads for vulnerabilities and runtime issues,
and will provide recommendations for KnownRisks based on the findings.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Create repository
		repo, err := knownrisk.NewFileRepository(GetDataDir())
		if err != nil {
			Fatal("Failed to create repository: %v", err)
		}

		// Create scanner registry
		registry := scanner.NewVulnerabilityScannerRegistry()

		// Register scanners
		registry.RegisterScanner(scanner.NewTrivyScanner())
		registry.RegisterScanner(scanner.NewFalcoScanner())

		// Create scan orchestrator
		orchestrator := scanner.NewScanOrchestrator(registry, repo)

		// Prepare scan options
		options := scanner.ScanOptions{
			MinimumSeverity: scanner.MapSeverity(scanMinSeverity),
			MaxFindings:     scanMaxResults,
			Timeout:         time.Duration(scanTimeout) * time.Second,
		}

		// Add namespace filter if specified
		if scanNamespace != "" {
			options.IncludeNamespaces = strings.Split(scanNamespace, ",")
		}

		// Add workload filter if specified
		if scanWorkload != "" {
			options.IncludeWorkloads = strings.Split(scanWorkload, ",")
		}

		// Create context with timeout
		ctx, cancel := context.WithTimeout(context.Background(), options.Timeout)
		defer cancel()

		// Run scan
		fmt.Println("Running security scans...")
		result, err := orchestrator.Scan(ctx, options)
		if err != nil {
			Fatal("Scan failed: %v", err)
		}

		// Display scan summary
		displayScanSummary(result)

		// Display findings
		if result.Summary.TotalFindings > 0 {
			displayFindings(result, scanIgnoreExisting)
		}

		// Display proposed actions
		if len(result.ProposedActions) > 0 {
			displayProposedActions(result.ProposedActions)

			// Accept proposed KnownRisks if requested
			if scanAcceptProposed {
				acceptProposedKnownRisks(result.ProposedActions, repo)
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)

	// Add flags
	scanCmd.Flags().StringVar(&scanMinSeverity, "min-severity", "Low", "Minimum severity (Critical, High, Medium, Low)")
	scanCmd.Flags().StringVar(&scanNamespace, "namespace", "", "Filter by namespace (comma-separated)")
	scanCmd.Flags().StringVar(&scanWorkload, "workload", "", "Filter by workload name (comma-separated)")
	scanCmd.Flags().IntVar(&scanMaxResults, "max-results", 100, "Maximum number of findings to display")
	scanCmd.Flags().BoolVar(&scanIgnoreExisting, "ignore-existing", false, "Ignore findings that are already covered by existing KnownRisks")
	scanCmd.Flags().BoolVar(&scanAcceptProposed, "accept-proposed", false, "Automatically accept proposed KnownRisks")
	scanCmd.Flags().IntVar(&scanTimeout, "timeout", 60, "Scan timeout in seconds")
}

// displayScanSummary displays a summary of scan results
func displayScanSummary(result *scanner.OrchestratedScanResult) {
	fmt.Println("\n=== Scan Summary ===")
	fmt.Printf("Scan completed in %.2f seconds\n", result.EndTime.Sub(result.StartTime).Seconds())
	fmt.Printf("Total findings: %d\n", result.Summary.TotalFindings)

	// Display findings by severity
	fmt.Println("\nFindings by severity:")
	for _, severity := range []scanner.VulnerabilitySeverity{
		scanner.SeverityCritical, scanner.SeverityHigh,
		scanner.SeverityMedium, scanner.SeverityLow, scanner.SeverityUnknown} {
		count := result.Summary.FindingsBySeverity[severity]
		if count > 0 {
			fmt.Printf("  %s: %d\n", severity, count)
		}
	}

	// Display findings by scanner
	fmt.Println("\nFindings by scanner:")
	for scanner, count := range result.Summary.FindingsByScanner {
		fmt.Printf("  %s: %d\n", scanner, count)
	}

	// Display findings by namespace
	fmt.Println("\nFindings by namespace:")
	var namespaces []string
	for namespace := range result.Summary.FindingsByNamespace {
		namespaces = append(namespaces, namespace)
	}
	sort.Strings(namespaces)
	for _, namespace := range namespaces {
		fmt.Printf("  %s: %d\n", namespace, result.Summary.FindingsByNamespace[namespace])
	}

	// Display proposed actions count
	fmt.Printf("\nProposed KnownRisks: %d\n", len(result.ProposedActions))
}

// displayFindings displays the vulnerability findings
func displayFindings(result *scanner.OrchestratedScanResult, ignoreExisting bool) {
	fmt.Println("\n=== Vulnerability Findings ===")

	// Group findings by severity for better readability
	findingsBySeverity := map[scanner.VulnerabilitySeverity][]scanner.VulnerabilityFinding{}
	for _, finding := range result.AllFindings {
		findingsBySeverity[finding.Severity] = append(findingsBySeverity[finding.Severity], finding)
	}

	// Display findings in order of severity
	severities := []scanner.VulnerabilitySeverity{
		scanner.SeverityCritical,
		scanner.SeverityHigh,
		scanner.SeverityMedium,
		scanner.SeverityLow,
	}

	displayCount := 0
	for _, severity := range severities {
		findings := findingsBySeverity[severity]
		if len(findings) == 0 {
			continue
		}

		fmt.Printf("\n%s Severity (%d findings):\n", severity, len(findings))
		fmt.Println(strings.Repeat("-", 80))

		for i, finding := range findings {
			if displayCount >= scanMaxResults {
				fmt.Printf("... and %d more findings (increase --max-results to see more)\n",
					result.Summary.TotalFindings-displayCount)
				return
			}

			fmt.Printf("%d. %s (%s)\n", i+1, finding.Title, finding.ID)
			fmt.Printf("   Workload: %s/%s (%s)\n",
				finding.Namespace, finding.WorkloadName, finding.ResourceType)
			fmt.Printf("   Component: %s", finding.AffectedComponent)
			if finding.AffectedVersion != "" {
				fmt.Printf(" version %s", finding.AffectedVersion)
			}
			if finding.FixedVersion != "" {
				fmt.Printf(" (fixed in %s)", finding.FixedVersion)
			}
			fmt.Println()

			fmt.Printf("   Scanner: %s\n", finding.ScannerName)
			if finding.ExploitAvailable {
				fmt.Printf("   WARNING: Exploit available in the wild\n")
			}

			if IsVerbose() {
				fmt.Printf("   Description: %s\n", finding.Description)
				if len(finding.References) > 0 {
					fmt.Printf("   References: %s\n", strings.Join(finding.References, ", "))
				}
			}

			fmt.Println(strings.Repeat("-", 80))
			displayCount++
		}
	}
}

// displayProposedActions displays proposed KnownRisks
func displayProposedActions(proposals []scanner.ProposedKnownRisk) {
	fmt.Println("\n=== Proposed KnownRisks ===")

	// Sort proposals by criticality score (highest first)
	sort.Slice(proposals, func(i, j int) bool {
		return proposals[i].CriticalityScore > proposals[j].CriticalityScore
	})

	for i, proposal := range proposals {
		fmt.Printf("\n%d. Proposed KnownRisk for %s (%s)\n",
			i+1, proposal.Finding.ID, proposal.Finding.Title)
		fmt.Printf("   Workload: %s/%s (%s)\n",
			proposal.KnownRisk.WorkloadInfo.Namespace,
			proposal.KnownRisk.WorkloadInfo.Name,
			proposal.KnownRisk.WorkloadInfo.Type)
		fmt.Printf("   Severity: %s\n", proposal.KnownRisk.Severity)
		fmt.Printf("   Business Impact: %d/10\n", proposal.BusinessImpact)
		fmt.Printf("   Suggested Expiry: %d days\n", proposal.ExpiryDays)
		fmt.Printf("   Criticality Score: %.2f\n", proposal.CriticalityScore)
		fmt.Printf("   Justification: %s\n", proposal.Justification)

		fmt.Println(strings.Repeat("-", 80))
	}

	// Instructions for accepting proposals
	if !scanAcceptProposed {
		fmt.Println("\nTo accept these proposed KnownRisks, run the scan command with the --accept-proposed flag.")
	}
}

// acceptProposedKnownRisks saves the proposed KnownRisks to the repository
func acceptProposedKnownRisks(proposals []scanner.ProposedKnownRisk, repo knownrisk.Repository) {
	fmt.Println("\n=== Accepting Proposed KnownRisks ===")

	totalProposals := len(proposals)
	acceptedCount := 0
	errorCount := 0

	for _, proposal := range proposals {
		kr := proposal.KnownRisk

		// Save the KnownRisk
		err := repo.Save(kr)
		if err != nil {
			fmt.Printf("Error saving KnownRisk for %s: %v\n", kr.VulnerabilityID, err)
			errorCount++
			continue
		}

		fmt.Printf("Accepted KnownRisk for %s with ID: %s\n", kr.VulnerabilityID, kr.ID)
		acceptedCount++
	}

	fmt.Printf("\nAccepted %d of %d proposed KnownRisks.", acceptedCount, totalProposals)
	if errorCount > 0 {
		fmt.Printf(" %d errors occurred.", errorCount)
	}
	fmt.Println()
}
