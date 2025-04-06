package cmd

import (
	"fmt"
	"strings"
	"time"

	"github.com/PypNetty/Kyra/internal/knownrisk"
	"github.com/spf13/cobra"
)

var (
	// List command flags
	filterStatus    string
	filterSeverity  string
	filterWorkload  string
	filterNamespace string
	sortBy          string
	limit           int
)

// listCmd represents the list command
var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all KnownRisks",
	Long: `List all KnownRisks in the system with optional filtering and sorting.
You can filter by status, severity, workload, or namespace.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Create repository
		repo, err := knownrisk.NewFileRepository(GetDataDir())
		if err != nil {
			Fatal("Failed to create repository: %v", err)
		}

		// Get all KnownRisks
		risks, err := repo.List()
		if err != nil {
			Fatal("Failed to list KnownRisks: %v", err)
		}

		// Filter results
		filtered := filterRisks(risks)

		// Sort results
		sortRisks(filtered)

		// Apply limit
		if limit > 0 && limit < len(filtered) {
			filtered = filtered[:limit]
		}

		// Display results
		displayRisks(filtered)
	},
}

// GetDataDir returns the directory where data files are stored
func GetDataDir() string {

	return "./data"
}

func init() {
	rootCmd.AddCommand(listCmd)

	// Add flags for filtering and sorting
	listCmd.Flags().StringVar(&filterStatus, "status", "", "Filter by status (Active, Expired, Resolved)")
	listCmd.Flags().StringVar(&filterSeverity, "severity", "", "Filter by severity (Critical, High, Medium, Low)")
	listCmd.Flags().StringVar(&filterWorkload, "workload", "", "Filter by workload name")
	listCmd.Flags().StringVar(&filterNamespace, "namespace", "", "Filter by namespace")
	listCmd.Flags().StringVar(&sortBy, "sort", "expiry", "Sort by field (expiry, severity, workload)")
	listCmd.Flags().IntVar(&limit, "limit", 0, "Limit number of results (0 = no limit)")
}

// filterRisks applies filters to the list of KnownRisks
func filterRisks(risks []*knownrisk.KnownRisk) []*knownrisk.KnownRisk {
	var result []*knownrisk.KnownRisk

	for _, r := range risks {
		// Apply status filter
		if filterStatus != "" && string(r.Status) != filterStatus {
			continue
		}

		// Apply severity filter
		if filterSeverity != "" && string(r.Severity) != filterSeverity {
			continue
		}

		// Apply workload filter
		if filterWorkload != "" && !strings.Contains(r.WorkloadInfo.Name, filterWorkload) {
			continue
		}

		// Apply namespace filter
		if filterNamespace != "" && r.WorkloadInfo.Namespace != filterNamespace {
			continue
		}

		// All filters passed, include in results
		result = append(result, r)
	}

	return result
}

// sortRisks sorts the list of KnownRisks
func sortRisks(risks []*knownrisk.KnownRisk) {
	// Implement sorting based on sortBy
	// This is left as a simplification for now
}

// displayRisks prints the KnownRisks in a formatted way
func displayRisks(risks []*knownrisk.KnownRisk) {
	if len(risks) == 0 {
		fmt.Println("No KnownRisks found matching the criteria.")
		return
	}

	fmt.Printf("Found %d KnownRisks\n", len(risks))
	fmt.Println(strings.Repeat("-", 80))

	for i, kr := range risks {
		// Calculate time until expiry
		timeUntilExpiry := kr.ExpiresAt.Sub(time.Now())
		var expiryInfo string
		if timeUntilExpiry > 0 {
			expiryInfo = fmt.Sprintf("Expires in: %.1f days", timeUntilExpiry.Hours()/24)
		} else {
			expiryInfo = fmt.Sprintf("Expired: %.1f days ago", -timeUntilExpiry.Hours()/24)
		}

		fmt.Printf("%d. %s (%s)\n", i+1, kr.VulnerabilityID, kr.ID)
		fmt.Printf("   Workload: %s/%s (%s)\n",
			kr.WorkloadInfo.Namespace,
			kr.WorkloadInfo.Name,
			kr.WorkloadInfo.Type)
		fmt.Printf("   Severity: %s | Status: %s | %s\n",
			kr.Severity,
			kr.Status,
			expiryInfo)
		fmt.Printf("   Accepted by: %s on %s\n",
			kr.AcceptedBy,
			kr.AcceptedAt.Format("2006-01-02"))

		if IsVerbose() {
			fmt.Printf("   Justification: %s\n", kr.Justification)
			if len(kr.Tags) > 0 {
				fmt.Printf("   Tags: %s\n", strings.Join(kr.Tags, ", "))
			}
			if len(kr.RelatedTickets) > 0 {
				fmt.Printf("   Tickets: %s\n", strings.Join(kr.RelatedTickets, ", "))
			}
		}

		fmt.Println(strings.Repeat("-", 80))
	}
}
