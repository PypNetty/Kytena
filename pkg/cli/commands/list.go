// pkg/cli/commands/list.go
package commands

import (
	"fmt"
	"strings"
	"time"

	"github.com/PypNetty/Kytena/pkg/cli"
	"github.com/PypNetty/Kytena/pkg/models"
	"github.com/PypNetty/Kytena/pkg/storage"
	"github.com/spf13/cobra"
)

// ListOptions contient les options spécifiques à la commande list
type ListOptions struct {
	FilterStatus    string
	FilterSeverity  string
	FilterWorkload  string
	FilterNamespace string
	SortBy          string
	Limit           int
}

// NewListCommand crée une nouvelle commande list
func NewListCommand() *cobra.Command {
	options := ListOptions{
		SortBy: "expiry",
	}

	cmd := cli.NewBaseCommand(
		"list",
		"List all KnownRisks",
		`List all KnownRisks in the system with optional filtering and sorting.
You can filter by status, severity, workload, or namespace.`,
		func(cmd *cobra.Command, args []string, globalOptions cli.GlobalOptions) error {
			return runList(cmd, args, globalOptions, options)
		},
	)

	baseCmd := cmd.Setup()

	// Ajouter les flags spécifiques à la commande list
	baseCmd.Flags().StringVar(&options.FilterStatus, "status", "", "Filter by status (Active, Expired, Resolved)")
	baseCmd.Flags().StringVar(&options.FilterSeverity, "severity", "", "Filter by severity (Critical, High, Medium, Low)")
	baseCmd.Flags().StringVar(&options.FilterWorkload, "workload", "", "Filter by workload name")
	baseCmd.Flags().StringVar(&options.FilterNamespace, "namespace", "", "Filter by namespace")
	baseCmd.Flags().StringVar(&options.SortBy, "sort", "expiry", "Sort by field (expiry, severity, workload)")
	baseCmd.Flags().IntVar(&options.Limit, "limit", 0, "Limit number of results (0 = no limit)")

	return baseCmd
}

// runList exécute la commande list
func runList(_ *cobra.Command, _ []string, globalOptions cli.GlobalOptions, options ListOptions) error {
	// Créer le repository
	repo, err := cli.CreateRepository(globalOptions)
	if err != nil {
		return fmt.Errorf("failed to create repository: %w", err)
	}

	// Préparer les options de filtrage
	filter := storage.Filter{
		Status:    options.FilterStatus,
		Severity:  options.FilterSeverity,
		Workload:  options.FilterWorkload,
		Namespace: options.FilterNamespace,
	}

	// Préparer les options de tri
	sortOptions := storage.SortOptions{
		Field:     options.SortBy,
		Direction: "asc",
	}

	// Si on trie par expiry, on veut les plus proches en premier
	if options.SortBy == "expiry" {
		sortOptions.Direction = "asc"
	}

	// Lister les KnownRisks
	listOptions := storage.ListOptions{
		Filter: filter,
		Sort:   sortOptions,
		Limit:  options.Limit,
	}

	knownRisks, err := repo.List(globalOptions.Context, listOptions)
	if err != nil {
		return fmt.Errorf("failed to list KnownRisks: %w", err)
	}

	// Afficher les résultats
	displayRisks(knownRisks, globalOptions.Verbose)

	return nil
}

// displayRisks affiche les KnownRisks de manière formatée
func displayRisks(risks []*models.KnownRisk, verbose bool) {
	if len(risks) == 0 {
		fmt.Println("No KnownRisks found matching the criteria.")
		return
	}

	fmt.Printf("Found %d KnownRisks\n", len(risks))
	fmt.Println(strings.Repeat("-", 80))

	for i, kr := range risks {
		// Calculer le temps jusqu'à l'expiration
		timeUntilExpiry := kr.ExpiresAt.Sub(time.Now())
		var expiryInfo string
		if timeUntilExpiry > 0 {
			expiryInfo = fmt.Sprintf("Expires in: %.1f days", timeUntilExpiry.Hours()/24)
		} else {
			expiryInfo = fmt.Sprintf("Expired: %.1f days ago", -timeUntilExpiry.Hours()/24)
		}

		fmt.Printf("%d. %s (%s)\n", i+1, kr.VulnerabilityID, kr.ID)
		fmt.Printf("  Workload: %s/%s (%s)\n",
			kr.WorkloadInfo.Namespace,
			kr.WorkloadInfo.Name,
			kr.WorkloadInfo.Type)
		fmt.Printf("  Severity: %s | Status: %s | %s\n",
			kr.Severity,
			kr.Status,
			expiryInfo)
		fmt.Printf("  Accepted by: %s on %s\n",
			kr.AcceptedBy,
			kr.AcceptedAt.Format("2006-01-02"))

		if verbose {
			fmt.Printf("  Justification: %s\n", kr.Justification)
			if len(kr.Tags) > 0 {
				fmt.Printf("  Tags: %s\n", strings.Join(kr.Tags, ", "))
			}
			if len(kr.RelatedTickets) > 0 {
				fmt.Printf("  Tickets: %s\n", strings.Join(kr.RelatedTickets, ", "))
			}
		}

		fmt.Println(strings.Repeat("-", 80))
	}
}
