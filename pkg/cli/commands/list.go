// pkg/cli/commands/list.go
package commands

import (
	"fmt"
	"strings"
	"time"

	"github.com/PypNetty/kytena/pkg/cli/common"
	"github.com/PypNetty/kytena/pkg/models"
	"github.com/PypNetty/kytena/pkg/storage"
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

	baseCmd := common.CreateBaseCommand(
		"list",
		"List all KnownRisks",
		`List all KnownRisks in the system with optional filtering and sorting.
You can filter by status, severity, workload, or namespace.`,
		func(cmd *cobra.Command, args []string, globalOptions common.GlobalOptions) error {
			return runList(cmd, args, globalOptions, options)
		},
	)

	cmd := baseCmd.Setup()

	// Ajouter les flags spécifiques à la commande list
	cmd.Flags().StringVar(&options.FilterStatus, "status", "", "Filter by status (Active, Expired, Resolved)")
	cmd.Flags().StringVar(&options.FilterSeverity, "severity", "", "Filter by severity (Critical, High, Medium, Low)")
	cmd.Flags().StringVar(&options.FilterWorkload, "workload", "", "Filter by workload name")
	cmd.Flags().StringVar(&options.FilterNamespace, "namespace", "", "Filter by namespace")
	cmd.Flags().StringVar(&options.SortBy, "sort", "expiry", "Sort by field (expiry, severity, workload)")
	cmd.Flags().IntVar(&options.Limit, "limit", 0, "Limit number of results (0 = no limit)")

	return cmd
}

// runList exécute la commande list
func runList(_ *cobra.Command, _ []string, globalOptions common.GlobalOptions, options ListOptions) error {
	// Créer le repository
	repo, err := common.NewRepositoryWrapper(globalOptions.DataDir, globalOptions.Logger)
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
	displayRisks(knownRisks, globalOptions.Debug) // Utiliser Debug au lieu de Flags["verbose"]

	return nil
}

// displayRisks affiche les KnownRisks de manière formatée
func displayRisks(risks []*models.KnownRisk, verbose bool) {
	if len(risks) == 0 {
		common.PrintInfo("No KnownRisks found matching the criteria.")
		return
	}

	common.PrintInfo("Found %d KnownRisks", len(risks))

	headers := []string{"ID", "WORKLOAD", "SEVERITY", "STATUS", "EXPIRY", "ACCEPTED BY"}
	rows := make([][]string, len(risks))

	for i, kr := range risks {
		timeUntilExpiry := kr.ExpiresAt.Sub(time.Now())
		expiryInfo := common.FormatDuration(timeUntilExpiry)
		if timeUntilExpiry < 0 {
			expiryInfo = fmt.Sprintf("%s ago", common.FormatDuration(-timeUntilExpiry))
		}

		rows[i] = []string{
			kr.ID,
			fmt.Sprintf("%s/%s", kr.WorkloadInfo.Namespace, kr.WorkloadInfo.Name),
			string(kr.Severity),
			string(kr.Status),
			expiryInfo,
			fmt.Sprintf("%s (%s)", kr.AcceptedBy, kr.AcceptedAt.Format("2006-01-02")),
		}

		if verbose {
			// Ajouter les détails supplémentaires sous forme de lignes additionnelles
			if kr.Justification != "" {
				rows = append(rows, []string{"", "Justification:", kr.Justification, "", "", ""})
			}
			if len(kr.Tags) > 0 {
				rows = append(rows, []string{"", "Tags:", strings.Join(kr.Tags, ", "), "", "", ""})
			}
			if len(kr.RelatedTickets) > 0 {
				rows = append(rows, []string{"", "Tickets:", strings.Join(kr.RelatedTickets, ", "), "", "", ""})
			}
		}
	}

	common.PrintTable(headers, rows)
}
