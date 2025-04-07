// pkg/cli/commands/delete.go
package commands

import (
	"fmt"

	"github.com/PypNetty/Kytena/pkg/cli"
	"github.com/spf13/cobra"
)

// DeleteOptions contient les options spécifiques à la commande delete
type DeleteOptions struct {
	ForceDelete bool
}

// NewDeleteCommand crée une nouvelle commande delete
func NewDeleteCommand() *cobra.Command {
	options := DeleteOptions{}

	cmd := cli.NewBaseCommand(
		"delete [id]",
		"Delete a KnownRisk",
		`Delete a KnownRisk by its ID.
By default, you will be asked to confirm the deletion.`,
		func(cmd *cobra.Command, args []string, globalOptions cli.GlobalOptions) error {
			if len(args) != 1 {
				return fmt.Errorf("exactly one argument is required: the ID of the KnownRisk")
			}

			id := args[0]

			// Créer le repository
			repo, err := cli.CreateRepository(globalOptions)
			if err != nil {
				return fmt.Errorf("failed to create repository: %w", err)
			}

			// Récupérer le KnownRisk pour confirmer son existence et afficher les détails
			kr, err := repo.Get(globalOptions.Context, id)
			if err != nil {
				return fmt.Errorf("failed to get KnownRisk: %w", err)
			}

			// Afficher les détails et demander confirmation sauf si le flag force est défini
			if !options.ForceDelete {
				fmt.Printf("You are about to delete the following KnownRisk:\n")
				fmt.Printf("ID: %s\n", kr.ID)
				fmt.Printf("Vulnerability: %s\n", kr.VulnerabilityID)
				fmt.Printf("Workload: %s/%s\n", kr.WorkloadInfo.Namespace, kr.WorkloadInfo.Name)
				fmt.Printf("Status: %s\n", kr.Status)

				if !cli.AskForConfirmation("Are you sure you want to delete this KnownRisk?") {
					fmt.Println("Deletion cancelled.")
					return nil
				}
			}

			// Supprimer le KnownRisk
			if err := repo.Delete(globalOptions.Context, id); err != nil {
				return fmt.Errorf("failed to delete KnownRisk: %w", err)
			}

			cli.PrintSuccess("KnownRisk %s deleted successfully", id)
			return nil
		},
	)

	baseCmd := cmd.Setup()

	// Ajouter le flag force
	baseCmd.Flags().BoolVarP(&options.ForceDelete, "force", "f", false, "Force deletion without confirmation")

	return baseCmd
}
