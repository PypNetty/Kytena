// pkg/cli/commands/get.go
package commands

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/PypNetty/Kytena/pkg/cli"
	"github.com/PypNetty/Kytena/pkg/models"
	"github.com/spf13/cobra"
)

// NewGetCommand crée une nouvelle commande get
func NewGetCommand() *cobra.Command {
	// Créer la commande de base
	cmd := cli.NewBaseCommand(
		"get [id]",
		"Get details of a specific KnownRisk",
		`Retrieve and display detailed information about a specific KnownRisk
identified by its ID.`,
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

			// Récupérer le KnownRisk
			kr, err := repo.Get(context.Background(), id)
			if err != nil {
				return fmt.Errorf("failed to get KnownRisk: %w", err)
			}

			// Afficher le KnownRisk selon le format de sortie spécifié
			if globalOptions.OutputFormat == "json" {
				displayKnownRiskJSON(kr)
			} else {
				cli.RenderKnownRiskDetails(kr)
			}

			return nil
		},
	)

	return cmd.Setup()
}

// displayKnownRiskJSON affiche le KnownRisk au format JSON
func displayKnownRiskJSON(kr *models.KnownRisk) {
	jsonData, err := json.MarshalIndent(kr, "", "  ")
	if err != nil {
		cli.PrintError("Failed to marshal KnownRisk to JSON: %v", err)
		return
	}

	fmt.Println(string(jsonData))
}
