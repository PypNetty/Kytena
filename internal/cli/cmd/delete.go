package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/PypNetty/Kyra/internal/knownrisk"
	"github.com/spf13/cobra"
)

var (
	forceDelete bool
)

// deleteCmd represents the delete command
var deleteCmd = &cobra.Command{
	Use:   "delete [id]",
	Short: "Delete a KnownRisk",
	Long: `Delete a KnownRisk by its ID.
By default, you will be asked to confirm the deletion.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		id := args[0]

		// Create repository
		repo, err := knownrisk.NewFileRepository(GetDataDir())
		if err != nil {
			Fatal("Failed to create repository: %v", err)
		}

		// Get the KnownRisk to confirm it exists and show details
		kr, err := repo.Get(id)
		if err != nil {
			Fatal("Failed to get KnownRisk: %v", err)
		}

		// Show details and confirm unless force flag is set
		if !forceDelete {
			fmt.Printf("You are about to delete the following KnownRisk:\n")
			fmt.Printf("ID: %s\n", kr.ID)
			fmt.Printf("Vulnerability: %s\n", kr.VulnerabilityID)
			fmt.Printf("Workload: %s/%s\n", kr.WorkloadInfo.Namespace, kr.WorkloadInfo.Name)
			fmt.Printf("Status: %s\n", kr.Status)

			if !confirmDeletion() {
				fmt.Println("Deletion cancelled.")
				return
			}
		}

		// Delete the KnownRisk
		if err := repo.Delete(id); err != nil {
			Fatal("Failed to delete KnownRisk: %v", err)
		}

		fmt.Printf("KnownRisk %s deleted successfully.\n", id)
	},
}

func init() {
	rootCmd.AddCommand(deleteCmd)

	// Add force flag
	deleteCmd.Flags().BoolVarP(&forceDelete, "force", "f", false, "Force deletion without confirmation")
}

// confirmDeletion asks the user to confirm deletion
func confirmDeletion() bool {
	fmt.Print("Are you sure you want to delete this KnownRisk? (y/N): ")
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	response := strings.ToLower(strings.TrimSpace(scanner.Text()))
	return response == "y" || response == "yes"
}
