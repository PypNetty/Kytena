// pkg/cli/commands/update.go
package commands

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/PypNetty/Kytena/pkg/cli"
	"github.com/PypNetty/Kytena/pkg/models"
	"github.com/spf13/cobra"
)

// UpdateOptions contient les options spécifiques à la commande update
type UpdateOptions struct {
	ExtendDays int
	NewStatus  string
	AddTags    string
	AddTickets string
}

// NewUpdateCommand crée une nouvelle commande update
func NewUpdateCommand() *cobra.Command {
	options := UpdateOptions{}

	cmd := cli.NewBaseCommand(
		"update [id]",
		"Update an existing KnownRisk",
		`Update properties of an existing KnownRisk.
You can extend the expiry date, update the status, or add tags and tickets.`,
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
			kr, err := repo.Get(globalOptions.Context, id)
			if err != nil {
				return fmt.Errorf("failed to get KnownRisk: %w", err)
			}

			// Afficher les détails actuels
			fmt.Println("Current KnownRisk details:")
			fmt.Printf("ID: %s\n", kr.ID)
			fmt.Printf("Vulnerability: %s\n", kr.VulnerabilityID)
			fmt.Printf("Workload: %s/%s\n", kr.WorkloadInfo.Namespace, kr.WorkloadInfo.Name)
			fmt.Printf("Status: %s\n", kr.Status)
			fmt.Printf("Expires: %s\n", kr.ExpiresAt.Format("2006-01-02 15:04:05"))

			// Traiter les mises à jour basées sur les flags
			updated := false

			// Étendre l'expiration si spécifié
			if options.ExtendDays > 0 {
				newExpiry := time.Now().Add(time.Duration(options.ExtendDays) * 24 * time.Hour)
				if err := kr.ExtendExpiration(newExpiry); err != nil {
					return fmt.Errorf("failed to extend expiration: %w", err)
				}
				fmt.Printf("Extended expiry to: %s\n", kr.ExpiresAt.Format("2006-01-02 15:04:05"))
				updated = true
			}

			// Mettre à jour le statut si spécifié
			if options.NewStatus != "" {
				switch strings.ToLower(options.NewStatus) {
				case "active":
					kr.Status = models.StatusActive
				case "resolved":
					kr.MarkAsResolved()
				default:
					return fmt.Errorf("invalid status. Valid values: active, resolved")
				}
				fmt.Printf("Updated status to: %s\n", kr.Status)
				updated = true
			}

			// Ajouter des tags si spécifié
			if options.AddTags != "" {
				for _, tag := range strings.Split(options.AddTags, ",") {
					tag = strings.TrimSpace(tag)
					if tag != "" {
						kr.AddTag(tag)
						fmt.Printf("Added tag: %s\n", tag)
					}
				}
				updated = true
			}

			// Ajouter des tickets si spécifié
			if options.AddTickets != "" {
				for _, ticket := range strings.Split(options.AddTickets, ",") {
					ticket = strings.TrimSpace(ticket)
					if ticket != "" {
						kr.AddRelatedTicket(ticket)
						fmt.Printf("Added ticket: %s\n", ticket)
					}
				}
				updated = true
			}

			// Si aucun flag n'a été fourni, proposer une mise à jour interactive
			if !updated {
				updateInteractively(kr)
			}

			// Marquer comme revu
			kr.MarkAsReviewed()

			// Sauvegarder le KnownRisk mis à jour
			if err := repo.Update(globalOptions.Context, kr); err != nil {
				return fmt.Errorf("failed to update KnownRisk: %w", err)
			}

			cli.PrintSuccess("KnownRisk updated successfully")
			return nil
		},
	)

	baseCmd := cmd.Setup()

	// Ajouter les flags pour les mises à jour courantes
	baseCmd.Flags().IntVar(&options.ExtendDays, "extend", 0, "Extend expiry by specified number of days")
	baseCmd.Flags().StringVar(&options.NewStatus, "status", "", "Update status (active, resolved)")
	baseCmd.Flags().StringVar(&options.AddTags, "add-tags", "", "Add tags (comma-separated)")
	baseCmd.Flags().StringVar(&options.AddTickets, "add-tickets", "", "Add related tickets (comma-separated)")

	return baseCmd
}

// updateInteractively propose un menu interactif pour mettre à jour les propriétés d'un KnownRisk
func updateInteractively(kr *models.KnownRisk) {
	scanner := bufio.NewScanner(os.Stdin)

	fmt.Println("\nWhich field would you like to update?")
	fmt.Println("1. Justification")
	fmt.Println("2. Expiry date")
	fmt.Println("3. Status")
	fmt.Println("4. Add tags")
	fmt.Println("5. Add related tickets")
	fmt.Println("0. Cancel update")

	fmt.Print("Enter choice: ")
	scanner.Scan()
	choice := strings.TrimSpace(scanner.Text())

	switch choice {
	case "1":
		// Mettre à jour la justification
		fmt.Printf("Current justification: %s\n", kr.Justification)
		fmt.Print("New justification: ")
		scanner.Scan()
		newJustification := strings.TrimSpace(scanner.Text())
		if newJustification != "" {
			kr.Justification = newJustification
			fmt.Println("Justification updated.")
		}

	case "2":
		// Mettre à jour la date d'expiration
		fmt.Printf("Current expiry: %s\n", kr.ExpiresAt.Format("2006-01-02 15:04:05"))
		fmt.Print("Extend by how many days? ")
		scanner.Scan()
		daysStr := strings.TrimSpace(scanner.Text())
		days, err := strconv.Atoi(daysStr)
		if err != nil || days <= 0 {
			cli.Fatal("Extension must be a positive number of days")
		}

		newExpiry := time.Now().Add(time.Duration(days) * 24 * time.Hour)
		if err := kr.ExtendExpiration(newExpiry); err != nil {
			cli.Fatal("Failed to extend expiration: %v", err)
		}

		fmt.Printf("Extended expiry to: %s\n", kr.ExpiresAt.Format("2006-01-02 15:04:05"))

	case "3":
		// Mettre à jour le statut
		fmt.Printf("Current status: %s\n", kr.Status)
		fmt.Println("Available statuses:")
		fmt.Println("1. Active")
		fmt.Println("2. Resolved")

		fmt.Print("Select new status: ")
		scanner.Scan()
		statusChoice := strings.TrimSpace(scanner.Text())

		switch statusChoice {
		case "1":
			kr.Status = models.StatusActive
			fmt.Println("Status set to Active.")
		case "2":
			kr.MarkAsResolved()
			fmt.Println("Status set to Resolved.")
		default:
			fmt.Println("Invalid choice. Status not updated.")
		}

	case "4":
		// Ajouter des tags
		fmt.Printf("Current tags: %v\n", kr.Tags)
		fmt.Print("Tags to add (comma-separated): ")
		scanner.Scan()
		tagsStr := strings.TrimSpace(scanner.Text())

		if tagsStr != "" {
			for _, tag := range strings.Split(tagsStr, ",") {
				tag = strings.TrimSpace(tag)
				if tag != "" {
					kr.AddTag(tag)
					fmt.Printf("Added tag: %s\n", tag)
				}
			}
		}

	case "5":
		// Ajouter des tickets associés
		fmt.Printf("Current related tickets: %v\n", kr.RelatedTickets)
		fmt.Print("Tickets to add (comma-separated): ")
		scanner.Scan()
		ticketsStr := strings.TrimSpace(scanner.Text())

		if ticketsStr != "" {
			for _, ticket := range strings.Split(ticketsStr, ",") {
				ticket = strings.TrimSpace(ticket)
				if ticket != "" {
					kr.AddRelatedTicket(ticket)
					fmt.Printf("Added ticket: %s\n", ticket)
				}
			}
		}

	case "0":
		fmt.Println("Update cancelled.")
		os.Exit(0)

	default:
		fmt.Println("Invalid choice. Update cancelled.")
		os.Exit(1)
	}
}
