package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/PypNetty/Kytena/internal/knownrisk"
	"github.com/spf13/cobra"
)

var (
	// Update command flags
	extendDays int
	newStatus  string
	addTags    string
	addTickets string
)

// updateCmd represents the update command
var updateCmd = &cobra.Command{
	Use:   "update [id]",
	Short: "Update an existing KnownRisk",
	Long: `Update properties of an existing KnownRisk.
You can extend the expiry date, update the status, or add tags and tickets.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		id := args[0]

		// Create repository
		repo, err := knownrisk.NewFileRepository(GetDataDir())
		if err != nil {
			Fatal("Failed to create repository: %v", err)
		}

		// Get the KnownRisk
		kr, err := repo.Get(id)
		if err != nil {
			Fatal("Failed to get KnownRisk: %v", err)
		}

		// Show current details
		fmt.Println("Current KnownRisk details:")
		fmt.Printf("ID: %s\n", kr.ID)
		fmt.Printf("Vulnerability: %s\n", kr.VulnerabilityID)
		fmt.Printf("Workload: %s/%s\n", kr.WorkloadInfo.Namespace, kr.WorkloadInfo.Name)
		fmt.Printf("Status: %s\n", kr.Status)
		fmt.Printf("Expires: %s\n", kr.ExpiresAt.Format("2006-01-02 15:04:05"))

		// Handle flag-based updates
		updated := false

		// Extend expiry if specified
		if extendDays > 0 {
			newExpiry := time.Now().Add(time.Duration(extendDays) * 24 * time.Hour)
			if err := kr.ExtendExpiration(newExpiry); err != nil {
				Fatal("Failed to extend expiration: %v", err)
			}
			fmt.Printf("Extended expiry to: %s\n", kr.ExpiresAt.Format("2006-01-02 15:04:05"))
			updated = true
		}

		// Update status if specified
		if newStatus != "" {
			switch strings.ToLower(newStatus) {
			case "active":
				kr.Status = knownrisk.StatusActive
			case "resolved":
				kr.MarkAsResolved()
			default:
				Fatal("Invalid status. Valid values: active, resolved")
			}
			fmt.Printf("Updated status to: %s\n", kr.Status)
			updated = true
		}

		// Add tags if specified
		if addTags != "" {
			for _, tag := range strings.Split(addTags, ",") {
				tag = strings.TrimSpace(tag)
				if tag != "" {
					kr.AddTag(tag)
					fmt.Printf("Added tag: %s\n", tag)
				}
			}
			updated = true
		}

		// Add tickets if specified
		if addTickets != "" {
			for _, ticket := range strings.Split(addTickets, ",") {
				ticket = strings.TrimSpace(ticket)
				if ticket != "" {
					kr.AddRelatedTicket(ticket)
					fmt.Printf("Added ticket: %s\n", ticket)
				}
			}
			updated = true
		}

		// If no flags were provided, offer an interactive update
		if !updated {
			updateInteractively(kr)
		}

		// Mark as reviewed
		kr.MarkAsReviewed()

		// Save the updated KnownRisk
		if err := repo.Update(kr); err != nil {
			Fatal("Failed to update KnownRisk: %v", err)
		}

		fmt.Println("KnownRisk updated successfully.")
	},
}

func init() {
	rootCmd.AddCommand(updateCmd)

	// Add flags for common updates
	updateCmd.Flags().IntVar(&extendDays, "extend", 0, "Extend expiry by specified number of days")
	updateCmd.Flags().StringVar(&newStatus, "status", "", "Update status (active, resolved)")
	updateCmd.Flags().StringVar(&addTags, "add-tags", "", "Add tags (comma-separated)")
	updateCmd.Flags().StringVar(&addTickets, "add-tickets", "", "Add related tickets (comma-separated)")
}

// updateInteractively offers an interactive menu to update KnownRisk properties
func updateInteractively(kr *knownrisk.KnownRisk) {
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
		// Update justification
		fmt.Printf("Current justification: %s\n", kr.Justification)
		fmt.Print("New justification: ")
		scanner.Scan()
		newJustification := strings.TrimSpace(scanner.Text())
		if newJustification != "" {
			kr.Justification = newJustification
			fmt.Println("Justification updated.")
		}

	case "2":
		// Update expiry date
		fmt.Printf("Current expiry: %s\n", kr.ExpiresAt.Format("2006-01-02 15:04:05"))
		fmt.Print("Extend by how many days? ")
		scanner.Scan()
		daysStr := strings.TrimSpace(scanner.Text())
		days, err := strconv.Atoi(daysStr)
		if err != nil || days <= 0 {
			Fatal("Extension must be a positive number of days")
		}
		newExpiry := time.Now().Add(time.Duration(days) * 24 * time.Hour)
		if err := kr.ExtendExpiration(newExpiry); err != nil {
			Fatal("Failed to extend expiration: %v", err)
		}
		fmt.Printf("Extended expiry to: %s\n", kr.ExpiresAt.Format("2006-01-02 15:04:05"))

	case "3":
		// Update status
		fmt.Printf("Current status: %s\n", kr.Status)
		fmt.Println("Available statuses:")
		fmt.Println("1. Active")
		fmt.Println("2. Resolved")
		fmt.Print("Select new status: ")
		scanner.Scan()
		statusChoice := strings.TrimSpace(scanner.Text())

		switch statusChoice {
		case "1":
			kr.Status = knownrisk.StatusActive
			fmt.Println("Status set to Active.")
		case "2":
			kr.MarkAsResolved()
			fmt.Println("Status set to Resolved.")
		default:
			fmt.Println("Invalid choice. Status not updated.")
		}

	case "4":
		// Add tags
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
		// Add related tickets
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
