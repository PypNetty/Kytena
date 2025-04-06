package cmd

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/PypNetty/Kytena/internal/knownrisk"
	"github.com/spf13/cobra"
)

// getCmd represents the get command
var getCmd = &cobra.Command{
	Use:   "get [id]",
	Short: "Get details of a specific KnownRisk",
	Long: `Retrieve and display detailed information about a specific KnownRisk 
identified by its ID.`,
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

		// Display the KnownRisk according to the selected output format
		if outputFmt == "json" {
			displayKnownRiskJSON(kr)
		} else {
			displayKnownRiskText(kr)
		}
	},
}

func init() {
	rootCmd.AddCommand(getCmd)
}

// displayKnownRiskText prints the KnownRisk in formatted text
func displayKnownRiskText(kr *knownrisk.KnownRisk) {
	fmt.Println(strings.Repeat("=", 80))
	fmt.Printf("KnownRisk: %s\n", kr.ID)
	fmt.Println(strings.Repeat("=", 80))

	// Calculate time until expiry
	timeUntilExpiry := kr.ExpiresAt.Sub(time.Now())
	var expiryInfo string
	if timeUntilExpiry > 0 {
		expiryInfo = fmt.Sprintf("Expires in %.1f days", timeUntilExpiry.Hours()/24)
	} else {
		expiryInfo = fmt.Sprintf("Expired %.1f days ago", -timeUntilExpiry.Hours()/24)
	}

	// Core details
	fmt.Printf("Vulnerability: %s\n", kr.VulnerabilityID)
	fmt.Printf("Status: %s (%s)\n", kr.Status, expiryInfo)
	fmt.Printf("Severity: %s\n", kr.Severity)

	// Workload details
	fmt.Println("\n--- Workload Information ---")
	fmt.Printf("Name: %s\n", kr.WorkloadInfo.Name)
	fmt.Printf("Namespace: %s\n", kr.WorkloadInfo.Namespace)
	fmt.Printf("Type: %s\n", kr.WorkloadInfo.Type)
	fmt.Printf("Image: %s\n", kr.WorkloadInfo.ImageID)
	fmt.Printf("Business Criticality: %d/10\n", kr.WorkloadInfo.BusinessCriticality)

	if len(kr.WorkloadInfo.Labels) > 0 {
		fmt.Println("\nLabels:")
		for k, v := range kr.WorkloadInfo.Labels {
			fmt.Printf("  %s: %s\n", k, v)
		}
	}

	if len(kr.WorkloadInfo.Annotations) > 0 {
		fmt.Println("\nAnnotations:")
		for k, v := range kr.WorkloadInfo.Annotations {
			fmt.Printf("  %s: %s\n", k, v)
		}
	}

	// Risk details
	fmt.Println("\n--- Risk Information ---")
	fmt.Printf("Justification: %s\n", kr.Justification)
	fmt.Printf("Accepted by: %s\n", kr.AcceptedBy)
	fmt.Printf("Accepted on: %s\n", kr.AcceptedAt.Format("2006-01-02 15:04:05"))
	fmt.Printf("Expires on: %s\n", kr.ExpiresAt.Format("2006-01-02 15:04:05"))

	if !kr.LastReviewedAt.IsZero() {
		fmt.Printf("Last reviewed: %s\n", kr.LastReviewedAt.Format("2006-01-02 15:04:05"))
	}

	// Tags and tickets
	if len(kr.Tags) > 0 {
		fmt.Printf("\nTags: %s\n", strings.Join(kr.Tags, ", "))
	}

	if len(kr.RelatedTickets) > 0 {
		fmt.Printf("Related tickets: %s\n", strings.Join(kr.RelatedTickets, ", "))
	}
}

// displayKnownRiskJSON prints the KnownRisk as JSON
func displayKnownRiskJSON(kr *knownrisk.KnownRisk) {
	jsonData, err := json.MarshalIndent(kr, "", "  ")
	if err != nil {
		Fatal("Failed to marshal KnownRisk to JSON: %v", err)
	}
	fmt.Println(string(jsonData))
}
