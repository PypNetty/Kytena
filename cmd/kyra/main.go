package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/PypNetty/Kyra/internal/knownrisk"
	"github.com/PypNetty/Kyra/internal/reevaluator"
	"github.com/PypNetty/Kyra/internal/workload"
)

func main() {
	fmt.Println("Kyra - Intelligent Kubernetes Security Orchestrator")
	fmt.Println("-----------------------------------------------------")

	// Define data directories
	dataDir := "./data/knownrisks"
	logsDir := "./logs"

	// Create a repository for KnownRisks persistence
	repo, err := knownrisk.NewFileRepository(dataDir)
	if err != nil {
		fmt.Printf("Error creating repository: %v\n", err)
		os.Exit(1)
	}

	// Create a console notification handler
	consoleHandler := reevaluator.ConsoleNotificationHandler()

	// Create a file logging notification handler
	fileHandler, err := reevaluator.LoggingNotificationHandler(logsDir)
	if err != nil {
		fmt.Printf("Warning: Failed to create logging handler: %v\n", err)
		// Continue without file logging
	}

	// Create a reevaluator
	evaluator := reevaluator.NewPeriodicReevaluator(repo, 1*time.Minute)
	evaluator.RegisterNotificationHandler(consoleHandler)
	if fileHandler != nil {
		evaluator.RegisterNotificationHandler(fileHandler)
	}

	// Create a context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// 1. First example: Create a KnownRisk that is active
	fmt.Println("\n=== Example 1: Creating an active KnownRisk ===")

	// Simulate a Kubernetes workload
	activeWorkload := workload.NewWorkload(
		"api-gateway",
		"production",
		workload.TypeDeployment,
		"nginx:1.19.0",
		8, // High business criticality
		map[string]string{"app": "gateway", "tier": "frontend"},
		map[string]string{"description": "Main API Gateway"},
	)

	// Create a KnownRisk for a vulnerability that will expire in 30 days
	activeKR := knownrisk.NewKnownRisk(
		"CVE-2023-12345",
		*activeWorkload,
		"Vulnerability in Nginx, but not exploitable in our configuration. Will be fixed in the next planned update.",
		"team-security@example.com",
		time.Now(),
		time.Now().Add(30*24*time.Hour), // Expires in 30 days
		knownrisk.SeverityHigh,
	)

	// Add tags and related tickets
	activeKR.AddTag("frontend")
	activeKR.AddTag("nginx")
	activeKR.AddRelatedTicket("JIRA-1234")

	// Save the KnownRisk
	fmt.Println("Saving active KnownRisk...")
	if err := repo.Save(activeKR); err != nil {
		fmt.Printf("Error saving KnownRisk: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Active KnownRisk saved with ID: %s\n", activeKR.ID)

	// 2. Second example: Create a KnownRisk that will expire soon
	fmt.Println("\n=== Example 2: Creating a KnownRisk that will expire soon ===")

	// Simulate another Kubernetes workload
	expiringWorkload := workload.NewWorkload(
		"legacy-service",
		"production",
		workload.TypeDeployment,
		"mysql:5.7",
		6, // Medium business criticality
		map[string]string{"app": "database", "tier": "backend"},
		map[string]string{"description": "Legacy MySQL database"},
	)

	// Create a KnownRisk that will expire very soon (1 hour)
	expiringKR := knownrisk.NewKnownRisk(
		"CVE-2023-67890",
		*expiringWorkload,
		"MySQL vulnerability that requires database restart. Scheduled for tonight's maintenance window.",
		"team-dba@example.com",
		time.Now(),
		time.Now().Add(1*time.Hour), // Expires in 1 hour
		knownrisk.SeverityMedium,
	)

	// Add tags
	expiringKR.AddTag("database")
	expiringKR.AddTag("mysql")
	expiringKR.AddRelatedTicket("JIRA-5678")

	// Save the KnownRisk
	fmt.Println("Saving expiring KnownRisk...")
	if err := repo.Save(expiringKR); err != nil {
		fmt.Printf("Error saving KnownRisk: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Expiring KnownRisk saved with ID: %s\n", expiringKR.ID)

	// 3. Third example: Create a KnownRisk that is already expired
	fmt.Println("\n=== Example 3: Creating an expired KnownRisk ===")

	// Simulate another Kubernetes workload
	expiredWorkload := workload.NewWorkload(
		"auth-service",
		"production",
		workload.TypeDeployment,
		"redis:6.0",
		7, // High business criticality
		map[string]string{"app": "auth", "tier": "backend"},
		map[string]string{"description": "Authentication cache"},
	)

	// Create a KnownRisk that is already expired
	expiredKR := knownrisk.NewKnownRisk(
		"CVE-2023-24680",
		*expiredWorkload,
		"Redis vulnerability, accepted temporarily while testing patch. Patch test was delayed.",
		"team-security@example.com",
		time.Now().Add(-48*time.Hour), // Accepted 2 days ago
		time.Now().Add(-24*time.Hour), // Expired 1 day ago
		knownrisk.SeverityHigh,
	)

	// Add tags
	expiredKR.AddTag("cache")
	expiredKR.AddTag("redis")
	expiredKR.AddRelatedTicket("JIRA-9012")

	// Save the KnownRisk
	fmt.Println("Saving expired KnownRisk...")
	if err := repo.Save(expiredKR); err != nil {
		fmt.Printf("Error saving KnownRisk: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Expired KnownRisk saved with ID: %s\n", expiredKR.ID)

	// Run the reevaluator once to see initial notifications
	fmt.Println("\n=== Running initial reevaluation ===")
	notifications, err := evaluator.RunOnce(ctx)
	if err != nil {
		fmt.Printf("Error running reevaluation: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Generated %d notifications\n", len(notifications))

	// Start the periodic reevaluator
	fmt.Println("\n=== Starting periodic reevaluation (every minute) ===")
	if err := evaluator.Start(ctx); err != nil {
		fmt.Printf("Error starting reevaluator: %v\n", err)
		os.Exit(1)
	}

	// Display information about the stored KnownRisks
	displayStoredKnownRisks(repo, dataDir)

	// Wait for the expiring KnownRisk to expire
	fmt.Println("\n=== Waiting for the expiring KnownRisk to expire... ===")
	fmt.Println("(This will take about 1 hour in a real scenario, but we'll just wait 10 seconds for the demo)")
	fmt.Println("Watch for notifications as the reevaluator processes them...")

	// Sleep to simulate time passing
	time.Sleep(10 * time.Second)

	// Run the reevaluator manually again to see if there are new notifications
	fmt.Println("\n=== Running final reevaluation ===")
	notifications, err = evaluator.RunOnce(ctx)
	if err != nil {
		fmt.Printf("Error running reevaluation: %v\n", err)
	} else {
		fmt.Printf("Generated %d notifications\n", len(notifications))
	}

	// Stop the reevaluator
	if err := evaluator.Stop(); err != nil {
		fmt.Printf("Error stopping reevaluator: %v\n", err)
	}

	fmt.Println("\n=== Reevaluator demonstration completed ===")
	fmt.Println("Check the logs directory for the reevaluation log file.")
}

// displayStoredKnownRisks displays information about all stored KnownRisks
func displayStoredKnownRisks(repo knownrisk.Repository, dataDir string) {
	fmt.Println("\n=== Stored KnownRisks ===")

	// List all KnownRisks
	knownRisks, err := repo.List()
	if err != nil {
		fmt.Printf("Error listing KnownRisks: %v\n", err)
		return
	}

	fmt.Printf("Found %d KnownRisks\n", len(knownRisks))

	// Display each KnownRisk
	for i, kr := range knownRisks {
		fmt.Printf("\n%d. KnownRisk: %s\n", i+1, kr.ID)
		fmt.Printf("   Vulnerability: %s\n", kr.VulnerabilityID)
		fmt.Printf("   Workload: %s/%s (%s)\n",
			kr.WorkloadInfo.Namespace,
			kr.WorkloadInfo.Name,
			kr.WorkloadInfo.Type)
		fmt.Printf("   Severity: %s\n", kr.Severity)
		fmt.Printf("   Status: %s\n", kr.Status)
		fmt.Printf("   Expires: %s\n", kr.ExpiresAt.Format("2006-01-02 15:04:05"))

		// Calculate time until expiry
		timeUntilExpiry := kr.ExpiresAt.Sub(time.Now())
		if timeUntilExpiry > 0 {
			fmt.Printf("   Expires in: %.1f days\n", timeUntilExpiry.Hours()/24)
		} else {
			fmt.Printf("   Expired: %.1f days ago\n", -timeUntilExpiry.Hours()/24)
		}

		// Display file path
		filePath := filepath.Join(dataDir, fmt.Sprintf("%s.yaml", kr.ID))
		fmt.Printf("   File: %s\n", filePath)
	}
}
