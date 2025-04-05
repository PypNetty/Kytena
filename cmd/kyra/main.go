package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/PypNetty/Kyra/internal/knownrisk"
	"github.com/PypNetty/Kyra/internal/workload"
)

func main() {
	fmt.Println("Kyra - Intelligent Kubernetes Security Orchestrator")
	fmt.Println("-----------------------------------------------------")

	dataDir := "./data/knownrisks"

	// Create a repository for known risks
	repo, err := knownrisk.NewFileRepository(dataDir)
	if err != nil {
		fmt.Printf("Error creating repository: %v\n", err)
		os.Exit(1)
	}

	// simulate a workload Kubernetes
	w := workload.NewWorkload(
		"api-gateway",
		"prod",
		workload.TypeDeployment,
		"nginx:1.19.0",
		8,
		map[string]string{"app": "gateway", "tier": "frontend"},
		map[string]string{"description": "API Gateway principal"},
	)

	// Create a new known risk
	kr := knownrisk.NewKnownRisk(
		"CVE-2023-12345",
		*w,
		"Vulnerability in Nginx, but not exploitable in our configuration. Will be fixed in next scheduled update.",
		"team-security@example.com",
		time.Now().Add(30*24*time.Hour), // 30 days from now
		knownrisk.SeverityHigh,
	)

	// add the tags and tickets associated with the known risk
	kr.AddTag("frontend")
	kr.AddTag("nginx")
	kr.AddRelatedTicket("JIRA-1234")

	// Save the known risk to the repository
	fmt.Println("Saving known risk...")
	if err := repo.Save(kr); err != nil {
		fmt.Printf("Error saving known risk: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(("KnownRisk saved with ID: "), kr.ID)

	// Recuperate the known risk
	fmt.Println("\nRetrieving known risk...")
	retrievedKR, err := repo.Get(kr.ID)
	if err != nil {
		fmt.Printf("Error retrieving known risk: %v\n", err)
		os.Exit(1)
	}

	// Display the retrieved known risk
	fmt.Println("\nKnownRisk Details:")
	fmt.Printf("ID: %s\n", retrievedKR.ID)
	fmt.Printf("Vulnerability: %s\n", retrievedKR.VulnerabilityID)
	fmt.Printf("Workload: %s/%s (%s)\n",
		retrievedKR.WorkloadInfo.Namespace,
		retrievedKR.WorkloadInfo.Name,
		retrievedKR.WorkloadInfo.Type)
	fmt.Printf("Business Criticality: %d/10\n", retrievedKR.WorkloadInfo.BusinessCriticality)
	fmt.Printf("Image: %s\n", retrievedKR.WorkloadInfo.ImageID)
	fmt.Printf("Severity: %s\n", retrievedKR.Severity)
	fmt.Printf("Status: %s\n", retrievedKR.Status)
	fmt.Printf("Accepted by: %s\n", retrievedKR.AcceptedBy)
	fmt.Printf("Accepted on: %s\n", retrievedKR.AcceptedAt.Format("2006-01-02 15:04:05"))
	fmt.Printf("Expires on: %s\n", retrievedKR.ExpiresAt.Format("2006-01-02 15:04:05"))
	fmt.Printf("Justification: %s\n", retrievedKR.Justification)

	// Display tags and tickets
	fmt.Printf("Tags: %v\n", retrievedKR.Tags)
	fmt.Printf("Related tickets: %v\n", retrievedKR.RelatedTickets)

	// Display the file path for reference
	filePath := filepath.Join(dataDir, fmt.Sprintf("%s.yaml", kr.ID))
	fmt.Printf("\nThe KnownRisk is stored in: %s\n", filePath)

	fmt.Println("\nDemonstration completed.")
}
