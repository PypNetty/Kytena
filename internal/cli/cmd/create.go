package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/PypNetty/Kytena/internal/knownrisk"
	"github.com/PypNetty/Kytena/internal/workload"
	"github.com/spf13/cobra"
)

// createCmd represents the create command
var createCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new KnownRisk",
	Long: `Create a new KnownRisk entry interactively.
You will be prompted to enter all necessary information.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Create repository
		repo, err := knownrisk.NewFileRepository(GetDataDir())
		if err != nil {
			Fatal("Failed to create repository: %v", err)
		}

		// Collect information interactively
		kr := collectKnownRiskInfo()

		// Save the KnownRisk
		if err := repo.Save(kr); err != nil {
			Fatal("Failed to save KnownRisk: %v", err)
		}

		fmt.Printf("KnownRisk created successfully with ID: %s\n", kr.ID)
	},
}

func init() {
	rootCmd.AddCommand(createCmd)
}

// collectKnownRiskInfo prompts the user for KnownRisk information
func collectKnownRiskInfo() *knownrisk.KnownRisk {
	scanner := bufio.NewScanner(os.Stdin)

	// Collect vulnerability information
	fmt.Print("Vulnerability ID (e.g., CVE-2023-12345): ")
	scanner.Scan()
	vulnID := strings.TrimSpace(scanner.Text())
	if vulnID == "" {
		Fatal("Vulnerability ID cannot be empty")
	}

	// Collect workload information
	w := collectWorkloadInfo(scanner)

	// Collect justification
	fmt.Print("Justification for accepting this risk: ")
	scanner.Scan()
	justification := strings.TrimSpace(scanner.Text())
	if justification == "" {
		Fatal("Justification cannot be empty")
	}

	// Collect accepted by
	fmt.Print("Accepted by (email or name): ")
	scanner.Scan()
	acceptedBy := strings.TrimSpace(scanner.Text())
	if acceptedBy == "" {
		Fatal("Accepted by cannot be empty")
	}

	// Collect expiry time
	fmt.Print("Expiry time in days from now: ")
	scanner.Scan()
	daysStr := strings.TrimSpace(scanner.Text())
	days, err := strconv.Atoi(daysStr)
	if err != nil || days <= 0 {
		Fatal("Expiry time must be a positive number of days")
	}
	expiresAt := time.Now().Add(time.Duration(days) * 24 * time.Hour)

	// Collect severity
	fmt.Println("Severity (1-4):")
	fmt.Println("1. Critical")
	fmt.Println("2. High")
	fmt.Println("3. Medium")
	fmt.Println("4. Low")
	fmt.Print("Select severity: ")
	scanner.Scan()
	severityStr := strings.TrimSpace(scanner.Text())
	severityNum, err := strconv.Atoi(severityStr)
	if err != nil || severityNum < 1 || severityNum > 4 {
		Fatal("Severity must be a number between 1 and 4")
	}

	var severity knownrisk.Severity
	switch severityNum {
	case 1:
		severity = knownrisk.SeverityCritical
	case 2:
		severity = knownrisk.SeverityHigh
	case 3:
		severity = knownrisk.SeverityMedium
	case 4:
		severity = knownrisk.SeverityLow
	}

	// Create the KnownRisk
	kr := knownrisk.NewKnownRisk(
		vulnID,
		*w,
		justification,
		acceptedBy,
		time.Now(), // acceptedAt
		expiresAt,
		severity,
	)

	// Collect tags (optional)
	fmt.Print("Tags (comma-separated, optional): ")
	scanner.Scan()
	tags := strings.TrimSpace(scanner.Text())
	if tags != "" {
		for _, tag := range strings.Split(tags, ",") {
			kr.AddTag(strings.TrimSpace(tag))
		}
	}

	// Collect related tickets (optional)
	fmt.Print("Related tickets (comma-separated, optional): ")
	scanner.Scan()
	tickets := strings.TrimSpace(scanner.Text())
	if tickets != "" {
		for _, ticket := range strings.Split(tickets, ",") {
			kr.AddRelatedTicket(strings.TrimSpace(ticket))
		}
	}

	return kr
}

// collectWorkloadInfo prompts the user for Workload information
func collectWorkloadInfo(scanner *bufio.Scanner) *workload.Workload {
	fmt.Print("Workload name: ")
	scanner.Scan()
	name := strings.TrimSpace(scanner.Text())
	if name == "" {
		Fatal("Workload name cannot be empty")
	}

	fmt.Print("Namespace: ")
	scanner.Scan()
	namespace := strings.TrimSpace(scanner.Text())
	if namespace == "" {
		Fatal("Namespace cannot be empty")
	}

	fmt.Println("Workload type:")
	fmt.Println("1. Deployment")
	fmt.Println("2. StatefulSet")
	fmt.Println("3. DaemonSet")
	fmt.Println("4. CronJob")
	fmt.Println("5. Job")
	fmt.Println("6. Pod")
	fmt.Print("Select type: ")
	scanner.Scan()
	typeStr := strings.TrimSpace(scanner.Text())
	typeNum, err := strconv.Atoi(typeStr)
	if err != nil || typeNum < 1 || typeNum > 6 {
		Fatal("Type must be a number between 1 and 6")
	}

	var wType workload.WorkloadType
	switch typeNum {
	case 1:
		wType = workload.TypeDeployment
	case 2:
		wType = workload.TypeStatefulSet
	case 3:
		wType = workload.TypeDaemonSet
	case 4:
		wType = workload.TypeCronJob
	case 5:
		wType = workload.TypeJob
	case 6:
		wType = workload.TypePod
	}

	fmt.Print("Image ID (e.g., nginx:1.19.0): ")
	scanner.Scan()
	imageID := strings.TrimSpace(scanner.Text())
	if imageID == "" {
		Fatal("Image ID cannot be empty")
	}

	fmt.Print("Business criticality (1-10): ")
	scanner.Scan()
	criticalityStr := strings.TrimSpace(scanner.Text())
	criticality, err := strconv.Atoi(criticalityStr)
	if err != nil || criticality < 1 || criticality > 10 {
		Fatal("Business criticality must be a number between 1 and 10")
	}

	// Create labels map (optional)
	labels := make(map[string]string)
	fmt.Print("Labels (key=value,key=value format, optional): ")
	scanner.Scan()
	labelsStr := strings.TrimSpace(scanner.Text())
	if labelsStr != "" {
		for _, pair := range strings.Split(labelsStr, ",") {
			kv := strings.Split(pair, "=")
			if len(kv) == 2 {
				labels[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
			}
		}
	}

	// Create annotations map (optional)
	annotations := make(map[string]string)
	fmt.Print("Annotations (key=value,key=value format, optional): ")
	scanner.Scan()
	annotationsStr := strings.TrimSpace(scanner.Text())
	if annotationsStr != "" {
		for _, pair := range strings.Split(annotationsStr, ",") {
			kv := strings.Split(pair, "=")
			if len(kv) == 2 {
				annotations[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
			}
		}
	}

	return workload.NewWorkload(
		name,
		namespace,
		wType,
		imageID,
		criticality,
		labels,
		annotations,
	)
}
