// pkg/cli/commands/create.go
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

// NewCreateCommand crée une nouvelle commande create
func NewCreateCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new KnownRisk",
		Long: `Create a new KnownRisk entry interactively.
You will be prompted to enter all necessary information.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			globalOptions := &cli.GlobalOptions{
				Context: cmd.Context(),
			}
			// Add other global options as needed
			// Créer le repository
			repo, err := cli.CreateRepository(*globalOptions)
			if err != nil {
				return fmt.Errorf("failed to create repository: %w", err)
			}

			// Collecter les informations de manière interactive
			kr := collectKnownRiskInfo()

			// Sauvegarder le KnownRisk
			if err := repo.Save(globalOptions.Context, kr); err != nil {
				return fmt.Errorf("failed to save KnownRisk: %w", err)
			}

			cli.PrintSuccess("KnownRisk created successfully with ID: %s", kr.ID)
			return nil
		},
	}

	return cmd.Setup()
}

// collectKnownRiskInfo demande à l'utilisateur les informations pour un KnownRisk
func collectKnownRiskInfo() *models.KnownRisk {
	scanner := bufio.NewScanner(os.Stdin)

	// Collecter les informations sur la vulnérabilité
	fmt.Print("Vulnerability ID (e.g., CVE-2023-12345): ")
	scanner.Scan()
	vulnID := strings.TrimSpace(scanner.Text())
	if vulnID == "" {
		cli.Fatal("Vulnerability ID cannot be empty")
	}

	// Collecter les informations sur le workload
	w := collectWorkloadInfo(scanner)

	// Collecter la justification
	fmt.Print("Justification for accepting this risk: ")
	scanner.Scan()
	justification := strings.TrimSpace(scanner.Text())
	if justification == "" {
		cli.Fatal("Justification cannot be empty")
	}

	// Collecter accepted by
	fmt.Print("Accepted by (email or name): ")
	scanner.Scan()
	acceptedBy := strings.TrimSpace(scanner.Text())
	if acceptedBy == "" {
		cli.Fatal("Accepted by cannot be empty")
	}

	// Collecter le temps d'expiration
	fmt.Print("Expiry time in days from now: ")
	scanner.Scan()
	daysStr := strings.TrimSpace(scanner.Text())
	days, err := strconv.Atoi(daysStr)
	if err != nil || days <= 0 {
		cli.Fatal("Expiry time must be a positive number of days")
	}
	expiresAt := time.Now().Add(time.Duration(days) * 24 * time.Hour)

	// Collecter la sévérité
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
		cli.Fatal("Severity must be a number between 1 and 4")
	}

	var severity models.Severity
	switch severityNum {
	case 1:
		severity = models.SeverityCritical
	case 2:
		severity = models.SeverityHigh
	case 3:
		severity = models.SeverityMedium
	case 4:
		severity = models.SeverityLow
	}

	// Créer le KnownRisk
	kr := models.NewKnownRisk(
		vulnID,
		*w,
		justification,
		acceptedBy,
		time.Now(), // acceptedAt
		expiresAt,
		severity,
	)

	// Collecter les tags (optionnel)
	fmt.Print("Tags (comma-separated, optional): ")
	scanner.Scan()
	tags := strings.TrimSpace(scanner.Text())
	if tags != "" {
		for _, tag := range strings.Split(tags, ",") {
			kr.AddTag(strings.TrimSpace(tag))
		}
	}

	// Collecter les tickets associés (optionnel)
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

// collectWorkloadInfo demande à l'utilisateur les informations pour un Workload
func collectWorkloadInfo(scanner *bufio.Scanner) *models.Workload {
	fmt.Print("Workload name: ")
	scanner.Scan()
	name := strings.TrimSpace(scanner.Text())
	if name == "" {
		cli.Fatal("Workload name cannot be empty")
	}

	fmt.Print("Namespace: ")
	scanner.Scan()
	namespace := strings.TrimSpace(scanner.Text())
	if namespace == "" {
		cli.Fatal("Namespace cannot be empty")
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
		cli.Fatal("Type must be a number between 1 and 6")
	}

	var wType models.WorkloadType
	switch typeNum {
	case 1:
		wType = models.TypeDeployment
	case 2:
		wType = models.TypeStatefulSet
	case 3:
		wType = models.TypeDaemonSet
	case 4:
		wType = models.TypeCronJob
	case 5:
		wType = models.TypeJob
	case 6:
		wType = models.TypePod
	}

	fmt.Print("Image ID (e.g., nginx:1.19.0): ")
	scanner.Scan()
	imageID := strings.TrimSpace(scanner.Text())
	if imageID == "" {
		cli.Fatal("Image ID cannot be empty")
	}

	fmt.Print("Business criticality (1-10): ")
	scanner.Scan()
	criticalityStr := strings.TrimSpace(scanner.Text())
	criticality, err := strconv.Atoi(criticalityStr)
	if err != nil || criticality < 1 || criticality > 10 {
		cli.Fatal("Business criticality must be a number between 1 and 10")
	}

	// Créer la map de labels (optionnel)
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

	// Créer la map d'annotations (optionnel)
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

	return models.NewWorkload(
		name,
		namespace,
		wType,
		imageID,
		criticality,
		labels,
		annotations,
	)
}
