package cmd

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/PypNetty/Kytena/internal/knownrisk"
	"github.com/spf13/cobra"
)

var (
	// Dashboard command flags
	dashboardNamespace    string
	dashboardWorkload     string
	dashboardDetail       bool
	dashboardMaxWorkloads int
)

// dashboardCmd represents the dashboard command
var dashboardCmd = &cobra.Command{
	Use:   "dashboard",
	Short: "Display a security risk dashboard",
	Long: `Display a comprehensive dashboard of your security posture based on KnownRisks.
This provides an overview of your security debt and highlights critical areas that need attention.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Create repository
		repo, err := knownrisk.NewFileRepository(GetDataDir())
		if err != nil {
			Fatal("Failed to create repository: %v", err)
		}

		// Get all KnownRisks
		risks, err := repo.List()
		if err != nil {
			Fatal("Failed to list KnownRisks: %v", err)
		}

		// Filter risks if needed
		filteredRisks := filterKnownRisks(risks, dashboardNamespace, dashboardWorkload)

		// Display dashboard header
		displayDashboardHeader(len(filteredRisks), len(risks))

		// Display risk summary
		displayRiskSummary(filteredRisks)

		// Display risk distribution
		displaySeverityDistribution(filteredRisks)
		displayStatusDistribution(filteredRisks)
		displayExpirationDistribution(filteredRisks)

		// Display workload risk scores
		displayWorkloadRiskScores(filteredRisks, dashboardMaxWorkloads)

		// Display detailed view if requested
		if dashboardDetail {
			displayDetailedRiskView(filteredRisks)
		}
	},
}

func init() {
	rootCmd.AddCommand(dashboardCmd)

	// Add flags
	dashboardCmd.Flags().StringVar(&dashboardNamespace, "namespace", "", "Filter by namespace")
	dashboardCmd.Flags().StringVar(&dashboardWorkload, "workload", "", "Filter by workload name")
	dashboardCmd.Flags().BoolVar(&dashboardDetail, "detail", false, "Show detailed risk information")
	dashboardCmd.Flags().IntVar(&dashboardMaxWorkloads, "max-workloads", 5, "Maximum number of workloads to display in risk ranking")
}

// filterKnownRisks filters KnownRisks based on namespace and workload
func filterKnownRisks(risks []*knownrisk.KnownRisk, namespace, workload string) []*knownrisk.KnownRisk {
	if namespace == "" && workload == "" {
		return risks
	}

	var filtered []*knownrisk.KnownRisk
	for _, kr := range risks {
		if namespace != "" && kr.WorkloadInfo.Namespace != namespace {
			continue
		}

		if workload != "" && !strings.Contains(kr.WorkloadInfo.Name, workload) {
			continue
		}

		filtered = append(filtered, kr)
	}

	return filtered
}

// displayDashboardHeader displays the dashboard header
func displayDashboardHeader(filteredCount, totalCount int) {
	fmt.Println("┌─────────────────────────────────────────────────────────────┐")
	fmt.Println("│                KYRA SECURITY RISK DASHBOARD                 │")
	fmt.Println("└─────────────────────────────────────────────────────────────┘")

	fmt.Printf("Date: %s\n", time.Now().Format("2006-01-02 15:04:05"))

	if filteredCount < totalCount {
		fmt.Printf("Showing %d of %d KnownRisks (filtered view)\n", filteredCount, totalCount)
	} else {
		fmt.Printf("Total KnownRisks: %d\n", totalCount)
	}

	fmt.Println(strings.Repeat("─", 80))
}

// displayRiskSummary displays a summary of risks by status and severity
func displayRiskSummary(risks []*knownrisk.KnownRisk) {
	fmt.Println("\n▶ RISK SUMMARY")

	// Count by status
	activeCount := 0
	expiredCount := 0
	resolvedCount := 0

	// Count by severity
	criticalCount := 0
	highCount := 0
	mediumCount := 0
	lowCount := 0

	// Count expiring soon (within 7 days)
	expiringSoonCount := 0

	for _, kr := range risks {
		// Update status first to ensure it's current
		kr.UpdateStatus()

		// Count by status
		switch kr.Status {
		case knownrisk.StatusActive:
			activeCount++

			// Check if expiring soon
			timeUntilExpiry := kr.ExpiresAt.Sub(time.Now())
			if timeUntilExpiry > 0 && timeUntilExpiry <= 7*24*time.Hour {
				expiringSoonCount++
			}
		case knownrisk.StatusExpired:
			expiredCount++
		case knownrisk.StatusResolved:
			resolvedCount++
		}

		// Count by severity
		switch kr.Severity {
		case knownrisk.SeverityCritical:
			criticalCount++
		case knownrisk.SeverityHigh:
			highCount++
		case knownrisk.SeverityMedium:
			mediumCount++
		case knownrisk.SeverityLow:
			lowCount++
		}
	}

	// Print summary table
	fmt.Println("┌─────────────────────────┬────────────────────────────┐")
	fmt.Println("│ STATUS                   │ SEVERITY                   │")
	fmt.Println("├─────────────────────────┼────────────────────────────┤")
	fmt.Printf("│ Active: %-16d │ Critical: %-16d │\n", activeCount, criticalCount)
	fmt.Printf("│ Expired: %-15d │ High: %-19d │\n", expiredCount, highCount)
	fmt.Printf("│ Resolved: %-14d │ Medium: %-17d │\n", resolvedCount, mediumCount)
	fmt.Printf("│ Expiring Soon: %-10d │ Low: %-20d │\n", expiringSoonCount, lowCount)
	fmt.Println("└─────────────────────────┴────────────────────────────┘")

	// Calculate risk score
	calculateOverallRiskScore(risks)
}

// calculateOverallRiskScore calculates and displays an overall risk score
func calculateOverallRiskScore(risks []*knownrisk.KnownRisk) {
	if len(risks) == 0 {
		fmt.Println("\nOverall Risk Score: N/A (No known risks)")
		return
	}

	// Simple scoring algorithm
	// Critical: 10 points, High: 5 points, Medium: 2 points, Low: 1 point
	// Expired risks get 2x weight

	totalScore := 0
	maxPossibleScore := 0

	for _, kr := range risks {
		// Skip resolved risks
		if kr.Status == knownrisk.StatusResolved {
			continue
		}

		// Calculate points for this risk
		points := 0
		switch kr.Severity {
		case knownrisk.SeverityCritical:
			points = 10
		case knownrisk.SeverityHigh:
			points = 5
		case knownrisk.SeverityMedium:
			points = 2
		case knownrisk.SeverityLow:
			points = 1
		}

		// Double points for expired risks
		if kr.Status == knownrisk.StatusExpired {
			points *= 2
		}

		totalScore += points

		// Always use Critical value for max possible score
		maxPossibleScore += 10
	}

	// Calculate percentage score (higher is worse)
	var scorePercentage int
	if maxPossibleScore > 0 {
		scorePercentage = (totalScore * 100) / maxPossibleScore
	}

	// Determine risk level
	var riskLevel string
	if scorePercentage >= 75 {
		riskLevel = "CRITICAL"
	} else if scorePercentage >= 50 {
		riskLevel = "HIGH"
	} else if scorePercentage >= 25 {
		riskLevel = "MEDIUM"
	} else {
		riskLevel = "LOW"
	}

	fmt.Printf("\nOverall Risk Score: %d%% (%s)\n", scorePercentage, riskLevel)

	// Display score bar
	displayScoreBar(scorePercentage)
}

// displayScoreBar displays a visual score bar
func displayScoreBar(percentage int) {
	barLength := 50
	completedLength := (percentage * barLength) / 100

	fmt.Print("[")
	for i := 0; i < barLength; i++ {
		if i < completedLength {
			if percentage >= 75 {
				fmt.Print("!")
			} else if percentage >= 50 {
				fmt.Print("*")
			} else {
				fmt.Print("=")
			}
		} else {
			fmt.Print(" ")
		}
	}
	fmt.Println("]")
}

// displaySeverityDistribution displays a histogram of severities
func displaySeverityDistribution(risks []*knownrisk.KnownRisk) {
	fmt.Println("\n▶ SEVERITY DISTRIBUTION")

	// Count by severity
	counts := map[knownrisk.Severity]int{
		knownrisk.SeverityCritical: 0,
		knownrisk.SeverityHigh:     0,
		knownrisk.SeverityMedium:   0,
		knownrisk.SeverityLow:      0,
	}

	for _, kr := range risks {
		counts[kr.Severity]++
	}

	// Skip if no data
	if len(risks) == 0 {
		fmt.Println("No data available.")
		return
	}

	// Find the maximum count for scaling
	maxCount := 0
	for _, count := range counts {
		if count > maxCount {
			maxCount = count
		}
	}

	// Graph scaling
	scale := 40
	if maxCount > 0 {
		// Calculate the character width per item
		scale = 40 / maxCount
		if scale == 0 {
			scale = 1
		}
	}

	// Display the histogram
	fmt.Println("Critical │" + strings.Repeat("■", counts[knownrisk.SeverityCritical]*scale) +
		fmt.Sprintf(" %d", counts[knownrisk.SeverityCritical]))

	fmt.Println("High     │" + strings.Repeat("■", counts[knownrisk.SeverityHigh]*scale) +
		fmt.Sprintf(" %d", counts[knownrisk.SeverityHigh]))

	fmt.Println("Medium   │" + strings.Repeat("■", counts[knownrisk.SeverityMedium]*scale) +
		fmt.Sprintf(" %d", counts[knownrisk.SeverityMedium]))

	fmt.Println("Low      │" + strings.Repeat("■", counts[knownrisk.SeverityLow]*scale) +
		fmt.Sprintf(" %d", counts[knownrisk.SeverityLow]))

	fmt.Println("         └" + strings.Repeat("─", 40))
}

// displayStatusDistribution displays a distribution of statuses
func displayStatusDistribution(risks []*knownrisk.KnownRisk) {
	fmt.Println("\n▶ STATUS DISTRIBUTION")

	// Count by status
	counts := map[knownrisk.Status]int{
		knownrisk.StatusActive:   0,
		knownrisk.StatusExpired:  0,
		knownrisk.StatusResolved: 0,
	}

	for _, kr := range risks {
		counts[kr.Status]++
	}

	// Skip if no data
	if len(risks) == 0 {
		fmt.Println("No data available.")
		return
	}

	// Calculate percentages
	totalRisks := len(risks)
	activePercent := 0
	expiredPercent := 0
	resolvedPercent := 0

	if totalRisks > 0 {
		activePercent = (counts[knownrisk.StatusActive] * 100) / totalRisks
		expiredPercent = (counts[knownrisk.StatusExpired] * 100) / totalRisks
		resolvedPercent = (counts[knownrisk.StatusResolved] * 100) / totalRisks
	}

	// Display the pie chart (ASCII art approximation)
	fmt.Println("┌────────────────────────────────────────────┐")
	fmt.Printf("│ Active:   %3d%%  %-30s │\n", activePercent, strings.Repeat("A", activePercent/5))
	fmt.Printf("│ Expired:  %3d%%  %-30s │\n", expiredPercent, strings.Repeat("E", expiredPercent/5))
	fmt.Printf("│ Resolved: %3d%%  %-30s │\n", resolvedPercent, strings.Repeat("R", resolvedPercent/5))
	fmt.Println("└────────────────────────────────────────────┘")
}

// displayExpirationDistribution displays a histogram of expiration times
func displayExpirationDistribution(risks []*knownrisk.KnownRisk) {
	fmt.Println("\n▶ EXPIRATION TIMELINE")

	// Skip if no active risks
	activeRisks := 0
	for _, kr := range risks {
		if kr.Status == knownrisk.StatusActive {
			activeRisks++
		}
	}

	if activeRisks == 0 {
		fmt.Println("No active risks to display.")
		return
	}

	// Group by expiration time buckets
	expireCounts := map[string]int{
		"< 1 day":   0,
		"< 1 week":  0,
		"< 1 month": 0,
		"> 1 month": 0,
	}

	for _, kr := range risks {
		if kr.Status != knownrisk.StatusActive {
			continue
		}

		timeUntilExpiry := kr.ExpiresAt.Sub(time.Now())
		if timeUntilExpiry <= 24*time.Hour {
			expireCounts["< 1 day"]++
		} else if timeUntilExpiry <= 7*24*time.Hour {
			expireCounts["< 1 week"]++
		} else if timeUntilExpiry <= 30*24*time.Hour {
			expireCounts["< 1 month"]++
		} else {
			expireCounts["> 1 month"]++
		}
	}

	// Find the maximum count for scaling
	maxCount := 0
	for _, count := range expireCounts {
		if count > maxCount {
			maxCount = count
		}
	}

	// Graph scaling
	scale := 40
	if maxCount > 0 {
		scale = 40 / maxCount
		if scale == 0 {
			scale = 1
		}
	}

	// Display the histogram
	fmt.Println("< 1 day   │" + strings.Repeat("■", expireCounts["< 1 day"]*scale) +
		fmt.Sprintf(" %d", expireCounts["< 1 day"]))

	fmt.Println("< 1 week  │" + strings.Repeat("■", expireCounts["< 1 week"]*scale) +
		fmt.Sprintf(" %d", expireCounts["< 1 week"]))

	fmt.Println("< 1 month │" + strings.Repeat("■", expireCounts["< 1 month"]*scale) +
		fmt.Sprintf(" %d", expireCounts["< 1 month"]))

	fmt.Println("> 1 month │" + strings.Repeat("■", expireCounts["> 1 month"]*scale) +
		fmt.Sprintf(" %d", expireCounts["> 1 month"]))

	fmt.Println("          └" + strings.Repeat("─", 40))
}

// WorkloadRiskScore represents the risk score for a workload
type WorkloadRiskScore struct {
	Namespace           string
	Name                string
	Type                string
	BusinessCriticality int
	RiskScore           int
	ActiveRisks         int
	ExpiredRisks        int
	CriticalRisks       int
}

// displayWorkloadRiskScores displays a ranking of workloads by risk
func displayWorkloadRiskScores(risks []*knownrisk.KnownRisk, maxWorkloads int) {
	fmt.Println("\n▶ TOP RISKY WORKLOADS")

	// Skip if no risks
	if len(risks) == 0 {
		fmt.Println("No risks to analyze.")
		return
	}

	// First identify all unique workloads
	workloadMap := make(map[string]*WorkloadRiskScore)

	for _, kr := range risks {
		// Skip resolved risks
		if kr.Status == knownrisk.StatusResolved {
			continue
		}

		workloadKey := fmt.Sprintf("%s/%s", kr.WorkloadInfo.Namespace, kr.WorkloadInfo.Name)

		score, exists := workloadMap[workloadKey]
		if !exists {
			// Initialize a new workload score
			score = &WorkloadRiskScore{
				Namespace:           kr.WorkloadInfo.Namespace,
				Name:                kr.WorkloadInfo.Name,
				Type:                string(kr.WorkloadInfo.Type),
				BusinessCriticality: kr.WorkloadInfo.BusinessCriticality,
			}
			workloadMap[workloadKey] = score
		}

		// Add to risk count
		if kr.Status == knownrisk.StatusActive {
			score.ActiveRisks++
		} else if kr.Status == knownrisk.StatusExpired {
			score.ExpiredRisks++
		}

		// Count critical risks
		if kr.Severity == knownrisk.SeverityCritical {
			score.CriticalRisks++
		}

		// Calculate risk score for this finding
		riskPoints := 0
		switch kr.Severity {
		case knownrisk.SeverityCritical:
			riskPoints = 10
		case knownrisk.SeverityHigh:
			riskPoints = 5
		case knownrisk.SeverityMedium:
			riskPoints = 2
		case knownrisk.SeverityLow:
			riskPoints = 1
		}

		// Double points for expired risks
		if kr.Status == knownrisk.StatusExpired {
			riskPoints *= 2
		}

		// Apply business criticality multiplier (1.0 to 2.0)
		businessMultiplier := 1.0 + float64(kr.WorkloadInfo.BusinessCriticality)/10.0
		riskPoints = int(float64(riskPoints) * businessMultiplier)

		score.RiskScore += riskPoints
	}

	// Convert map to slice for sorting
	var workloadScores []WorkloadRiskScore
	for _, score := range workloadMap {
		workloadScores = append(workloadScores, *score)
	}

	// Sort by risk score (highest first)
	sort.Slice(workloadScores, func(i, j int) bool {
		return workloadScores[i].RiskScore > workloadScores[j].RiskScore
	})

	// Display top workloads by risk
	fmt.Println("┌───────────────────────────────────────────────────────────────────────────────┐")
	fmt.Println("│ WORKLOAD                         │ CRIT │ SCORE │ ACTIVE │ EXPIRED │ BIZ CRIT │")
	fmt.Println("├───────────────────────────────────────────────────────────────────────────────┤")

	displayCount := len(workloadScores)
	if maxWorkloads > 0 && displayCount > maxWorkloads {
		displayCount = maxWorkloads
	}

	for i := 0; i < displayCount && i < len(workloadScores); i++ {
		ws := workloadScores[i]
		workloadID := fmt.Sprintf("%s/%s (%s)", ws.Namespace, ws.Name, ws.Type)
		if len(workloadID) > 30 {
			workloadID = workloadID[:27] + "..."
		} else {
			workloadID = workloadID + strings.Repeat(" ", 30-len(workloadID))
		}

		fmt.Printf("│ %s │ %4d │ %5d │ %6d │ %7d │ %8d │\n",
			workloadID, ws.CriticalRisks, ws.RiskScore, ws.ActiveRisks, ws.ExpiredRisks, ws.BusinessCriticality)
	}

	fmt.Println("└───────────────────────────────────────────────────────────────────────────────┘")
}

// displayDetailedRiskView displays a detailed view of all risks
func displayDetailedRiskView(risks []*knownrisk.KnownRisk) {
	fmt.Println("\n▶ DETAILED RISK VIEW")

	if len(risks) == 0 {
		fmt.Println("No risks to display.")
		return
	}

	// Sort first by status (Expired, Active, Resolved), then by severity, then by workload
	sort.Slice(risks, func(i, j int) bool {
		// First sort by status priority
		iStatusPriority := getStatusPriority(risks[i].Status)
		jStatusPriority := getStatusPriority(risks[j].Status)

		if iStatusPriority != jStatusPriority {
			return iStatusPriority > jStatusPriority
		}

		// Then by severity
		iSeverityPriority := getSeverityPriority(risks[i].Severity)
		jSeverityPriority := getSeverityPriority(risks[j].Severity)

		if iSeverityPriority != jSeverityPriority {
			return iSeverityPriority > jSeverityPriority
		}

		// Then by workload name
		return risks[i].WorkloadInfo.Name < risks[j].WorkloadInfo.Name
	})

	fmt.Println("┌─────────────────────────────────────────────────────────────────────────────────────────┐")
	fmt.Println("│ ID        │ VULNERABILITY │ WORKLOAD           │ SEVERITY │ STATUS   │ EXPIRY           │")
	fmt.Println("├─────────────────────────────────────────────────────────────────────────────────────────┤")

	for _, kr := range risks {
		// Format ID (truncated)
		idStr := kr.ID
		if len(idStr) > 10 {
			idStr = idStr[:7] + "..."
		}

		// Format vulnerability ID
		vulnStr := kr.VulnerabilityID
		if len(vulnStr) > 13 {
			vulnStr = vulnStr[:10] + "..."
		} else {
			vulnStr = vulnStr + strings.Repeat(" ", 13-len(vulnStr))
		}

		// Format workload
		workloadStr := fmt.Sprintf("%s/%s", kr.WorkloadInfo.Namespace, kr.WorkloadInfo.Name)
		if len(workloadStr) > 18 {
			workloadStr = workloadStr[:15] + "..."
		} else {
			workloadStr = workloadStr + strings.Repeat(" ", 18-len(workloadStr))
		}

		// Format expiry info
		var expiryStr string
		if kr.Status == knownrisk.StatusResolved {
			expiryStr = "N/A"
		} else if kr.Status == knownrisk.StatusExpired {
			timeSinceExpiry := time.Since(kr.ExpiresAt)
			expiryStr = fmt.Sprintf("%.1f days ago", timeSinceExpiry.Hours()/24)
		} else {
			timeUntilExpiry := kr.ExpiresAt.Sub(time.Now())
			expiryStr = fmt.Sprintf("in %.1f days", timeUntilExpiry.Hours()/24)
		}

		// Format strings for consistent column width
		severityStr := string(kr.Severity) + strings.Repeat(" ", 8-len(string(kr.Severity)))
		statusStr := string(kr.Status) + strings.Repeat(" ", 8-len(string(kr.Status)))

		fmt.Printf("│ %s │ %s │ %s │ %s │ %s │ %-16s │\n",
			idStr, vulnStr, workloadStr, severityStr, statusStr, expiryStr)
	}

	fmt.Println("└─────────────────────────────────────────────────────────────────────────────────────────┘")
}

// getStatusPriority returns a priority value for sorting statuses
func getStatusPriority(status knownrisk.Status) int {
	switch status {
	case knownrisk.StatusExpired:
		return 3 // Highest priority
	case knownrisk.StatusActive:
		return 2
	case knownrisk.StatusResolved:
		return 1 // Lowest priority
	default:
		return 0
	}
}

// getSeverityPriority returns a priority value for sorting severities
func getSeverityPriority(severity knownrisk.Severity) int {
	switch severity {
	case knownrisk.SeverityCritical:
		return 4 // Highest priority
	case knownrisk.SeverityHigh:
		return 3
	case knownrisk.SeverityMedium:
		return 2
	case knownrisk.SeverityLow:
		return 1 // Lowest priority
	default:
		return 0
	}
}
