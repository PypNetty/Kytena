// pkg/cli/commands/dashboard.go
package commands

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/PypNetty/kytena/pkg/cli/common"
	"github.com/PypNetty/kytena/pkg/models"
	"github.com/PypNetty/kytena/pkg/storage"
	"github.com/spf13/cobra"
)

// DashboardOptions contient les options spécifiques à la commande dashboard
type DashboardOptions struct {
	Namespace    string
	Workload     string
	Detail       bool
	MaxWorkloads int
}

// WorkloadRiskScore représente le score de risque pour un workload
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

// NewDashboardCommand crée une nouvelle commande dashboard
func NewDashboardCommand() *cobra.Command {
	options := DashboardOptions{
		MaxWorkloads: 5,
	}

	cmd := common.CreateBaseCommand(
		"dashboard",
		"Display a security risk dashboard",
		`Display a comprehensive dashboard of your security posture based on KnownRisks.
This provides an overview of your security debt and highlights critical areas that need attention.`,
		func(cmd *cobra.Command, args []string, globalOptions common.GlobalOptions) error {
			return runDashboard(cmd, args, globalOptions, options)
		},
	)

	baseCmd := cmd.Setup()

	// Ajouter les flags
	baseCmd.Flags().StringVar(&options.Namespace, "namespace", "", "Filter by namespace")
	baseCmd.Flags().StringVar(&options.Workload, "workload", "", "Filter by workload name")
	baseCmd.Flags().BoolVar(&options.Detail, "detail", false, "Show detailed risk information")
	baseCmd.Flags().IntVar(&options.MaxWorkloads, "max-workloads", 5, "Maximum number of workloads to display in risk ranking")

	return baseCmd
}

// runDashboard exécute la commande dashboard
func runDashboard(_ *cobra.Command, _ []string, globalOptions common.GlobalOptions, options DashboardOptions) error {
	// Créer le repository
	repo, err := common.NewRepositoryWrapper(globalOptions.DataDir, globalOptions.Logger)
	if err != nil {
		return fmt.Errorf("failed to create repository: %w", err)
	}

	// Récupérer tous les KnownRisks
	risks, err := repo.List(globalOptions.Context, storage.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list KnownRisks: %w", err)
	}

	// Filtrer les risques si nécessaire
	filteredRisks := filterKnownRisks(risks, options.Namespace, options.Workload)

	// Afficher l'entête du dashboard
	displayDashboardHeader(len(filteredRisks), len(risks))

	// Afficher le résumé des risques
	displayRiskSummary(filteredRisks)

	// Afficher la distribution des risques
	displaySeverityDistribution(filteredRisks)
	displayStatusDistribution(filteredRisks)
	displayExpirationDistribution(filteredRisks)

	// Afficher les scores de risque des workloads
	displayWorkloadRiskScores(filteredRisks, options.MaxWorkloads)

	// Afficher la vue détaillée si demandée
	if options.Detail {
		displayDetailedRiskView(filteredRisks)
	}

	return nil
}

// filterKnownRisks filtre les KnownRisks en fonction du namespace et du workload
func filterKnownRisks(risks []*models.KnownRisk, namespace, workload string) []*models.KnownRisk {
	if namespace == "" && workload == "" {
		return risks
	}

	var filtered []*models.KnownRisk
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

// displayDashboardHeader affiche l'entête du dashboard
func displayDashboardHeader(filteredCount, totalCount int) {
	fmt.Println("┌─────────────────────────────────────────────────────────────┐")
	fmt.Println("│ KYRA SECURITY RISK DASHBOARD                                │")
	fmt.Println("└─────────────────────────────────────────────────────────────┘")
	fmt.Printf("Date: %s\n", time.Now().Format("2006-01-02 15:04:05"))

	if filteredCount < totalCount {
		fmt.Printf("Showing %d of %d KnownRisks (filtered view)\n", filteredCount, totalCount)
	} else {
		fmt.Printf("Total KnownRisks: %d\n", totalCount)
	}

	fmt.Println(strings.Repeat("─", 80))
}

// displayRiskSummary affiche un résumé des risques par statut et sévérité
func displayRiskSummary(risks []*models.KnownRisk) {
	fmt.Println("\n▶ RISK SUMMARY")

	// Compteurs par statut
	activeCount := 0
	expiredCount := 0
	resolvedCount := 0

	// Compteurs par sévérité
	criticalCount := 0
	highCount := 0
	mediumCount := 0
	lowCount := 0

	// Compteur d'expiration imminente (dans les 7 jours)
	expiringSoonCount := 0

	for _, kr := range risks {
		// Mettre à jour le statut d'abord pour s'assurer qu'il est à jour
		kr.UpdateStatus()

		// Compter par statut
		switch kr.Status {
		case models.StatusActive:
			activeCount++
			// Vérifier si l'expiration est imminente
			timeUntilExpiry := kr.ExpiresAt.Sub(time.Now())
			if timeUntilExpiry > 0 && timeUntilExpiry <= 7*24*time.Hour {
				expiringSoonCount++
			}
		case models.StatusExpired:
			expiredCount++
		case models.StatusResolved:
			resolvedCount++
		}

		// Compter par sévérité
		switch kr.Severity {
		case models.SeverityCritical:
			criticalCount++
		case models.SeverityHigh:
			highCount++
		case models.SeverityMedium:
			mediumCount++
		case models.SeverityLow:
			lowCount++
		}
	}

	// Afficher le tableau de résumé
	fmt.Println("┌─────────────────────────┬────────────────────────────┐")
	fmt.Println("│ STATUS                   │ SEVERITY                   │")
	fmt.Println("├─────────────────────────┼────────────────────────────┤")
	fmt.Printf("│ Active: %-16d │ Critical: %-16d │\n", activeCount, criticalCount)
	fmt.Printf("│ Expired: %-15d │ High: %-19d │\n", expiredCount, highCount)
	fmt.Printf("│ Resolved: %-14d │ Medium: %-17d │\n", resolvedCount, mediumCount)
	fmt.Printf("│ Expiring Soon: %-10d │ Low: %-20d │\n", expiringSoonCount, lowCount)
	fmt.Println("└─────────────────────────┴────────────────────────────┘")

	// Calculer le score de risque global
	calculateOverallRiskScore(risks)
}

// calculateOverallRiskScore calcule et affiche un score de risque global
func calculateOverallRiskScore(risks []*models.KnownRisk) {
	if len(risks) == 0 {
		fmt.Println("\nOverall Risk Score: N/A (No known risks)")
		return
	}

	// Algorithme de scoring simple
	// Critical: 10 points, High: 5 points, Medium: 2 points, Low: 1 point
	// Les risques expirés ont un poids 2x
	totalScore := 0
	maxPossibleScore := 0

	for _, kr := range risks {
		// Ignorer les risques résolus
		if kr.Status == models.StatusResolved {
			continue
		}

		// Calculer les points pour ce risque
		points := 0
		switch kr.Severity {
		case models.SeverityCritical:
			points = 10
		case models.SeverityHigh:
			points = 5
		case models.SeverityMedium:
			points = 2
		case models.SeverityLow:
			points = 1
		}

		// Doubler les points pour les risques expirés
		if kr.Status == models.StatusExpired {
			points *= 2
		}

		totalScore += points

		// Toujours utiliser la valeur critique pour le score maximum possible
		maxPossibleScore += 10
	}

	// Calculer le pourcentage du score (plus élevé est pire)
	var scorePercentage int
	if maxPossibleScore > 0 {
		scorePercentage = (totalScore * 100) / maxPossibleScore
	}

	// Déterminer le niveau de risque
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

	// Afficher la barre de score
	common.DisplayScoreBar(scorePercentage, 50)
}

// displaySeverityDistribution affiche un histogramme des sévérités
func displaySeverityDistribution(risks []*models.KnownRisk) {
	fmt.Println("\n▶ SEVERITY DISTRIBUTION")

	// Compter par sévérité
	counts := map[models.Severity]int{
		models.SeverityCritical: 0,
		models.SeverityHigh:     0,
		models.SeverityMedium:   0,
		models.SeverityLow:      0,
	}

	for _, kr := range risks {
		counts[kr.Severity]++
	}

	// Ignorer si pas de données
	if len(risks) == 0 {
		fmt.Println("No data available.")
		return
	}

	// Trouver le maximum pour l'échelle
	maxCount := 0
	for _, count := range counts {
		if count > maxCount {
			maxCount = count
		}
	}

	// Échelle du graphique
	scale := 40
	if maxCount > 0 {
		// Calculer la largeur de caractères par élément
		scale = 40 / maxCount
		if scale == 0 {
			scale = 1
		}
	}

	// Afficher l'histogramme
	fmt.Println("Critical │" + strings.Repeat("■", counts[models.SeverityCritical]*scale) +
		fmt.Sprintf(" %d", counts[models.SeverityCritical]))
	fmt.Println("High     │" + strings.Repeat("■", counts[models.SeverityHigh]*scale) +
		fmt.Sprintf(" %d", counts[models.SeverityHigh]))
	fmt.Println("Medium   │" + strings.Repeat("■", counts[models.SeverityMedium]*scale) +
		fmt.Sprintf(" %d", counts[models.SeverityMedium]))
	fmt.Println("Low      │" + strings.Repeat("■", counts[models.SeverityLow]*scale) +
		fmt.Sprintf(" %d", counts[models.SeverityLow]))
	fmt.Println("         └" + strings.Repeat("─", 40))
}

// displayStatusDistribution affiche une distribution des statuts
func displayStatusDistribution(risks []*models.KnownRisk) {
	fmt.Println("\n▶ STATUS DISTRIBUTION")

	// Compter par statut
	counts := map[models.Status]int{
		models.StatusActive:   0,
		models.StatusExpired:  0,
		models.StatusResolved: 0,
	}

	for _, kr := range risks {
		counts[kr.Status]++
	}

	// Ignorer si pas de données
	if len(risks) == 0 {
		fmt.Println("No data available.")
		return
	}

	// Calculer les pourcentages
	totalRisks := len(risks)
	activePercent := 0
	expiredPercent := 0
	resolvedPercent := 0

	if totalRisks > 0 {
		activePercent = (counts[models.StatusActive] * 100) / totalRisks
		expiredPercent = (counts[models.StatusExpired] * 100) / totalRisks
		resolvedPercent = (counts[models.StatusResolved] * 100) / totalRisks
	}

	// Afficher le graphique en secteurs (approximation ASCII)
	fmt.Println("┌────────────────────────────────────────────┐")
	fmt.Printf("│ Active: %3d%% %-30s │\n", activePercent, strings.Repeat("A", activePercent/5))
	fmt.Printf("│ Expired: %3d%% %-30s │\n", expiredPercent, strings.Repeat("E", expiredPercent/5))
	fmt.Printf("│ Resolved: %3d%% %-30s │\n", resolvedPercent, strings.Repeat("R", resolvedPercent/5))
	fmt.Println("└────────────────────────────────────────────┘")
}

// displayExpirationDistribution affiche un histogramme des délais d'expiration
func displayExpirationDistribution(risks []*models.KnownRisk) {
	fmt.Println("\n▶ EXPIRATION TIMELINE")

	// Ignorer s'il n'y a pas de risques actifs
	activeRisks := 0
	for _, kr := range risks {
		if kr.Status == models.StatusActive {
			activeRisks++
		}
	}

	if activeRisks == 0 {
		fmt.Println("No active risks to display.")
		return
	}

	// Grouper par délai d'expiration
	expireCounts := map[string]int{
		"< 1 day":   0,
		"< 1 week":  0,
		"< 1 month": 0,
		"> 1 month": 0,
	}

	for _, kr := range risks {
		if kr.Status != models.StatusActive {
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

	// Trouver le maximum pour l'échelle
	maxCount := 0
	for _, count := range expireCounts {
		if count > maxCount {
			maxCount = count
		}
	}

	// Échelle du graphique
	scale := 40
	if maxCount > 0 {
		scale = 40 / maxCount
		if scale == 0 {
			scale = 1
		}
	}

	// Afficher l'histogramme
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

// displayWorkloadRiskScores affiche un classement des workloads par risque
func displayWorkloadRiskScores(risks []*models.KnownRisk, maxWorkloads int) {
	fmt.Println("\n▶ TOP RISKY WORKLOADS")

	// Ignorer s'il n'y a pas de risques
	if len(risks) == 0 {
		fmt.Println("No risks to analyze.")
		return
	}

	// Identifier tous les workloads uniques
	workloadMap := make(map[string]*WorkloadRiskScore)

	for _, kr := range risks {
		// Ignorer les risques résolus
		if kr.Status == models.StatusResolved {
			continue
		}

		workloadKey := fmt.Sprintf("%s/%s", kr.WorkloadInfo.Namespace, kr.WorkloadInfo.Name)

		score, exists := workloadMap[workloadKey]
		if !exists {
			// Initialiser un nouveau score de workload
			score = &WorkloadRiskScore{
				Namespace:           kr.WorkloadInfo.Namespace,
				Name:                kr.WorkloadInfo.Name,
				Type:                string(kr.WorkloadInfo.Type),
				BusinessCriticality: kr.WorkloadInfo.BusinessCriticality,
			}
			workloadMap[workloadKey] = score
		}

		// Ajouter au compteur de risques
		if kr.Status == models.StatusActive {
			score.ActiveRisks++
		} else if kr.Status == models.StatusExpired {
			score.ExpiredRisks++
		}

		// Compter les risques critiques
		if kr.Severity == models.SeverityCritical {
			score.CriticalRisks++
		}

		// Calculer le score de risque pour cette découverte
		riskPoints := 0
		switch kr.Severity {
		case models.SeverityCritical:
			riskPoints = 10
		case models.SeverityHigh:
			riskPoints = 5
		case models.SeverityMedium:
			riskPoints = 2
		case models.SeverityLow:
			riskPoints = 1
		}

		// Doubler les points pour les risques expirés
		if kr.Status == models.StatusExpired {
			riskPoints *= 2
		}

		// Appliquer le multiplicateur de criticité business (1.0 à 2.0)
		businessMultiplier := 1.0 + float64(kr.WorkloadInfo.BusinessCriticality)/10.0
		riskPoints = int(float64(riskPoints) * businessMultiplier)

		score.RiskScore += riskPoints
	}

	// Convertir la map en slice pour le tri
	var workloadScores []WorkloadRiskScore
	for _, score := range workloadMap {
		workloadScores = append(workloadScores, *score)
	}

	// Trier par score de risque (le plus élevé en premier)
	sort.Slice(workloadScores, func(i, j int) bool {
		return workloadScores[i].RiskScore > workloadScores[j].RiskScore
	})

	// Afficher les workloads les plus risqués
	fmt.Println("┌───────────────────────────────────────────────────────────────────────────────┐")
	fmt.Println("│ WORKLOAD                       │ CRIT │ SCORE │ ACTIVE │ EXPIRED │ BIZ CRIT   │")
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
			workloadID, ws.CriticalRisks, ws.RiskScore, ws.ActiveRisks,
			ws.ExpiredRisks, ws.BusinessCriticality)
	}

	fmt.Println("└───────────────────────────────────────────────────────────────────────────────┘")
}

// displayDetailedRiskView affiche une vue détaillée de tous les risques
func displayDetailedRiskView(risks []*models.KnownRisk) {
	fmt.Println("\n▶ DETAILED RISK VIEW")

	if len(risks) == 0 {
		fmt.Println("No risks to display.")
		return
	}

	// Trier d'abord par statut (Expired, Active, Resolved), puis par sévérité, puis par workload
	sort.Slice(risks, func(i, j int) bool {
		// D'abord trier par priorité de statut
		iStatusPriority := models.GetStatusPriority(risks[i].Status)
		jStatusPriority := models.GetStatusPriority(risks[j].Status)

		if iStatusPriority != jStatusPriority {
			return iStatusPriority > jStatusPriority
		}

		// Puis par sévérité
		iSeverityPriority := models.GetSeverityPriority(risks[i].Severity)
		jSeverityPriority := models.GetSeverityPriority(risks[j].Severity)

		if iSeverityPriority != jSeverityPriority {
			return iSeverityPriority > jSeverityPriority
		}

		// Puis par nom de workload
		return risks[i].WorkloadInfo.Name < risks[j].WorkloadInfo.Name
	})

	fmt.Println("┌─────────────────────────────────────────────────────────────────────────────────────────┐")
	fmt.Println("│ ID        │ VULNERABILITY   │ WORKLOAD             │ SEVERITY │ STATUS   │ EXPIRY       │")
	fmt.Println("├─────────────────────────────────────────────────────────────────────────────────────────┤")

	for _, kr := range risks {
		// Formater l'ID (tronqué)
		idStr := kr.ID
		if len(idStr) > 10 {
			idStr = idStr[:7] + "..."
		}

		// Formater l'ID de vulnérabilité
		vulnStr := kr.VulnerabilityID
		if len(vulnStr) > 13 {
			vulnStr = vulnStr[:10] + "..."
		} else {
			vulnStr = vulnStr + strings.Repeat(" ", 13-len(vulnStr))
		}

		// Formater le workload
		workloadStr := fmt.Sprintf("%s/%s", kr.WorkloadInfo.Namespace, kr.WorkloadInfo.Name)
		if len(workloadStr) > 18 {
			workloadStr = workloadStr[:15] + "..."
		} else {
			workloadStr = workloadStr + strings.Repeat(" ", 18-len(workloadStr))
		}

		// Formater l'info d'expiration
		var expiryStr string
		if kr.Status == models.StatusResolved {
			expiryStr = "N/A"
		} else if kr.Status == models.StatusExpired {
			timeSinceExpiry := time.Since(kr.ExpiresAt)
			expiryStr = fmt.Sprintf("%.1f days ago", timeSinceExpiry.Hours()/24)
		} else {
			timeUntilExpiry := kr.ExpiresAt.Sub(time.Now())
			expiryStr = fmt.Sprintf("in %.1f days", timeUntilExpiry.Hours()/24)
		}

		// Formater les chaînes pour une largeur de colonne cohérente
		severityStr := string(kr.Severity) + strings.Repeat(" ", 8-len(string(kr.Severity)))
		statusStr := string(kr.Status) + strings.Repeat(" ", 8-len(string(kr.Status)))

		fmt.Printf("│ %s │ %s │ %s │ %s │ %s │ %-16s │\n",
			idStr, vulnStr, workloadStr, severityStr, statusStr, expiryStr)
	}

	fmt.Println("└─────────────────────────────────────────────────────────────────────────────────────────┘")
}
