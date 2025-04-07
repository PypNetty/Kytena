// pkg/cli/utils.go
package cli

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/PypNetty/Kytena/pkg/models"
	"github.com/fatih/color"
)

var (
	// Couleurs pour la console
	InfoColor    = color.New(color.FgCyan)
	SuccessColor = color.New(color.FgGreen)
	WarningColor = color.New(color.FgYellow)
	ErrorColor   = color.New(color.FgRed)

	// Symboles pour les différents niveaux de notification
	InfoSymbol    = "ℹ"
	SuccessSymbol = "✓"
	WarningSymbol = "⚠"
	ErrorSymbol   = "✗"
)

// FormatDuration formate une durée de manière lisible
func FormatDuration(d time.Duration) string {
	if d.Hours() > 24 {
		return fmt.Sprintf("%.0fd", d.Hours()/24)
	}
	if d.Hours() >= 1 {
		return fmt.Sprintf("%.0fh", d.Hours())
	}
	if d.Minutes() >= 1 {
		return fmt.Sprintf("%.0fm", d.Minutes())
	}
	return fmt.Sprintf("%ds", int(d.Seconds()))
}

// FormatPercentage formate un pourcentage avec le nombre spécifié de décimales
func FormatPercentage(value float64, decimals int) string {
	format := fmt.Sprintf("%%.%df%%%%", decimals)
	return fmt.Sprintf(format, value)
}

// PrintTable affiche des données sous forme de tableau
func PrintTable(headers []string, rows [][]string) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, strings.Join(headers, "\t"))

	for _, row := range rows {
		fmt.Fprintln(w, strings.Join(row, "\t"))
	}

	w.Flush()
}

// PrintInfo affiche un message d'information
func PrintInfo(format string, args ...interface{}) {
	InfoColor.Printf("%s %s\n", InfoSymbol, fmt.Sprintf(format, args...))
}

// PrintSuccess affiche un message de succès
func PrintSuccess(format string, args ...interface{}) {
	SuccessColor.Printf("%s %s\n", SuccessSymbol, fmt.Sprintf(format, args...))
}

// PrintWarning affiche un message d'avertissement
func PrintWarning(format string, args ...interface{}) {
	WarningColor.Printf("%s %s\n", WarningSymbol, fmt.Sprintf(format, args...))
}

// PrintError affiche un message d'erreur
func PrintError(format string, args ...interface{}) {
	ErrorColor.Printf("%s %s\n", ErrorSymbol, fmt.Sprintf(format, args...))
}

// Fatal affiche une erreur fatale et quitte l'application
func Fatal(format string, args ...interface{}) {
	PrintError(format, args...)
	os.Exit(1)
}

// AskForConfirmation demande une confirmation à l'utilisateur (y/n)
func AskForConfirmation(prompt string) bool {
	var response string

	fmt.Print(prompt + " (y/N): ")
	_, err := fmt.Scanln(&response)
	if err != nil {
		return false
	}

	response = strings.ToLower(strings.TrimSpace(response))
	return response == "y" || response == "yes"
}

// GetUserInput demande une saisie à l'utilisateur
func GetUserInput(prompt string) string {
	var input string

	fmt.Print(prompt + ": ")
	_, err := fmt.Scanln(&input)
	if err != nil {
		return ""
	}

	return strings.TrimSpace(input)
}

// RenderKnownRiskDetails affiche les détails d'un KnownRisk
func RenderKnownRiskDetails(kr *models.KnownRisk) {
	fmt.Println(strings.Repeat("=", 80))
	fmt.Printf("KnownRisk: %s\n", kr.ID)
	fmt.Println(strings.Repeat("=", 80))

	// Calculer le temps jusqu'à l'expiration
	timeUntilExpiry := kr.ExpiresAt.Sub(time.Now())
	var expiryInfo string
	if timeUntilExpiry > 0 {
		expiryInfo = fmt.Sprintf("Expires in %.1f days", timeUntilExpiry.Hours()/24)
	} else {
		expiryInfo = fmt.Sprintf("Expired %.1f days ago", -timeUntilExpiry.Hours()/24)
	}

	// Informations principales
	fmt.Printf("Vulnerability: %s\n", kr.VulnerabilityID)

	// Afficher le statut avec une couleur appropriée
	fmt.Printf("Status: ")
	switch kr.Status {
	case models.StatusActive:
		SuccessColor.Printf("%s", kr.Status)
	case models.StatusExpired:
		ErrorColor.Printf("%s", kr.Status)
	case models.StatusResolved:
		InfoColor.Printf("%s", kr.Status)
	default:
		fmt.Printf("%s", kr.Status)
	}
	fmt.Printf(" (%s)\n", expiryInfo)

	// Afficher la sévérité avec une couleur appropriée
	fmt.Printf("Severity: ")
	switch kr.Severity {
	case models.SeverityCritical:
		ErrorColor.Printf("%s", kr.Severity)
	case models.SeverityHigh:
		WarningColor.Printf("%s", kr.Severity)
	case models.SeverityMedium:
		InfoColor.Printf("%s", kr.Severity)
	case models.SeverityLow:
		SuccessColor.Printf("%s", kr.Severity)
	default:
		fmt.Printf("%s", kr.Severity)
	}
	fmt.Println()

	// Informations sur le workload
	fmt.Println("\n--- Workload Information ---")
	fmt.Printf("Name: %s\n", kr.WorkloadInfo.Name)
	fmt.Printf("Namespace: %s\n", kr.WorkloadInfo.Namespace)
	fmt.Printf("Type: %s\n", kr.WorkloadInfo.Type)
	fmt.Printf("Image: %s\n", kr.WorkloadInfo.ImageID)
	fmt.Printf("Business Criticality: %d/10\n", kr.WorkloadInfo.BusinessCriticality)

	// Afficher les labels s'il y en a
	if len(kr.WorkloadInfo.Labels) > 0 {
		fmt.Println("\nLabels:")
		for k, v := range kr.WorkloadInfo.Labels {
			fmt.Printf("  %s: %s\n", k, v)
		}
	}

	// Afficher les annotations s'il y en a
	if len(kr.WorkloadInfo.Annotations) > 0 {
		fmt.Println("\nAnnotations:")
		for k, v := range kr.WorkloadInfo.Annotations {
			fmt.Printf("  %s: %s\n", k, v)
		}
	}

	// Informations sur le risque
	fmt.Println("\n--- Risk Information ---")
	fmt.Printf("Justification: %s\n", kr.Justification)
	fmt.Printf("Accepted by: %s\n", kr.AcceptedBy)
	fmt.Printf("Accepted on: %s\n", kr.AcceptedAt.Format("2006-01-02 15:04:05"))
	fmt.Printf("Expires on: %s\n", kr.ExpiresAt.Format("2006-01-02 15:04:05"))

	if !kr.LastReviewedAt.IsZero() {
		fmt.Printf("Last reviewed: %s\n", kr.LastReviewedAt.Format("2006-01-02 15:04:05"))
	}

	// Tags et tickets associés
	if len(kr.Tags) > 0 {
		fmt.Printf("\nTags: %s\n", strings.Join(kr.Tags, ", "))
	}

	if len(kr.RelatedTickets) > 0 {
		fmt.Printf("Related tickets: %s\n", strings.Join(kr.RelatedTickets, ", "))
	}
}

// DisplayScoreBar affiche une barre de score visuelle
func DisplayScoreBar(percentage int, width int) {
	completed := (percentage * width) / 100

	fmt.Print("[")
	for i := 0; i < width; i++ {
		if i < completed {
			if percentage >= 75 {
				ErrorColor.Print("!")
			} else if percentage >= 50 {
				WarningColor.Print("*")
			} else {
				SuccessColor.Print("=")
			}
		} else {
			fmt.Print(" ")
		}
	}
	fmt.Println("]")
}
