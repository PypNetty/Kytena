package common

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"
)

// PrintInfo affiche un message d'information formaté
func PrintInfo(format string, args ...interface{}) {
	fmt.Printf("Info: "+format+"\n", args...)
}

// PrintError affiche un message d'erreur formaté
func PrintError(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "Error: "+format+"\n", args...)
}

// PrintTable affiche des données sous forme de tableau
func PrintTable(headers []string, rows [][]string) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, strings.Join(headers, "\t"))
	fmt.Fprintln(w, strings.Repeat("-", len(strings.Join(headers, "  "))))

	for _, row := range rows {
		fmt.Fprintln(w, strings.Join(row, "\t"))
	}
	w.Flush()
}

// FormatDuration formate une durée en format lisible
func FormatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%.2f seconds", d.Seconds())
	}
	if d < time.Hour {
		return fmt.Sprintf("%.2f minutes", d.Minutes())
	}
	return fmt.Sprintf("%.2f hours", d.Hours())
}

// Add this function to the existing file:

// DisplayScoreBar displays a visual representation of a score as a progress bar
func DisplayScoreBar(score int, width int) {
	if width <= 0 {
		width = 50
	}

	// Calculate filled and empty sections
	filled := (score * width) / 100
	empty := width - filled

	// Create the bar sections
	filledBar := strings.Repeat("█", filled)
	emptyBar := strings.Repeat("░", empty)

	// Choose color based on score
	var color string
	switch {
	case score >= 75:
		color = "\033[31m" // Red
	case score >= 50:
		color = "\033[33m" // Yellow
	case score >= 25:
		color = "\033[36m" // Cyan
	default:
		color = "\033[32m" // Green
	}

	// Reset color code
	reset := "\033[0m"

	// Print the bar with percentage
	fmt.Printf("[%s%s%s%s] %d%%\n", color, filledBar, emptyBar, reset, score)
}
