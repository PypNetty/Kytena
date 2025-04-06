package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/PypNetty/Kyra/internal/knownrisk"
	"github.com/PypNetty/Kyra/internal/reevaluator"
	"github.com/spf13/cobra"
)

var (
	// Monitor command flags
	interval         int
	warningThreshold int
	logDir           string
)

// monitorCmd represents the monitor command
var monitorCmd = &cobra.Command{
	Use:   "monitor",
	Short: "Start the KnownRisk monitor",
	Long: `Start the KnownRisk monitor that periodically reevaluates KnownRisks
and generates notifications for expired or soon-to-expire risks.

The monitor runs continuously until interrupted (Ctrl+C).`,
	Run: func(cmd *cobra.Command, args []string) {
		// Create repository
		repo, err := knownrisk.NewFileRepository(GetDataDir())
		if err != nil {
			Fatal("Failed to create repository: %v", err)
		}

		// Create a console notification handler
		consoleHandler := reevaluator.ConsoleNotificationHandler()

		// Create a file logging notification handler if logDir is specified
		var fileHandler reevaluator.NotificationHandler
		if logDir != "" {
			fileHandler, err = reevaluator.LoggingNotificationHandler(logDir)
			if err != nil {
				fmt.Printf("Warning: Failed to create logging handler: %v\n", err)
				fmt.Println("Continuing with console notifications only.")
			}
		}

		// Create a reevaluator
		evaluator := reevaluator.NewPeriodicReevaluator(
			repo,
			time.Duration(interval)*time.Second,
		)

		// Set warning threshold
		evaluator.SetWarningThreshold(time.Duration(warningThreshold) * time.Hour)

		// Register notification handlers
		evaluator.RegisterNotificationHandler(consoleHandler)
		if fileHandler != nil {
			evaluator.RegisterNotificationHandler(fileHandler)
		}

		// Create a context with cancellation
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// Set up signal handling for graceful shutdown
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

		go func() {
			<-sigs
			fmt.Println("\nShutting down monitor...")
			cancel()
		}()

		// Run initial evaluation
		fmt.Println("Running initial evaluation...")
		notifications, err := evaluator.RunOnce(ctx)
		if err != nil {
			Fatal("Failed to run initial evaluation: %v", err)
		}
		fmt.Printf("Generated %d notifications initially\n", len(notifications))

		// Start periodic reevaluation
		fmt.Printf("Starting periodic monitoring every %d seconds...\n", interval)
		fmt.Printf("Warning threshold set to %d hours before expiry\n", warningThreshold)
		fmt.Println("Press Ctrl+C to stop monitoring")

		if err := evaluator.Start(ctx); err != nil {
			Fatal("Failed to start reevaluator: %v", err)
		}

		// Wait for context cancellation
		<-ctx.Done()

		// Stop the reevaluator
		if err := evaluator.Stop(); err != nil {
			fmt.Printf("Warning: Error stopping reevaluator: %v\n", err)
		}

		fmt.Println("Monitor stopped.")
	},
}

func init() {
	rootCmd.AddCommand(monitorCmd)

	// Add flags
	monitorCmd.Flags().IntVar(&interval, "interval", 60, "Reevaluation interval in seconds")
	monitorCmd.Flags().IntVar(&warningThreshold, "warning-threshold", 72, "Warning threshold in hours before expiry")
	monitorCmd.Flags().StringVar(&logDir, "log-dir", "./logs", "Directory for notification logs")
}
