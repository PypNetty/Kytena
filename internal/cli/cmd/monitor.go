package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/PypNetty/Kytena/internal/knownrisk"
	"github.com/PypNetty/Kytena/internal/reevaluator"
	"github.com/spf13/cobra"
)

var (
	interval         int
	warningThreshold int
	logDir           string
)

var monitorCmd = &cobra.Command{
	Use:   "monitor",
	Short: "Start the KnownRisk monitor",
	Long: `Start the KnownRisk monitor that periodically reevaluates KnownRisks
and generates notifications for expired or soon-to-expire risks.

The monitor runs continuously until interrupted (Ctrl+C).`,
	Run: func(cmd *cobra.Command, args []string) {
		repo, err := knownrisk.NewFileRepository(GetDataDir())
		if err != nil {
			Fatal("Failed to create repository: %v", err)
		}

		consoleHandler := reevaluator.ConsoleNotificationHandler()
		var fileHandler reevaluator.NotificationHandler
		if logDir != "" {
			fileHandler, err = reevaluator.LoggingNotificationHandler(logDir)
			if err != nil {
				fmt.Printf("Warning: Failed to create logging handler: %v\n", err)
				fmt.Println("Continuing with console notifications only.")
			}
		}

		evaluator := reevaluator.NewPeriodicReevaluator(
			repo,
			time.Duration(interval)*time.Second,
		)
		evaluator.SetWarningThreshold(time.Duration(warningThreshold) * time.Hour)
		evaluator.RegisterNotificationHandler(consoleHandler)
		if fileHandler != nil {
			evaluator.RegisterNotificationHandler(fileHandler)
		}

		ctx, cancel := context.WithCancel(context.Background())
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

		go func() {
			<-sigs
			fmt.Println("\nShutting down monitor...")
			cancel()
		}()

		fmt.Println("Running initial evaluation...")
		notifications, err := evaluator.RunOnce(ctx)
		if err != nil {
			Fatal("Failed to run initial evaluation: %v", err)
		}
		fmt.Printf("Generated %d notifications initially\n", len(notifications))
		fmt.Printf("Starting periodic monitoring every %d seconds...\n", interval)
		fmt.Printf("Warning threshold set to %d hours before expiry\n", warningThreshold)
		fmt.Println("Press Ctrl+C to stop monitoring")

		done := make(chan struct{})
		go func() {
			if err := evaluator.Start(ctx); err != nil {
				fmt.Printf("Error running reevaluator: %v\n", err)
			}
			close(done)
		}()

		<-ctx.Done()
		if err := evaluator.Stop(ctx); err != nil {
			fmt.Printf("Warning: Error stopping reevaluator: %v\n", err)
		}
		fmt.Println("Monitor stopped.")
	},
}

func init() {
	rootCmd.AddCommand(monitorCmd)
	monitorCmd.Flags().IntVar(&interval, "interval", 60, "Reevaluation interval in seconds")
	monitorCmd.Flags().IntVar(&warningThreshold, "warning-threshold", 72, "Warning threshold in hours before expiry")
	monitorCmd.Flags().StringVar(&logDir, "log-dir", "./logs", "Directory for notification logs")
}
