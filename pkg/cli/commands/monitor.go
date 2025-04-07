// pkg/cli/commands/monitor.go
package commands

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/PypNetty/Kytena/pkg/cli"
	"github.com/PypNetty/Kytena/pkg/reevaluator"
	"github.com/spf13/cobra"
)

// MonitorOptions contient les options spécifiques à la commande monitor
type MonitorOptions struct {
	Interval         int
	WarningThreshold int
	LogDir           string
}

// NewMonitorCommand crée une nouvelle commande monitor
func NewMonitorCommand() *cobra.Command {
	options := MonitorOptions{
		Interval:         60,
		WarningThreshold: 72,
		LogDir:           "./logs",
	}

	cmd := cli.NewBaseCommand(
		"monitor",
		"Start the KnownRisk monitor",
		`Start the KnownRisk monitor that periodically reevaluates KnownRisks
and generates notifications for expired or soon-to-expire risks.
The monitor runs continuously until interrupted (Ctrl+C).`,
		func(cmd *cobra.Command, args []string, globalOptions cli.GlobalOptions) error {
			return runMonitor(cmd, args, globalOptions, options)
		},
	)

	baseCmd := cmd.Setup()

	// Ajouter les flags
	baseCmd.Flags().IntVar(&options.Interval, "interval", options.Interval, "Reevaluation interval in seconds")
	baseCmd.Flags().IntVar(&options.WarningThreshold, "warning-threshold", options.WarningThreshold, "Warning threshold in hours before expiry")
	baseCmd.Flags().StringVar(&options.LogDir, "log-dir", options.LogDir, "Directory for notification logs")

	return baseCmd
}

// runMonitor exécute la commande monitor
func runMonitor(_ *cobra.Command, _ []string, globalOptions cli.GlobalOptions, options MonitorOptions) error {
	// Créer le repository
	repo, err := cli.CreateRepository(globalOptions)
	if err != nil {
		return fmt.Errorf("failed to create repository: %w", err)
	}

	// Créer le gestionnaire de notifications pour la console
	consoleHandler := reevaluator.ConsoleNotificationHandler()

	// Créer le gestionnaire de notifications pour les fichiers logs si un répertoire est spécifié
	var fileHandler reevaluator.NotificationHandler
	if options.LogDir != "" {
		fileHandler, err = reevaluator.LoggingNotificationHandler(options.LogDir)
		if err != nil {
			globalOptions.Logger.Warnf("Failed to create logging handler: %v", err)
			globalOptions.Logger.Warn("Continuing with console notifications only.")
		}
	}

	// Créer le réévaluateur périodique
	evaluator := reevaluator.NewPeriodicReevaluator(
		repo,
		time.Duration(options.Interval)*time.Second,
		globalOptions.Logger,
	)

	// Configurer le seuil d'avertissement
	evaluator.SetWarningThreshold(time.Duration(options.WarningThreshold) * time.Hour)

	// Enregistrer les gestionnaires de notification
	evaluator.RegisterNotificationHandler(consoleHandler)

	if fileHandler != nil {
		evaluator.RegisterNotificationHandler(fileHandler)
	}

	// Créer un contexte qui peut être annulé lors d'un signal d'interruption
	ctx, cancel := context.WithCancel(globalOptions.Context)
	defer cancel()

	// Configurer la gestion des signaux d'interruption
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigs
		fmt.Println("\nShutting down monitor...")
		cancel()
	}()

	// Exécuter une évaluation initiale
	fmt.Println("Running initial evaluation...")
	notifications, err := evaluator.RunOnce(ctx)
	if err != nil {
		return fmt.Errorf("failed to run initial evaluation: %w", err)
	}

	fmt.Printf("Generated %d notifications initially\n", len(notifications))
	fmt.Printf("Starting periodic monitoring every %d seconds...\n", options.Interval)
	fmt.Printf("Warning threshold set to %d hours before expiry\n", options.WarningThreshold)
	fmt.Println("Press Ctrl+C to stop monitoring")

	// Démarrer le réévaluateur périodique
	done := make(chan struct{})

	go func() {
		if err := evaluator.Start(ctx); err != nil {
			globalOptions.Logger.Errorf("Error running reevaluator: %v", err)
		}
		close(done)
	}()

	// Attendre la fin de l'exécution (annulation du contexte)
	<-ctx.Done()

	// Arrêter proprement le réévaluateur
	if err := evaluator.Stop(); err != nil {
		globalOptions.Logger.Warnf("Warning: Error stopping reevaluator: %v", err)
	}

	fmt.Println("Monitor stopped.")
	return nil
}
