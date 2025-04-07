package main

import (
	"github.com/PypNetty/Kytena/pkg/cli"
	"github.com/PypNetty/Kytena/pkg/cli/commands"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func main() {
	// Initialiser le logger
	logger := logrus.New()

	// Créer la commande racine
	rootCmd := &cobra.Command{
		Use:   "kyra",
		Short: "Kytena - Intelligent Kubernetes Security Orchestrator",
		Long: `Kytena is an intelligent security orchestrator for Kubernetes that manages 
the lifecycle of known security risks (KnownRisks) with traceability and 
automatic reevalutation. It provides a way to document, track, and manage 
accepted security exceptions in your Kubernetes environments.`,
	}

	// Initialiser les options globales
	options := cli.NewGlobalOptions()
	options.Logger = logger

	// Configurer les flags globaux
	cli.SetupGlobalFlags(rootCmd, &options)

	// Ajouter les sous-commandes
	rootCmd.AddCommand(commands.NewScanCommand())
	rootCmd.AddCommand(commands.NewClusterCommand())
	rootCmd.AddCommand(commands.NewListCommand())
	rootCmd.AddCommand(commands.NewGetCommand())
	rootCmd.AddCommand(commands.NewCreateCommand())
	rootCmd.AddCommand(commands.NewUpdateCommand())
	rootCmd.AddCommand(commands.NewDeleteCommand())
	rootCmd.AddCommand(commands.NewDashboardCommand())
	rootCmd.AddCommand(commands.NewMonitorCommand())

	// Exécuter la commande racine
	cli.ExecuteRootCommand(rootCmd)
}
