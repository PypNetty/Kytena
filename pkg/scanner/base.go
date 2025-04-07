// pkg/cli/base.go
package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/PypNetty/Kytena/pkg/kubernetes"
	"github.com/PypNetty/Kytena/pkg/scanner"
	"github.com/PypNetty/Kytena/pkg/storage"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// GlobalOptions contient les options globales pour toutes les commandes
type GlobalOptions struct {
	// DataDir est le répertoire pour le stockage des données
	DataDir string
	// OutputFormat est le format de sortie (text, json)
	OutputFormat string
	// Verbose active la sortie verbeuse
	Verbose bool
	// Logger est le logger utilisé
	Logger *logrus.Logger
	// KubeConfig est le chemin vers le fichier kubeconfig
	KubeConfig string
	// InCluster indique s'il faut utiliser la configuration in-cluster
	InCluster bool
	// Context est le contexte d'annulation
	Context context.Context
	// CancelFunc est la fonction d'annulation du contexte
	CancelFunc context.CancelFunc
}

// CommandHandler est une fonction qui gère l'exécution d'une commande
type CommandHandler func(cmd *cobra.Command, args []string, options GlobalOptions) error

// NewGlobalOptions crée de nouvelles options globales avec des valeurs par défaut
func NewGlobalOptions() GlobalOptions {
	ctx, cancel := context.WithCancel(context.Background())

	logger := logrus.New()
	logger.SetOutput(os.Stdout)
	logger.SetLevel(logrus.InfoLevel)

	return GlobalOptions{
		DataDir:      "./data",
		OutputFormat: "text",
		Verbose:      false,
		Logger:       logger,
		KubeConfig:   "",
		InCluster:    false,
		Context:      ctx,
		CancelFunc:   cancel,
	}
}

// SetupGlobalFlags configure les flags globaux pour une commande
func SetupGlobalFlags(cmd *cobra.Command, options *GlobalOptions) {
	cmd.PersistentFlags().StringVar(&options.DataDir, "data-dir", options.DataDir, "Directory for data storage")
	cmd.PersistentFlags().StringVar(&options.OutputFormat, "output", options.OutputFormat, "Output format (text, json)")
	cmd.PersistentFlags().BoolVarP(&options.Verbose, "verbose", "v", options.Verbose, "Enable verbose output")
	cmd.PersistentFlags().StringVar(&options.KubeConfig, "kubeconfig", options.KubeConfig, "Path to the kubeconfig file (default is $HOME/.kube/config)")
	cmd.PersistentFlags().BoolVar(&options.InCluster, "in-cluster", options.InCluster, "Use in-cluster configuration")
}

// CreateCommand crée une nouvelle commande avec un gestionnaire
func CreateCommand(use, short, long string, handler CommandHandler, options *GlobalOptions) *cobra.Command {
	if options == nil {
		globalOptions := NewGlobalOptions()
		options = &globalOptions
	}

	cmd := &cobra.Command{
		Use:   use,
		Short: short,
		Long:  long,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Configurer le niveau de log
			if options.Verbose {
				options.Logger.SetLevel(logrus.DebugLevel)
			}

			// Gérer les signaux d'interruption pour un arrêt propre
			setupSignalHandler(options)

			// Exécuter le gestionnaire de commande
			return handler(cmd, args, *options)
		},
	}

	// Configurer les flags globaux
	SetupGlobalFlags(cmd, options)

	return cmd
}

// setupSignalHandler configure un gestionnaire de signaux pour un arrêt propre
func setupSignalHandler(options *GlobalOptions) {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigs
		fmt.Println("\nShutting down...")
		options.CancelFunc()
	}()
}

// CreateRepository crée un repository de stockage à partir des options globales
func CreateRepository(options GlobalOptions) (storage.Repository, error) {
	// Créer le répertoire de données s'il n'existe pas
	if err := os.MkdirAll(options.DataDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}

	// Créer le repository avec cache
	return storage.NewFileRepository(options.DataDir, storage.WithCache(5*time.Minute))
}

// CreateKubernetesClient crée un client Kubernetes à partir des options globales
func CreateKubernetesClient(options GlobalOptions) (*kubernetes.Client, error) {
	clientOptions := kubernetes.ClientOptions{
		KubeConfig: options.KubeConfig,
		InCluster:  options.InCluster,
		Logger:     options.Logger,
	}

	return kubernetes.NewClient(clientOptions)
}

// CreateScannerRegistry crée un registre de scanners et enregistre les scanners par défaut
func CreateScannerRegistry(options GlobalOptions) *scanner.VulnerabilityScannerRegistry {
	registry := scanner.NewVulnerabilityScannerRegistry(options.Logger)

	// Enregistrer les scanners par défaut
	trivyScanner := scanner.NewTrivyScanner(options.Logger)
	registry.RegisterScanner(trivyScanner)

	falcoScanner := scanner.NewFalcoScanner(options.Logger)
	registry.RegisterScanner(falcoScanner)

	return registry
}

// BaseCommand est une structure de base pour les commandes
type BaseCommand struct {
	// Use est la chaîne d'utilisation de la commande
	Use string
	// Short est la description courte de la commande
	Short string
	// Long est la description longue de la commande
	Long string
	// Handler est le gestionnaire de commande
	Handler CommandHandler
	// Options sont les options globales
	Options GlobalOptions
	// Command est la commande Cobra
	Command *cobra.Command
}

// NewBaseCommand crée une nouvelle commande de base
func NewBaseCommand(use, short, long string, handler CommandHandler) *BaseCommand {
	options := NewGlobalOptions()

	return &BaseCommand{
		Use:     use,
		Short:   short,
		Long:    long,
		Handler: handler,
		Options: options,
	}
}

// Setup initialise la commande
func (bc *BaseCommand) Setup() *cobra.Command {
	bc.Command = CreateCommand(bc.Use, bc.Short, bc.Long, bc.Handler, &bc.Options)
	return bc.Command
}

// AddFlag ajoute un flag à la commande
func (bc *BaseCommand) AddFlag(name, shorthand, defaultValue, usage string, variable *string) {
	if bc.Command == nil {
		bc.Setup()
	}

	if shorthand != "" {
		bc.Command.Flags().StringVarP(variable, name, shorthand, defaultValue, usage)
	} else {
		bc.Command.Flags().StringVar(variable, name, defaultValue, usage)
	}
}

// AddFlagBool ajoute un flag booléen à la commande
func (bc *BaseCommand) AddFlagBool(name, shorthand string, defaultValue bool, usage string, variable *bool) {
	if bc.Command == nil {
		bc.Setup()
	}

	if shorthand != "" {
		bc.Command.Flags().BoolVarP(variable, name, shorthand, defaultValue, usage)
	} else {
		bc.Command.Flags().BoolVar(variable, name, defaultValue, usage)
	}
}

// AddFlagInt ajoute un flag entier à la commande
func (bc *BaseCommand) AddFlagInt(name, shorthand string, defaultValue int, usage string, variable *int) {
	if bc.Command == nil {
		bc.Setup()
	}

	if shorthand != "" {
		bc.Command.Flags().IntVarP(variable, name, shorthand, defaultValue, usage)
	} else {
		bc.Command.Flags().IntVar(variable, name, defaultValue, usage)
	}
}

// ExecuteRootCommand exécute la commande racine
func ExecuteRootCommand(rootCmd *cobra.Command) {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
