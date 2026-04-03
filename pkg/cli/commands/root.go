package commands

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/PypNetty/kytena/pkg/cli/common"
	"github.com/spf13/cobra"
)

// RootCmd représente la commande de base
var RootCmd = &cobra.Command{
	Use:   "kytena",
	Short: "Kytena - Kubernetes Security Risk Manager",
	Long: `Kytena est un outil de gestion des risques de sécurité pour Kubernetes.
Il permet de scanner, suivre et gérer les vulnérabilités et les risques connus
dans vos clusters Kubernetes.`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		common.InitGlobalOptions()
		baseOpts := common.GetGlobalOptions()

		// Initialiser les options globales
		globalOpts := common.GlobalOptions{
			DataDir:    dataDir,
			KubeConfig: kubeConfig,
			Debug:      debug,
			Logger:     baseOpts.Logger,
			Context:    cmd.Context(),
		}

		// Configurer le mode debug si activé
		if debug {
			fmt.Println("Debug mode enabled")
		}

		// Créer le répertoire de données s'il n'existe pas
		if err := os.MkdirAll(dataDir, 0755); err != nil {
			return fmt.Errorf("failed to create data directory: %w", err)
		}

		common.SetGlobalOptions(globalOpts)
		return nil
	},
}

var (
	dataDir    string
	kubeConfig string
	debug      bool
)

// Execute ajoute toutes les commandes enfants à la commande root et configure les flags
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {

	// Initialiser le répertoire de données par défaut

	homeDir, err := os.UserHomeDir()

	if err != nil {

		fmt.Println("Error getting user home directory:", err)

		os.Exit(1)

	}

	defaultDataDir := filepath.Join(homeDir, ".kytena")

	// Configurer les flags persistants

	RootCmd.PersistentFlags().StringVar(&dataDir, "data-dir", defaultDataDir, "Répertoire de données")

	RootCmd.PersistentFlags().StringVar(&kubeConfig, "kubeconfig", "", "Chemin du fichier kubeconfig")

	RootCmd.PersistentFlags().BoolVar(&debug, "debug", false, "Activer le mode debug")

	// Ajouter les sous-commandes

	RootCmd.AddCommand(NewScanCommand()) // Retirer l'argument GetGlobalOptions()

	RootCmd.AddCommand(NewUpdateCommand())

	RootCmd.AddCommand(NewListCommand())

	RootCmd.AddCommand(NewDashboardCommand())

}

// GetRootCmd retourne la commande racine pour les tests
func GetRootCmd() *cobra.Command {
	return RootCmd
}
