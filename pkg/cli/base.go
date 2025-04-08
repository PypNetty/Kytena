package cli

import (
	"context"

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

// GetGlobalOptions extrait les options globales de la commande
func GetGlobalOptions(cmd *cobra.Command) GlobalOptions {
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	logger := logrus.New()
	logger.SetLevel(logrus.InfoLevel)

	options := GlobalOptions{
		Context:      ctx,
		Logger:       logger,
		DataDir:      "./data",
		OutputFormat: "text",
		KubeConfig:   cmd.Flag("kubeconfig").Value.String(),
	}

	if cmd.Flag("verbose").Value.String() == "true" {
		options.Logger.SetLevel(logrus.DebugLevel)
	}

	return options
}
