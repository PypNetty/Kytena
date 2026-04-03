package cli

import (
	"context"

	logruspkg "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	logger "github.com/PypNetty/kytena/pkg/loggers"
)

// logrusAdapter adapte *logrus.Logger vers logger.Logger
type logrusAdapter struct {
	base *logruspkg.Logger
}

func (l *logrusAdapter) Debug(args ...interface{})                 { l.base.Debug(args...) }
func (l *logrusAdapter) Debugf(format string, args ...interface{}) { l.base.Debugf(format, args...) }
func (l *logrusAdapter) Info(args ...interface{})                  { l.base.Info(args...) }
func (l *logrusAdapter) Infof(format string, args ...interface{})  { l.base.Infof(format, args...) }
func (l *logrusAdapter) Warn(args ...interface{})                  { l.base.Warn(args...) }
func (l *logrusAdapter) Warnf(format string, args ...interface{})  { l.base.Warnf(format, args...) }
func (l *logrusAdapter) Error(args ...interface{})                 { l.base.Error(args...) }
func (l *logrusAdapter) Errorf(format string, args ...interface{}) { l.base.Errorf(format, args...) }

// GlobalOptions contient les options globales pour toutes les commandes
type GlobalOptions struct {
	// DataDir est le répertoire pour le stockage des données
	DataDir string
	// OutputFormat est le format de sortie (text, json)
	OutputFormat string
	// Verbose active la sortie verbeuse
	Verbose bool
	// Logger est le logger utilisé
	Logger logger.Logger
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

	baseLogger := logruspkg.New()
	baseLogger.SetLevel(logruspkg.InfoLevel)

	if cmd.Flag("verbose").Value.String() == "true" {
		baseLogger.SetLevel(logruspkg.DebugLevel)
	}

	options := GlobalOptions{
		Context:      ctx,
		Logger:       &logrusAdapter{base: baseLogger},
		DataDir:      "./data",
		OutputFormat: "text",
		KubeConfig:   cmd.Flag("kubeconfig").Value.String(),
	}

	return options
}
