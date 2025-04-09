package common

import (
	"context"
	"os"
	"path/filepath"

	"github.com/PypNetty/Kytena/pkg/logger"
	"github.com/sirupsen/logrus"
)

type GlobalOptions struct {
	Context    context.Context
	DataDir    string
	KubeConfig string
	Logger     logger.Logger
	Debug      bool
}

var globalOptions GlobalOptions

func InitGlobalOptions() {
	// Initialise le logger logrus et adapte à l'interface logger.Logger
	base := logrus.New()
	base.SetLevel(logrus.InfoLevel)

	debug := os.Getenv("KYTENA_DEBUG") == "1"
	if debug {
		base.SetLevel(logrus.DebugLevel)
	}

	globalOptions = GlobalOptions{
		Context: context.Background(),
		DataDir: filepath.Join(os.Getenv("HOME"), ".kytena"),
		Logger:  logger.FromLogrus(base), // ⚠️ cette fonction doit exister dans pkg/logger
		Debug:   debug,
	}
}

func GetGlobalOptions() GlobalOptions {
	return globalOptions
}

func SetGlobalOptions(opts GlobalOptions) {
	globalOptions = opts
}
