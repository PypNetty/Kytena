package common

import (
	"context"
	"os"
	"path/filepath"

	"github.com/PypNetty/kytena/pkg/loggers"
	"github.com/PypNetty/kytena/pkg/loggers/adapters"
	"github.com/sirupsen/logrus"
)

type GlobalOptions struct {
	Context    context.Context
	DataDir    string
	KubeConfig string
	Logger     loggers.Logger
	Debug      bool
}

var globalOptions GlobalOptions

func InitGlobalOptions() {
	// Initialise le logger logrus et adapte à l'interface loggers.Logger
	base := logrus.New()
	base.SetLevel(logrus.InfoLevel)

	debug := os.Getenv("KYTENA_DEBUG") == "1"
	if debug {
		base.SetLevel(logrus.DebugLevel)
	}

	globalOptions = GlobalOptions{
		Context: context.Background(),
		DataDir: filepath.Join(os.Getenv("HOME"), ".kytena"),
		Logger:  &adapters.LogrusAdapter{Base: base},
		Debug:   debug,
	}
}

func GetGlobalOptions() GlobalOptions {
	return globalOptions
}

func SetGlobalOptions(opts GlobalOptions) {
	globalOptions = opts
}
