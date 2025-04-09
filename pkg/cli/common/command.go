package common

import (
	"github.com/spf13/cobra"
)

// CommandFunc définit la signature des fonctions de commande
type CommandFunc func(cmd *cobra.Command, args []string, opts GlobalOptions) error

// CommandBuilder contient les informations nécessaires pour construire une commande
type CommandBuilder struct {
	Use         string
	Short       string
	Long        string
	RunE        CommandFunc
	Flags       func(*cobra.Command)
	Subcommands []*cobra.Command
}

// NewBaseCommand crée une nouvelle commande avec la configuration standard
func NewBaseCommand(builder CommandBuilder) *cobra.Command {
	cmd := &cobra.Command{
		Use:   builder.Use,
		Short: builder.Short,
		Long:  builder.Long,
		RunE: func(cmd *cobra.Command, args []string) error {
			return builder.RunE(cmd, args, GetGlobalOptions())
		},
	}

	if builder.Flags != nil {
		builder.Flags(cmd)
	}

	for _, sub := range builder.Subcommands {
		cmd.AddCommand(sub)
	}

	return cmd
}
