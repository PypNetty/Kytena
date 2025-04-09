package common

import (
	"github.com/spf13/cobra"
)

type BaseCommand struct {
	Use     string
	Short   string
	Long    string
	RunFunc func(cmd *cobra.Command, args []string, globalOptions GlobalOptions) error
}

func CreateBaseCommand(use string, short string, long string, runFunc func(cmd *cobra.Command, args []string, globalOptions GlobalOptions) error) *BaseCommand {
	return &BaseCommand{
		Use:     use,
		Short:   short,
		Long:    long,
		RunFunc: runFunc,
	}
}

func (bc *BaseCommand) Setup() *cobra.Command {
	cmd := &cobra.Command{
		Use:   bc.Use,
		Short: bc.Short,
		Long:  bc.Long,
		RunE: func(cmd *cobra.Command, args []string) error {
			globalOptions := GetGlobalOptions()
			return bc.RunFunc(cmd, args, globalOptions)
		},
	}
	return cmd
}
