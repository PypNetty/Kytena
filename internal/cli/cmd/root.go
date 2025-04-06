package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	dataDir   string
	outputFmt string
	verbose   bool
)

var rootCmd = &cobra.Command{
	Use:   "kyra",
	Short: "Kyra - Intelligent Kubernetes Security Orchestrator",
	Long: `Kyra is an intelligent security orchestrator for Kubernetes that manages the lifecycle of known security risks (KnownRisks) with tracability and automatic reevalutation. It provides a way to document, track, and manage accepted security exceptions
in your Kubernetes environments.`,
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(&dataDir, "data-dir", "./data/knownrisks", "Directory for KnonwRisk storage")
	rootCmd.PersistentFlags().StringVar(&outputFmt, "output", "text", "Output format (text, json)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
}

func GetDataDIr() string {
	return dataDir
}

func IsVerbose() bool {
	return verbose
}

func Fatal(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "error,  "+format+"\n", args...)
	os.Exit(1)
}
