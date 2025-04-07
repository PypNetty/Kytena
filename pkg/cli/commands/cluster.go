// pkg/cli/commands/cluster.go
package commands

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/PypNetty/Kytena/pkg/cli"
	"github.com/PypNetty/Kytena/pkg/kubernetes"
	"github.com/spf13/cobra"
)

// ClusterOptions contient les options spécifiques aux commandes cluster
type ClusterOptions struct {
	Namespace   string
	IncludePods bool
	IncludeJobs bool
}

// NewClusterCommand crée une nouvelle commande cluster
func NewClusterCommand() *cobra.Command {
	// Créer la commande principale de cluster
	clusterCmd := &cobra.Command{
		Use:   "cluster",
		Short: "Interact with Kubernetes cluster",
		Long:  `Interact with Kubernetes cluster to discover workloads, view resources, and map Kubernetes resources to Kytena workloads.`,
	}

	// Ajouter les sous-commandes
	clusterCmd.AddCommand(newWorkloadsCommand())
	clusterCmd.AddCommand(newNamespacesCommand())

	return clusterCmd
}

// newWorkloadsCommand crée une nouvelle commande cluster workloads
func newWorkloadsCommand() *cobra.Command {
	options := ClusterOptions{}

	cmd := cli.NewBaseCommand(
		"workloads",
		"List workloads in the Kubernetes cluster",
		`Discover and list workloads in the Kubernetes cluster.
This command connects to the cluster using your kubeconfig
and maps Kubernetes resources to Kytena workload models.`,
		func(cmd *cobra.Command, args []string, globalOptions cli.GlobalOptions) error {
			// Créer le client Kubernetes
			client, err := cli.CreateKubernetesClient(globalOptions)
			if err != nil {
				return fmt.Errorf("failed to create Kubernetes client: %w", err)
			}

			// Préparer les options de découverte
			discoveryOptions := kubernetes.DiscoveryOptions{
				IncludeJobs: options.IncludeJobs,
				IncludePods: options.IncludePods,
			}

			if options.Namespace != "" {
				discoveryOptions.Namespaces = []string{options.Namespace}
			}

			fmt.Println("Discovering workloads in Kubernetes cluster...")

			// Récupérer les workloads
			workloads, err := client.GetWorkloads(globalOptions.Context, discoveryOptions)
			if err != nil {
				if len(workloads) == 0 {
					return fmt.Errorf("failed to discover workloads: %w", err)
				}
				fmt.Printf("Warning: encountered errors during discovery: %v\n", err)
			}

			fmt.Printf("Found %d workloads\n\n", len(workloads))

			// Afficher les workloads dans un tableau
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "NAMESPACE\tNAME\tTYPE\tIMAGE\tBUSINESS CRITICALITY\tLABELS")

			for _, workload := range workloads {
				var labelStrs []string
				for k, v := range workload.Labels {
					labelStrs = append(labelStrs, fmt.Sprintf("%s=%s", k, v))
				}
				labelsStr := strings.Join(labelStrs, ",")
				if len(labelsStr) > 30 {
					labelsStr = labelsStr[:27] + "..."
				}

				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%s\n",
					workload.Namespace,
					workload.Name,
					workload.Type,
					workload.ImageID,
					workload.BusinessCriticality,
					labelsStr,
				)
			}

			w.Flush()
			return nil
		},
	)

	baseCmd := cmd.Setup()

	// Ajouter les flags
	baseCmd.Flags().StringVarP(&options.Namespace, "namespace", "n", "", "Namespace to filter workloads")
	baseCmd.Flags().BoolVar(&options.IncludePods, "include-pods", false, "Include pods in the workload discovery")
	baseCmd.Flags().BoolVar(&options.IncludeJobs, "include-jobs", false, "Include jobs in the workload discovery")

	return baseCmd
}

// newNamespacesCommand crée une nouvelle commande cluster namespaces
func newNamespacesCommand() *cobra.Command {
	cmd := cli.NewBaseCommand(
		"namespaces",
		"List namespaces in the Kubernetes cluster",
		`List namespaces in the Kubernetes cluster.
This command connects to the cluster using your kubeconfig
and retrieves all namespaces.`,
		func(cmd *cobra.Command, args []string, globalOptions cli.GlobalOptions) error {
			// Créer le client Kubernetes
			client, err := cli.CreateKubernetesClient(globalOptions)
			if err != nil {
				return fmt.Errorf("failed to create Kubernetes client: %w", err)
			}

			fmt.Println("Fetching namespaces from Kubernetes cluster...")

			// Récupérer les namespaces
			namespaces, err := client.GetNamespaces(globalOptions.Context)
			if err != nil {
				return fmt.Errorf("failed to get namespaces: %w", err)
			}

			fmt.Printf("Found %d namespaces\n\n", len(namespaces))

			// Afficher les namespaces dans un tableau
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "NAME\tSTATUS\tAGE")

			for _, ns := range namespaces {
				age := time.Since(ns.CreationTimestamp.Time).Round(time.Second)
				fmt.Fprintf(w, "%s\t%s\t%s\n",
					ns.Name,
					ns.Status.Phase,
					cli.FormatDuration(age),
				)
			}

			w.Flush()
			return nil
		},
	)

	return cmd.Setup()
}
