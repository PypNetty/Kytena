package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/PypNetty/Kyra/internal/kubernetes"
	"github.com/spf13/cobra"
)

var (
	kubeconfig       string
	inCluster        bool
	clusterNamespace string
	includePods      bool
	includeJobs      bool
)

// clusterCmd represents the cluster command
var clusterCmd = &cobra.Command{
	Use:   "cluster",
	Short: "Interact with Kubernetes cluster",
	Long: `Interact with Kubernetes cluster to discover workloads, view resources,
and map Kubernetes resources to Kyra workloads.`,
}

// workloadsCmd represents the cluster workloads command
var workloadsCmd = &cobra.Command{
	Use:   "workloads",
	Short: "List workloads in the Kubernetes cluster",
	Long: `Discover and list workloads in the Kubernetes cluster.
This command connects to the cluster using your kubeconfig
and maps Kubernetes resources to Kyra workload models.`,
	Run: func(cmd *cobra.Command, args []string) {
		clientOptions := kubernetes.ClientOptions{
			KubeConfig: kubeconfig,
			InCluster:  inCluster,
		}

		client, err := kubernetes.NewClient(clientOptions)
		if err != nil {
			Fatal("Failed to create Kubernetes client: %v", err)
		}

		mapper := kubernetes.NewWorkloadMapper()
		discovery := kubernetes.NewDiscovery(client, mapper)

		options := kubernetes.DiscoveryOptions{
			IncludeJobs: includeJobs,
			IncludePods: includePods,
		}

		if clusterNamespace != "" {
			options.Namespaces = []string{clusterNamespace}
		}

		fmt.Println("Discovering workloads in Kubernetes cluster...")
		workloads, err := discovery.DiscoverWorkloads(context.Background(), options)
		if err != nil {
			if len(workloads) == 0 {
				Fatal("Failed to discover workloads: %v", err)
			}
			fmt.Printf("Warning: encountered errors during discovery: %v\n", err)
		}

		fmt.Printf("Found %d workloads\n\n", len(workloads))

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
	},
}

// namespacesCmd represents the cluster namespaces command
var namespacesCmd = &cobra.Command{
	Use:   "namespaces",
	Short: "List namespaces in the Kubernetes cluster",
	Long: `List namespaces in the Kubernetes cluster.
This command connects to the cluster using your kubeconfig
and retrieves all namespaces.`,
	Run: func(cmd *cobra.Command, args []string) {
		clientOptions := kubernetes.ClientOptions{
			KubeConfig: kubeconfig,
			InCluster:  inCluster,
		}

		client, err := kubernetes.NewClient(clientOptions)
		if err != nil {
			Fatal("Failed to create Kubernetes client: %v", err)
		}

		fmt.Println("Fetching namespaces from Kubernetes cluster...")
		namespaces, err := client.GetNamespaces(context.Background())
		if err != nil {
			Fatal("Failed to get namespaces: %v", err)
		}

		fmt.Printf("Found %d namespaces\n\n", len(namespaces))

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "NAME\tSTATUS\tAGE")

		for _, ns := range namespaces {
			age := time.Since(ns.CreationTimestamp.Time).Round(time.Second)
			fmt.Fprintf(w, "%s\t%s\t%s\n",
				ns.Name,
				ns.Status.Phase,
				formatDuration(age),
			)
		}

		w.Flush()
	},
}

func init() {
	rootCmd.AddCommand(clusterCmd)
	clusterCmd.AddCommand(workloadsCmd)
	clusterCmd.AddCommand(namespacesCmd)

	clusterCmd.PersistentFlags().StringVar(&kubeconfig, "kubeconfig", "", "Path to the kubeconfig file (default is $HOME/.kube/config)")
	clusterCmd.PersistentFlags().BoolVar(&inCluster, "in-cluster", false, "Use in-cluster configuration")

	workloadsCmd.Flags().StringVarP(&clusterNamespace, "namespace", "n", "", "Namespace to filter workloads")
	workloadsCmd.Flags().BoolVar(&includePods, "include-pods", false, "Include pods in the workload discovery")
	workloadsCmd.Flags().BoolVar(&includeJobs, "include-jobs", false, "Include jobs in the workload discovery")
}

func formatDuration(d time.Duration) string {
	if d.Hours() > 24 {
		return fmt.Sprintf("%.0fd", d.Hours()/24)
	}
	if d.Hours() >= 1 {
		return fmt.Sprintf("%.0fh", d.Hours())
	}
	if d.Minutes() >= 1 {
		return fmt.Sprintf("%.0fm", d.Minutes())
	}
	return fmt.Sprintf("%ds", int(d.Seconds()))
}
