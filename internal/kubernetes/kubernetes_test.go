package kubernetes

import (
	"context"
	"testing"
)

func TestKubernetesIntegration(t *testing.T) {
	// Ignorer le test si nous sommes en mode court
	if testing.Short() {
		t.Skip("Skipping Kubernetes integration test in short mode")
	}

	// Créer un client Kubernetes en utilisant la fonction existante
	client, err := CreateClientFromConfig("") // Utilise la fonction que nous avons ajoutée
	if err != nil {
		t.Fatalf("Failed to create Kubernetes client: %v", err)
	}

	// Vérifier la connexion
	_, err = client.
	.ServerVersion()
	if err != nil {
		t.Skip("Cannot connect to Kubernetes cluster, skipping test")
	}

	// Récupérer les namespaces
	ctx := context.Background()
	discovery := NewDiscovery(&Client{clientset: client.Clientset}, NewWorkloadMapper())

	// Tester le discovery
	options := DiscoveryOptions{
		IncludeJobs: true,
		IncludePods: true,
	}

	workloads, err := discovery.DiscoverWorkloads(ctx, options)
	if err != nil {
		t.Fatalf("Failed to discover workloads: %v", err)
	}

	t.Logf("Found %d workloads in the cluster", len(workloads))

	// Créer un workload manager et tester
	wm := NewWorkloadManager(client)
	scannerWorkloads, err := wm.GetWorkloads(ctx, "")
	if err != nil {
		t.Fatalf("Failed to get workloads: %v", err)
	}

	t.Logf("Found %d scanner workloads in the cluster", len(scannerWorkloads))
	for i, w := range scannerWorkloads {
		t.Logf("Workload %d: %s/%s (%s)", i+1, w.Namespace, w.Name, w.Type)
		for j, c := range w.Containers {
			t.Logf(" Container %d: %s -> %s", j+1, c.Name, c.Image)
		}
	}
}

type Client struct {
	Clientset any
}

func CreateClientFromConfig(s string) (*Client, error) {
	// This is a stub implementation for testing
	panic("unimplemented")
}
