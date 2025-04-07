package kubernetes

import (
	"context"
	"fmt"

	"github.com/PypNetty/Kytena/internal/models"
	"github.com/PypNetty/Kytena/internal/workload"
	log "github.com/sirupsen/logrus"
	k8s "k8s.io/client-go/kubernetes"
)

// KubernetesClient wraps the Kubernetes clientset
type KubernetesClient struct {
	Clientset *k8s.Clientset
}

// GetWorkloads retrieves workloads from Kubernetes and converts them to models.Workload
func (k *KubernetesClient) GetWorkloads(ctx context.Context, namespace string) ([]models.Workload, error) {
	// Utiliser le Discovery existant
	discovery := NewDiscovery(&Client{clientset: k.Clientset}, NewWorkloadMapper())
	options := DiscoveryOptions{
		IncludeJobs: false,
		IncludePods: false,
	}

	if namespace != "" {
		options.Namespaces = []string{namespace}
	}

	// Récupérer les workloads
	k8sWorkloads, err := discovery.DiscoverWorkloads(ctx, options)
	if err != nil {
		return nil, fmt.Errorf("failed to discover workloads: %w", err)
	}

	// Convertir les workloads Kubernetes en models.Workload
	var modelWorkloads []models.Workload
	for _, w := range k8sWorkloads {
		// Extraire les conteneurs du workload et les mapper au modèle
		modelContainers := extractContainersFromWorkload(w)

		if len(modelContainers) > 0 {
			modelWorkload := models.Workload{
				Name:       w.Name,
				Namespace:  w.Namespace,
				Type:       string(w.Type),
				Containers: modelContainers,
			}
			modelWorkloads = append(modelWorkloads, modelWorkload)
		}
	}

	log.Infof("Discovered %d Kubernetes workloads", len(modelWorkloads))
	return modelWorkloads, nil
}

// extractContainersFromWorkload extracts container information from a workload
func extractContainersFromWorkload(w workload.Workload) []models.Container {
	var containers []models.Container

	// Get containers from the workload
	for _, container := range w.Containers {
		if container.Image != "" {
			containers = append(containers, models.Container{
				Name:  container.Name,
				Image: container.Image,
			})
		}
	}

	return containers
}

// WorkloadManager implements models.WorkloadManager for Kubernetes
type WorkloadManager struct {
	client *KubernetesClient
}

// NewWorkloadManager creates a new WorkloadManager
func NewWorkloadManager(client *KubernetesClient) *WorkloadManager {
	return &WorkloadManager{
		client: client,
	}
}

// ListWorkloads lists workloads from Kubernetes
func (m *WorkloadManager) ListWorkloads(namespace string) ([]models.Workload, error) {
	return m.client.GetWorkloads(context.Background(), namespace)
}

// GetWorkload retrieves a specific workload
func (m *WorkloadManager) GetWorkload(namespace, name string) (*models.Workload, error) {
	// Basic implementation for retrieving a specific workload
	workloads, err := m.ListWorkloads(namespace)
	if err != nil {
		return nil, err
	}

	for i, w := range workloads {
		if w.Name == name && w.Namespace == namespace {
			return &workloads[i], nil
		}
	}

	return nil, fmt.Errorf("workload %s/%s not found", namespace, name)
}
