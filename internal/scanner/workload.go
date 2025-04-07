// internal/scanner/workload.go
package scanner

// WorkloadManager gère l'accès aux workloads
type WorkloadManager interface {
	// ListWorkloads liste les workloads selon les critères donnés
	ListWorkloads(namespace string) ([]Workload, error)

	// GetWorkload récupère un workload spécifique
	GetWorkload(namespace, name string) (*Workload, error)
}

// Workload représente un workload Kubernetes
type Workload struct {
	Name        string
	Namespace   string
	Type        string
	Containers  []Container
	Labels      map[string]string
	Annotations map[string]string
}

// Container représente un conteneur dans un workload
type Container struct {
	Name  string
	Image string
}
