package models

// Container représente un conteneur dans un workload
type Container struct {
	Name  string
	Image string
}

// Workload représente un workload Kubernetes (deployment, statefulset, etc.)
type Workload struct {
	Name       string
	Namespace  string
	Type       string
	Containers []Container
}

// WorkloadManager est l'interface qui définit les opérations sur les workloads
type WorkloadManager interface {
	// ListWorkloads liste les workloads depuis une source (Kubernetes ou autre)
	ListWorkloads(namespace string) ([]Workload, error)

	// GetWorkload récupère un workload spécifique
	GetWorkload(namespace, name string) (*Workload, error)
}
