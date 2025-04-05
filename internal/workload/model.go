package workload

import (
	"errors"
	"strings"
)

type WorkloadType string

const (
	TypeDeployment  WorkloadType = "Deployment"
	TypeStatefulSet WorkloadType = "StatefulSet"
	TypeDaemonSet   WorkloadType = "DaemonSet"
	TypeCronJob     WorkloadType = "CronJob"
	TypeJob         WorkloadType = "Job"
	TypePod         WorkloadType = "Pod"
)

// Workload represents a Kubernetes workload with its metadata
type Workload struct {
	Name                string            `yaml:"name"`
	Namespace           string            `yaml:"namespace"`
	Type                WorkloadType      `yaml:"type"`
	ImageID             string            `yaml:"imageId"`
	BusinessCriticality int               `yaml:"businessCriticality"`
	Labels              map[string]string `yaml:"labels,omitempty"`
	Annotations         map[string]string `yaml:"annotations,omitempty"`
}

//Validate verifies workload information

func (w *Workload) Validate() error {
	if w.Name == "" {
		return errors.New("workload name cannot be empty")
	}

	if w.Namespace == "" {
		return errors.New("namespace cannot be empty")
	}

	if w.Type == "" {
		return errors.New("workload type cannot be empty")
	}
	if !isValidWorkloadType(w.Type) {
		return errors.New("invalid workload type")
	}

	if w.ImageID == "" {
		return errors.New("image ID cannot be empty")
	}

	if w.BusinessCriticality < 0 || w.BusinessCriticality > 10 {
		return errors.New("business criticality must be between 0 and 10")
	}
	return nil

}

// isValidWorkloadType checks if the workload type is valid
func isValidWorkloadType(wt WorkloadType) bool {
	switch wt {
	case TypeDeployment, TypeStatefulSet, TypeDaemonSet, TypeCronJob, TypeJob, TypePod:
		return true
	default:
		return false
	}
}

// FormattedName returns the formatted name of the workload (name and namespace)
func (w *Workload) FormattedName() string {
	return w.Namespace + "/" + w.Name
}

// GetLabel returns the value of a specific label
func (w *Workload) GetLabel(key string) string {
	if w.Labels == nil {
		return ""
	}
	return w.Labels[key]
}

// GetAnnotation returns the value of a specific annotation
func (w *Workload) GetAnnotation(key string) string {
	if w.Annotations == nil {
		return ""
	}
	return w.Annotations[key]
}

// HasLabel checks if the workload has a specific label and value
func (w *Workload) HasLabel(key, value string) bool {
	if w.Labels == nil {
		return false
	}
	v, exists := w.Labels[key]
	return exists && v == value
}

// HasLabelPrefix checks if the workload has a label with a specific prefix
func (w *Workload) HasLabelPrefix(prefix string) bool {
	if w.Labels == nil {
		return false
	}
	for key := range w.Labels {
		if strings.HasPrefix(key, prefix) {
			return true
		}
	}
	return false
}

// NewWorkload creates a new Workload instance
func NewWorkload(name, namespace string, wType WorkloadType, imageID string, businessCriticality int, labels, annotations map[string]string) *Workload {

	if labels == nil {
		labels = make(map[string]string)
	}
	if annotations == nil {
		annotations = make(map[string]string)
	}
	return &Workload{
		Name:                name,
		Namespace:           namespace,
		Type:                wType,
		ImageID:             imageID,
		BusinessCriticality: businessCriticality,
		Labels:              labels,
		Annotations:         annotations,
	}
}
