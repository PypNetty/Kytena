// pkg/models/workload.go
package models

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// WorkloadType représente le type d'un workload Kubernetes
type WorkloadType string

const (
	// Types de workloads supportés
	TypeDeployment  WorkloadType = "Deployment"
	TypeStatefulSet WorkloadType = "StatefulSet"
	TypeDaemonSet   WorkloadType = "DaemonSet"
	TypeCronJob     WorkloadType = "CronJob"
	TypeJob         WorkloadType = "Job"
	TypePod         WorkloadType = "Pod"
)

// Container représente un conteneur dans un workload
type Container struct {
	Name  string `json:"name" yaml:"name"`
	Image string `json:"image" yaml:"image"`
}

// Workload représente un workload Kubernetes avec ses métadonnées
type Workload struct {
	Name                string            `json:"name" yaml:"name"`
	Namespace           string            `json:"namespace" yaml:"namespace"`
	Type                WorkloadType      `json:"type" yaml:"type"`
	ImageID             string            `json:"imageId" yaml:"imageId"`
	BusinessCriticality int               `json:"businessCriticality" yaml:"businessCriticality"`
	Labels              map[string]string `json:"labels,omitempty" yaml:"labels,omitempty"`
	Annotations         map[string]string `json:"annotations,omitempty" yaml:"annotations,omitempty"`
	Containers          []Container       `json:"containers,omitempty" yaml:"containers,omitempty"`
	CreationTimestamp   time.Time         `json:"creationTimestamp,omitempty" yaml:"creationTimestamp,omitempty"`
}

// Validate vérifie la validité d'un workload
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
	if !IsValidWorkloadType(w.Type) {
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

// IsValidWorkloadType vérifie si le type de workload est valide
func IsValidWorkloadType(wt WorkloadType) bool {
	switch wt {
	case TypeDeployment, TypeStatefulSet, TypeDaemonSet, TypeCronJob, TypeJob, TypePod:
		return true
	default:
		return false
	}
}

// FormattedName retourne le nom formaté du workload (namespace/nom)
func (w *Workload) FormattedName() string {
	return fmt.Sprintf("%s/%s", w.Namespace, w.Name)
}

// GetLabel retourne la valeur d'un label spécifique
func (w *Workload) GetLabel(key string) string {
	if w.Labels == nil {
		return ""
	}
	return w.Labels[key]
}

// GetAnnotation retourne la valeur d'une annotation spécifique
func (w *Workload) GetAnnotation(key string) string {
	if w.Annotations == nil {
		return ""
	}
	return w.Annotations[key]
}

// HasLabel vérifie si le workload a un label spécifique avec une valeur donnée
func (w *Workload) HasLabel(key, value string) bool {
	if w.Labels == nil {
		return false
	}
	v, exists := w.Labels[key]
	return exists && v == value
}

// HasLabelPrefix vérifie si le workload a un label avec un préfixe spécifique
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

// NewWorkload crée une nouvelle instance de Workload
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
		Containers:          []Container{},
		CreationTimestamp:   time.Now(),
	}
}

// AddContainer ajoute un conteneur au workload
func (w *Workload) AddContainer(name, image string) {
	w.Containers = append(w.Containers, Container{
		Name:  name,
		Image: image,
	})
}

// GetPrimaryImage retourne l'image principale du workload
func (w *Workload) GetPrimaryImage() string {
	if w.ImageID != "" {
		return w.ImageID
	}

	if len(w.Containers) > 0 {
		return w.Containers[0].Image
	}

	return ""
}
