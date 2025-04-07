// pkg/kubernetes/mapper.go
package kubernetes

import (
	"fmt"
	"strings"

	"github.com/PypNetty/Kytena/pkg/models"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
)

// WorkloadMapper mappe les ressources Kubernetes vers les modèles de workload Kytena
type WorkloadMapper struct {
	// BusinessCriticalityLabels contient les labels utilisés pour déterminer la criticité business
	BusinessCriticalityLabels []string
	// DefaultBusinessCriticality est la criticité business par défaut quand aucun label n'est trouvé
	DefaultBusinessCriticality int
}

// NewWorkloadMapper crée un nouveau WorkloadMapper avec des paramètres par défaut
func NewWorkloadMapper() *WorkloadMapper {
	return &WorkloadMapper{
		BusinessCriticalityLabels: []string{
			"kyra.io/business-criticality",
			"app.kubernetes.io/criticality",
			"business-criticality",
		},
		DefaultBusinessCriticality: 5, // Criticité moyenne par défaut
	}
}

// getContainerImages extrait les images de conteneurs d'un template de pod
func getContainerImages(podTemplate corev1.PodTemplateSpec) []string {
	var images []string

	// Extraire les images des conteneurs d'initialisation
	for _, container := range podTemplate.Spec.InitContainers {
		images = append(images, container.Image)
	}

	// Extraire les images des conteneurs réguliers
	for _, container := range podTemplate.Spec.Containers {
		images = append(images, container.Image)
	}

	return images
}

// GetBusinessCriticality extrait la criticité business des labels
func (m *WorkloadMapper) GetBusinessCriticality(labels map[string]string) int {
	for _, labelKey := range m.BusinessCriticalityLabels {
		if value, ok := labels[labelKey]; ok {
			// Essayer de parser la valeur comme un entier
			var criticality int
			if _, err := fmt.Sscanf(value, "%d", &criticality); err == nil {
				// S'assurer que la valeur est dans l'intervalle
				if criticality >= 1 && criticality <= 10 {
					return criticality
				}
			}

			// Gérer les valeurs textuelles
			switch strings.ToLower(value) {
			case "critical", "high":
				return 9
			case "important", "medium-high":
				return 7
			case "medium":
				return 5
			case "low", "minimal":
				return 3
			}
		}
	}

	return m.DefaultBusinessCriticality
}

// extractContainers extrait les informations de conteneurs d'un template de pod
func (m *WorkloadMapper) extractContainers(podTemplate corev1.PodTemplateSpec) []models.Container {
	var containers []models.Container

	// Extraire les conteneurs d'initialisation
	for _, container := range podTemplate.Spec.InitContainers {
		containers = append(containers, models.Container{
			Name:  container.Name,
			Image: container.Image,
		})
	}

	// Extraire les conteneurs réguliers
	for _, container := range podTemplate.Spec.Containers {
		containers = append(containers, models.Container{
			Name:  container.Name,
			Image: container.Image,
		})
	}

	return containers
}

// MapDeploymentToWorkload mappe un Deployment Kubernetes vers un Workload Kytena
func (m *WorkloadMapper) MapDeploymentToWorkload(deployment appsv1.Deployment) models.Workload {
	images := getContainerImages(deployment.Spec.Template)

	primaryImage := ""
	if len(images) > 0 {
		primaryImage = images[0]
	}

	businessCriticality := m.GetBusinessCriticality(deployment.Labels)

	workload := models.Workload{
		Name:                deployment.Name,
		Namespace:           deployment.Namespace,
		Type:                models.TypeDeployment,
		ImageID:             primaryImage,
		BusinessCriticality: businessCriticality,
		Labels:              deployment.Labels,
		Annotations:         deployment.Annotations,
		Containers:          m.extractContainers(deployment.Spec.Template),
		CreationTimestamp:   deployment.CreationTimestamp.Time,
	}

	return workload
}

// MapStatefulSetToWorkload mappe un StatefulSet Kubernetes vers un Workload Kytena
func (m *WorkloadMapper) MapStatefulSetToWorkload(statefulSet appsv1.StatefulSet) models.Workload {
	images := getContainerImages(statefulSet.Spec.Template)

	primaryImage := ""
	if len(images) > 0 {
		primaryImage = images[0]
	}

	businessCriticality := m.GetBusinessCriticality(statefulSet.Labels)

	workload := models.Workload{
		Name:                statefulSet.Name,
		Namespace:           statefulSet.Namespace,
		Type:                models.TypeStatefulSet,
		ImageID:             primaryImage,
		BusinessCriticality: businessCriticality,
		Labels:              statefulSet.Labels,
		Annotations:         statefulSet.Annotations,
		Containers:          m.extractContainers(statefulSet.Spec.Template),
		CreationTimestamp:   statefulSet.CreationTimestamp.Time,
	}

	return workload
}

// MapDaemonSetToWorkload mappe un DaemonSet Kubernetes vers un Workload Kytena
func (m *WorkloadMapper) MapDaemonSetToWorkload(daemonSet appsv1.DaemonSet) models.Workload {
	images := getContainerImages(daemonSet.Spec.Template)

	primaryImage := ""
	if len(images) > 0 {
		primaryImage = images[0]
	}

	businessCriticality := m.GetBusinessCriticality(daemonSet.Labels)

	workload := models.Workload{
		Name:                daemonSet.Name,
		Namespace:           daemonSet.Namespace,
		Type:                models.TypeDaemonSet,
		ImageID:             primaryImage,
		BusinessCriticality: businessCriticality,
		Labels:              daemonSet.Labels,
		Annotations:         daemonSet.Annotations,
		Containers:          m.extractContainers(daemonSet.Spec.Template),
		CreationTimestamp:   daemonSet.CreationTimestamp.Time,
	}

	return workload
}

// MapJobToWorkload mappe un Job Kubernetes vers un Workload Kytena
func (m *WorkloadMapper) MapJobToWorkload(job batchv1.Job) models.Workload {
	images := getContainerImages(job.Spec.Template)

	primaryImage := ""
	if len(images) > 0 {
		primaryImage = images[0]
	}

	businessCriticality := m.GetBusinessCriticality(job.Labels)

	workload := models.Workload{
		Name:                job.Name,
		Namespace:           job.Namespace,
		Type:                models.TypeJob,
		ImageID:             primaryImage,
		BusinessCriticality: businessCriticality,
		Labels:              job.Labels,
		Annotations:         job.Annotations,
		Containers:          m.extractContainers(job.Spec.Template),
		CreationTimestamp:   job.CreationTimestamp.Time,
	}

	return workload
}

// MapCronJobToWorkload mappe un CronJob Kubernetes vers un Workload Kytena
func (m *WorkloadMapper) MapCronJobToWorkload(cronJob batchv1.CronJob) models.Workload {
	images := getContainerImages(cronJob.Spec.JobTemplate.Spec.Template)

	primaryImage := ""
	if len(images) > 0 {
		primaryImage = images[0]
	}

	businessCriticality := m.GetBusinessCriticality(cronJob.Labels)

	workload := models.Workload{
		Name:                cronJob.Name,
		Namespace:           cronJob.Namespace,
		Type:                models.TypeCronJob,
		ImageID:             primaryImage,
		BusinessCriticality: businessCriticality,
		Labels:              cronJob.Labels,
		Annotations:         cronJob.Annotations,
		Containers:          m.extractContainers(cronJob.Spec.JobTemplate.Spec.Template),
		CreationTimestamp:   cronJob.CreationTimestamp.Time,
	}

	return workload
}

// MapPodToWorkload mappe un Pod Kubernetes vers un Workload Kytena
func (m *WorkloadMapper) MapPodToWorkload(pod corev1.Pod) models.Workload {
	var containers []models.Container

	// Extraire les conteneurs d'initialisation
	for _, container := range pod.Spec.InitContainers {
		containers = append(containers, models.Container{
			Name:  container.Name,
			Image: container.Image,
		})
	}

	// Extraire les conteneurs réguliers
	for _, container := range pod.Spec.Containers {
		containers = append(containers, models.Container{
			Name:  container.Name,
			Image: container.Image,
		})
	}

	primaryImage := ""
	if len(containers) > 0 {
		primaryImage = containers[0].Image
	}

	businessCriticality := m.GetBusinessCriticality(pod.Labels)

	workload := models.Workload{
		Name:                pod.Name,
		Namespace:           pod.Namespace,
		Type:                models.TypePod,
		ImageID:             primaryImage,
		BusinessCriticality: businessCriticality,
		Labels:              pod.Labels,
		Annotations:         pod.Annotations,
		Containers:          containers,
		CreationTimestamp:   pod.CreationTimestamp.Time,
	}

	return workload
}
