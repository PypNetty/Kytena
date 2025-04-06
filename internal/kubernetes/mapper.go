package kubernetes

import (
	"fmt"
	"strings"

	"github.com/PypNetty/Kytena/internal/workload"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
)

// WorkloadMapper maps Kubernetes resources to Kytena workload models
type WorkloadMapper struct {
	// BusinessCriticalityLabels contains the labels used to determine business criticality
	BusinessCriticalityLabels []string

	// DefaultBusinessCriticality is the default business criticality when no label is found
	DefaultBusinessCriticality int
}

// NewWorkloadMapper creates a new WorkloadMapper with default settings
func NewWorkloadMapper() *WorkloadMapper {
	return &WorkloadMapper{
		BusinessCriticalityLabels:  []string{"kyra.io/business-criticality", "app.kubernetes.io/criticality"},
		DefaultBusinessCriticality: 5, // Medium criticality by default
	}
}

// GetContainerImages extracts container images from a pod template
func getContainerImages(podTemplate corev1.PodTemplateSpec) []string {
	var images []string

	// Extract images from init containers
	for _, container := range podTemplate.Spec.InitContainers {
		images = append(images, container.Image)
	}

	// Extract images from regular containers
	for _, container := range podTemplate.Spec.Containers {
		images = append(images, container.Image)
	}

	return images
}

// GetBusinessCriticality extracts business criticality from labels
func (m *WorkloadMapper) GetBusinessCriticality(labels map[string]string) int {
	for _, labelKey := range m.BusinessCriticalityLabels {
		if value, ok := labels[labelKey]; ok {
			// Try to parse the value as an integer
			var criticality int
			if _, err := fmt.Sscanf(value, "%d", &criticality); err == nil {
				// Ensure the value is within range
				if criticality >= 1 && criticality <= 10 {
					return criticality
				}
			}

			// Handle text-based values
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

// MapDeploymentToWorkload maps a Kubernetes Deployment to a Kytena Workload
func (m *WorkloadMapper) MapDeploymentToWorkload(deployment appsv1.Deployment) workload.Workload {
	images := getContainerImages(deployment.Spec.Template)
	primaryImage := ""
	if len(images) > 0 {
		primaryImage = images[0]
	}

	businessCriticality := m.GetBusinessCriticality(deployment.Labels)

	return *workload.NewWorkload(
		deployment.Name,
		deployment.Namespace,
		workload.TypeDeployment,
		primaryImage,
		businessCriticality,
		deployment.Labels,
		deployment.Annotations,
	)
}

// MapStatefulSetToWorkload maps a Kubernetes StatefulSet to a Kytena Workload
func (m *WorkloadMapper) MapStatefulSetToWorkload(statefulSet appsv1.StatefulSet) workload.Workload {
	images := getContainerImages(statefulSet.Spec.Template)
	primaryImage := ""
	if len(images) > 0 {
		primaryImage = images[0]
	}

	businessCriticality := m.GetBusinessCriticality(statefulSet.Labels)

	return *workload.NewWorkload(
		statefulSet.Name,
		statefulSet.Namespace,
		workload.TypeStatefulSet,
		primaryImage,
		businessCriticality,
		statefulSet.Labels,
		statefulSet.Annotations,
	)
}

// MapDaemonSetToWorkload maps a Kubernetes DaemonSet to a Kytena Workload
func (m *WorkloadMapper) MapDaemonSetToWorkload(daemonSet appsv1.DaemonSet) workload.Workload {
	images := getContainerImages(daemonSet.Spec.Template)
	primaryImage := ""
	if len(images) > 0 {
		primaryImage = images[0]
	}

	businessCriticality := m.GetBusinessCriticality(daemonSet.Labels)

	return *workload.NewWorkload(
		daemonSet.Name,
		daemonSet.Namespace,
		workload.TypeDaemonSet,
		primaryImage,
		businessCriticality,
		daemonSet.Labels,
		daemonSet.Annotations,
	)
}

// MapJobToWorkload maps a Kubernetes Job to a Kytena Workload
func (m *WorkloadMapper) MapJobToWorkload(job batchv1.Job) workload.Workload {
	images := getContainerImages(job.Spec.Template)
	primaryImage := ""
	if len(images) > 0 {
		primaryImage = images[0]
	}

	businessCriticality := m.GetBusinessCriticality(job.Labels)

	return *workload.NewWorkload(
		job.Name,
		job.Namespace,
		workload.TypeJob,
		primaryImage,
		businessCriticality,
		job.Labels,
		job.Annotations,
	)
}

// MapCronJobToWorkload maps a Kubernetes CronJob to a Kytena Workload
func (m *WorkloadMapper) MapCronJobToWorkload(cronJob batchv1.CronJob) workload.Workload {
	images := getContainerImages(cronJob.Spec.JobTemplate.Spec.Template)
	primaryImage := ""
	if len(images) > 0 {
		primaryImage = images[0]
	}

	businessCriticality := m.GetBusinessCriticality(cronJob.Labels)

	return *workload.NewWorkload(
		cronJob.Name,
		cronJob.Namespace,
		workload.TypeCronJob,
		primaryImage,
		businessCriticality,
		cronJob.Labels,
		cronJob.Annotations,
	)
}

// MapPodToWorkload maps a Kubernetes Pod to a Kytena Workload
func (m *WorkloadMapper) MapPodToWorkload(pod corev1.Pod) workload.Workload {
	var images []string

	// Extract images from init containers
	for _, container := range pod.Spec.InitContainers {
		images = append(images, container.Image)
	}

	// Extract images from regular containers
	for _, container := range pod.Spec.Containers {
		images = append(images, container.Image)
	}

	primaryImage := ""
	if len(images) > 0 {
		primaryImage = images[0]
	}

	businessCriticality := m.GetBusinessCriticality(pod.Labels)

	return *workload.NewWorkload(
		pod.Name,
		pod.Namespace,
		workload.TypePod,
		primaryImage,
		businessCriticality,
		pod.Labels,
		pod.Annotations,
	)
}
