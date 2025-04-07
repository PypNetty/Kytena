package kubernetes

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// Client represents a Kubernetes client wrapper
type Client struct {
	clientset *kubernetes.Clientset
}

func (c *Client) GetClientset() *kubernetes.Clientset {
	return c.clientset
}

// ClientOptions contains options for creating a new Kubernetes client
type ClientOptions struct {
	// KubeConfig is the path to the kubeconfig file
	KubeConfig string

	// InCluster indicates whether to use in-cluster configuration
	InCluster bool
}

// NewClient creates a new Kubernetes client
func NewClient(options ClientOptions) (*Client, error) {
	var config *rest.Config
	var err error

	if options.InCluster {
		// Use in-cluster configuration
		config, err = rest.InClusterConfig()
		if err != nil {
			return nil, fmt.Errorf("failed to create in-cluster config: %w", err)
		}
	} else {
		// Use kubeconfig file
		kubeconfig := options.KubeConfig
		if kubeconfig == "" {
			// Try to use default kubeconfig path
			home := os.Getenv("HOME")
			kubeconfig = filepath.Join(home, ".kube", "config")
		}

		// Build config from kubeconfig file
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, fmt.Errorf("failed to build config from kubeconfig: %w", err)
		}
	}

	// Create clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create clientset: %w", err)
	}

	return &Client{
		clientset: clientset,
	}, nil
}

// CreateClientFromConfig crée un nouveau client Kubernetes à partir d'un fichier kubeconfig
func CreateClientFromConfig(kubeconfigPath string) (*Client, error) {
	options := ClientOptions{
		KubeConfig: kubeconfigPath,
		InCluster:  false,
	}

	return NewClient(options)
}

// IsConnected vérifie si le client est connecté au cluster Kubernetes
func (c *Client) IsConnected() bool {
	_, err := c.clientset.ServerVersion()
	return err == nil
}

// GetNamespaces returns a list of all namespaces
func (c *Client) GetNamespaces(ctx context.Context) ([]corev1.Namespace, error) {
	namespaces, err := c.clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list namespaces: %w", err)
	}

	return namespaces.Items, nil
}

// GetDeployments returns a list of deployments in the specified namespace
// If namespace is empty, deployments from all namespaces are returned
func (c *Client) GetDeployments(ctx context.Context, namespace string) ([]appsv1.Deployment, error) {
	var deployments *appsv1.DeploymentList
	var err error

	if namespace == "" {
		// List deployments across all namespaces
		deployments, err = c.clientset.AppsV1().Deployments("").List(ctx, metav1.ListOptions{})
	} else {
		// List deployments in the specified namespace
		deployments, err = c.clientset.AppsV1().Deployments(namespace).List(ctx, metav1.ListOptions{})
	}

	if err != nil {
		return nil, fmt.Errorf("failed to list deployments: %w", err)
	}

	return deployments.Items, nil
}

// GetStatefulSets returns a list of stateful sets in the specified namespace
// If namespace is empty, stateful sets from all namespaces are returned
func (c *Client) GetStatefulSets(ctx context.Context, namespace string) ([]appsv1.StatefulSet, error) {
	var statefulSets *appsv1.StatefulSetList
	var err error

	if namespace == "" {
		// List stateful sets across all namespaces
		statefulSets, err = c.clientset.AppsV1().StatefulSets("").List(ctx, metav1.ListOptions{})
	} else {
		// List stateful sets in the specified namespace
		statefulSets, err = c.clientset.AppsV1().StatefulSets(namespace).List(ctx, metav1.ListOptions{})
	}

	if err != nil {
		return nil, fmt.Errorf("failed to list stateful sets: %w", err)
	}

	return statefulSets.Items, nil
}

// GetDaemonSets returns a list of daemon sets in the specified namespace
// If namespace is empty, daemon sets from all namespaces are returned
func (c *Client) GetDaemonSets(ctx context.Context, namespace string) ([]appsv1.DaemonSet, error) {
	var daemonSets *appsv1.DaemonSetList
	var err error

	if namespace == "" {
		// List daemon sets across all namespaces
		daemonSets, err = c.clientset.AppsV1().DaemonSets("").List(ctx, metav1.ListOptions{})
	} else {
		// List daemon sets in the specified namespace
		daemonSets, err = c.clientset.AppsV1().DaemonSets(namespace).List(ctx, metav1.ListOptions{})
	}

	if err != nil {
		return nil, fmt.Errorf("failed to list daemon sets: %w", err)
	}

	return daemonSets.Items, nil
}

// GetJobs returns a list of jobs in the specified namespace
// If namespace is empty, jobs from all namespaces are returned
func (c *Client) GetJobs(ctx context.Context, namespace string) ([]batchv1.Job, error) {
	var jobs *batchv1.JobList
	var err error

	if namespace == "" {
		// List jobs across all namespaces
		jobs, err = c.clientset.BatchV1().Jobs("").List(ctx, metav1.ListOptions{})
	} else {
		// List jobs in the specified namespace
		jobs, err = c.clientset.BatchV1().Jobs(namespace).List(ctx, metav1.ListOptions{})
	}

	if err != nil {
		return nil, fmt.Errorf("failed to list jobs: %w", err)
	}

	return jobs.Items, nil
}

// GetCronJobs returns a list of cron jobs in the specified namespace
// If namespace is empty, cron jobs from all namespaces are returned
func (c *Client) GetCronJobs(ctx context.Context, namespace string) ([]batchv1.CronJob, error) {
	var cronJobs *batchv1.CronJobList
	var err error

	if namespace == "" {
		// List cron jobs across all namespaces
		cronJobs, err = c.clientset.BatchV1().CronJobs("").List(ctx, metav1.ListOptions{})
	} else {
		// List cron jobs in the specified namespace
		cronJobs, err = c.clientset.BatchV1().CronJobs(namespace).List(ctx, metav1.ListOptions{})
	}

	if err != nil {
		return nil, fmt.Errorf("failed to list cron jobs: %w", err)
	}

	return cronJobs.Items, nil
}

// GetPods returns a list of pods in the specified namespace
// If namespace is empty, pods from all namespaces are returned
func (c *Client) GetPods(ctx context.Context, namespace string) ([]corev1.Pod, error) {
	var pods *corev1.PodList
	var err error

	if namespace == "" {
		// List pods across all namespaces
		pods, err = c.clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	} else {
		// List pods in the specified namespace
		pods, err = c.clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	}

	if err != nil {
		return nil, fmt.Errorf("failed to list pods: %w", err)
	}

	return pods.Items, nil
}
