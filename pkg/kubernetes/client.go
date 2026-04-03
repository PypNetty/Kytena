// pkg/kubernetes/client.go
package kubernetes

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/PypNetty/kytena/pkg/models"
	"github.com/sirupsen/logrus"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// ClientOptions contient les options pour créer un nouveau client Kubernetes
type ClientOptions struct {
	// KubeConfig est le chemin vers le fichier kubeconfig
	KubeConfig string
	// InCluster indique s'il faut utiliser la configuration in-cluster
	InCluster bool
	// Timeout est le timeout par défaut pour les opérations
	Timeout time.Duration
	// Logger est le logger à utiliser
	Logger *logrus.Logger
}

// Client représente un wrapper client Kubernetes
type Client struct {
	clientset *kubernetes.Clientset
	options   ClientOptions
	logger    *logrus.Logger
	mapper    *WorkloadMapper
}

// NewClient crée un nouveau client Kubernetes
func NewClient(options ClientOptions) (*Client, error) {
	// Initialiser le logger s'il n'est pas fourni
	logger := options.Logger
	if logger == nil {
		logger = logrus.New()
		logger.SetLevel(logrus.InfoLevel)
	}

	logger.Debug("Creating new Kubernetes client")

	var config *rest.Config
	var err error

	if options.InCluster {
		// Utiliser la configuration in-cluster
		logger.Debug("Using in-cluster configuration")
		config, err = rest.InClusterConfig()
		if err != nil {
			return nil, fmt.Errorf("failed to create in-cluster config: %w", err)
		}
	} else {
		// Utiliser le fichier kubeconfig
		kubeconfig := options.KubeConfig
		if kubeconfig == "" {
			// Essayer d'utiliser le chemin par défaut du kubeconfig
			home := os.Getenv("HOME")
			kubeconfig = filepath.Join(home, ".kube", "config")
			logger.Debugf("Using default kubeconfig path: %s", kubeconfig)
		}

		// Construire la configuration à partir du fichier kubeconfig
		logger.Debugf("Building config from kubeconfig: %s", kubeconfig)
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, fmt.Errorf("failed to build config from kubeconfig: %w", err)
		}
	}

	// Créer le clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create clientset: %w", err)
	}

	logger.Debug("Kubernetes client created successfully")

	// Créer le mapper
	mapper := NewWorkloadMapper()

	return &Client{
		clientset: clientset,
		options:   options,
		logger:    logger,
		mapper:    mapper,
	}, nil
}

// GetClientset retourne le clientset Kubernetes sous-jacent
func (c *Client) GetClientset() *kubernetes.Clientset {
	return c.clientset
}

// IsConnected vérifie si le client est connecté au cluster Kubernetes
func (c *Client) IsConnected() bool {
	_, err := c.clientset.ServerVersion()
	return err == nil
}

// GetNamespaces retourne la liste de tous les namespaces
func (c *Client) GetNamespaces(ctx context.Context) ([]corev1.Namespace, error) {
	c.logger.Debug("Getting namespaces")

	namespaces, err := c.clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list namespaces: %w", err)
	}

	c.logger.Debugf("Found %d namespaces", len(namespaces.Items))
	return namespaces.Items, nil
}

// GetWorkloads récupère tous les workloads Kubernetes et les convertit en modèles Kytena
func (c *Client) GetWorkloads(ctx context.Context, options DiscoveryOptions) ([]models.Workload, error) {
	c.logger.Debug("Getting workloads")

	// Récupérer ou utiliser les namespaces spécifiés
	namespaces := options.Namespaces
	if len(namespaces) == 0 {
		ns, err := c.GetNamespaces(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get namespaces: %w", err)
		}

		for _, n := range ns {
			namespaces = append(namespaces, n.Name)
		}
	}

	var workloads []models.Workload
	var mutex sync.Mutex
	var errs []error
	var wg sync.WaitGroup

	// Pour chaque namespace, découvrir les workloads en parallèle
	for _, namespace := range namespaces {
		wg.Add(1)

		go func(ns string) {
			defer wg.Done()

			// Récupérer les différents types de workloads
			deployments, err := c.GetDeployments(ctx, ns)
			if err != nil {
				mutex.Lock()
				errs = append(errs, fmt.Errorf("failed to get deployments in namespace %s: %w", ns, err))
				mutex.Unlock()
			} else {
				for _, deployment := range deployments {
					w := c.mapper.MapDeploymentToWorkload(deployment)
					mutex.Lock()
					workloads = append(workloads, w)
					mutex.Unlock()
				}
			}

			// StatefulSets
			statefulSets, err := c.GetStatefulSets(ctx, ns)
			if err != nil {
				mutex.Lock()
				errs = append(errs, fmt.Errorf("failed to get statefulsets in namespace %s: %w", ns, err))
				mutex.Unlock()
			} else {
				for _, statefulSet := range statefulSets {
					w := c.mapper.MapStatefulSetToWorkload(statefulSet)
					mutex.Lock()
					workloads = append(workloads, w)
					mutex.Unlock()
				}
			}

			// DaemonSets
			daemonSets, err := c.GetDaemonSets(ctx, ns)
			if err != nil {
				mutex.Lock()
				errs = append(errs, fmt.Errorf("failed to get daemonsets in namespace %s: %w", ns, err))
				mutex.Unlock()
			} else {
				for _, daemonSet := range daemonSets {
					w := c.mapper.MapDaemonSetToWorkload(daemonSet)
					mutex.Lock()
					workloads = append(workloads, w)
					mutex.Unlock()
				}
			}

			// CronJobs
			cronJobs, err := c.GetCronJobs(ctx, ns)
			if err != nil {
				mutex.Lock()
				errs = append(errs, fmt.Errorf("failed to get cronjobs in namespace %s: %w", ns, err))
				mutex.Unlock()
			} else {
				for _, cronJob := range cronJobs {
					w := c.mapper.MapCronJobToWorkload(cronJob)
					mutex.Lock()
					workloads = append(workloads, w)
					mutex.Unlock()
				}
			}

			// Jobs si demandé
			if options.IncludeJobs {
				jobs, err := c.GetJobs(ctx, ns)
				if err != nil {
					mutex.Lock()
					errs = append(errs, fmt.Errorf("failed to get jobs in namespace %s: %w", ns, err))
					mutex.Unlock()
				} else {
					for _, job := range jobs {
						w := c.mapper.MapJobToWorkload(job)
						mutex.Lock()
						workloads = append(workloads, w)
						mutex.Unlock()
					}
				}
			}

			// Pods si demandé
			if options.IncludePods {
				pods, err := c.GetPods(ctx, ns)
				if err != nil {
					mutex.Lock()
					errs = append(errs, fmt.Errorf("failed to get pods in namespace %s: %w", ns, err))
					mutex.Unlock()
				} else {
					for _, pod := range pods {
						// Ignorer les pods gérés par d'autres contrôleurs
						if len(pod.OwnerReferences) > 0 {
							continue
						}

						w := c.mapper.MapPodToWorkload(pod)
						mutex.Lock()
						workloads = append(workloads, w)
						mutex.Unlock()
					}
				}
			}
		}(namespace)
	}

	// Attendre que toutes les goroutines de découverte soient terminées
	wg.Wait()

	// S'il y a eu des erreurs, les retourner
	if len(errs) > 0 {
		return workloads, fmt.Errorf("encountered %d errors during discovery: %v", len(errs), errs[0])
	}

	c.logger.Debugf("Found %d workloads", len(workloads))
	return workloads, nil
}

// GetDeployments retourne la liste des deployments dans le namespace spécifié
// Si namespace est vide, les deployments de tous les namespaces sont retournés
func (c *Client) GetDeployments(ctx context.Context, namespace string) ([]appsv1.Deployment, error) {
	var deployments *appsv1.DeploymentList
	var err error

	if namespace == "" {
		// Lister les deployments dans tous les namespaces
		deployments, err = c.clientset.AppsV1().Deployments("").List(ctx, metav1.ListOptions{})
	} else {
		// Lister les deployments dans le namespace spécifié
		deployments, err = c.clientset.AppsV1().Deployments(namespace).List(ctx, metav1.ListOptions{})
	}

	if err != nil {
		return nil, fmt.Errorf("failed to list deployments: %w", err)
	}

	return deployments.Items, nil
}

// GetStatefulSets retourne la liste des statefulsets dans le namespace spécifié
// Si namespace est vide, les statefulsets de tous les namespaces sont retournés
func (c *Client) GetStatefulSets(ctx context.Context, namespace string) ([]appsv1.StatefulSet, error) {
	var statefulSets *appsv1.StatefulSetList
	var err error

	if namespace == "" {
		// Lister les statefulsets dans tous les namespaces
		statefulSets, err = c.clientset.AppsV1().StatefulSets("").List(ctx, metav1.ListOptions{})
	} else {
		// Lister les statefulsets dans le namespace spécifié
		statefulSets, err = c.clientset.AppsV1().StatefulSets(namespace).List(ctx, metav1.ListOptions{})
	}

	if err != nil {
		return nil, fmt.Errorf("failed to list statefulsets: %w", err)
	}

	return statefulSets.Items, nil
}

// GetDaemonSets retourne la liste des daemonsets dans le namespace spécifié
// Si namespace est vide, les daemonsets de tous les namespaces sont retournés
func (c *Client) GetDaemonSets(ctx context.Context, namespace string) ([]appsv1.DaemonSet, error) {
	var daemonSets *appsv1.DaemonSetList
	var err error

	if namespace == "" {
		// Lister les daemonsets dans tous les namespaces
		daemonSets, err = c.clientset.AppsV1().DaemonSets("").List(ctx, metav1.ListOptions{})
	} else {
		// Lister les daemonsets dans le namespace spécifié
		daemonSets, err = c.clientset.AppsV1().DaemonSets(namespace).List(ctx, metav1.ListOptions{})
	}

	if err != nil {
		return nil, fmt.Errorf("failed to list daemonsets: %w", err)
	}

	return daemonSets.Items, nil
}

// GetJobs retourne la liste des jobs dans le namespace spécifié
// Si namespace est vide, les jobs de tous les namespaces sont retournés
func (c *Client) GetJobs(ctx context.Context, namespace string) ([]batchv1.Job, error) {
	var jobs *batchv1.JobList
	var err error

	if namespace == "" {
		// Lister les jobs dans tous les namespaces
		jobs, err = c.clientset.BatchV1().Jobs("").List(ctx, metav1.ListOptions{})
	} else {
		// Lister les jobs dans le namespace spécifié
		jobs, err = c.clientset.BatchV1().Jobs(namespace).List(ctx, metav1.ListOptions{})
	}

	if err != nil {
		return nil, fmt.Errorf("failed to list jobs: %w", err)
	}

	return jobs.Items, nil
}

// GetCronJobs retourne la liste des cronjobs dans le namespace spécifié
// Si namespace est vide, les cronjobs de tous les namespaces sont retournés
func (c *Client) GetCronJobs(ctx context.Context, namespace string) ([]batchv1.CronJob, error) {
	var cronJobs *batchv1.CronJobList
	var err error

	if namespace == "" {
		// Lister les cronjobs dans tous les namespaces
		cronJobs, err = c.clientset.BatchV1().CronJobs("").List(ctx, metav1.ListOptions{})
	} else {
		// Lister les cronjobs dans le namespace spécifié
		cronJobs, err = c.clientset.BatchV1().CronJobs(namespace).List(ctx, metav1.ListOptions{})
	}

	if err != nil {
		return nil, fmt.Errorf("failed to list cronjobs: %w", err)
	}

	return cronJobs.Items, nil
}

// GetPods retourne la liste des pods dans le namespace spécifié
// Si namespace est vide, les pods de tous les namespaces sont retournés
func (c *Client) GetPods(ctx context.Context, namespace string) ([]corev1.Pod, error) {
	var pods *corev1.PodList
	var err error

	if namespace == "" {
		// Lister les pods dans tous les namespaces
		pods, err = c.clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	} else {
		// Lister les pods dans le namespace spécifié
		pods, err = c.clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	}

	if err != nil {
		return nil, fmt.Errorf("failed to list pods: %w", err)
	}

	return pods.Items, nil
}

// DiscoveryOptions contient les options pour la découverte des workloads
type DiscoveryOptions struct {
	// Namespaces limite la découverte à des namespaces spécifiques
	Namespaces []string
	// IncludeJobs indique s'il faut inclure les Jobs
	IncludeJobs bool
	// IncludePods indique s'il faut inclure les Pods autonomes
	IncludePods bool
}
