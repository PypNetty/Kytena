package kubernetes

import (
	"context"
	"fmt"
	"sync"

	"github.com/PypNetty/Kytena/internal/workload"
)

// Discovery is responsible for discovering Kubernetes workloads
type Discovery struct {
	client *Client
	mapper *WorkloadMapper
}

// DiscoveryOptions contains options for workload discovery
type DiscoveryOptions struct {
	// Namespaces limits discovery to specific namespaces
	Namespaces []string

	// IncludeJobs indicates whether to include Jobs
	IncludeJobs bool

	// IncludePods indicates whether to include standalone Pods
	IncludePods bool
}

// NewDiscovery creates a new workload discovery service
func NewDiscovery(client *Client, mapper *WorkloadMapper) *Discovery {
	if mapper == nil {
		mapper = NewWorkloadMapper()
	}

	return &Discovery{
		client: client,
		mapper: mapper,
	}
}

// DiscoverWorkloads discovers Kubernetes workloads and converts them to Kytena Workload models
func (d *Discovery) DiscoverWorkloads(ctx context.Context, options DiscoveryOptions) ([]workload.Workload, error) {
	var workloads []workload.Workload
	var mutex sync.Mutex
	var errs []error
	var wg sync.WaitGroup

	// If no namespaces are specified, discover in all namespaces
	namespaces := options.Namespaces
	if len(namespaces) == 0 {
		var err error
		ns, err := d.client.GetNamespaces(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get namespaces: %w", err)
		}

		for _, n := range ns {
			namespaces = append(namespaces, n.Name)
		}
	}

	// For each namespace, discover workloads in parallel
	for _, namespace := range namespaces {
		wg.Add(1)
		go func(ns string) {
			defer wg.Done()

			// Discover deployments
			deployments, err := d.client.GetDeployments(ctx, ns)
			if err != nil {
				mutex.Lock()
				errs = append(errs, fmt.Errorf("failed to get deployments in namespace %s: %w", ns, err))
				mutex.Unlock()
			} else {
				for _, deployment := range deployments {
					w := d.mapper.MapDeploymentToWorkload(deployment)
					mutex.Lock()
					workloads = append(workloads, w)
					mutex.Unlock()
				}
			}

			// Discover stateful sets
			statefulSets, err := d.client.GetStatefulSets(ctx, ns)
			if err != nil {
				mutex.Lock()
				errs = append(errs, fmt.Errorf("failed to get stateful sets in namespace %s: %w", ns, err))
				mutex.Unlock()
			} else {
				for _, statefulSet := range statefulSets {
					w := d.mapper.MapStatefulSetToWorkload(statefulSet)
					mutex.Lock()
					workloads = append(workloads, w)
					mutex.Unlock()
				}
			}

			// Discover daemon sets
			daemonSets, err := d.client.GetDaemonSets(ctx, ns)
			if err != nil {
				mutex.Lock()
				errs = append(errs, fmt.Errorf("failed to get daemon sets in namespace %s: %w", ns, err))
				mutex.Unlock()
			} else {
				for _, daemonSet := range daemonSets {
					w := d.mapper.MapDaemonSetToWorkload(daemonSet)
					mutex.Lock()
					workloads = append(workloads, w)
					mutex.Unlock()
				}
			}

			// Discover cron jobs
			cronJobs, err := d.client.GetCronJobs(ctx, ns)
			if err != nil {
				mutex.Lock()
				errs = append(errs, fmt.Errorf("failed to get cron jobs in namespace %s: %w", ns, err))
				mutex.Unlock()
			} else {
				for _, cronJob := range cronJobs {
					w := d.mapper.MapCronJobToWorkload(cronJob)
					mutex.Lock()
					workloads = append(workloads, w)
					mutex.Unlock()
				}
			}

			// Discover jobs if requested
			if options.IncludeJobs {
				jobs, err := d.client.GetJobs(ctx, ns)
				if err != nil {
					mutex.Lock()
					errs = append(errs, fmt.Errorf("failed to get jobs in namespace %s: %w", ns, err))
					mutex.Unlock()
				} else {
					for _, job := range jobs {
						w := d.mapper.MapJobToWorkload(job)
						mutex.Lock()
						workloads = append(workloads, w)
						mutex.Unlock()
					}
				}
			}

			// Discover pods if requested
			if options.IncludePods {
				pods, err := d.client.GetPods(ctx, ns)
				if err != nil {
					mutex.Lock()
					errs = append(errs, fmt.Errorf("failed to get pods in namespace %s: %w", ns, err))
					mutex.Unlock()
				} else {
					for _, pod := range pods {
						// Skip pods that are managed by other controllers
						if len(pod.OwnerReferences) > 0 {
							continue
						}

						w := d.mapper.MapPodToWorkload(pod)
						mutex.Lock()
						workloads = append(workloads, w)
						mutex.Unlock()
					}
				}
			}
		}(namespace)
	}

	// Wait for all discovery goroutines to complete
	wg.Wait()

	// If there were any errors, return them
	if len(errs) > 0 {
		return workloads, fmt.Errorf("encountered %d errors during discovery: %v", len(errs), errs[0])
	}

	return workloads, nil
}
