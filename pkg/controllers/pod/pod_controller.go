// Copyright (c) 2017 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pod

import (
	"reflect"
	"sync"

	"time"

	calicocache "github.com/projectcalico/kube-controllers/pkg/cache"
	"github.com/projectcalico/kube-controllers/pkg/controllers/controller"
	"github.com/projectcalico/kube-controllers/pkg/converter"
	"github.com/projectcalico/libcalico-go/lib/api"
	"github.com/projectcalico/libcalico-go/lib/client"
	"github.com/projectcalico/libcalico-go/lib/errors"
	log "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/fields"
	uruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/pkg/api/v1"
	"k8s.io/client-go/tools/cache"
)

type EndpointCache struct {
	sync.RWMutex
	m map[string]api.WorkloadEndpoint
}

// PodController implements the Controller interface.  It is responsible for monitoring
// kubernetes pods and updating workload endpoints in the Calico datastore if changed.
type PodController struct {
	indexer       cache.Indexer
	informer      cache.Controller
	wepDataCache  calicocache.ResourceCache
	endpointCache *EndpointCache
	calicoClient  *client.Client
	k8sClientset  *kubernetes.Clientset
}

// NewPodController Constructor for PodController
func NewPodController(k8sClientset *kubernetes.Clientset, calicoClient *client.Client) controller.Controller {
	podConverter := converter.NewPodConverter()

	// Function returns map of key->WorkloadEndpointData from the Calico datastore.
	listFunc := func() (map[string]interface{}, error) {
		// Get all workloadEndpoints for kubernetes orchestrator from the Calico datastore
		workloadEndpoints, err := calicoClient.WorkloadEndpoints().List(api.WorkloadEndpointMetadata{Orchestrator: "k8s"})
		if err != nil {
			return nil, err
		}

		// Iterate through and collect data from workload endpoints that we care about.
		m := make(map[string]interface{})
		for _, endpoint := range workloadEndpoints.Items {
			d := converter.BuildWorkloadEndpointData(endpoint)
			key := podConverter.GetKey(d)
			m[key] = d
		}
		log.Debugf("Found %d workload endpoints in Calico datastore:", len(m))
		return m, nil
	}

	cacheArgs := calicocache.ResourceCacheArgs{
		ListFunc:   listFunc,
		ObjectType: reflect.TypeOf(converter.WorkloadEndpointData{}),

		// We don't handle the cases where data is missing in the cache
		// or in the datastore, so disable those events in the reconciler. They
		// just cause unecessary work for us.
		ReconcilerConfig: calicocache.ReconcilerConfig{
			DisableMissingInCache:     true,
			DisableMissingInDatastore: true,
		},
	}

	wepDataCache := calicocache.NewResourceCache(cacheArgs)
	endpointCache := EndpointCache{m: make(map[string]api.WorkloadEndpoint)}

	// Create a Pod watcher.
	listWatcher := cache.NewListWatchFromClient(k8sClientset.Core().RESTClient(), "pods", "", fields.Everything())

	// Bind the Calico cache to kubernetes cache with the help of an informer. This way we make sure that
	// whenever the kubernetes cache is updated, changes get reflected in the Calico cache as well.
	indexer, informer := cache.NewIndexerInformer(listWatcher, &v1.Pod{}, 0, cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			key, err := cache.MetaNamespaceKeyFunc(obj)
			if err != nil {
				log.WithError(err).Error("Failed to generate key")
				return
			}
			log.Debugf("Got ADD event for pod: %s", key)

			// Ignore updates for host networked pods.
			if isHostNetworked(obj.(*v1.Pod)) {
				log.Debugf("Skipping irrelevant pod %s", key)
				return
			}

			wepInterface, err := podConverter.Convert(obj)
			if err != nil {
				log.WithError(err).Errorf("Error while converting %v to wep.", key)
				return
			}

			// Prime the cache - we only need to make changes to the datastore when the controller
			// receives an update, because initial state is written to the datastore by the CNI plugin.
			wepData := wepInterface.(converter.WorkloadEndpointData)
			k := podConverter.GetKey(wepData)
			wepDataCache.Prime(k, wepData)
		},
		UpdateFunc: func(oldObj interface{}, newObj interface{}) {
			key, err := cache.MetaNamespaceKeyFunc(newObj)
			if err != nil {
				log.WithError(err).Error("Failed to generate key")
				return
			}
			log.Debugf("Got UPDATE event for pod: %s", key)

			// Ignore updates for not ready / irrelevant pods.
			if !isReadyCalicoPod(newObj.(*v1.Pod)) {
				log.Debugf("Skipping irrelevant pod %s", key)
				return
			}

			wepInterface, err := podConverter.Convert(newObj)
			if err != nil {
				log.WithError(err).Errorf("Error while converting %v to wep.", key)
				return
			}

			// Update the cache.
			wepData := wepInterface.(converter.WorkloadEndpointData)
			k := podConverter.GetKey(wepData)
			wepDataCache.Set(k, wepData)
		},
		DeleteFunc: func(obj interface{}) {
			key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
			if err != nil {
				log.WithError(err).Error("Failed to generate key")
				return
			}
			log.Debugf("Got DELETE event for pod: %s", key)

			// Ignore updates for host networked pods.
			if isHostNetworked(obj.(*v1.Pod)) {
				log.Debugf("Skipping irrelevant pod %s", key)
				return
			}

			wepInterface, err := podConverter.Convert(obj)
			if err != nil {
				log.WithError(err).Errorf("Error while converting %v to wep.", key)
				return
			}

			// Clean up after the deleted workload endpoint.
			wep := wepInterface.(converter.WorkloadEndpointData)
			k := podConverter.GetKey(wep)
			wepDataCache.Clean(k)
			endpointCache.Lock()
			delete(endpointCache.m, k)
			endpointCache.Unlock()
		},
	}, cache.Indexers{})

	return &PodController{indexer, informer, wepDataCache, &endpointCache, calicoClient, k8sClientset}
}

// Run starts controller.Internally it starts syncing
// kubernetes and calico caches.
func (c *PodController) Run(threadiness int, reconcilerPeriod string, stopCh chan struct{}) {
	defer uruntime.HandleCrash()

	// Let the workers stop when we are done
	workqueue := c.wepDataCache.GetQueue()
	defer workqueue.ShutDown()

	log.Info("Starting Pod/WorkloadEndpoint controller")

	// Load endpoint cache. Retry when failed.
	log.Debug("Loading endpoint cache at start of day")
	for err := c.populateEndpointCache(); err != nil; {
		log.WithError(err).Errorf("Failed to load workload endpoint cache, retrying in 5s")
		time.Sleep(5 * time.Second)
	}

	// Wait till k8s cache is synced
	go c.informer.Run(stopCh)
	log.Debug("Waiting to sync with Kubernetes API (Pods)")
	for !c.informer.HasSynced() {
	}
	log.Debug("Finished syncing with Kubernetes API (Pods)")

	// Start Calico cache.
	c.wepDataCache.Run(reconcilerPeriod)

	// Start a number of worker threads to read from the queue.
	for i := 0; i < threadiness; i++ {
		go c.runWorker()
	}
	log.Info("Pod/WorkloadEndpoint controller is now running")

	<-stopCh
	log.Info("Stopping Pod controller")
}

func (c *PodController) runWorker() {
	for c.processNextItem() {
	}
}

func (c *PodController) processNextItem() bool {
	// Wait until there is a new item in the work queue.
	workqueue := c.wepDataCache.GetQueue()
	key, quit := workqueue.Get()
	if quit {
		return false
	}

	// Sync the object to the Calico datastore.
	if err := c.syncToCalico(key.(string)); err != nil {
		c.handleErr(err, key.(string))
	}

	// Indicate that we're done processing this key, allowing for safe parallel processing such that
	// two objects with the same key are never processed in parallel.
	workqueue.Done(key)
	return true
}

// syncToCalico syncs the given update to the Calico datastore.
func (c *PodController) syncToCalico(key string) error {
	// Check if the wep data exists in our cache.  If it doesn't, then we don't need to do anything,
	// since CNI handles deletion of workload endpoints.
	if wepData, exists := c.wepDataCache.Get(key); exists {
		// Get workloadEndpoint from cache
		clog := log.WithField("wep", key)
		c.endpointCache.RLock()
		endpoint, exists := c.endpointCache.m[key]
		c.endpointCache.RUnlock()
		if !exists {
			// Load endpoint cache.
			clog.Warnf("No corresponding WorkloadEndpoint in cache, re-loading cache from datastore")
			if err := c.populateEndpointCache(); err != nil {
				clog.WithError(err).Error("Failed to load workload endpoint cache")
				return err
			}

			// See if it is in the cache now.
			c.endpointCache.RLock()
			endpoint, exists = c.endpointCache.m[key]
			c.endpointCache.RUnlock()
			if !exists {
				// No endpoint in datastore - this means the pod hasn't been
				// created by the CNI plugin yet. Just wait until it has been.
				// This can only be hit when pod changes before
				// the pod has been deployed, so should be pretty uncommon.
				clog.Infof("Pod hasn't been created by the CNI plugin yet.")
				return nil
			}
		}

		// Compare to see if the workload endpoint data has changed.
		old := converter.BuildWorkloadEndpointData(endpoint)
		new := wepData.(converter.WorkloadEndpointData)
		if !reflect.DeepEqual(old, new) {
			// The relevant wep data has changed - update the wep and write it to the datastore.
			log.Infof("Writing endpoint %s with updated data %#v to Calico datastore", key, new)
			converter.MergeWorkloadEndpointData(&endpoint, new)
			_, err := c.calicoClient.WorkloadEndpoints().Update(&endpoint)
			if err != nil {
				if _, ok := err.(errors.ErrorResourceUpdateConflict); !ok {
					// Not an update conflict - return the error right away.
					clog.WithError(err).Errorf("failed to update workload endpoint")
					return err
				}

				// We hit an update conflict, re-query the WorkloadEndpoint before we try again.
				clog.Warn("Update conflict, re-querying workload endpoint")
				qwep, gErr := c.calicoClient.WorkloadEndpoints().Get(endpoint.Metadata)
				if gErr != nil {
					log.WithError(err).Errorf("failed to query workload endpoint %s", key)
					return gErr
				}
				clog.Warn("Updated cache with latest wep from datastore.")
				c.endpointCache.Lock()
				c.endpointCache.m[key] = *qwep
				c.endpointCache.Unlock()
				return err
			}

			// Update endpoint cache as well with the modified endpoint.
			updatedWep, err := c.calicoClient.WorkloadEndpoints().Get(endpoint.Metadata)
			if err != nil {
				log.WithError(err).Errorf("failed to query workload endpoint %s", key)
				return err
			}
			c.endpointCache.Lock()
			c.endpointCache.m[key] = *updatedWep
			c.endpointCache.Unlock()
			return nil
		}
	}
	return nil
}

// populateEndpointCache() Loads map of workload endpoint objects from the Calico datastore
func (c *PodController) populateEndpointCache() error {
	// List all workload endpoints for kubernetes orchestrator
	workloadEndpointList, err := c.calicoClient.WorkloadEndpoints().List(api.WorkloadEndpointMetadata{Orchestrator: "k8s"})
	if err != nil {
		return err
	}

	c.endpointCache.Lock()
	for _, wep := range workloadEndpointList.Items {
		c.endpointCache.m[wep.Metadata.Workload] = wep
	}
	c.endpointCache.Unlock()
	return nil
}

// handleErr checks if an error happened and makes sure we will retry later.
func (c *PodController) handleErr(err error, key string) {
	workqueue := c.wepDataCache.GetQueue()
	if err == nil {
		// Forget about the #AddRateLimited history of the key on every successful synchronization.
		// This ensures that future processing of updates for this key is not delayed because of
		// an outdated error history.
		log.WithField("key", key).Debug("Error for key is no more, drop from retry queue")
		workqueue.Forget(key)
		return
	}

	// This controller retries 5 times if something goes wrong. After that, it stops trying.
	if workqueue.NumRequeues(key) < 5 {
		log.WithError(err).Errorf("Error syncing pod, will retry: %v: %v", key, err)
		// Re-enqueue the key rate limited. Based on the rate limiter on the
		// queue and the re-enqueue history, the key will be processed later again.
		workqueue.AddRateLimited(key)
		return
	}
	workqueue.Forget(key)

	// Report to an external entity that, even after several retries, we could not successfully process this key
	uruntime.HandleError(err)
	log.WithError(err).Errorf("Dropping pod %q out of the retry queue: %v", key, err)
}

func isReadyCalicoPod(pod *v1.Pod) bool {
	if isHostNetworked(pod) {
		log.WithField("pod", pod.Name).Debug("Pod is host networked.")
		return false
	} else if !hasIPAddress(pod) {
		log.WithField("pod", pod.Name).Debug("Pod does not have an IP address.")
		return false
	} else if !isScheduled(pod) {
		log.WithField("pod", pod.Name).Debug("Pod is not scheduled.")
		return false
	}
	return true
}

func isScheduled(pod *v1.Pod) bool {
	return pod.Spec.NodeName != ""
}

func isHostNetworked(pod *v1.Pod) bool {
	return pod.Spec.HostNetwork
}

func hasIPAddress(pod *v1.Pod) bool {
	return pod.Status.PodIP != ""
}
