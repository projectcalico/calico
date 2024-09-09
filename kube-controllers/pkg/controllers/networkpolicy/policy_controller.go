// Copyright (c) 2017, 2020 Tigera, Inc. All rights reserved.
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

package networkpolicy

import (
	"context"
	"reflect"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	rcache "github.com/projectcalico/calico/kube-controllers/pkg/cache"
	"github.com/projectcalico/calico/kube-controllers/pkg/config"
	"github.com/projectcalico/calico/kube-controllers/pkg/controllers/controller"

	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/kube-controllers/pkg/converter"
	kdd "github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/conversion"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/options"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	uruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

// policyController implements the Controller interface for managing Kubernetes network policies
// and syncing them to the Calico datastore as NetworkPolicies.
type policyController struct {
	informer      cache.Controller
	resourceCache rcache.ResourceCache
	calicoClient  client.Interface
	ctx           context.Context
	cfg           config.GenericControllerConfig
}

// NewPolicyController returns a controller which manages NetworkPolicy objects.
func NewPolicyController(ctx context.Context, clientset *kubernetes.Clientset, c client.Interface, cfg config.GenericControllerConfig) controller.Controller {
	policyConverter := converter.NewPolicyConverter()

	// Create a NetworkPolicy watcher.
	listWatcher := cache.NewListWatchFromClient(clientset.NetworkingV1().RESTClient(), "networkpolicies", "", fields.Everything())

	// Function returns map of policyName:policy stored by policy controller
	// in datastore.
	listFunc := func() (map[string]interface{}, error) {
		// Get all policies from datastore
		calicoPolicies, err := c.NetworkPolicies().List(ctx, options.ListOptions{})
		if err != nil {
			return nil, err
		}

		// Filter in only objects that are written by policy controller.
		m := make(map[string]interface{})
		for _, policy := range calicoPolicies.Items {
			if strings.HasPrefix(policy.Name, kdd.K8sNetworkPolicyNamePrefix) {
				// Update the network policy's ObjectMeta so that it simply contains the name and namespace.
				// There is other metadata that we might receive (like resource version) that we don't want to
				// compare in the cache.
				policy.ObjectMeta = metav1.ObjectMeta{Name: policy.Name, Namespace: policy.Namespace}
				k := policyConverter.GetKey(policy)
				m[k] = policy
			}
		}

		log.Debugf("Found %d policies in Calico datastore:", len(m))
		return m, nil
	}

	cacheArgs := rcache.ResourceCacheArgs{
		ListFunc:   listFunc,
		ObjectType: reflect.TypeOf(api.NetworkPolicy{}),
	}
	ccache := rcache.NewResourceCache(cacheArgs)

	// Bind the Calico cache to kubernetes cache with the help of an informer. This way we make sure that
	// whenever the kubernetes cache is updated, changes get reflected in the Calico cache as well.
	_, informer := cache.NewIndexerInformer(listWatcher, &networkingv1.NetworkPolicy{}, 0, cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			log.Debugf("Got ADD event for network policy: %#v", obj)
			policy, err := policyConverter.Convert(obj)
			if err != nil {
				log.WithError(err).Errorf("Error while converting %#v to calico network policy.", obj)
				return
			}

			// Add to cache.
			k := policyConverter.GetKey(policy)
			ccache.Set(k, policy)
		},
		UpdateFunc: func(oldObj interface{}, newObj interface{}) {
			log.Debugf("Got UPDATE event for NetworkPolicy.")
			log.Debugf("Old object: \n%#v\n", oldObj)
			log.Debugf("New object: \n%#v\n", newObj)
			policy, err := policyConverter.Convert(newObj)
			if err != nil {
				log.WithError(err).Errorf("Error converting to Calico policy.")
				return
			}

			// Add to cache.
			k := policyConverter.GetKey(policy)
			ccache.Set(k, policy)
		},
		DeleteFunc: func(obj interface{}) {
			log.Debugf("Got DELETE event for NetworkPolicy: %#v", obj)
			policy, err := policyConverter.Convert(obj)
			if err != nil {
				log.WithError(err).Errorf("Error converting to Calico policy.")
				return
			}

			calicoKey := policyConverter.GetKey(policy)
			ccache.Delete(calicoKey)
		},
	}, cache.Indexers{})

	return &policyController{informer, ccache, c, ctx, cfg}
}

// Run starts the controller.
func (c *policyController) Run(stopCh chan struct{}) {
	defer uruntime.HandleCrash()

	// Let the workers stop when we are done
	workqueue := c.resourceCache.GetQueue()
	defer workqueue.ShutDown()

	// Start the Kubernetes informer, which will start syncing with the Kubernetes API.
	log.Info("Starting NetworkPolicy controller")
	go c.informer.Run(stopCh)

	// Wait until we are in sync with the Kubernetes API before starting the
	// resource cache.
	log.Debug("Waiting to sync with Kubernetes API (NetworkPolicy)")
	if !cache.WaitForNamedCacheSync("network-policies", stopCh, c.informer.HasSynced) {
		log.Info("Failed to sync resources, received signal for controller to shut down.")
		return
	}
	log.Debug("Finished syncing with Kubernetes API (NetworkPolicy)")

	// Start the resource cache - this will trigger the queueing of any keys
	// that are out of sync onto the resource cache event queue.
	c.resourceCache.Run(c.cfg.ReconcilerPeriod.String())

	// Start a number of worker threads to read from the queue. Each worker
	// will pull keys off the resource cache event queue and sync them to the
	// Calico datastore.
	for i := 0; i < c.cfg.NumberOfWorkers; i++ {
		go wait.Until(c.runWorker, time.Second, stopCh)
	}
	log.Info("NetworkPolicy controller is now running")

	<-stopCh
	log.Info("Stopping NetworkPolicy controller")
}

func (c *policyController) runWorker() {
	for c.processNextItem() {
	}
}

// processNextItem waits for an event on the output queue from the resource cache and syncs
// any received keys to the datastore.
func (c *policyController) processNextItem() bool {
	// Wait until there is a new item in the work queue.
	workqueue := c.resourceCache.GetQueue()
	key, quit := workqueue.Get()
	if quit {
		return false
	}

	// Sync the object to the Calico datastore.
	err := c.syncToDatastore(key.(string))
	c.handleErr(err, key.(string))

	// Indicate that we're done processing this key, allowing for safe parallel processing such that
	// two objects with the same key are never processed in parallel.
	workqueue.Done(key)
	return true
}

// syncToDatastore syncs the given update to the Calico datastore. The provided key can be used to
// find the corresponding resource within the resource cache. If the resource for the provided key
// exists in the cache, then the value should be written to the datastore. If it does not exist
// in the cache, then it should be deleted from the datastore.
func (c *policyController) syncToDatastore(key string) error {
	clog := log.WithField("key", key)

	// Check if it exists in the controller's cache.
	obj, exists := c.resourceCache.Get(key)
	if !exists {
		// The object no longer exists - delete from the datastore.
		clog.Infof("Deleting NetworkPolicy from Calico datastore")
		ns, name := converter.NewPolicyConverter().DeleteArgsFromKey(key)
		_, err := c.calicoClient.NetworkPolicies().Delete(c.ctx, ns, name, options.DeleteOptions{})
		if _, ok := err.(errors.ErrorResourceDoesNotExist); !ok {
			// We hit an error other than "does not exist".
			return err
		}
		return nil
	} else {
		// The object exists - update the datastore to reflect.
		clog.Infof("Create/Update NetworkPolicy in Calico datastore")
		p := obj.(api.NetworkPolicy)

		// Lookup to see if this object already exists in the datastore.
		gp, err := c.calicoClient.NetworkPolicies().Get(c.ctx, p.Namespace, p.Name, options.GetOptions{})
		if err != nil {
			if _, ok := err.(errors.ErrorResourceDoesNotExist); !ok {
				clog.WithError(err).Warning("Failed to get network policy from datastore")
				return err
			}

			// Doesn't exist - create it.
			_, err := c.calicoClient.NetworkPolicies().Create(c.ctx, &p, options.SetOptions{})
			if err != nil {
				clog.WithError(err).Warning("Failed to create network policy")
				return err
			}
			clog.Infof("Successfully created network policy")
			return nil
		}

		// The policy already exists, update it and write it back to the datastore.
		gp.Spec = p.Spec
		clog.Infof("Update NetworkPolicy in Calico datastore with resource version %s", p.ResourceVersion)
		_, err = c.calicoClient.NetworkPolicies().Update(c.ctx, gp, options.SetOptions{})
		if err != nil {
			clog.WithError(err).Warning("Failed to update network policy")
			return err
		}
		clog.Infof("Successfully updated network policy")
		return nil
	}
}

// handleErr handles errors which occur while processing a key received from the resource cache.
// For a given error, we will re-queue the key in order to retry the datastore sync up to 5 times,
// at which point the update is dropped.
func (c *policyController) handleErr(err error, key string) {
	workqueue := c.resourceCache.GetQueue()
	if err == nil {
		// Forget about the #AddRateLimited history of the key on every successful synchronization.
		// This ensures that future processing of updates for this key is not delayed because of
		// an outdated error history.
		workqueue.Forget(key)
		return
	}

	// This controller retries 5 times if something goes wrong. After that, it stops trying.
	if workqueue.NumRequeues(key) < 5 {
		// Re-enqueue the key rate limited. Based on the rate limiter on the
		// queue and the re-enqueue history, the key will be processed later again.
		log.WithError(err).Errorf("Error syncing Policy %v: %v", key, err)
		workqueue.AddRateLimited(key)
		return
	}
	workqueue.Forget(key)

	// Report to an external entity that, even after several retries, we could not successfully process this key
	uruntime.HandleError(err)
	log.WithError(err).Errorf("Dropping Policy %q out of the queue: %v", key, err)
}
