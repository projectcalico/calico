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

package networkpolicy

import (
	"reflect"
	"strings"
	"time"

	calicocache "github.com/projectcalico/k8s-policy/pkg/cache"
	"github.com/projectcalico/k8s-policy/pkg/controllers/controller"
	"github.com/projectcalico/k8s-policy/pkg/converter"
	"github.com/projectcalico/libcalico-go/lib/api"
	"github.com/projectcalico/libcalico-go/lib/client"
	"github.com/projectcalico/libcalico-go/lib/errors"
	log "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/fields"
	uruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/pkg/apis/extensions/v1beta1"
	"k8s.io/client-go/tools/cache"
)

// PolicyController Implements Controller interface
// Responsible for monitoring kubernetes network policies and
// syncing them to Calico datastore.
type PolicyController struct {
	indexer        cache.Indexer
	informer       cache.Controller
	calicoObjCache calicocache.ResourceCache
	calicoClient   *client.Client
	k8sClientset   *kubernetes.Clientset
}

// NewPolicyController Constructor for PolicyController
func NewPolicyController(k8sClientset *kubernetes.Clientset, calicoClient *client.Client) controller.Controller {
	policyConverter := converter.NewPolicyConverter()

	// Function returns map of policyName:policy stored by policy controller
	// in datastore.
	listFunc := func() (map[string]interface{}, error) {
		// Get all policies from datastore
		calicoPolicies, err := calicoClient.Policies().List(api.PolicyMetadata{})
		if err != nil {
			return nil, err
		}

		// Filter out only objects that are written by policy controller
		npMap := make(map[string]interface{})
		for _, policy := range calicoPolicies.Items {
			policyName := policyConverter.GetKey(policy)
			if strings.HasPrefix(policyName, "knp.default.") {
				npMap[policyName] = policy
			}
		}

		log.Debugf("Found %d policies in Calico datastore:", len(npMap))
		return npMap, nil
	}

	cacheArgs := calicocache.ResourceCacheArgs{
		ListFunc:   listFunc,
		ObjectType: reflect.TypeOf(api.Policy{}),
	}
	ccache := calicocache.NewResourceCache(cacheArgs)

	// Create a NetworkPolicy watcher.
	listWatcher := cache.NewListWatchFromClient(k8sClientset.Extensions().RESTClient(), "networkpolicies", "", fields.Everything())

	// Bind the Calico cache to kubernetes cache with the help of an informer. This way we make sure that
	// whenever the kubernetes cache is updated, changes get reflected in the Calico cache as well.
	indexer, informer := cache.NewIndexerInformer(listWatcher, &v1beta1.NetworkPolicy{}, 0, cache.ResourceEventHandlerFuncs{
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

	return &PolicyController{indexer, informer, ccache, calicoClient, k8sClientset}
}

// Run starts the controller.
func (c *PolicyController) Run(threadiness int, reconcilerPeriod string, stopCh chan struct{}) {
	defer uruntime.HandleCrash()

	// Let the workers stop when we are done
	workqueue := c.calicoObjCache.GetQueue()
	defer workqueue.ShutDown()

	log.Info("Starting NetworkPolicy controller")

	// Wait till k8s cache is synced
	go c.informer.Run(stopCh)
	log.Debug("Waiting to sync with Kubernetes API (NetworkPolicy)")
	for !c.informer.HasSynced() {
	}
	log.Debug("Finished syncing with Kubernetes API (NetworkPolicy)")

	// Start Calico cache.
	c.calicoObjCache.Run(reconcilerPeriod)

	// Start a number of worker threads to read from the queue.
	for i := 0; i < threadiness; i++ {
		go wait.Until(c.runWorker, time.Second, stopCh)
	}
	log.Info("NetworkPolicy controller is now running")

	<-stopCh
	log.Info("Stopping NetworkPolicy controller")
}

func (c *PolicyController) runWorker() {
	for c.processNextItem() {
	}
}

func (c *PolicyController) processNextItem() bool {
	// Wait until there is a new item in the work queue.
	workqueue := c.calicoObjCache.GetQueue()
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
func (c *PolicyController) syncToCalico(key string) error {
	// Check if it exists in the controller's cache.
	obj, exists := c.calicoObjCache.Get(key)
	if !exists {
		// The object no longer exists - delete from the datastore.
		log.Infof("Deleting Policy %s from Calico datastore", key)
		if err := c.calicoClient.Policies().Delete(api.PolicyMetadata{Name: key}); err != nil {
			if _, ok := err.(errors.ErrorResourceDoesNotExist); !ok {
				// We hit an error other than "does not exist".
				return err
			}
		}
		return nil
	} else {
		// The object exists - update the datastore to reflect.
		log.Infof("Add/Update Policy %s in Calico datastore", key)
		p := obj.(api.Policy)
		_, err := c.calicoClient.Policies().Apply(&p)
		return err
	}
}

// handleErr checks if an error happened and makes sure we will retry later.
func (c *PolicyController) handleErr(err error, key string) {
	workqueue := c.calicoObjCache.GetQueue()
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
