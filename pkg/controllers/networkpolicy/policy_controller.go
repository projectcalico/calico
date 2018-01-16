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
	"fmt"
	"reflect"
	"strings"
	"time"

	calicocache "github.com/projectcalico/kube-controllers/pkg/cache"
	"github.com/projectcalico/kube-controllers/pkg/controllers/controller"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/kube-controllers/pkg/converter"
	"github.com/projectcalico/libcalico-go/lib/api"
	extensions "github.com/projectcalico/libcalico-go/lib/backend/extensions"
	"github.com/projectcalico/libcalico-go/lib/client"
	"github.com/projectcalico/libcalico-go/lib/errors"
	log "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	uruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/rest"
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
}

// NewPolicyController Constructor for PolicyController
func NewPolicyController(extensionsClient *rest.RESTClient, calicoClient *client.Client) controller.Controller {
	policyConverter := converter.NewPolicyConverter()

	// Create a NetworkPolicy watcher.
	listWatcher := cache.NewListWatchFromClient(extensionsClient, "networkpolicies", "", fields.Everything())
	listWatcher.ListFunc = func(options metav1.ListOptions) (runtime.Object, error) {
		list := extensions.NetworkPolicyList{}
		err := extensionsClient.
			Get().
			Resource("networkpolicies").
			Timeout(10 * time.Second).
			Do().Into(&list)
		return &list, err
	}

	// Function returns map of policyName:policy stored by policy controller
	// in datastore.
	listFunc := func() (map[string]interface{}, error) {
		var policyMap map[string]bool

		// Get all policies from datastore
		calicoPolicies, err := calicoClient.Policies().List(api.PolicyMetadata{})
		if err != nil {
			return nil, err
		}

		// Filter in only objects that are written by policy controller.
		m := make(map[string]interface{})
		for _, policy := range calicoPolicies.Items {
			policyName := policyConverter.GetKey(policy)
			if strings.HasPrefix(policyName, "knp.default.") {
				m[policyName] = policy
			} else if len(strings.Split(policyName, ".")) > 1 {
				// Older versions of the controller used the name format `namespace.name`.
				// This is a best-effort attempt to sync those policies as well.  If it has a `.` and
				// exists in the k8s API, then sync the policy.
				// TODO: Remove this section once we don't care about upgrade from the Python controller.
				l, err := listWatcher.List(metav1.ListOptions{})
				if err != nil {
					log.WithError(err).Warnf("Failed to process policy %s", policyName)
				}
				items, err := meta.ExtractList(l)
				if err != nil {
					log.WithError(err).Warnf("Failed to process policy %s", policyName)
				}
				if policyMap == nil {
					// Populate the policy map with data from the API so we can do a lookup
					// on whether or not this policy exists in the k8s API.  Only do this if we haven't
					// already populated the map in order to minimize work.
					policyMap = map[string]bool{}
					for _, i := range items {
						k := fmt.Sprintf("%s.%s", i.(*extensions.NetworkPolicy).Namespace, i.(*extensions.NetworkPolicy).Name)
						policyMap[k] = true
					}
				}
				log.Debugf("Checking if we care about policy %s", policyName)
				log.Debugf("Policies we might care about: %#v", policyMap)
				if _, ok := policyMap[policyName]; ok {
					// The policy exists in the API and in etcd - assume it was created by the old policy
					// controller and add it to the batch so that we sync it away.
					log.Infof("Assuming we're responsible for policy %s", policyName)
					m[policyName] = policy
				}
			} else if policyName == "k8s-policy-no-match" {
				// Older versions of the controller programmed this policy, but we don't
				// want it around any more.  TODO: Remove this section once we don't care about
				// upgrade from the Python controller.
				log.Infof("Assuming we're responsible for policy %s", policyName)
				m[policyName] = policy
			}
		}

		log.Debugf("Found %d policies in Calico datastore:", len(m))
		return m, nil
	}

	cacheArgs := calicocache.ResourceCacheArgs{
		ListFunc:   listFunc,
		ObjectType: reflect.TypeOf(api.Policy{}),
	}
	ccache := calicocache.NewResourceCache(cacheArgs)

	// Bind the Calico cache to kubernetes cache with the help of an informer. This way we make sure that
	// whenever the kubernetes cache is updated, changes get reflected in the Calico cache as well.
	indexer, informer := cache.NewIndexerInformer(listWatcher, &extensions.NetworkPolicy{}, 0, cache.ResourceEventHandlerFuncs{
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

	return &PolicyController{indexer, informer, ccache, calicoClient}
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
