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

package namespace

import (
	"reflect"
	"strings"

	calicocache "github.com/projectcalico/k8s-policy/pkg/cache"
	"github.com/projectcalico/k8s-policy/pkg/controllers/controller"
	"github.com/projectcalico/k8s-policy/pkg/converter"
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

// NamespaceController Implements Controller interface
// Responsible for monitoring kubernetes namespaces and
// syncing them to Calico datastore.
type NamespaceController struct {
	indexer        cache.Indexer
	informer       cache.Controller
	calicoObjCache calicocache.ResourceCache
	calicoClient   *client.Client
	k8sClientset   *kubernetes.Clientset
}

// NewNamespaceController Constructor for NamespaceController
func NewNamespaceController(k8sClientset *kubernetes.Clientset, calicoClient *client.Client) controller.Controller {
	namespaceConverter := converter.NewNamespaceConverter()

	// Function returns map of profile_name:object stored by policy controller
	// in the Calico datastore. Indentifies controller writen objects by
	// their naming convention.
	listFunc := func() (map[string]interface{}, error) {
		log.Debugf("Listing profiles from Calico datastore")
		filteredProfiles := make(map[string]interface{})

		// Get all profile objects from Calico datastore
		calicoProfiles, err := calicoClient.Profiles().List(api.ProfileMetadata{})
		if err != nil {
			return nil, err
		}

		// Filter out only objects that are written by policy controller
		for _, profile := range calicoProfiles.Items {
			profileName := profile.Metadata.Name
			if strings.HasPrefix(profileName, converter.ProfileNameFormat) {
				key := namespaceConverter.GetKey(profile)
				filteredProfiles[key] = profile
			}
		}
		log.Debugf("Found %d profiles in Calico datastore", len(filteredProfiles))
		return filteredProfiles, nil
	}

	// Create a Cache to store Profiles in.
	cacheArgs := calicocache.ResourceCacheArgs{
		ListFunc:   listFunc,
		ObjectType: reflect.TypeOf(api.Profile{}),
	}
	ccache := calicocache.NewResourceCache(cacheArgs)

	// Create a Namespace watcher.
	listWatcher := cache.NewListWatchFromClient(k8sClientset.Core().RESTClient(), "namespaces", "", fields.Everything())

	// Bind the calico cache to kubernetes cache with the help of an informer. This way we make sure that
	// whenever the kubernetes cache is updated, changes get reflected in the Calico cache as well.
	indexer, informer := cache.NewIndexerInformer(listWatcher, &v1.Namespace{}, 0, cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			log.Debugf("Got ADD event for Namespace: %#v", obj)
			profile, err := namespaceConverter.Convert(obj)
			if err != nil {
				log.WithError(err).Errorf("Error while converting %#v to calico profile.", obj)
				return
			}

			// Add to cache.
			k := namespaceConverter.GetKey(profile)
			ccache.Set(k, profile)
		},
		UpdateFunc: func(oldObj interface{}, newObj interface{}) {
			log.Debugf("Got UPDATE event for Namespace")
			log.Debugf("Old object: \n%#v\n", oldObj)
			log.Debugf("New object: \n%#v\n", newObj)
			if newObj.(*v1.Namespace).Status.Phase == "Terminating" {
				// Ignore any updates with "Terminating" status, since
				// we will soon receive a DELETE event to remove this object.
				log.Debugf("Ignoring 'Terminating' update for Namespace %s.", newObj.(*v1.Namespace).ObjectMeta.GetName())
				return
			}

			// Convert the namespace into a Profile.
			profile, err := namespaceConverter.Convert(newObj)
			if err != nil {
				log.WithError(err).Errorf("Error while converting %#v to calico profile.", newObj)
				return
			}

			// Update in the cache.
			k := namespaceConverter.GetKey(profile)
			ccache.Set(k, profile)
		},
		DeleteFunc: func(obj interface{}) {
			// Convert the namespace into a Profile.
			log.Debugf("Got DELETE event for namespace: %#v", obj)
			profile, err := namespaceConverter.Convert(obj)
			if err != nil {
				log.WithError(err).Errorf("Error converting %#v to Calico profile.", obj)
				return
			}

			k := namespaceConverter.GetKey(profile)
			ccache.Delete(k)
		},
	}, cache.Indexers{})

	return &NamespaceController{indexer, informer, ccache, calicoClient, k8sClientset}
}

// Run starts the controller.
func (c *NamespaceController) Run(threadiness int, reconcilerPeriod string, stopCh chan struct{}) {
	defer uruntime.HandleCrash()

	// Let the workers stop when we are done
	workqueue := c.calicoObjCache.GetQueue()
	defer workqueue.ShutDown()

	log.Info("Starting Namespace/Profile controller")

	// Wait till k8s cache is synced
	log.Debug("Waiting to sync with Kubernetes API (Namespaces)")
	go c.informer.Run(stopCh)
	for !c.informer.HasSynced() {
	}
	log.Debug("Finished syncing with Kubernetes API (Namespaces)")

	// Start Calico cache.
	c.calicoObjCache.Run(reconcilerPeriod)

	// Start a number of worker threads to read from the queue.
	for i := 0; i < threadiness; i++ {
		go c.runWorker()
	}
	log.Info("Namespace/Profile controller is now running")

	<-stopCh
	log.Info("Stopping Namespace/Profile controller")
}

func (c *NamespaceController) runWorker() {
	for c.processNextItem() {
	}
}

func (c *NamespaceController) processNextItem() bool {
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
func (c *NamespaceController) syncToCalico(key string) error {
	// Check if it exists in the controller's cache.
	obj, exists := c.calicoObjCache.Get(key)
	if !exists {
		// The object no longer exists - delete from the datastore.
		log.Infof("Deleting Profile %s from Calico datastore", key)
		if err := c.calicoClient.Profiles().Delete(api.ProfileMetadata{Name: key}); err != nil {
			if _, ok := err.(errors.ErrorResourceDoesNotExist); !ok {
				// We hit an error other than "does not exist".
				return err
			}
		}
		return nil
	} else {
		// The object exists - update the datastore to reflect.
		log.Infof("Add/Update Profile %s in Calico datastore", key)
		p := obj.(api.Profile)
		_, err := c.calicoClient.Profiles().Apply(&p)
		return err
	}
}

// handleErr checks if an error happened and makes sure we will retry later.
func (c *NamespaceController) handleErr(err error, key string) {
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
		log.WithError(err).Errorf("Error syncing Profile %v: %v", key, err)
		workqueue.AddRateLimited(key)
		return
	}
	workqueue.Forget(key)

	// Report to an external entity that, even after several retries, we could not successfully process this key
	uruntime.HandleError(err)
	log.WithError(err).Errorf("Dropping Profile %q out of the queue: %v", key, err)
}
