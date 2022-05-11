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

package namespace

import (
	"context"
	"reflect"
	"strings"

	log "github.com/sirupsen/logrus"

	api "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	rcache "github.com/projectcalico/calico/kube-controllers/pkg/cache"
	"github.com/projectcalico/calico/kube-controllers/pkg/config"
	"github.com/projectcalico/calico/kube-controllers/pkg/controllers/controller"
	"github.com/projectcalico/calico/kube-controllers/pkg/converter"
	kdd "github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/conversion"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/options"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	uruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

// namespaceController implements the Controller interface for managing Kubernetes namespaces
// and syncing them to the Calico datastore as Profiles.
type namespaceController struct {
	informer      cache.Controller
	resourceCache rcache.ResourceCache
	calicoClient  client.Interface
	ctx           context.Context
	cfg           config.GenericControllerConfig
}

// NewNamespaceController returns a controller which manages Namespace objects.
func NewNamespaceController(ctx context.Context, k8sClientset *kubernetes.Clientset, c client.Interface, cfg config.GenericControllerConfig) controller.Controller {
	namespaceConverter := converter.NewNamespaceConverter()

	// Function returns map of profile_name:object stored by policy controller
	// in the Calico datastore. Identifies controller written objects by
	// their naming convention.
	listFunc := func() (map[string]interface{}, error) {
		log.Debugf("Listing profiles from Calico datastore")
		filteredProfiles := make(map[string]interface{})

		// Get all profile objects from Calico datastore.
		profileList, err := c.Profiles().List(ctx, options.ListOptions{})
		if err != nil {
			return nil, err
		}

		// Filter out only objects that are written by policy controller.
		for _, profile := range profileList.Items {
			if strings.HasPrefix(profile.Name, kdd.NamespaceProfileNamePrefix) {
				// Update the profile's ObjectMeta so that it simply contains the name.
				// There is other metadata that we might receive (like resource version) that we don't want to
				// compare in the cache.
				profile.ObjectMeta = metav1.ObjectMeta{Name: profile.Name}
				key := namespaceConverter.GetKey(profile)
				filteredProfiles[key] = profile
			}
		}
		log.Debugf("Found %d profiles in Calico datastore", len(filteredProfiles))
		return filteredProfiles, nil
	}

	// Create a Cache to store Profiles in.
	cacheArgs := rcache.ResourceCacheArgs{
		ListFunc:    listFunc,
		ObjectType:  reflect.TypeOf(api.Profile{}),
		LogTypeDesc: "Namespace",
	}
	ccache := rcache.NewResourceCache(cacheArgs)

	// Create a Namespace watcher.
	listWatcher := cache.NewListWatchFromClient(k8sClientset.CoreV1().RESTClient(), "namespaces", "", fields.Everything())

	// Bind the calico cache to kubernetes cache with the help of an informer. This way we make sure that
	// whenever the kubernetes cache is updated, changes get reflected in the Calico cache as well.
	_, informer := cache.NewIndexerInformer(listWatcher, &v1.Namespace{}, 0, cache.ResourceEventHandlerFuncs{
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

	return &namespaceController{informer, ccache, c, ctx, cfg}
}

// Run starts the controller.
func (c *namespaceController) Run(stopCh chan struct{}) {
	defer uruntime.HandleCrash()

	// Let the workers stop when we are done
	workqueue := c.resourceCache.GetQueue()
	defer workqueue.ShutDown()

	log.Info("Starting Namespace/Profile controller")

	// Wait till k8s cache is synced
	log.Debug("Waiting to sync with Kubernetes API (Namespaces)")
	go c.informer.Run(stopCh)
	if !cache.WaitForNamedCacheSync("namespaces", stopCh, c.informer.HasSynced) {
		log.Info("Failed to sync resources, received signal for controller to shut down.")
		return
	}
	log.Debug("Finished syncing with Kubernetes API (Namespaces)")

	// Start Calico cache.
	c.resourceCache.Run(c.cfg.ReconcilerPeriod.String())

	// Start a number of worker threads to read from the queue.
	for i := 0; i < c.cfg.NumberOfWorkers; i++ {
		go c.runWorker()
	}
	log.Info("Namespace/Profile controller is now running")

	<-stopCh
	log.Info("Stopping Namespace/Profile controller")
}

func (c *namespaceController) runWorker() {
	for c.processNextItem() {
	}
}

// processNextItem waits for an event on the output queue from the resource cache and syncs
// any received keys to the datastore.
func (c *namespaceController) processNextItem() bool {
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
func (c *namespaceController) syncToDatastore(key string) error {
	clog := log.WithField("key", key)

	// Check if it exists in the controller's cache.
	obj, exists := c.resourceCache.Get(key)
	if !exists {
		// The object no longer exists - delete from the datastore.
		clog.Infof("Deleting Profile from Calico datastore")
		_, name := converter.NewNamespaceConverter().DeleteArgsFromKey(key)
		_, err := c.calicoClient.Profiles().Delete(c.ctx, name, options.DeleteOptions{})
		if _, ok := err.(errors.ErrorResourceDoesNotExist); !ok {
			// We hit an error other than "does not exist".
			return err
		}
		return nil
	} else {
		// The object exists - update the datastore to reflect.
		clog.Info("Create/Update Profile in Calico datastore")
		p := obj.(api.Profile)

		// Lookup to see if this object already exists in the datastore.
		gp, err := c.calicoClient.Profiles().Get(c.ctx, p.Name, options.GetOptions{})
		if err != nil {
			if _, ok := err.(errors.ErrorResourceDoesNotExist); !ok {
				clog.WithError(err).Warning("Failed to get profile from datastore")
				return err
			}

			// Doesn't exist - create it.
			_, err := c.calicoClient.Profiles().Create(c.ctx, &p, options.SetOptions{})
			if err != nil {
				clog.WithError(err).Warning("Failed to create profile")
				return err
			}
			clog.Info("Successfully created profile")
			return nil
		}

		// The profile already exists, update it and write it back to the datastore.
		gp.Spec = p.Spec
		clog.Infof("Update Profile in Calico datastore with resource version %s", gp.ResourceVersion)
		_, err = c.calicoClient.Profiles().Update(c.ctx, gp, options.SetOptions{})
		if err != nil {
			clog.WithError(err).Warning("Failed to update profile")
			return err
		}
		clog.Infof("Successfully updated profile")
		return nil
	}
}

// handleErr handles errors which occur while processing a key received from the resource cache.
// For a given error, we will re-queue the key in order to retry the datastore sync up to 5 times,
// at which point the update is dropped.
func (c *namespaceController) handleErr(err error, key string) {
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
		log.WithError(err).Errorf("Error syncing Profile %v: %v", key, err)
		workqueue.AddRateLimited(key)
		return
	}
	workqueue.Forget(key)

	// Report to an external entity that, even after several retries, we could not successfully process this key
	uruntime.HandleError(err)
	log.WithError(err).Errorf("Dropping Profile %q out of the queue: %v", key, err)
}
