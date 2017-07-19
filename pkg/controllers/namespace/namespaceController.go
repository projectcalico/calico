package namespace

import (
	log "github.com/Sirupsen/logrus"
	calicocache "github.com/projectcalico/k8s-policy/pkg/cache"
	"github.com/projectcalico/k8s-policy/pkg/controllers/controller"
	"github.com/projectcalico/k8s-policy/pkg/converter"
	"github.com/projectcalico/libcalico-go/lib/api"
	"github.com/projectcalico/libcalico-go/lib/client"
	"github.com/projectcalico/libcalico-go/lib/errors"
	"k8s.io/apimachinery/pkg/fields"
	uruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/pkg/api/v1"
	"k8s.io/client-go/tools/cache"
	"reflect"
	"strings"
	"time"
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
	// Function returns map of profile_name:object stored by policy controller
	// on ETCD datastore. Indentifies controller writen objects by
	// their naming convention.
	listFunc := func() (map[string]interface{}, error) {
		filteredProfiles := make(map[string]interface{})

		// Get all profile objects from ETCD datastore
		calicoProfiles, err := calicoClient.Profiles().List(api.ProfileMetadata{})
		if err != nil {
			return filteredProfiles, err
		}

		// Filter out only objects that are written by policy controller
		for _, profile := range calicoProfiles.Items {

			profileName := profile.Metadata.Name
			if strings.HasPrefix(profileName, converter.ProfileNameFormat) {
				filteredProfiles[profileName] = profile
			}
		}
		log.Debugf("Found %d profiles in calico ETCD:", len(filteredProfiles))
		return filteredProfiles, nil
	}

	cacheArgs := calicocache.ResourceCacheArgs{
		ListFunc:   listFunc,
		ObjectType: reflect.TypeOf(api.Profile{}), // Restrict cache to store calico profiles only.
	}

	ccache := calicocache.NewResourceCache(cacheArgs)
	namespaceConverter := converter.NewNamespaceConverter()

	// create the watcher
	listWatcher := cache.NewListWatchFromClient(k8sClientset.Core().RESTClient(), "namespaces", "", fields.Everything())

	// Bind the calico cache to kubernetes cache with the help of an informer. This way we make sure that
	// whenever the kubernetes cache is updated, changes get reflected in calico cache as well.
	indexer, informer := cache.NewIndexerInformer(listWatcher, &v1.Namespace{}, 0, cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			key, err := cache.MetaNamespaceKeyFunc(obj)
			log.Debugf("Got ADD event for namespace: %s\n", key)

			if err != nil {
				log.WithError(err).Error("Failed to generate key")
				return
			}

			profile, err := namespaceConverter.Convert(obj)
			if err != nil {
				log.WithError(err).Errorf("Error while converting %#v to calico profile.", obj)
				return
			}
			
			calicoKey := namespaceConverter.GetKey(profile)

			// Add key:profile in calicoCache
			ccache.Set(calicoKey, profile)
		},
		UpdateFunc: func(oldObj interface{}, newObj interface{}) {
			key, err := cache.MetaNamespaceKeyFunc(newObj)

			log.Debugf("Got UPDATE event for namespace: %s\n", key)
			log.Debugf("Old object: %#v\n", oldObj)
			log.Debugf("New object: %#v\n", newObj)

			if err != nil {
				log.WithError(err).Error("Failed to generate key")
				return
			}

			if newObj.(*v1.Namespace).Status.Phase == "Terminating" {

				// If object status is updated to "Terminating", object
				// is getting deleted. Ignore this event. When deletion
				// completes another DELETE event will be raised.
				// Let DeleteFunc handle that.
				log.Debugf("Namespace %s is getting deleted.", newObj.(*v1.Namespace).ObjectMeta.GetName())
				return
			}
			profile, err := namespaceConverter.Convert(newObj)
			if err != nil {
				log.WithError(err).Errorf("Error while converting %#v to calico profile.", newObj)
				return
			}

			calicoKey := namespaceConverter.GetKey(profile)

			// Add key:profile in calicoCache
			ccache.Set(calicoKey, profile)
		},
		DeleteFunc: func(obj interface{}) {
			// IndexerInformer uses a delta queue, therefore for deletes we have to use this
			// key function.
			key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
			log.Debugf("Got DELETE event for namespace: %s\n", key)

			if err != nil {
				log.WithError(err).Error("Failed to generate key")
				return
			}

			profile, err := namespaceConverter.Convert(obj)
			if err != nil {
				log.WithError(err).Errorf("Error while converting %#v to calico profile.", obj)
				return
			}
			calicoKey := namespaceConverter.GetKey(profile)
			ccache.Delete(calicoKey)
		},
	}, cache.Indexers{})

	return &NamespaceController{indexer, informer, ccache, calicoClient, k8sClientset}
}

// Run starts controller.Internally it starts syncing
// kubernetes and calico caches.
func (c *NamespaceController) Run(threadiness int, reconcilerPeriod string, stopCh chan struct{}) {
	defer uruntime.HandleCrash()

	// Let the workers stop when we are done
	workqueue := c.calicoObjCache.GetQueue()
	defer workqueue.ShutDown()

	log.Info("Starting namespace controller")

	// Start Calico cache. Cache gets loaded with objects
	// from ETCD datastore.
	c.calicoObjCache.Run(reconcilerPeriod)

	go c.informer.Run(stopCh)

	// Wait till k8s cache is synced
	for !c.informer.HasSynced() {
	}

	// Start a number of worker threads to read from the queue.
	for i := 0; i < threadiness; i++ {
		go wait.Until(c.runWorker, time.Second, stopCh)
	}

	<-stopCh
	log.Info("Stopping Node controller")
}

func (c *NamespaceController) runWorker() {
	for c.processNextItem() {
	}
}

func (c *NamespaceController) processNextItem() bool {
	// Wait until there is a new item in the working queue
	workqueue := c.calicoObjCache.GetQueue()
	key, quit := workqueue.Get()
	if quit {
		return false
	}

	// Tell the queue that we are done with processing this key. This unblocks the key for other workers
	// This allows safe parallel processing because two nodes with the same key are never processed in
	// parallel.
	defer workqueue.Done(key)

	// Invoke the method containing the business logic
	err := c.syncToCalico(key.(string))

	// Handle the error if something went wrong during the execution of the business logic
	c.handleErr(err, key.(string))
	return true
}

// syncToCalico syncs the given update to Calico's etcd, as well as the in-memory cache
// of Calico objects.
func (c *NamespaceController) syncToCalico(key string) error {
	// Check if it exists in our cache.
	obj, exists := c.calicoObjCache.Get(key)

	if !exists {

		log.Debugf("namespace %s does not exist anymore on kubernetes\n", key)
		log.Infof("Deleting namespace %s on ETCD \n", key)

		err := c.calicoClient.Profiles().Delete(api.ProfileMetadata{
			Name: key,
		})

		// Let Delete() operation be idompotent. Ignore the error while deletion if
		// object does not exists on ETCD already.
		if _, ok := err.(errors.ErrorResourceDoesNotExist); ok {
			err = nil
		}

		return err
	}else{

		var p api.Profile
		p = obj.(api.Profile)
		log.Infof("Applying namespace %s on ETCD \n", key)
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
		
		log.WithError(err).Errorf("Error syncing namespace %v: %v", key, err)
		// Re-enqueue the key rate limited. Based on the rate limiter on the
		// queue and the re-enqueue history, the key will be processed later again.
		workqueue.AddRateLimited(key)
		return
	}

	workqueue.Forget(key)
	
	// Report to an external entity that, even after several retries, we could not successfully process this key
	uruntime.HandleError(err)
	log.WithError(err).Errorf("Dropping namespace %q out of the queue: %v", key, err)
}
