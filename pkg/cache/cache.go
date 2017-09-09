package cache

import (
	"reflect"
	"sync"
	"time"

	"github.com/patrickmn/go-cache"
	log "github.com/sirupsen/logrus"
	"k8s.io/client-go/util/workqueue"
)

// ResourceCache stores resources and queues updates when those resources
// are created, modified, or deleted. It de-duplicates updates by ensuring
// updates are only queued when an object has changed.
type ResourceCache interface {
	// Set sets the key to the provided value, and generates an update
	// on the queue the value has changed.
	Set(key string, value interface{})

	// Get gets the value associated with the given key.  Returns nil
	// if the key is not present.
	Get(key string) (interface{}, bool)

	// Prime sets the key to the provided value, but does not generate
	// and update on the queue ever.
	Prime(key string, value interface{})

	// Delete deletes the value identified by the given key from the cache, and
	// generates an update on the queue if a value was deleted.
	Delete(key string)

	// Clean removes the object identified by the given key from the cache.
	// It does not generate an update on the queue.
	Clean(key string)

	// ListKeys lists the keys currently in the cache.
	ListKeys() []string

	// Run enables the generation of events on the output queue starts
	// cache reconciliation.
	Run(reconcilerPeriod string)

	// GetQueue returns the cache's output queue, which emits a stream
	// of any keys which have been created, modified, or deleted.
	GetQueue() workqueue.RateLimitingInterface
}

// ResourceCacheArgs struct passed to constructor of ResourceCache.
// Groups togather all the arguments to pass in single struct.
type ResourceCacheArgs struct {
	// ListFunc returns a mapping of keys to objects from the Calico datastore.
	ListFunc func() (map[string]interface{}, error)

	// ObjectType is the type of object which is to be stored in this cache.
	ObjectType reflect.Type
}

// calicoCache implements the ResourceCache interface
type calicoCache struct {
	threadSafeCache *cache.Cache
	workqueue       workqueue.RateLimitingInterface
	ListFunc        func() (map[string]interface{}, error)
	ObjectType      reflect.Type
	log             *log.Entry
	running         bool
	mut             *sync.Mutex
}

// NewResourceCache builds and returns a resource cache using the provided arguments.
func NewResourceCache(args ResourceCacheArgs) ResourceCache {
	// Make sure logging is context aware.
	return &calicoCache{
		threadSafeCache: cache.New(cache.NoExpiration, cache.DefaultExpiration),
		workqueue:       workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),
		ListFunc:        args.ListFunc,
		ObjectType:      args.ObjectType,
		log:             log.WithFields(log.Fields{"type": args.ObjectType}),
		mut:             &sync.Mutex{},
	}
}

func (c *calicoCache) Set(key string, newObj interface{}) {
	if reflect.TypeOf(newObj) != c.ObjectType {
		c.log.Fatalf("Wrong object type recieved to store in cache. Expected: %s, Found: %s", c.ObjectType, reflect.TypeOf(newObj))
	}

	// Check if the object exists in the cache already.  If it does and hasn't changed,
	// then we don't need to send an update on the queue.
	if existingObj, found := c.threadSafeCache.Get(key); found {
		c.log.Debugf("%#v already exists in cache - comparing.", existingObj)
		if !reflect.DeepEqual(existingObj, newObj) {
			// The objects do not match - send an update over the queue.
			c.threadSafeCache.Set(key, newObj, cache.NoExpiration)
			if c.isRunning() {
				c.log.Debugf("Queueing update - %#v and %#v do not match.", newObj, existingObj)
				c.workqueue.Add(key)
			}
		}
	} else {
		c.threadSafeCache.Set(key, newObj, cache.NoExpiration)
		if c.isRunning() {
			c.log.Debugf("%#v not found in cache, adding it + queuing update.", newObj)
			c.workqueue.Add(key)
		}
	}
}

func (c *calicoCache) Delete(key string) {
	c.log.Debugf("Deleting %s from cache", key)
	c.threadSafeCache.Delete(key)
	c.workqueue.Add(key)
}

func (c *calicoCache) Clean(key string) {
	c.log.Debugf("Cleaning %s from cache, no update required", key)
	c.threadSafeCache.Delete(key)
}

func (c *calicoCache) Get(key string) (interface{}, bool) {
	obj, found := c.threadSafeCache.Get(key)
	if found {
		return obj, true
	}
	return nil, false
}

// Prime adds the key and value to the cache but will never generate
// an update on the queue.
func (c *calicoCache) Prime(key string, value interface{}) {
	c.threadSafeCache.Set(key, value, cache.NoExpiration)
}

// ListKeys returns a list of all the keys in the cache.
func (c *calicoCache) ListKeys() []string {
	cacheItems := c.threadSafeCache.Items()
	keys := make([]string, 0, len(cacheItems))
	for k := range cacheItems {
		keys = append(keys, k)
	}

	return keys
}

// GetQueue returns the output queue from the cache.  Whenever a key/value pair
// is modified, an event will appear on this queue.
func (c *calicoCache) GetQueue() workqueue.RateLimitingInterface {
	return c.workqueue
}

// Run starts the cache.  Any Set() calls prior to calling Run() will
// prime the cache, but not trigger any updates on the output queue.
func (c *calicoCache) Run(reconcilerPeriod string) {
	go c.reconcile(reconcilerPeriod)

	// Indicate that the cache is running, and so updates
	// can be queued.
	c.mut.Lock()
	c.running = true
	c.mut.Unlock()
}

func (c *calicoCache) isRunning() bool {
	c.mut.Lock()
	defer c.mut.Unlock()
	return c.running
}

// reconcile ensures a reconciliation is run every `reconcilerPeriod` in order to bring the datastore
// in sync with the cache. This is to correct any manual changes made in the datastore
// without the cache being aware.
func (c *calicoCache) reconcile(reconcilerPeriod string) {
	duration, err := time.ParseDuration(reconcilerPeriod)
	if err != nil {
		c.log.Fatalf("Invalid time duration format for reconciler: %s. Some valid examples: 5m, 30s, 2m30s etc.", reconcilerPeriod)
	}

	// If user has set duration to 0 then disable the reconciler job.
	if duration.Nanoseconds() == 0 {
		c.log.Infof("Reconciler period set to %d. Disabling reconciler.", duration.Nanoseconds())
		return
	}

	// Loop forever, performing a datastore reconciliation periodically.
	for {
		c.log.Debugf("Performing reconciliation")
		err := c.performDatastoreSync()
		if err != nil {
			c.log.WithError(err).Error("Reconciliation failed")
			continue
		}

		// Reconciliation was successful, sleep the configured duration.
		c.log.Debugf("Reconciliation complete, %+v until next one.", duration)
		time.Sleep(duration)
	}
}

func (c *calicoCache) performDatastoreSync() error {
	// Get all the objects we care about from the datastore using ListFunc.
	objMap, err := c.ListFunc()
	if err != nil {
		c.log.WithError(err).Errorf("unable to list objects from datastore while reconciling.")
		return err
	}

	// Build a map of existing keys in the datastore.
	allKeys := map[string]bool{}
	for key := range objMap {
		allKeys[key] = true
	}

	// Also add all existing keys in the cache.
	for _, key := range c.ListKeys() {
		allKeys[key] = true
	}

	c.log.Debugf("Reconciling %d keys in total", len(allKeys))
	for key := range allKeys {
		cachedObj, exists := c.Get(key)
		if !exists {
			// Key does not exist in the cache, queue an update to
			// remove it from the datastore.
			c.log.WithField("key", key).Warn("Value for key should not exist, queueing update to remove")
			c.workqueue.Add(key)
			continue
		}

		if _, exists := objMap[key]; !exists {
			// Key exists in the cache but not in the datastore - queue an update
			// to re-add it.
			c.log.WithField("key", key).Warn("Value for key is missing in datastore, queueing update to reprogram")
			c.workqueue.Add(key)
			continue
		}

		obj := objMap[key]
		if !reflect.DeepEqual(obj, cachedObj) {
			// Objects differ - queue an update to re-program.
			c.log.WithField("key", key).Warn("Value for key has changed, queueing update to reprogram")
			c.workqueue.Add(key)
			continue
		}
	}
	return nil
}
