// Copyright (c) 2017-2018 Tigera, Inc. All rights reserved.
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
package calico

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"

	logutils "github.com/kelseyhightower/confd/pkg/log"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/libcalico-go/lib/backend/syncersv1/bgpsyncer"
	"github.com/projectcalico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/libcalico-go/lib/errors"
	"github.com/projectcalico/libcalico-go/lib/options"
)

const (
	// Handle a few keys that we need to default if not specified.
	globalASN      = "/calico/bgp/v1/global/as_num"
	globalNodeMesh = "/calico/bgp/v1/global/node_mesh"
	globalLogging  = "/calico/bgp/v1/global/loglevel"
)

// backendClientAccessor is an interface to access the backend client from the main v2 client.
type backendClientAccessor interface {
	Backend() api.Client
}

func NewCalicoClient(configfile string, routeReflector bool) (*client, error) {
	// Load the client config.  This loads from the environment if a filename
	// has not been specified.
	config, err := apiconfig.LoadClientConfig(configfile)
	if err != nil {
		log.Errorf("Failed to load Calico client configuration: %v", err)
		return nil, err
	}

	// Query the current BGP configuration to determine if the node to node mesh is enabled or
	// not.  If it is we need to monitor all node configuration.  If it is not enabled then we
	// only need to monitor our own node.  If this setting changes, we terminate confd (so that
	// when restarted it will start watching the correct resources).
	cc, err := clientv3.New(*config)
	if err != nil {
		log.Errorf("Failed to create main Calico client: %v", err)
		return nil, err
	}
	cfg, err := cc.BGPConfigurations().Get(
		context.Background(),
		"default",
		options.GetOptions{},
	)
	if _, ok := err.(errors.ErrorResourceDoesNotExist); err != nil && !ok {
		// Failed to get the BGP configuration (and not because it doesn't exist).
		// Exit.
		log.Errorf("Failed to query current BGP settings: %v", err)
		return nil, err
	}
	nodeMeshEnabled := true
	if cfg != nil && cfg.Spec.NodeToNodeMeshEnabled != nil {
		nodeMeshEnabled = *cfg.Spec.NodeToNodeMeshEnabled
	}

	// We know the v2 client implements the backendClientAccessor interface.  Use it to
	// get the backend client.
	bc := cc.(backendClientAccessor).Backend()

	// Create the client.  Initialize the cache revision to 1 so that the watcher
	// code can handle the first iteration by always rendering.
	c := &client{
		client:            bc,
		cache:             make(map[string]string),
		cacheRevision:     1,
		revisionsByPrefix: make(map[string]uint64),
		nodeMeshEnabled:   nodeMeshEnabled,
		routeReflector:    routeReflector,
	}

	// Create a conditional that we use to wake up all of the watcher threads when there
	// may some actionable updates.
	c.watcherCond = sync.NewCond(&c.cacheLock)

	// Increment the waitForSync wait group.  This blocks the GetValues call until the
	// syncer has completed it's initial snapshot and is in sync.  The syncer is started
	// from the SetPrefixes() call from confd.
	c.waitForSync.Add(1)

	// Start the main syncer loop.  If the node-to-node mesh is enabled then we need to
	// monitor all nodes.  If this setting changes (which we will monitor in the OnUpdates
	// callback) then we terminate confd - the calico/node init process will restart the
	// confd process.
	nodeName := os.Getenv("NODENAME")
	c.nodeLogKey = fmt.Sprintf("/calico/bgp/v1/host/%s/loglevel", nodeName)
	c.syncer = bgpsyncer.New(c.client, c, nodeName, nodeMeshEnabled || routeReflector)
	c.syncer.Start()

	return c, nil
}

// client implements the StoreClient interface for confd, and also implements the
// Calico api.SyncerCallbacks and api.SyncerParseFailCallbacks interfaces for the
// BGP Syncer.
type client struct {
	// The Calico backend client.
	client api.Client

	// The BGP syncer.
	syncer api.Syncer

	// Whether we have received the in-sync notification from the syncer.  We cannot
	// start rendering until we are in-sync, so we block calls to GetValues until we
	// have synced.
	synced      bool
	waitForSync sync.WaitGroup

	// Our internal cache of key/values, and our (internally defined) cache revision.
	cache         map[string]string
	cacheRevision uint64

	// The current revision for each prefix.  A revision is updated when we have a sync
	// event that updates any keys with that prefix.
	revisionsByPrefix map[string]uint64

	// Lock used to synchronize access to any of the shared mutable data.
	cacheLock   sync.Mutex
	watcherCond *sync.Cond

	// Whether the node to node mesh is enabled or not.
	nodeMeshEnabled bool

	// This node's log level key.
	nodeLogKey string

	// Whether we're running for a route reflector.
	routeReflector bool
}

// SetPrefixes is called from confd to notify this client of the full set of prefixes that will
// be watched.
// This client uses this information to initialize the revision map used to keep track of the
// revision number of each prefix that the template is monitoring.
func (c *client) SetPrefixes(keys []string) error {
	log.Debugf("Set prefixes called with: %v", keys)
	for _, k := range keys {
		// Initialise the revision that we are watching for this prefix.  This will be updated
		// if we receive any syncer events for keys with this prefix.  The Watcher function will
		// then check the revisions it is interested in to see if there is an updated revision
		// that it needs to process.
		c.revisionsByPrefix[k] = 0
	}

	return nil
}

// OnStatusUpdated is called from the BGP syncer to indicate that the sync status is updated.
// This client only cares about the InSync status as we use that to unlock the GetValues
// processing.
func (c *client) OnStatusUpdated(status api.SyncStatus) {
	// We should only get a single in-sync status update.  When we do, unblock the GetValues
	// calls.
	if status == api.InSync {
		c.cacheLock.Lock()
		defer c.cacheLock.Unlock()
		c.synced = true
		c.waitForSync.Done()
		log.Debugf("Data is now syncd, can start rendering templates")

		// Now that we're in-sync, check if we should update our log level
		// based on the datastore config.
		c.updateLogLevel()
	}
}

// OnUpdates is called from the BGP syncer to indicate that new updates are available from the
// Calico datastore.
// This client does the following:
// -  stores the updates in it's local cache
// -  increments the revision number associated with each of the affected watch prefixes
// -  wakes up the watchers so that they can check if any of the prefixes they are
//    watching have been updated.
func (c *client) OnUpdates(updates []api.Update) {
	// Update our cache from the updates.
	c.cacheLock.Lock()
	defer c.cacheLock.Unlock()

	// If we are in-sync then this is an incremental update, so increment our internal
	// cache revision.
	if c.synced {
		c.cacheRevision++
		log.Debugf("Processing new updates, revision is now: %d", c.cacheRevision)
	}

	// Update our cache from each of the individual updates, and keep track of
	// any of the prefixes that are impacted.
	for _, u := range updates {
		// Update our cache of current entries.
		k, err := model.KeyToDefaultPath(u.Key)
		if err != nil {
			log.Errorf("Ignoring update: unable to create path from Key %v: %v", u.Key, err)
			continue
		}

		switch u.UpdateType {
		case api.UpdateTypeKVDeleted:
			delete(c.cache, k)
		case api.UpdateTypeKVNew, api.UpdateTypeKVUpdated:
			value, err := model.SerializeValue(&u.KVPair)
			if err != nil {
				log.Errorf("Ignoring update: unable to serialize value %v: %v", u.KVPair.Value, err)
				continue
			}
			c.cache[k] = string(value)
		}

		log.Debugf("Cache entry updated from event type %d: %s=%s", u.UpdateType, k, c.cache[k])
		if c.synced {
			c.keyUpdated(k)
		}
	}

	if c.synced {
		// If we're not running for a route reflector, and the node-to-node mesh
		// configuration has been toggled, we need to terminate so that confd can be
		// restarted and monitor the correct set of nodes.  (If we running for a route
		// reflector, we always monitor all nodes.)
		if !c.routeReflector {
			// The node is disabled if the setting is present and is set to false.  Although this
			// is a json blob, it only contains a single field, so searching for "false" will
			// suffice.
			nodeMeshEnabled := !strings.Contains(c.cache[globalNodeMesh], "false")
			if nodeMeshEnabled != c.nodeMeshEnabled {
				log.Info("Node to node mesh setting has been modified - restarting confd")
				os.Exit(1)
			}
		}

		// Wake up the watchers to let them know there may be some updates of interest.  We only
		// need to do this once we're synced because until that point all of the Watcher threads
		// will be blocked getting values.
		log.Debug("Notify watchers of new event data")
		c.watcherCond.Broadcast()
	}
}

// ParseFailed is called from the BGP syncer when an event could not be parsed.
// We use this purely for logging.
func (c *client) ParseFailed(rawKey string, rawValue string) {
	log.Errorf("Unable to parse datastore entry Key=%s; Value=%s", rawKey, rawValue)
}

// GetValues is called from confd to obtain the cached data for the required set of prefixes.
// We simply populate the values from our cache, only returning values which have the requested
// set of prefixes.
func (c *client) GetValues(keys []string) (map[string]string, error) {
	// We should block GetValues until we have the sync'd notification - until that point we
	// only have a partial snapshot and we should never write out partial config.
	c.waitForSync.Wait()

	log.Debugf("Requesting values for keys: %v", keys)

	// For simplicity always populate the results with the common set of default values
	// (event if we haven't been asked for them).
	values := map[string]string{}

	// The bird templates that confd is used to render assumes some global defaults are always
	// configured.  Add in these defaults if the required keys includes them.  The configured
	// values may override these.
	if c.matchesPrefix(globalLogging, keys) {
		values[globalLogging] = "info"
	}
	if c.matchesPrefix(globalASN, keys) {
		values[globalASN] = "64512"
	}
	if c.matchesPrefix(globalNodeMesh, keys) {
		values[globalNodeMesh] = `{"enabled": true}`
	}

	// Lock the data and then populate the results from our cache, selecting the data
	// whose path matches the set of prefix keys.
	c.cacheLock.Lock()
	defer c.cacheLock.Unlock()
	for k, v := range c.cache {
		if c.matchesPrefix(k, keys) {
			values[k] = v
		}
	}

	log.Debugf("Returning %d results", len(values))

	return values, nil
}

// WatchPrefix is called from confd.  It blocks waiting for updates to the data which have any
// of the requested set of prefixes.
//
// Since we keep track of revisions per prefix, all we need to do is check the revisions for an
// update, and if there is no update we wait on the conditional which is woken by the OnUpdates
// thread after updating the cache.  If any of the watched revisions is greater than the waitIndex
// then exit to render.
func (c *client) WatchPrefix(prefix string, keys []string, lastRevision uint64, stopChan chan bool) error {
	c.cacheLock.Lock()
	defer c.cacheLock.Unlock()

	if lastRevision == 0 {
		// If this is the first iteration, we always exit to ensure we render with the initial
		// synced settings.
		log.Debug("First watch call for template - exiting to render template")
		return nil
	}

	for {
		// Loop through each key, if the revision associated with the key is higher than the lastRevision
		// then exit with the current cacheRevision and render with the current data.
		log.Debugf("Checking for updated key revisions, watching from rev %d", lastRevision)
		for _, key := range keys {
			rev, ok := c.revisionsByPrefix[key]
			if !ok {
				log.Fatalf("Watch prefix check for unknown prefix: %s", key)
			}
			log.Debugf("Found key prefix %s at rev %d", key, rev)
			if rev > lastRevision {
				log.Debug("Exiting to render template")
				return nil
			}
		}

		// No changes for this watcher, so wait until there are more syncer events.
		log.Debug("No updated keys for this template - waiting for event notification")
		c.watcherCond.Wait()
	}
}

// GetCurrentRevision returns the current revision of the data in our cache.
func (c *client) GetCurrentRevision() uint64 {
	c.cacheLock.Lock()
	defer c.cacheLock.Unlock()
	return c.cacheRevision
}

// matchesPrefix returns true if the key matches any of the supplied prefixes.
func (c *client) matchesPrefix(key string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(key, p) {
			return true
		}
	}
	return false
}

// Called when a key is updated.  This updates the revision associated with key prefixes
// affected by this key.
// The caller should be holding the cacheLock.
func (c *client) keyUpdated(key string) {
	for prefix, rev := range c.revisionsByPrefix {
		log.Debugf("Prefix %s has rev %d", prefix, rev)
		if rev != c.cacheRevision && strings.HasPrefix(key, prefix) {
			log.Debugf("Updating prefix to rev %d", c.cacheRevision)
			c.revisionsByPrefix[prefix] = c.cacheRevision

			// If this is a change to either the global log level, or the per-node
			// log level, then configure confd's log level to match.
			if strings.HasSuffix(key, "loglevel") {
				log.WithField("key", key).Info("Potential log level configuration change on key")
				c.updateLogLevel()
			}
		}
	}
}

func (c *client) updateLogLevel() {
	if envLevel := os.Getenv("BGP_LOGSEVERITYSCREEN"); envLevel != "" {
		logutils.SetLevel(envLevel)
	} else if nodeLevel := c.cache[c.nodeLogKey]; nodeLevel != "" {
		logutils.SetLevel(nodeLevel)
	} else if globalLogLevel := c.cache[globalLogging]; globalLogLevel != "" {
		logutils.SetLevel(globalLogLevel)
	} else {
		logutils.SetLevel("info")
	}
}
