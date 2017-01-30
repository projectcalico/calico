// Copyright (c) 2016 Tigera, Inc. All rights reserved.
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

package k8s

import (
	"time"

	"reflect"

	log "github.com/Sirupsen/logrus"
	"github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/compat"
	"github.com/projectcalico/libcalico-go/lib/backend/k8s/resources"
	"github.com/projectcalico/libcalico-go/lib/backend/k8s/thirdparty"
	"github.com/projectcalico/libcalico-go/lib/backend/model"

	k8sapi "k8s.io/client-go/pkg/api/v1"
	extensions "k8s.io/client-go/pkg/apis/extensions/v1beta1"
	"k8s.io/client-go/pkg/fields"
	"k8s.io/client-go/pkg/watch"
	"k8s.io/client-go/tools/cache"
)

func newSyncer(kc KubeClient, callbacks api.SyncerCallbacks) *kubeSyncer {
	syn := &kubeSyncer{
		kc:         kc,
		callbacks:  callbacks,
		tracker:    map[string]model.Key{},
		labelCache: map[string]map[string]string{},
	}
	return syn
}

type kubeSyncer struct {
	kc         KubeClient
	callbacks  api.SyncerCallbacks
	OneShot    bool
	tracker    map[string]model.Key
	labelCache map[string]map[string]string
}

// Holds resource version information.
type resourceVersions struct {
	podVersion           string
	namespaceVersion     string
	networkPolicyVersion string
	globalConfigVersion  string
	poolVersion          string
}

func (syn *kubeSyncer) Start() {
	// Start a background thread to read snapshots from and watch the Kubernetes API,
	// and pass updates via callbacks.
	go syn.readFromKubernetesAPI()
}

// sendUpdates sends updates to the callback and updates the resource
// tracker.
func (syn *kubeSyncer) sendUpdates(kvps []model.KVPair) {
	updates := syn.convertKVPairsToUpdates(kvps)

	// Send to the callback and update the tracker.
	syn.callbacks.OnUpdates(updates)
	syn.updateTracker(updates)
}

// convertKVPairsToUpdates converts a list of KVPairs to the list
// of api.Update objects which should be sent to OnUpdates.  It filters out
// deletes for any KVPairs which we don't know about.
func (syn *kubeSyncer) convertKVPairsToUpdates(kvps []model.KVPair) []api.Update {
	updates := []api.Update{}
	for _, kvp := range kvps {
		if _, ok := syn.tracker[kvp.Key.String()]; !ok && kvp.Value == nil {
			// The given KVPair is not in the tracker, and is a delete, so no need to
			// send a delete update.
			continue
		}
		updates = append(updates, api.Update{KVPair: kvp, UpdateType: syn.getUpdateType(kvp)})
	}
	return updates
}

// updateTracker updates the global object tracker with the given update.
// updateTracker should be called after sending a update to the OnUpdates callback.
func (syn *kubeSyncer) updateTracker(updates []api.Update) {
	for _, upd := range updates {
		if upd.UpdateType == api.UpdateTypeKVDeleted {
			log.Debugf("Delete from tracker: %+v", upd.KVPair.Key)
			delete(syn.tracker, upd.KVPair.Key.String())
		} else {
			log.Debugf("Update tracker: %+v: %+v", upd.KVPair.Key, upd.KVPair.Revision)
			syn.tracker[upd.KVPair.Key.String()] = upd.KVPair.Key
		}
	}
}

func (syn *kubeSyncer) getUpdateType(kvp model.KVPair) api.UpdateType {
	if kvp.Value == nil {
		// If the value is nil, then this is a delete.
		return api.UpdateTypeKVDeleted
	}

	// Not a delete.
	if _, ok := syn.tracker[kvp.Key.String()]; !ok {
		// If not a delete and it does not exist in the tracker, this is an add.
		return api.UpdateTypeKVNew
	} else {
		// If not a delete and it exists in the tracker, this is an update.
		return api.UpdateTypeKVUpdated
	}
}

func (syn *kubeSyncer) readFromKubernetesAPI() {
	log.Info("Starting Kubernetes API read worker")

	// Keep track of the latest resource versions.
	latestVersions := resourceVersions{}

	// Other watcher vars.
	var nsChan, poChan, npChan, gcChan, poolChan <-chan watch.Event
	var event watch.Event
	var kvp *model.KVPair
	var opts k8sapi.ListOptions

	// Always perform an initial snapshot.
	needsResync := true

	log.Info("Starting Kubernetes API read loop")
	for {
		// If we need to resync, do so.
		if needsResync {
			// Set status to ResyncInProgress.
			log.Warnf("Resync required - latest versions: %+v", latestVersions)
			syn.callbacks.OnStatusUpdated(api.ResyncInProgress)

			// Get snapshot from datastore.
			snap, existingKeys, latestVersions := syn.performSnapshot()
			log.Debugf("Snapshot: %+v, keys: %+v, versions: %+v", snap, existingKeys, latestVersions)

			// Go through and delete anything that existed before, but doesn't anymore.
			syn.performSnapshotDeletes(existingKeys)

			// Send the snapshot through.
			syn.sendUpdates(snap)

			log.Warnf("Snapshot complete - start watch from %+v", latestVersions)
			syn.callbacks.OnStatusUpdated(api.InSync)

			// Create the Kubernetes API watchers.
			opts = k8sapi.ListOptions{ResourceVersion: latestVersions.namespaceVersion}
			nsWatch, err := syn.kc.clientSet.Namespaces().Watch(opts)
			if err != nil {
				log.Warn("Failed to watch Namespaces, retrying: %s", err)
				time.Sleep(1 * time.Second)
				continue
			}
			opts = k8sapi.ListOptions{ResourceVersion: latestVersions.podVersion}
			poWatch, err := syn.kc.clientSet.Pods("").Watch(opts)
			if err != nil {
				log.Warn("Failed to watch Pods, retrying: %s", err)
				time.Sleep(1 * time.Second)
				continue
			}
			opts = k8sapi.ListOptions{ResourceVersion: latestVersions.networkPolicyVersion}

			// Create watcher for NetworkPolicy objects.
			netpolListWatcher := cache.NewListWatchFromClient(
				syn.kc.clientSet.Extensions().RESTClient(),
				"networkpolicies",
				"",
				fields.Everything())
			npWatch, err := netpolListWatcher.WatchFunc(opts)
			if err != nil {
				log.Warnf("Failed to watch NetworkPolicies, retrying: %s", err)
				time.Sleep(1 * time.Second)
				continue
			}

			// Create watcher for Calico global config resources.
			globalConfigWatcher := cache.NewListWatchFromClient(
				syn.kc.tprClient,
				"globalconfigs",
				"kube-system",
				fields.Everything())
			globalConfigWatch, err := globalConfigWatcher.WatchFunc(opts)
			if err != nil {
				log.Warnf("Failed to watch GlobalConfig, retrying: %s", err)
				time.Sleep(1 * time.Second)
				continue
			}

			// Watcher for Calico IP Pool resources.
			ipPoolWatcher := cache.NewListWatchFromClient(
				syn.kc.tprClient,
				"ippools",
				"kube-system",
				fields.Everything())
			ipPoolWatch, err := ipPoolWatcher.WatchFunc(opts)
			if err != nil {
				log.Warnf("Failed to watch IPPools, retrying: %s", err)
				time.Sleep(1 * time.Second)
				continue
			}

			nsChan = nsWatch.ResultChan()
			poChan = poWatch.ResultChan()
			npChan = npWatch.ResultChan()
			gcChan = globalConfigWatch.ResultChan()
			poolChan = ipPoolWatch.ResultChan()

			// Success - reset the flag.
			needsResync = false
		}

		// Don't start watches if we're in oneshot mode.
		if syn.OneShot {
			return
		}

		// Select on the various watch channels.
		select {
		case event = <-nsChan:
			log.Debugf("Incoming Namespace watch event. Type=%s", event.Type)
			if needsResync = syn.eventTriggersResync(event); needsResync {
				// We need to resync.  Break out into the sync loop.
				log.Warn("Event triggered resync: %+v", event)
				continue
			}

			// Event is OK - parse it.
			kvps := syn.parseNamespaceEvent(event)
			latestVersions.namespaceVersion = kvps[0].Revision.(string)
			syn.sendUpdates(kvps)
			continue
		case event = <-poChan:
			log.Debugf("Incoming Pod watch event. Type=%s", event.Type)
			if needsResync = syn.eventTriggersResync(event); needsResync {
				// We need to resync.  Break out into the sync loop.
				log.Warn("Event triggered resync: %+v", event)
				continue
			}

			// Event is OK - parse it.
			if kvp = syn.parsePodEvent(event); kvp != nil {
				// Only send the update if we care about it.  We filter
				// out a number of events that aren't useful for us.
				latestVersions.podVersion = kvp.Revision.(string)
				syn.sendUpdates([]model.KVPair{*kvp})
			}
		case event = <-npChan:
			log.Debugf("Incoming NetworkPolicy watch event. Type=%s", event.Type)
			if needsResync = syn.eventTriggersResync(event); needsResync {
				// We need to resync.  Break out into the sync loop.
				log.Warn("Event triggered resync: %+v", event)
				continue
			}

			// Event is OK - parse it and send it over the channel.
			kvp = syn.parseNetworkPolicyEvent(event)
			latestVersions.networkPolicyVersion = kvp.Revision.(string)
			syn.sendUpdates([]model.KVPair{*kvp})
		case event = <-gcChan:
			log.Debugf("Incoming GlobalConfig watch event. Type=%s", event.Type)
			if needsResync = syn.eventTriggersResync(event); needsResync {
				// We need to resync.  Break out into the sync loop.
				log.Warn("Event triggered resync: %+v", event)
				continue
			}

			// Event is OK - parse it and send it over the channel.
			kvp = syn.parseGlobalConfigEvent(event)
			latestVersions.globalConfigVersion = kvp.Revision.(string)
			syn.sendUpdates([]model.KVPair{*kvp})
		case event = <-poolChan:
			log.Debugf("Incoming IPPool watch event. Type=%s", event.Type)
			if needsResync = syn.eventTriggersResync(event); needsResync {
				// We need to resync.  Break out into the sync loop.
				log.Warn("Event triggered resync: %+v", event)
				continue
			}

			// Event is OK - parse it and send it over the channel.
			kvp = syn.parseIPPoolEvent(event)
			latestVersions.poolVersion = kvp.Revision.(string)
			syn.sendUpdates([]model.KVPair{*kvp})
		}
	}
}

func (syn *kubeSyncer) performSnapshotDeletes(exists map[string]bool) {
	log.Info("Checking for any deletes for snapshot")
	deletes := []model.KVPair{}
	log.Debugf("Keys in snapshot: %+v", exists)
	for cachedKey, k := range syn.tracker {
		// Check each cached key to see if it exists in the snapshot.  If it doesn't,
		// we need to send a delete for it.
		if _, stillExists := exists[cachedKey]; !stillExists {
			log.Debugf("Cached key not in snapshot: %+v", cachedKey)
			deletes = append(deletes, model.KVPair{Key: k, Value: nil})
		}
	}
	log.Infof("Sending snapshot deletes: %+v", deletes)
	syn.sendUpdates(deletes)
}

// performSnapshot returns a list of existing objects in the datastore,
// a mapping of model.Key objects representing the objects which exist in the datastore, and
// populates the provided resourceVersions with the latest k8s resource version
// for each.
func (syn *kubeSyncer) performSnapshot() ([]model.KVPair, map[string]bool, resourceVersions) {
	opts := k8sapi.ListOptions{}
	versions := resourceVersions{}
	var snap []model.KVPair
	var keys map[string]bool

	// Loop until we successfully are able to accesss the API.
	for {
		// Initialize the values to return.
		snap = []model.KVPair{}
		keys = map[string]bool{}

		// Get Namespaces (Profiles)
		log.Info("Syncing Namespaces")
		nsList, err := syn.kc.clientSet.Namespaces().List(opts)
		if err != nil {
			log.Warnf("Error syncing Namespaces, retrying: %s", err)
			time.Sleep(1 * time.Second)
			continue
		}
		versions.namespaceVersion = nsList.ListMeta.ResourceVersion
		for _, ns := range nsList.Items {
			// The Syncer API expects a profile to be broken into its underlying
			// components - rules, tags, labels.
			profile, err := syn.kc.converter.namespaceToProfile(&ns)
			if err != nil {
				log.Panicf("%s", err)
			}
			rules, tags, labels := compat.ToTagsLabelsRules(profile)
			rules.Revision = profile.Revision
			tags.Revision = profile.Revision
			labels.Revision = profile.Revision

			// Also create a Policy for this Namespace.
			policy, err := syn.kc.converter.namespaceToPolicy(&ns)
			if err != nil {
				log.Panicf("%s", err)
			}

			snap = append(snap, *rules, *tags, *labels, *policy)
			keys[rules.Key.String()] = true
			keys[tags.Key.String()] = true
			keys[labels.Key.String()] = true
			keys[policy.Key.String()] = true
		}

		// Get NetworkPolicies (Policies)
		log.Info("Syncing NetworkPolicy")
		npList := extensions.NetworkPolicyList{}
		err = syn.kc.clientSet.Extensions().RESTClient().
			Get().
			Resource("networkpolicies").
			Timeout(10 * time.Second).
			Do().Into(&npList)
		if err != nil {
			log.Warnf("Error querying NetworkPolicies during snapshot, retrying: %s", err)
			time.Sleep(1 * time.Second)
			continue
		}

		versions.networkPolicyVersion = npList.ListMeta.ResourceVersion
		for _, np := range npList.Items {
			pol, _ := syn.kc.converter.networkPolicyToPolicy(&np)
			snap = append(snap, *pol)
			keys[pol.Key.String()] = true
		}

		// Get Pods (WorkloadEndpoints)
		log.Info("Syncing Pods")
		poList, err := syn.kc.clientSet.Pods("").List(opts)
		if err != nil {
			log.Warnf("Error querying Pods during snapshot, retrying: %s", err)
			time.Sleep(1 * time.Second)
			continue
		}

		versions.podVersion = poList.ListMeta.ResourceVersion
		for _, po := range poList.Items {
			wep, _ := syn.kc.converter.podToWorkloadEndpoint(&po)
			if wep != nil {
				snap = append(snap, *wep)
				keys[wep.Key.String()] = true
			}
		}

		// Sync GlobalConfig.
		confList, err := syn.kc.listGlobalConfig(model.GlobalConfigListOptions{})
		if err != nil {
			log.Warnf("Error querying GlobalConfig during snapshot, retrying: %s", err)
			time.Sleep(1 * time.Second)
			continue
		}

		for _, c := range confList {
			snap = append(snap, *c)
			keys[c.Key.String()] = true
		}

		// Sync IP Pools.
		poolList, err := syn.kc.List(model.IPPoolListOptions{})
		if err != nil {
			log.Warnf("Error querying IP Pools during snapshot, retrying: %s", err)
			time.Sleep(1 * time.Second)
			continue
		}

		for _, p := range poolList {
			snap = append(snap, *p)
			keys[p.Key.String()] = true
		}

		// Include ready state.
		ready, err := syn.kc.getReadyStatus(model.ReadyFlagKey{})
		if err != nil {
			log.Warnf("Error querying ready status during snapshot, retrying: %s", err)
			time.Sleep(1 * time.Second)
			continue
		}
		snap = append(snap, *ready)
		keys[ready.Key.String()] = true

		log.Infof("Snapshot resourceVersions: %+v", versions)
		log.Debugf("Created snapshot: %+v", snap)
		return snap, keys, versions
	}
}

// eventTriggersResync returns true of the given event requires a
// full datastore resync to occur, and false otherwise.
func (syn *kubeSyncer) eventTriggersResync(e watch.Event) bool {
	// If we encounter an error, or if the event is nil (which can indicate
	// an unexpected connection close).
	if e.Type == watch.Error || e.Object == nil {
		log.Warnf("Event requires snapshot: %+v", e)
		return true
	}
	return false
}

func (syn *kubeSyncer) parseNamespaceEvent(e watch.Event) []model.KVPair {
	ns, ok := e.Object.(*k8sapi.Namespace)
	if !ok {
		log.Panicf("Invalid namespace event: %+v", e.Object)
	}

	// Convert the received Namespace into a profile KVPair.
	profile, err := syn.kc.converter.namespaceToProfile(ns)
	if err != nil {
		log.Panicf("%s", err)
	}
	rules, tags, labels := compat.ToTagsLabelsRules(profile)
	rules.Revision = profile.Revision
	tags.Revision = profile.Revision
	labels.Revision = profile.Revision

	// Convert the Namespace into a policy KVPair.
	policy, err := syn.kc.converter.namespaceToPolicy(ns)
	if err != nil {
		log.Panicf("%s", err)
	}

	// For deletes, we need to nil out the Value part of the KVPair.
	if e.Type == watch.Deleted {
		rules.Value = nil
		tags.Value = nil
		labels.Value = nil
		policy.Value = nil
	}

	// Return the updates.
	return []model.KVPair{*rules, *tags, *labels, *policy}
}

// parsePodEvent returns a KVPair for the given event.  If the event isn't
// useful, parsePodEvent returns nil to indicate that there is nothing to do.
func (syn *kubeSyncer) parsePodEvent(e watch.Event) *model.KVPair {
	pod, ok := e.Object.(*k8sapi.Pod)
	if !ok {
		log.Panicf("Invalid pod event. Type: %s, Object: %+v", e.Type, e.Object)
	}

	// Ignore any updates for host networked pods.
	if syn.kc.converter.isHostNetworked(pod) {
		log.Debugf("Skipping host networked pod %s/%s", pod.ObjectMeta.Namespace, pod.ObjectMeta.Name)
		return nil
	}

	// Convert the received Namespace into a KVPair.
	kvp, err := syn.kc.converter.podToWorkloadEndpoint(pod)
	if err != nil {
		log.Panicf("%s", err)
	}

	// We behave differently based on the event type.
	switch e.Type {
	case watch.Deleted:
		// For deletes, we need to nil out the Value part of the KVPair.
		log.Debugf("Delete for pod %s/%s", pod.ObjectMeta.Namespace, pod.ObjectMeta.Name)
		kvp.Value = nil

		// Remove it from the cache, if it is there.
		workload := kvp.Key.(model.WorkloadEndpointKey).WorkloadID
		delete(syn.labelCache, workload)
	default:
		// Adds and modifies are treated the same.  First, if the pod doesn't have an
		// IP address, we ignore it until it does.
		if !syn.kc.converter.hasIPAddress(pod) {
			log.Debugf("Skipping pod with no IP: %s/%s", pod.ObjectMeta.Namespace, pod.ObjectMeta.Name)
			return nil
		}

		// If it does have an address, we only send if the labels have changed.
		workload := kvp.Key.(model.WorkloadEndpointKey).WorkloadID
		labels := kvp.Value.(*model.WorkloadEndpoint).Labels
		if reflect.DeepEqual(syn.labelCache[workload], labels) {
			// Labels haven't changed - no need to send an update for this add/modify.
			log.Debugf("Skipping pod event - labels didn't change: %s/%s", pod.ObjectMeta.Namespace, pod.ObjectMeta.Name)
			return nil
		}

		// Labels have changed on a running pod - update the label cache.
		syn.labelCache[workload] = labels
	}

	return kvp
}

func (syn *kubeSyncer) parseNetworkPolicyEvent(e watch.Event) *model.KVPair {
	log.Debug("Parsing NetworkPolicy watch event")
	// First, check the event type.
	np, ok := e.Object.(*extensions.NetworkPolicy)
	if !ok {
		log.Panicf("Invalid NetworkPolicy event. Type: %s, Object: %+v", e.Type, e.Object)
	}

	// Convert the received NetworkPolicy into a profile KVPair.
	kvp, err := syn.kc.converter.networkPolicyToPolicy(np)
	if err != nil {
		log.Panicf("%s", err)
	}

	// For deletes, we need to nil out the Value part of the KVPair
	if e.Type == watch.Deleted {
		kvp.Value = nil
	}
	return kvp
}

func (syn *kubeSyncer) parseGlobalConfigEvent(e watch.Event) *model.KVPair {
	log.Debug("Parsing GlobalConfig watch event")
	// First, check the event type.
	gc, ok := e.Object.(*thirdparty.GlobalConfig)
	if !ok {
		log.Panicf("Invalid GlobalConfig event. Type: %s, Object: %+v", e.Type, e.Object)
	}

	// Convert the received GlobalConfig into a KVPair.
	kvp := syn.kc.converter.tprToGlobalConfig(gc)

	// For deletes, we need to nil out the Value part of the KVPair
	if e.Type == watch.Deleted {
		kvp.Value = nil
	}
	return kvp
}

func (syn *kubeSyncer) parseIPPoolEvent(e watch.Event) *model.KVPair {
	log.Debug("Parsing IPPool watch event")
	// First, check the event type.
	tpr, ok := e.Object.(*thirdparty.IpPool)
	if !ok {
		log.Panicf("Invalid IPPool event. Type: %s, Object: %+v", e.Type, e.Object)
	}

	// Convert the received IPPool into a KVPair.
	kvp := resources.ThirdPartyToIPPool(tpr)

	// For deletes, we need to nil out the Value part of the KVPair
	if e.Type == watch.Deleted {
		kvp.Value = nil
	}
	return kvp
}
