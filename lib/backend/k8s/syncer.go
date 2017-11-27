// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.
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

	"github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/compat"
	"github.com/projectcalico/libcalico-go/lib/backend/k8s/resources"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	log "github.com/sirupsen/logrus"

	extensions "github.com/projectcalico/libcalico-go/lib/backend/extensions"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/watch"
	k8sapi "k8s.io/client-go/pkg/api/v1"
	"k8s.io/client-go/tools/cache"
)

type kubeAPI interface {
	NamespaceWatch(metav1.ListOptions) (watch.Interface, error)
	NamespaceList(metav1.ListOptions) (*k8sapi.NamespaceList, error)
	PodWatch(string, metav1.ListOptions) (watch.Interface, error)
	PodList(string, metav1.ListOptions) (*k8sapi.PodList, error)
	NetworkPolicyWatch(metav1.ListOptions) (watch.Interface, error)
	NetworkPolicyList() (extensions.NetworkPolicyList, error)
	GlobalFelixConfigWatch(metav1.ListOptions) (watch.Interface, error)
	GlobalFelixConfigList(model.GlobalConfigListOptions) ([]*model.KVPair, string, error)
	IPPoolWatch(metav1.ListOptions) (watch.Interface, error)
	IPPoolList(model.IPPoolListOptions) ([]*model.KVPair, string, error)
	NodeWatch(metav1.ListOptions) (watch.Interface, error)
	NodeList(metav1.ListOptions) (list *k8sapi.NodeList, err error)
	GlobalNetworkPolicyWatch(metav1.ListOptions) (watch.Interface, error)
	GlobalNetworkPolicyList() ([]*model.KVPair, string, error)
	HostConfigList(model.HostConfigListOptions) ([]*model.KVPair, error)
	getReadyStatus(k model.ReadyFlagKey) (*model.KVPair, error)
}

type realKubeAPI struct {
	kc *KubeClient
}

func (k *realKubeAPI) NamespaceWatch(opts metav1.ListOptions) (watch watch.Interface, err error) {
	watch, err = k.kc.clientSet.Namespaces().Watch(opts)
	return
}

func (k *realKubeAPI) PodWatch(namespace string, opts metav1.ListOptions) (watch watch.Interface, err error) {
	watch, err = k.kc.clientSet.Pods(namespace).Watch(opts)
	return
}

func (k *realKubeAPI) NetworkPolicyWatch(opts metav1.ListOptions) (watch watch.Interface, err error) {
	netpolListWatcher := cache.NewListWatchFromClient(
		k.kc.extensionsClientV1Beta1,
		"networkpolicies",
		"",
		fields.Everything())
	watch, err = netpolListWatcher.WatchFunc(opts)
	return
}

func (k *realKubeAPI) GlobalFelixConfigWatch(opts metav1.ListOptions) (watch watch.Interface, err error) {
	globalFelixConfigWatcher := cache.NewListWatchFromClient(
		k.kc.crdClientV1,
		resources.GlobalFelixConfigResourceName,
		"",
		fields.Everything())
	watch, err = globalFelixConfigWatcher.WatchFunc(opts)
	return
}

func (k *realKubeAPI) IPPoolWatch(opts metav1.ListOptions) (watch watch.Interface, err error) {
	ipPoolWatcher := cache.NewListWatchFromClient(
		k.kc.crdClientV1,
		resources.IPPoolResourceName,
		"",
		fields.Everything())
	watch, err = ipPoolWatcher.WatchFunc(opts)
	return
}

func (k *realKubeAPI) NodeWatch(opts metav1.ListOptions) (watch watch.Interface, err error) {
	watch, err = k.kc.clientSet.Nodes().Watch(opts)
	return
}

func (k *realKubeAPI) NamespaceList(opts metav1.ListOptions) (list *k8sapi.NamespaceList, err error) {
	list, err = k.kc.clientSet.Namespaces().List(opts)
	return
}

func (k *realKubeAPI) NetworkPolicyList() (list extensions.NetworkPolicyList, err error) {
	list = extensions.NetworkPolicyList{}
	err = k.kc.extensionsClientV1Beta1.
		Get().
		Resource("networkpolicies").
		Timeout(10 * time.Second).
		Do().Into(&list)
	return
}

func (k *realKubeAPI) GlobalNetworkPolicyWatch(opts metav1.ListOptions) (watch.Interface, error) {
	watcher := cache.NewListWatchFromClient(
		k.kc.crdClientV1,
		resources.GlobalNetworkPolicyResourceName,
		"",
		fields.Everything())
	return watcher.WatchFunc(opts)
}

func (k *realKubeAPI) GlobalNetworkPolicyList() ([]*model.KVPair, string, error) {
	return k.kc.gnpClient.List(model.PolicyListOptions{})
}

func (k *realKubeAPI) PodList(namespace string, opts metav1.ListOptions) (list *k8sapi.PodList, err error) {
	list, err = k.kc.clientSet.Pods(namespace).List(opts)
	return
}

func (k *realKubeAPI) GlobalFelixConfigList(l model.GlobalConfigListOptions) ([]*model.KVPair, string, error) {
	return k.kc.globalFelixConfigClient.List(l)
}

func (k *realKubeAPI) HostConfigList(l model.HostConfigListOptions) ([]*model.KVPair, error) {
	return k.kc.listHostConfig(l)
}

func (k *realKubeAPI) IPPoolList(l model.IPPoolListOptions) ([]*model.KVPair, string, error) {
	return k.kc.ipPoolClient.List(l)
}

func (k *realKubeAPI) NodeList(opts metav1.ListOptions) (list *k8sapi.NodeList, err error) {
	list, err = k.kc.clientSet.Nodes().List(opts)
	return
}

func (k *realKubeAPI) getReadyStatus(key model.ReadyFlagKey) (*model.KVPair, error) {
	return k.kc.getReadyStatus(key)
}

func newSyncer(kubeAPI kubeAPI, converter Converter, callbacks api.SyncerCallbacks, disableNodePoll bool) *kubeSyncer {
	syn := &kubeSyncer{
		kubeAPI:   kubeAPI,
		converter: converter,
		callbacks: callbacks,
		trackers: map[string]map[string]model.Key{
			KEY_NS:  map[string]model.Key{},
			KEY_PO:  map[string]model.Key{},
			KEY_NP:  map[string]model.Key{},
			KEY_GNP: map[string]model.Key{},
			KEY_GC:  map[string]model.Key{},
			KEY_HC:  map[string]model.Key{},
			KEY_IP:  map[string]model.Key{},
			KEY_NO:  map[string]model.Key{},
			KEY_RS:  map[string]model.Key{},
		},
		needsResync: map[string]bool{
			KEY_NS:  true,
			KEY_PO:  true,
			KEY_NP:  true,
			KEY_GNP: true,
			KEY_GC:  true,
			KEY_HC:  true,
			KEY_IP:  true,
			KEY_NO:  !disableNodePoll,
			KEY_RS:  true,
		},
		disableNodePoll: disableNodePoll,
		stopChan:        make(chan int),
		openWatchers:    map[string]watch.Interface{},
	}
	return syn
}

type kubeSyncer struct {
	kubeAPI         kubeAPI
	converter       Converter
	callbacks       api.SyncerCallbacks
	OneShot         bool
	disableNodePoll bool
	stopChan        chan int
	openWatchers    map[string]watch.Interface

	// Map of resource key to whether or not that resource needs a resync.
	needsResync map[string]bool

	// Trackers is a map from individual resource keys (KEY_*) to the tracking map
	// used to track sync state for that resource.
	trackers map[string]map[string]model.Key
}

// Holds resource version information.
type resourceVersions struct {
	nodeVersion                string
	podVersion                 string
	namespaceVersion           string
	networkPolicyVersion       string
	globalNetworkPolicyVersion string
	globalFelixConfigVersion   string
	poolVersion                string
}

func (syn *kubeSyncer) Start() {
	// Start a background thread to read snapshots from and watch the Kubernetes API,
	// and pass updates via callbacks.
	go syn.readFromKubernetesAPI()
}

func (syn *kubeSyncer) Stop() {
	syn.stopChan <- 1
}

// sendUpdates sends updates to the callback and updates the resource
// tracker for the given resourceType (e.g. KEY_NS).
func (syn *kubeSyncer) sendUpdates(kvps []model.KVPair, resourceType string) {
	updates := syn.convertKVPairsToUpdates(kvps, resourceType)

	// Send to the callback and update the tracker.
	syn.callbacks.OnUpdates(updates)
	syn.updateTracker(updates, resourceType)
}

// convertKVPairsToUpdates converts a list of KVPairs to the list
// of api.Update objects which should be sent to OnUpdates.  It filters out
// deletes for any KVPairs which we don't know about.
func (syn *kubeSyncer) convertKVPairsToUpdates(kvps []model.KVPair, resourceType string) []api.Update {
	updates := []api.Update{}
	for _, kvp := range kvps {
		if _, ok := syn.trackers[resourceType][kvp.Key.String()]; !ok && kvp.Value == nil {
			// The given KVPair is not in the tracker, and is a delete, so no need to
			// send a delete update.
			continue
		}
		updates = append(updates, api.Update{KVPair: kvp, UpdateType: syn.getUpdateType(kvp, resourceType)})
	}
	return updates
}

// updateTracker updates the per-resource object tracker with the given update.
// updateTracker should be called after sending a update to the OnUpdates callback.
func (syn *kubeSyncer) updateTracker(updates []api.Update, resourceType string) {
	for _, upd := range updates {
		// Update that particular resource type's tracker.
		if upd.UpdateType == api.UpdateTypeKVDeleted {
			log.Debugf("Delete from tracker: %+v", upd.KVPair.Key)
			delete(syn.trackers[resourceType], upd.KVPair.Key.String())
		} else {
			log.Debugf("Update tracker: %+v: %+v", upd.KVPair.Key, upd.KVPair.Revision)
			syn.trackers[resourceType][upd.KVPair.Key.String()] = upd.KVPair.Key
		}
	}
}

func (syn *kubeSyncer) getUpdateType(kvp model.KVPair, resourceType string) api.UpdateType {
	if kvp.Value == nil {
		// If the value is nil, then this is a delete.
		return api.UpdateTypeKVDeleted
	}

	// Not a delete.
	if _, ok := syn.trackers[resourceType][kvp.Key.String()]; !ok {
		// If not a delete and it does not exist in the tracker, this is an add.
		return api.UpdateTypeKVNew
	} else {
		// If not a delete and it exists in the tracker, this is an update.
		return api.UpdateTypeKVUpdated
	}
}

// Keys used to identify various bits of state stored on a per-resource basis.
const (
	KEY_NS  = "Namespace"
	KEY_PO  = "Pod"
	KEY_NP  = "NetworkPolicy"
	KEY_GNP = "GlobalNetworkPolicy"
	KEY_GC  = "GlobalFelixConfig"
	KEY_HC  = "HostConfig"
	KEY_IP  = "IPPool"
	KEY_NO  = "Node"
	KEY_RS  = "CalicoReadyState"
)

func (syn *kubeSyncer) readFromKubernetesAPI() {
	log.Info("Starting Kubernetes API read worker")

	// Keep track of the latest resource versions.
	latestVersions := resourceVersions{}

	// Other watcher vars.
	var nsChan, poChan, npChan, gnpChan, gcChan, poolChan, noChan <-chan watch.Event
	var event watch.Event
	var opts metav1.ListOptions

	log.Info("Starting Kubernetes API read loop")
	for {
		needSync := false

		// Find out if we need to resync.
		for _, resync := range syn.needsResync {
			// We found something that needs resync, we can stop and move on.
			if resync {
				needSync = true
				break
			}
		}

		// If we need to resync, do so.
		if needSync {
			// Set status to ResyncInProgress.
			log.Debugf("Resync required - latest versions: %+v", latestVersions)
			syn.callbacks.OnStatusUpdated(api.ResyncInProgress)

			// Get snapshot from datastore.
			snap, existingKeys := syn.performSnapshot(&latestVersions)
			log.Debugf("Snapshot: %+v, keys: %+v, versions: %+v", snap, existingKeys, latestVersions)

			// Go through and delete anything that existed before, but doesn't anymore.
			syn.performSnapshotDeletes(existingKeys)

			// Send the snapshot through for each resource type that went through
			// a resync.
			for resourceType, s := range snap {
				syn.sendUpdates(s, resourceType)
			}

			log.Debugf("Snapshot complete - start watch from %+v", latestVersions)
			syn.callbacks.OnStatusUpdated(api.InSync)

			// Don't start watches if we're in oneshot mode.
			if syn.OneShot {
				log.Info("OneShot mode, do not start watches")
				return
			}

			// Close out any watches that needed resync.
			for k, resync := range syn.needsResync {
				if _, exists := syn.openWatchers[k]; exists && resync {
					syn.closeWatcher(k)
				}
			}
		}

		// Create the Kubernetes API watchers.
		if _, exists := syn.openWatchers[KEY_NS]; !exists {
			opts = metav1.ListOptions{ResourceVersion: latestVersions.namespaceVersion}
			log.WithField("opts", opts).Debug("(Re)start Namespace watch")
			nsWatch, err := syn.kubeAPI.NamespaceWatch(opts)
			if err != nil {
				log.Warn("Failed to watch Namespaces, retrying: %s", err)
				time.Sleep(1 * time.Second)
				continue
			}
			syn.openWatchers[KEY_NS] = nsWatch
			nsChan = nsWatch.ResultChan()
			syn.needsResync[KEY_NS] = false
		}

		if _, exists := syn.openWatchers[KEY_PO]; !exists {
			opts = metav1.ListOptions{ResourceVersion: latestVersions.podVersion}
			log.WithField("opts", opts).Debug("(Re)start Pod watch")
			poWatch, err := syn.kubeAPI.PodWatch("", opts)
			if err != nil {
				log.Warn("Failed to watch Pods, retrying: %s", err)
				time.Sleep(1 * time.Second)
				continue
			}
			syn.openWatchers[KEY_PO] = poWatch
			poChan = poWatch.ResultChan()
			syn.needsResync[KEY_PO] = false
		}

		if _, exists := syn.openWatchers[KEY_NP]; !exists {
			// Create watcher for NetworkPolicy objects.
			opts = metav1.ListOptions{ResourceVersion: latestVersions.networkPolicyVersion}
			log.WithField("opts", opts).Debug("(Re)start NetworkPolicy watch")
			npWatch, err := syn.kubeAPI.NetworkPolicyWatch(opts)
			if err != nil {
				log.Warnf("Failed to watch NetworkPolicies, retrying: %s", err)
				time.Sleep(1 * time.Second)
				continue
			}
			syn.openWatchers[KEY_NP] = npWatch
			npChan = npWatch.ResultChan()
			syn.needsResync[KEY_NP] = false
		}

		if _, exists := syn.openWatchers[KEY_GNP]; !exists {
			// Create watcher for GlobalNetworkPolicy objects.
			opts = metav1.ListOptions{ResourceVersion: latestVersions.globalNetworkPolicyVersion}
			log.WithField("opts", opts).Debug("(Re)start GlobalNetworkPolicy watch")
			gnpWatch, err := syn.kubeAPI.GlobalNetworkPolicyWatch(opts)
			if err != nil {
				log.Warnf("Failed to watch GlobalNetworkPolicies, retrying: %s", err)
				time.Sleep(1 * time.Second)
				continue
			}
			syn.openWatchers[KEY_GNP] = gnpWatch
			gnpChan = gnpWatch.ResultChan()
			syn.needsResync[KEY_GNP] = false
		}

		if _, exists := syn.openWatchers[KEY_GC]; !exists {
			// Create watcher for Calico global felix config resources.
			opts = metav1.ListOptions{ResourceVersion: latestVersions.globalFelixConfigVersion}
			log.WithField("opts", opts).Info("(Re)start GlobalFelixConfig watch")
			globalFelixConfigWatch, err := syn.kubeAPI.GlobalFelixConfigWatch(opts)
			if err != nil {
				log.Warnf("Failed to watch GlobalFelixConfig, retrying: %s", err)
				time.Sleep(1 * time.Second)
				continue
			}
			syn.openWatchers[KEY_GC] = globalFelixConfigWatch
			gcChan = globalFelixConfigWatch.ResultChan()
			syn.needsResync[KEY_GC] = false
		}

		if _, exists := syn.openWatchers[KEY_IP]; !exists {
			// Watcher for Calico IP Pool resources.
			opts = metav1.ListOptions{ResourceVersion: latestVersions.poolVersion}
			log.WithField("opts", opts).Info("(Re)start IPPool watch")
			ipPoolWatch, err := syn.kubeAPI.IPPoolWatch(opts)
			if err != nil {
				log.Warnf("Failed to watch IPPools, retrying: %s", err)
				time.Sleep(1 * time.Second)
				continue
			}
			syn.openWatchers[KEY_IP] = ipPoolWatch
			poolChan = ipPoolWatch.ResultChan()
			syn.needsResync[KEY_IP] = false
		}

		if _, exists := syn.openWatchers[KEY_NO]; !exists && !syn.disableNodePoll {
			// Create watcher for Node objects
			opts := metav1.ListOptions{ResourceVersion: latestVersions.nodeVersion}
			log.WithField("opts", opts).Debug("(Re)start Node watch")
			nodeWatch, err := syn.kubeAPI.NodeWatch(opts)
			if err != nil {
				log.Warnf("Failed to watch Nodes, retrying: %s", err)
				time.Sleep(1 * time.Second)
				continue
			}
			syn.openWatchers[KEY_NO] = nodeWatch
			noChan = nodeWatch.ResultChan()
			syn.needsResync[KEY_NO] = false
			syn.needsResync[KEY_HC] = false
		}

		// Select on the various watch channels.
		select {
		case <-syn.stopChan:
			log.Info("Syncer told to stop reading")
			syn.closeAllWatchers()
			return
		case event = <-nsChan:
			log.Debugf("Incoming Namespace watch event. Type=%s", event.Type)
			if syn.eventNeedsResync(event) {
				syn.needsResync[KEY_NS] = true
				continue
			} else if syn.eventRestartsWatch(event, KEY_NS) {
				syn.closeWatcher(KEY_NS)
				continue
			}
			// Event is OK - parse it.
			kvps := syn.parseNamespaceEvent(event)
			latestVersions.namespaceVersion = kvps[0].Revision.(string)
			syn.sendUpdates(kvps, KEY_NS)
			continue
		case event = <-poChan:
			log.Debugf("Incoming Pod watch event. Type=%s", event.Type)
			if syn.eventNeedsResync(event) {
				syn.needsResync[KEY_PO] = true
				continue
			} else if syn.eventRestartsWatch(event, KEY_PO) {
				syn.closeWatcher(KEY_PO)
				continue
			}
			// Event is OK - parse it.
			if kvp := syn.parsePodEvent(event); kvp != nil {
				// Only send the update if we care about it.  We filter
				// out a number of events that aren't useful for us.
				latestVersions.podVersion = kvp.Revision.(string)
				syn.sendUpdates([]model.KVPair{*kvp}, KEY_PO)
			}
		case event = <-npChan:
			log.Debugf("Incoming NetworkPolicy watch event. Type=%s", event.Type)
			if syn.eventNeedsResync(event) {
				syn.needsResync[KEY_NP] = true
				continue
			} else if syn.eventRestartsWatch(event, KEY_NP) {
				syn.closeWatcher(KEY_NP)
				continue
			}
			// Event is OK - parse it and send it over the channel.
			kvp := syn.parseNetworkPolicyEvent(event)
			latestVersions.networkPolicyVersion = kvp.Revision.(string)
			syn.sendUpdates([]model.KVPair{*kvp}, KEY_NP)
		case event = <-gnpChan:
			log.Debugf("Incoming GlobalNetworkPolicy watch event. Type=%s", event.Type)
			if syn.eventNeedsResync(event) {
				syn.needsResync[KEY_GNP] = true
				continue
			} else if syn.eventRestartsWatch(event, KEY_GNP) {
				// Resources backed by TPRs need to be resynced on empty events.
				syn.needsResync[KEY_GNP] = true
				syn.closeWatcher(KEY_GNP)
				continue
			}
			// Event is OK - parse it and send it over the channel.
			if kvp := syn.parseGlobalNetworkPolicyEvent(event); kvp != nil {
				latestVersions.globalNetworkPolicyVersion = kvp.Revision.(string)
				syn.sendUpdates([]model.KVPair{*kvp}, KEY_GNP)
			}
		case event = <-gcChan:
			log.Debugf("Incoming GlobalFelixConfig watch event. Type=%s", event.Type)
			if syn.eventNeedsResync(event) {
				syn.needsResync[KEY_GC] = true
				continue
			} else if syn.eventRestartsWatch(event, KEY_GC) {
				// Resources backed by TPRs need to be resynced on empty events.
				syn.needsResync[KEY_GC] = true
				syn.closeWatcher(KEY_GC)
				continue
			}
			// Event is OK - parse it and send it over the channel.
			kvp := syn.parseGlobalFelixConfigEvent(event)
			latestVersions.globalFelixConfigVersion = kvp.Revision.(string)
			syn.sendUpdates([]model.KVPair{*kvp}, KEY_GC)
		case event = <-poolChan:
			log.Debugf("Incoming IPPool watch event. Type=%s", event.Type)
			if syn.eventNeedsResync(event) {
				syn.needsResync[KEY_IP] = true
				continue
			} else if syn.eventRestartsWatch(event, KEY_IP) {
				// Resources backed by TPRs need to be resynced on empty events.
				syn.needsResync[KEY_IP] = true
				syn.closeWatcher(KEY_IP)
				continue
			}
			// Event is OK - parse it and send it over the channel.
			if kvp := syn.parseIPPoolEvent(event); kvp != nil {
				latestVersions.poolVersion = kvp.Revision.(string)
				syn.sendUpdates([]model.KVPair{*kvp}, KEY_IP)
			}
		case event = <-noChan:
			log.Debugf("Incoming Node watch event. Type=%s", event.Type)
			if syn.eventNeedsResync(event) {
				syn.needsResync[KEY_NO] = true
				syn.needsResync[KEY_HC] = true
				continue
			} else if syn.eventRestartsWatch(event, KEY_NO) {
				syn.needsResync[KEY_NO] = true
				syn.needsResync[KEY_HC] = true
				syn.closeWatcher(KEY_NO)
				continue
			}
			// Event is OK - parse it and send it over the channel.
			kvpHostIP, kvpIPIPAddr := syn.parseNodeEvent(event)
			log.WithFields(log.Fields{
				"kvpHostIP":   kvpHostIP,
				"kvpIPIPAddr": kvpIPIPAddr,
			}).Debug("Got node KVs.")
			latestVersions.nodeVersion = kvpHostIP.Revision.(string)
			syn.sendUpdates([]model.KVPair{*kvpHostIP}, KEY_NO)
			syn.sendUpdates([]model.KVPair{*kvpIPIPAddr}, KEY_HC)
		}
	}
}

func (syn *kubeSyncer) performSnapshotDeletes(existsMap map[string]map[string]bool) {
	log.Info("Checking for any deletes for snapshot")
	for resourceType, exists := range existsMap {
		log.Debugf("%s keys in snapshot: %+v", resourceType, exists)
		deletes := []model.KVPair{}
		for cachedKey, k := range syn.trackers[resourceType] {
			// Check each cached key to see if it exists in the snapshot.  If it doesn't,
			// we need to send a delete for it.
			if _, stillExists := exists[cachedKey]; !stillExists {
				log.Debugf("Cached %s key not in snapshot: %+v", resourceType, cachedKey)
				deletes = append(deletes, model.KVPair{Key: k, Value: nil})
			}
		}
		log.Infof("Sending %s snapshot deletes: %+v", resourceType, deletes)
		syn.sendUpdates(deletes, resourceType)
	}
}

// performSnapshot returns a list of existing objects in the datastore,
// a mapping of model.Key objects representing the objects which exist in the datastore, and
// populates the provided resourceVersions with the latest k8s resource version
// for each.
func (syn *kubeSyncer) performSnapshot(versions *resourceVersions) (map[string][]model.KVPair, map[string]map[string]bool) {
	opts := metav1.ListOptions{}
	var snap map[string][]model.KVPair
	var keys map[string]map[string]bool

	// Loop until we successfully are able to accesss the API.
	for {
		// Initialize the values to return.
		snap = map[string][]model.KVPair{}
		keys = map[string]map[string]bool{}

		log.Infof("Needs resync: %+v", syn.needsResync)

		// Resync Namespaces only if needed.
		if syn.needsResync[KEY_NS] {
			log.Info("Syncing Namespaces")
			nsList, err := syn.kubeAPI.NamespaceList(opts)
			if err != nil {
				log.Warnf("Error syncing Namespaces, retrying: %s", err)
				time.Sleep(1 * time.Second)
				continue
			}
			log.Debug("Received Namespace List() response")

			// Ensure maps are initialized.
			snap[KEY_NS] = []model.KVPair{}
			keys[KEY_NS] = map[string]bool{}

			versions.namespaceVersion = nsList.ListMeta.ResourceVersion
			for _, ns := range nsList.Items {
				// The Syncer API expects a profile to be broken into its underlying
				// components - rules, tags, labels.
				profile, err := syn.converter.NamespaceToProfile(&ns)
				if err != nil {
					log.Panicf("%s", err)
				}
				rules, tags, labels := compat.ToTagsLabelsRules(profile)
				rules.Revision = profile.Revision
				tags.Revision = profile.Revision
				labels.Revision = profile.Revision

				snap[KEY_NS] = append(snap[KEY_NS], *rules, *tags, *labels)
				keys[KEY_NS][rules.Key.String()] = true
				keys[KEY_NS][tags.Key.String()] = true
				keys[KEY_NS][labels.Key.String()] = true
			}
		}

		// Resync NetworkPolicy only if needed.
		if syn.needsResync[KEY_NP] {
			log.Info("Syncing NetworkPolicy")
			npList, err := syn.kubeAPI.NetworkPolicyList()
			if err != nil {
				log.Warnf("Error querying NetworkPolicies during snapshot, retrying: %s", err)
				time.Sleep(1 * time.Second)
				continue
			}
			log.Debug("Received NetworkPolicy List() response")

			// Ensure maps are initialized.
			snap[KEY_NP] = []model.KVPair{}
			keys[KEY_NP] = map[string]bool{}

			versions.networkPolicyVersion = npList.ListMeta.ResourceVersion
			for _, np := range npList.Items {
				pol, _ := syn.converter.NetworkPolicyToPolicy(&np)
				snap[KEY_NP] = append(snap[KEY_NP], *pol)
				keys[KEY_NP][pol.Key.String()] = true
			}
		}

		// Resync GlobalNetworkPolicy only if needed.
		if syn.needsResync[KEY_GNP] {
			log.Info("Syncing GlobalNetworkPolicy")
			gnpList, resourceVersion, err := syn.kubeAPI.GlobalNetworkPolicyList()
			if err != nil {
				log.Warnf("Error querying GlobalNetworkPolicies during snapshot, retrying: %s", err)
				time.Sleep(1 * time.Second)
				continue
			}
			log.Debug("Received NetworkPolicy List() response")

			// Ensure maps are initialized.
			snap[KEY_GNP] = []model.KVPair{}
			keys[KEY_GNP] = map[string]bool{}

			versions.globalNetworkPolicyVersion = resourceVersion
			for _, p := range gnpList {
				snap[KEY_GNP] = append(snap[KEY_IP], *p)
				keys[KEY_GNP][p.Key.String()] = true
			}
		}

		// Resync Pods only if needed.
		if syn.needsResync[KEY_PO] {
			log.Info("Syncing Pods")
			poList, err := syn.kubeAPI.PodList("", opts)
			if err != nil {
				log.Warnf("Error querying Pods during snapshot, retrying: %s", err)
				time.Sleep(1 * time.Second)
				continue
			}
			log.Debug("Received Pod List() response")

			// Ensure maps are initialized.
			snap[KEY_PO] = []model.KVPair{}
			keys[KEY_PO] = map[string]bool{}

			versions.podVersion = poList.ListMeta.ResourceVersion
			for _, po := range poList.Items {
				// Ignore any updates for pods which are not ready / valid.
				if !syn.converter.isReadyCalicoPod(&po) {
					log.Debugf("Skipping pod %s/%s", po.ObjectMeta.Namespace, po.ObjectMeta.Name)
					continue
				}

				// Convert to a workload endpoint.
				wep, err := syn.converter.PodToWorkloadEndpoint(&po)
				if err != nil {
					log.WithError(err).Error("Failed to convert pod to workload endpoint")
					continue
				}
				snap[KEY_PO] = append(snap[KEY_PO], *wep)
				keys[KEY_PO][wep.Key.String()] = true
			}
		}

		// Resync GlobalFelixConfig only if needed.
		if syn.needsResync[KEY_GC] {
			log.Info("Syncing GlobalFelixConfig")
			confList, resourceVersion, err := syn.kubeAPI.GlobalFelixConfigList(model.GlobalConfigListOptions{})
			if err != nil {
				log.Warnf("Error querying GlobalFelixConfig during snapshot, retrying: %s", err)
				time.Sleep(1 * time.Second)
				continue
			}
			log.Debug("Received GlobalFelixConfig List() response")

			// Ensure maps are initialized.
			snap[KEY_GC] = []model.KVPair{}
			keys[KEY_GC] = map[string]bool{}

			versions.globalFelixConfigVersion = resourceVersion
			for _, c := range confList {
				snap[KEY_GC] = append(snap[KEY_GC], *c)
				keys[KEY_GC][c.Key.String()] = true
			}
		}

		// Resync HostConfig only if needed.
		if syn.needsResync[KEY_HC] {
			log.Info("Syncing HostConfig")
			hostConfList, err := syn.kubeAPI.HostConfigList(model.HostConfigListOptions{})
			if err != nil {
				log.Warnf("Error querying HostConfig during snapshot, retrying: %s", err)
				time.Sleep(1 * time.Second)
				continue
			}
			log.Debug("Received HostConfig List() response")

			// Ensure maps are initialized.
			snap[KEY_HC] = []model.KVPair{}
			keys[KEY_HC] = map[string]bool{}

			for _, h := range hostConfList {
				snap[KEY_HC] = append(snap[KEY_HC], *h)
				keys[KEY_HC][h.Key.String()] = true
			}
			// Special case: for other resources, we reset this flag at the same time that we
			// restart the watcher but HostConfig doesn't have its own watcher (and the Node watcher
			// that we piggy-back on may be disabled) so we pro-actively clear the flag here.
			syn.needsResync[KEY_HC] = false
		}

		// Resync IP Pools only if needed.
		if syn.needsResync[KEY_IP] {
			log.Info("Syncing IP Pools")
			poolList, resourceVersion, err := syn.kubeAPI.IPPoolList(model.IPPoolListOptions{})
			if err != nil {
				log.Warnf("Error querying IP Pools during snapshot, retrying: %s", err)
				time.Sleep(1 * time.Second)
				continue
			}
			log.Debug("Received IP Pools List() response")

			// Ensure maps are initialized.
			snap[KEY_IP] = []model.KVPair{}
			keys[KEY_IP] = map[string]bool{}

			versions.poolVersion = resourceVersion
			for _, p := range poolList {
				snap[KEY_IP] = append(snap[KEY_IP], *p)
				keys[KEY_IP][p.Key.String()] = true
			}
		}

		// Resync Nodes only if needed.
		if !syn.disableNodePoll && syn.needsResync[KEY_NO] {
			log.Info("Syncing Nodes")
			noList, err := syn.kubeAPI.NodeList(opts)
			if err != nil {
				log.Warnf("Error syncing Nodes, retrying: %s", err)
				time.Sleep(1 * time.Second)
				continue
			}
			log.Debug("Received Node List() response")

			// Ensure maps are initialized.
			snap[KEY_NO] = []model.KVPair{}
			keys[KEY_NO] = map[string]bool{}

			versions.nodeVersion = noList.ListMeta.ResourceVersion
			for _, no := range noList.Items {
				kvpHostIP, kvpIPIPAddr := splitNode(&no)
				log.WithFields(log.Fields{
					"kvpHostIP":   kvpHostIP,
					"kvpIPIPAddr": kvpIPIPAddr,
				}).Debug("Got node KVs.")
				snap[KEY_NO] = append(snap[KEY_NO], *kvpHostIP)
				keys[KEY_NO][kvpHostIP.Key.String()] = true
				snap[KEY_HC] = append(snap[KEY_HC], *kvpIPIPAddr)
				keys[KEY_HC][kvpIPIPAddr.Key.String()] = true
			}
		}

		// Include ready state always.
		ready, err := syn.kubeAPI.getReadyStatus(model.ReadyFlagKey{})
		if err != nil {
			log.Warnf("Error querying ready status during snapshot, retrying: %s", err)
			time.Sleep(1 * time.Second)
			continue
		}
		snap[KEY_RS] = []model.KVPair{*ready}
		keys[KEY_RS] = map[string]bool{ready.Key.String(): true}
		// There's no watcher for the ready state so we simply mark the resync as done.
		syn.needsResync[KEY_RS] = false

		log.Infof("Snapshot resourceVersions: %+v", versions)
		log.Debugf("Created snapshot: %+v", snap)
		return snap, keys
	}
}

// Returns whether this event triggers a full resync.
func (syn *kubeSyncer) eventNeedsResync(e watch.Event) bool {
	if e.Type == watch.Error {
		log.Warnf("Event requires resync: %+v", e)
		return true
	}
	return false
}

// Returns whether this event requires a watch restart, but
// not a full resync.
func (syn *kubeSyncer) eventRestartsWatch(e watch.Event, k string) bool {
	if e.Object == nil {
		log.Infof("Need to refresh %v watch: %+v", k, e)
		return true
	}
	return false
}

// Closes a specific watcher
func (syn *kubeSyncer) closeWatcher(k string) {
	w := syn.openWatchers[k]
	log.WithField("watcher", w).Debug("Closing old watcher.")
	w.Stop()
	delete(syn.openWatchers, k)
}

// Closes all watchers (iterates over map and calls closeWatcher)
func (syn *kubeSyncer) closeAllWatchers() {
	for _, w := range syn.openWatchers {
		log.WithField("watcher", w).Debug("Closing old watcher.")
		w.Stop()
	}
	syn.openWatchers = map[string]watch.Interface{}
}

func (syn *kubeSyncer) parseNamespaceEvent(e watch.Event) []model.KVPair {
	ns, ok := e.Object.(*k8sapi.Namespace)
	if !ok {
		log.Panicf("Invalid namespace event: %+v", e.Object)
	}

	// Convert the received Namespace into a profile KVPair.
	profile, err := syn.converter.NamespaceToProfile(ns)
	if err != nil {
		log.Panicf("%s", err)
	}
	rules, tags, labels := compat.ToTagsLabelsRules(profile)
	rules.Revision = profile.Revision
	tags.Revision = profile.Revision
	labels.Revision = profile.Revision

	// For deletes, we need to nil out the Value part of the KVPair.
	if e.Type == watch.Deleted {
		rules.Value = nil
		tags.Value = nil
		labels.Value = nil
	}

	// Return the updates.
	return []model.KVPair{*rules, *tags, *labels}
}

func splitNode(node *k8sapi.Node) (*model.KVPair, *model.KVPair) {
	kvp, err := resources.K8sNodeToCalico(node)
	if err != nil {
		log.WithError(err).Panic("Failed to convert k8s node to Calico node.")
	}

	kvpHostIp := &model.KVPair{
		Key:      model.HostIPKey{Hostname: node.Name},
		Revision: kvp.Revision,
	}
	caliNode := kvp.Value.(*model.Node)
	if caliNode.BGPIPv4Addr != nil {
		// Only set the value if it's non nil.  We want to avoid setting Value to
		// an interface containing a nil value instead of a nil interface.
		kvpHostIp.Value = caliNode.BGPIPv4Addr
	}

	kvpIPIPAddr, err := getTunIp(node)
	if err != nil || kvpIPIPAddr == nil {
		// If we failed to parse, err will be non-nil.  If it's missing, kvpIPIPAddr will be nil.
		// Either way, generate a delete.
		log.WithError(err).WithField("node", node.Name).Info(
			"Node has no (or invalid) pod CIDR. (Normal for a new node.)")
		kvpIPIPAddr = &model.KVPair{
			Key: model.HostConfigKey{
				Hostname: node.Name,
				Name:     "IpInIpTunnelAddr",
			},
			Value: nil,
		}
	}
	kvpIPIPAddr.Revision = kvp.Revision

	return kvpHostIp, kvpIPIPAddr
}

func (syn *kubeSyncer) parseNodeEvent(e watch.Event) (*model.KVPair, *model.KVPair) {
	node, ok := e.Object.(*k8sapi.Node)
	if !ok {
		log.Panicf("Invalid node event. Type: %s, Object: %+v", e.Type, e.Object)
	}

	kvpHostIp, kvpIPIPAddr := splitNode(node)

	if e.Type == watch.Deleted {
		kvpHostIp.Value = nil
		kvpIPIPAddr.Value = nil
	}

	return kvpHostIp, kvpIPIPAddr
}

// parsePodEvent returns a KVPair for the given event.  If the event isn't
// useful, parsePodEvent returns nil to indicate that there is nothing to do.
func (syn *kubeSyncer) parsePodEvent(e watch.Event) *model.KVPair {
	pod, ok := e.Object.(*k8sapi.Pod)
	if !ok {
		log.Panicf("Invalid pod event. Type: %s, Object: %+v", e.Type, e.Object)
	}

	switch e.Type {
	case watch.Deleted:
		// For deletes, the validity conditions are different.  We only care if the update
		// is not for a host-networked Pods, but don't care about IP / scheduled state.
		if syn.converter.isHostNetworked(pod) {
			log.WithField("pod", pod.Name).Debug("Pod is host networked.")
			log.Debugf("Skipping delete for pod %s/%s", pod.ObjectMeta.Namespace, pod.ObjectMeta.Name)
			return nil
		}
	default:
		// Ignore add/modify updates for Pods that shouldn't be shown in the Calico API.
		// e.g host networked Pods, or Pods that don't yet have an IP address.
		if !syn.converter.isReadyCalicoPod(pod) {
			log.Debugf("Skipping add/modify for pod %s/%s", pod.ObjectMeta.Namespace, pod.ObjectMeta.Name)
			return nil
		}
	}

	// Convert the received Pod into a KVPair.
	kvp, err := syn.converter.PodToWorkloadEndpoint(pod)
	if err != nil {
		// If we fail to parse, then ignore this update and emit a log.
		log.WithField("error", err).Error("Failed to parse Pod event")
		return nil
	}

	// We behave differently based on the event type.
	switch e.Type {
	case watch.Deleted:
		// For deletes, we need to nil out the Value part of the KVPair.
		log.Debugf("Delete for pod %s/%s", pod.ObjectMeta.Namespace, pod.ObjectMeta.Name)
		kvp.Value = nil
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
	kvp, err := syn.converter.NetworkPolicyToPolicy(np)
	if err != nil {
		log.Panicf("%s", err)
	}

	// For deletes, we need to nil out the Value part of the KVPair
	if e.Type == watch.Deleted {
		kvp.Value = nil
	}
	return kvp
}

func (syn *kubeSyncer) parseGlobalFelixConfigEvent(e watch.Event) *model.KVPair {
	return syn.parseCustomK8sResourceEvent(e, resources.GlobalFelixConfigConverter{}, "GlobalFelixConfig")
}

func (syn *kubeSyncer) parseGlobalNetworkPolicyEvent(e watch.Event) *model.KVPair {
	return syn.parseCustomK8sResourceEvent(e, resources.GlobalNetworkPolicyConverter{}, "GlobalNetworkPolicy")
}

func (syn *kubeSyncer) parseIPPoolEvent(e watch.Event) *model.KVPair {
	return syn.parseCustomK8sResourceEvent(e, resources.IPPoolConverter{}, "IPPool")
}

func (syn *kubeSyncer) parseCustomK8sResourceEvent(
	e watch.Event,
	converter resources.CustomK8sResourceConverter,
	resourceType string,
) *model.KVPair {
	// First, check the event type.
	logContext := log.WithFields(log.Fields{
		"ResourceType": resourceType,
		"EventType":    e.Type,
	})
	crd, ok := e.Object.(resources.CustomK8sResource)
	if !ok {
		logContext.Panicf("Invalid custom resource event. Object: %+v", e.Object)
	}

	logContext = logContext.WithField("Name", crd.GetObjectMeta().GetName())
	logContext.Debug("Parsing watch event")

	// Convert the received resource into a KVPair.
	kvp, err := converter.ToKVPair(crd)
	if err == nil {
		// For deletes, we need to nil out the Value part of the KVPair
		if e.Type == watch.Deleted {
			kvp.Value = nil
		}
		return kvp
	}

	// Error converting resource.  Attempt to determine the Key and treat as
	// a delete (Value will be nil).
	logContext.WithError(err).Info("Failed to parse resource - may treat as delete")
	key, err := converter.NameToKey(crd.GetObjectMeta().GetName())
	if err == nil {
		logContext.WithField("Key", key).WithError(err).Error("Failed to parse resource, treating as deleted")
		return &model.KVPair{
			Key: key,
		}
	}

	// Could not determine the Key from the resource name - all we can do is
	// ignore this event.
	logContext.WithError(err).Error("Failed to parse resource spec and metadata, ignoring event")
	return nil
}
