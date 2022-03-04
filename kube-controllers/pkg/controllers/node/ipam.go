// Copyright (c) 2019,2021 Tigera, Inc. All rights reserved.
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

package node

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"k8s.io/client-go/tools/cache"

	"github.com/projectcalico/calico/kube-controllers/pkg/controllers/flannelmigration"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/workqueue"

	"github.com/projectcalico/calico/kube-controllers/pkg/config"
	libapiv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	bapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/conversion"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

var (
	ipsGauge      *prometheus.GaugeVec
	blocksGauge   *prometheus.GaugeVec
	borrowedGauge *prometheus.GaugeVec
)

const (
	// Length of the update channel and the max items to handle in a batch
	// before kicking off a sync.
	batchUpdateSize = 1000
)

func init() {
	// Total IP allocations.
	ipsGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ipam_allocations_per_node",
		Help: "Number of IPs allocated",
	}, []string{"node"})
	prometheus.MustRegister(ipsGauge)

	// Borrowed IPs.
	borrowedGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ipam_allocations_borrowed_per_node",
		Help: "Number of allocated IPs that are from non-affine blocks.",
	}, []string{"node"})
	prometheus.MustRegister(borrowedGauge)

	// Blocks per-node.
	blocksGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ipam_blocks_per_node",
		Help: "Number of blocks in IPAM",
	}, []string{"node"})
	prometheus.MustRegister(blocksGauge)
}

func NewIPAMController(cfg config.NodeControllerConfig, c client.Interface, cs kubernetes.Interface, ni cache.Indexer) *ipamController {
	return &ipamController{
		client:    c,
		clientset: cs,
		config:    cfg,
		rl:        workqueue.DefaultControllerRateLimiter(),

		syncChan: make(chan interface{}, 1),

		nodeIndexer: ni,

		// Channel for updates

		// Buffered channels for potentially bursty channels.
		syncerUpdates: make(chan interface{}, batchUpdateSize),
		podUpdate:     make(chan podUpdate, batchUpdateSize),

		allBlocks:                   make(map[string]model.KVPair),
		allocationsByBlock:          make(map[string]map[string]*allocation),
		allocationsByNode:           make(map[string]map[string]*allocation),
		handleTracker:               newHandleTracker(),
		kubernetesNodesByCalicoName: make(map[string]string),
		confirmedLeaks:              make(map[string]*allocation),
		podCache:                    make(map[string]*v1.Pod),
		nodesByBlock:                make(map[string]string),
		blocksByNode:                make(map[string]map[string]bool),
		emptyBlocks:                 make(map[string]string),
		datastoreReady:              true,

		// For unit testing purposes.
		pauseRequestChannel: make(chan pauseRequest),
	}
}

type ipamController struct {
	rl          workqueue.RateLimiter
	client      client.Interface
	clientset   kubernetes.Interface
	nodeIndexer cache.Indexer
	config      config.NodeControllerConfig

	syncStatus bapi.SyncStatus

	// kubernetesNodesByCalicoName is a local cache that maps Calico nodes to their Kubernetes node name.
	kubernetesNodesByCalicoName map[string]string

	// syncChan triggers processing in response to an update.
	syncChan chan interface{}

	// For update / deletion events from the syncer.
	syncerUpdates chan interface{}

	podUpdate chan podUpdate

	// Raw block storage.
	allBlocks map[string]model.KVPair

	// Store allocations broken out from the raw blocks by their handle.
	allocationsByBlock map[string]map[string]*allocation
	allocationsByNode  map[string]map[string]*allocation
	handleTracker      *handleTracker
	nodesByBlock       map[string]string
	blocksByNode       map[string]map[string]bool
	emptyBlocks        map[string]string
	confirmedLeaks     map[string]*allocation

	// Cache pods to avoid unnecessary API queries.
	podCache map[string]*v1.Pod

	// Cache datastoreReady to avoid too much API queries.
	datastoreReady bool

	// For unit testing purposes.
	pauseRequestChannel chan pauseRequest
}

func (c *ipamController) Start(stop chan struct{}) {
	go c.acceptScheduleRequests(stop)
}

func (c *ipamController) RegisterWith(f *DataFeed) {
	f.RegisterForNotification(model.BlockKey{}, c.onUpdate)
	f.RegisterForNotification(model.ResourceKey{}, c.onUpdate)
	f.RegisterForSyncStatus(c.onStatusUpdate)
}

func (c *ipamController) onStatusUpdate(s bapi.SyncStatus) {
	c.syncerUpdates <- s
}

func (c *ipamController) onUpdate(update bapi.Update) {
	switch update.KVPair.Key.(type) {
	case model.ResourceKey:
		switch update.KVPair.Key.(model.ResourceKey).Kind {
		case libapiv3.KindNode, apiv3.KindClusterInformation:
			c.syncerUpdates <- update.KVPair
		}
	case model.BlockKey:
		c.syncerUpdates <- update.KVPair
	default:
		log.Warnf("Unexpected kind received over syncer: %s", update.KVPair.Key)
	}
}

func (c *ipamController) OnKubernetesNodeDeleted() {
	// When a Kubernetes node is deleted, trigger a sync.
	log.Debug("Kubernetes node deletion event")
	kick(c.syncChan)
}

func (c *ipamController) OnKubernetesPodUpdated(key string, p *v1.Pod) {
	c.podUpdate <- podUpdate{key: key, pod: p}
}

func (c *ipamController) OnKubernetesPodDeleted(key string) {
	c.podUpdate <- podUpdate{key: key}
}

// acceptScheduleRequests is the main worker routine of the IPAM controller. It monitors
// the updates channel and triggers syncs.
func (c *ipamController) acceptScheduleRequests(stopCh <-chan struct{}) {
	// Periodic sync ticker.
	period := 5 * time.Minute
	if c.config.LeakGracePeriod != nil {
		if c.config.LeakGracePeriod.Duration > 0 {
			period = c.config.LeakGracePeriod.Duration / 2
		}
	}
	t := time.NewTicker(period)
	log.Infof("Will run periodic IPAM sync every %s", period)
	for {
		// Wait until something wakes us up, or we are stopped
		select {
		case pu := <-c.podUpdate:
			c.handlePodUpdate(pu)

			// It's possible we get a rapid series of updates in a row. Use
			// a consolidation loop to handle "batches" of updates before triggering a sync.
			var i int
			for i = 1; i < batchUpdateSize; i++ {
				select {
				case pu = <-c.podUpdate:
					c.handlePodUpdate(pu)
				default:
					break
				}
			}
		case upd := <-c.syncerUpdates:
			c.handleUpdate(upd)

			// It's possible we get a rapid series of updates in a row. Use
			// a consolidation loop to handle "batches" of updates before triggering a sync.
			var i int
		consolidationLoop:
			for i = 1; i < batchUpdateSize; i++ {
				select {
				case upd = <-c.syncerUpdates:
					c.handleUpdate(upd)
				default:
					break consolidationLoop
				}
			}

			// Kick the sync channel to trigger a resync after handling a batch.
			log.WithField("batchSize", i).Debug("Triggering sync after batch of updates")
			kick(c.syncChan)
		case <-t.C:
			// Periodic IPAM sync.
			log.Debug("Periodic IPAM sync")
			err := c.syncIPAM()
			if err != nil {
				log.WithError(err).Warn("Periodic IPAM sync failed")
			}
			log.Debug("Periodic IPAM sync complete")
		case <-c.syncChan:
			// Triggered IPAM sync.
			log.Debug("Triggered IPAM sync")
			err := c.syncIPAM()
			if err != nil {
				// We can kick ourselves on error for a retry. We have rate limiting
				// built in to the cleanup code.
				log.WithError(err).Warn("error syncing IPAM data")
				kick(c.syncChan)
			}

			// Update prometheus metrics.
			c.updateMetrics()
			log.Debug("Triggered IPAM sync complete")
		case req := <-c.pauseRequestChannel:
			// For testing purposes - allow the tests to pause the main processing loop.
			log.Warn("Pausing main loop so tests can read state")
			req.pauseConfirmed <- struct{}{}
			<-req.doneChan
		case <-stopCh:
			return
		}
	}
}

// handleUpdate fans out proper handling of the update depending on the
// information in the update.
func (c *ipamController) handleUpdate(upd interface{}) {
	switch upd := upd.(type) {
	case bapi.SyncStatus:
		c.syncStatus = upd
		switch upd {
		case bapi.InSync:
			log.WithField("status", upd).Info("Syncer is InSync, kicking sync channel")
			kick(c.syncChan)
		}
		return
	case model.KVPair:
		switch upd.Key.(type) {
		case model.ResourceKey:
			switch upd.Key.(model.ResourceKey).Kind {
			case libapiv3.KindNode:
				c.handleNodeUpdate(upd)
				return
			case apiv3.KindClusterInformation:
				c.handleClusterInformationUpdate(upd)
				return
			}
		case model.BlockKey:
			c.handleBlockUpdate(upd)
			return
		}
	}
	log.WithField("update", upd).Warn("Unexpected update received")
}

// handleBlockUpdate wraps up the logic to execute when receiving a block update.
func (c *ipamController) handleBlockUpdate(kvp model.KVPair) {
	if kvp.Value != nil {
		c.onBlockUpdated(kvp)
	} else {
		c.onBlockDeleted(kvp.Key.(model.BlockKey))
	}
}

// handleNodeUpdate wraps up the logic to execute when receiving a node update.
func (c *ipamController) handleNodeUpdate(kvp model.KVPair) {
	if kvp.Value != nil {
		n := kvp.Value.(*libapiv3.Node)
		kn, err := getK8sNodeName(*n)
		if err != nil {
			log.WithError(err).Info("Unable to get corresponding k8s node name, skipping")

			// It's possible that a previous version of this node had an orchRef and so was added to the
			// map. If so, we need to remove it.
			if current, ok := c.kubernetesNodesByCalicoName[n.Name]; ok {
				log.Warnf("Update mapping calico node -> k8s node. %s -> %s (previously %s)", n.Name, kn, current)
				delete(c.kubernetesNodesByCalicoName, n.Name)
			}
		} else if kn != "" {
			if current, ok := c.kubernetesNodesByCalicoName[n.Name]; !ok {
				log.Debugf("Add mapping calico node -> k8s node. %s -> %s", n.Name, kn)
				c.kubernetesNodesByCalicoName[n.Name] = kn
			} else if current != kn {
				log.Warnf("Update mapping calico node -> k8s node. %s -> %s (previously %s)", n.Name, kn, current)
				c.kubernetesNodesByCalicoName[n.Name] = kn
			}
			// No change.
		}
	} else {
		cnode := kvp.Key.(model.ResourceKey).Name
		if _, ok := c.kubernetesNodesByCalicoName[cnode]; ok {
			log.Debugf("Remove mapping for calico node %s", cnode)
			delete(c.kubernetesNodesByCalicoName, cnode)
		}
	}
}

// handleClusterInformationUpdate wraps the logic to execute when receiving a clusterinformation update.
func (c *ipamController) handleClusterInformationUpdate(kvp model.KVPair) {
	if kvp.Value != nil {
		ci := kvp.Value.(*apiv3.ClusterInformation)
		if ci.Spec.DatastoreReady != nil {
			c.datastoreReady = *ci.Spec.DatastoreReady
		}
	} else {
		c.datastoreReady = false
	}
}

// handlePodUpdate wraps up the logic to execute when receiving a pod update.
func (c *ipamController) handlePodUpdate(pu podUpdate) {
	if pu.pod != nil {
		c.podCache[pu.key] = pu.pod
	} else {
		delete(c.podCache, pu.key)
	}
}

func (c *ipamController) onBlockUpdated(kvp model.KVPair) {
	blockCIDR := kvp.Key.(model.BlockKey).CIDR.String()
	log.WithField("block", blockCIDR).Debug("Received block update")
	b := kvp.Value.(*model.AllocationBlock)

	// Include affinity if it exists. We want to track nodes even
	// if there are no IPs actually assigned to that node so that we can
	// release their affinity if needed.
	var n string
	if b.Affinity != nil {
		if strings.HasPrefix(*b.Affinity, "host:") {
			n = strings.TrimPrefix(*b.Affinity, "host:")
			c.nodesByBlock[blockCIDR] = n
			if _, ok := c.blocksByNode[n]; !ok {
				c.blocksByNode[n] = map[string]bool{}
			}
			c.blocksByNode[n][blockCIDR] = true
		}
	} else {
		// Affinity may have been removed.
		if n, ok := c.nodesByBlock[blockCIDR]; ok {
			delete(c.nodesByBlock, blockCIDR)
			delete(c.blocksByNode[n], blockCIDR)
		}
	}

	// Update allocations contributed from this block.
	numAllocationsInBlock := 0
	currentAllocations := map[string]bool{}
	for ord, idx := range b.Allocations {
		if idx == nil {
			// Not allocated.
			continue
		}
		numAllocationsInBlock++
		attr := b.Attributes[*idx]

		// If there is no handle, then skip this IP. We need the handle
		// in order to release the IP below.
		if attr.AttrPrimary == nil {
			continue
		}
		handle := *attr.AttrPrimary

		alloc := allocation{
			ip:             ordinalToIP(b, ord).String(),
			handle:         handle,
			attrs:          attr.AttrSecondary,
			sequenceNumber: b.GetSequenceNumberForOrdinal(ord),
		}

		currentAllocations[alloc.id()] = true

		// Check if we already know about this allocation.
		if _, ok := c.allocationsByBlock[blockCIDR][alloc.id()]; ok {
			continue
		}

		// This is a new allocation.
		if _, ok := c.allocationsByBlock[blockCIDR]; !ok {
			c.allocationsByBlock[blockCIDR] = map[string]*allocation{}
		}
		c.allocationsByBlock[blockCIDR][alloc.id()] = &alloc

		// Update the allocations-by-node view.
		if node := alloc.node(); node != "" {
			if _, ok := c.allocationsByNode[node]; !ok {
				c.allocationsByNode[node] = map[string]*allocation{}
			}
			c.allocationsByNode[node][alloc.id()] = &alloc
		}
		c.handleTracker.setAllocation(&alloc)
		log.WithFields(alloc.fields()).Debug("New IP allocation")
	}

	// If the block is empty, mark it as such. We'll check if it needs to be
	// cleaned up in the sync loop.
	delete(c.emptyBlocks, blockCIDR)
	if n != "" && numAllocationsInBlock == 0 {
		c.emptyBlocks[blockCIDR] = n
	}

	// Remove any previously assigned allocations that have since been released.
	for id, alloc := range c.allocationsByBlock[blockCIDR] {
		if _, ok := currentAllocations[id]; !ok {
			// Needs release.
			c.handleTracker.removeAllocation(alloc)
			delete(c.allocationsByBlock[blockCIDR], id)

			// Also remove from the node view.
			node := alloc.node()
			if node != "" {
				delete(c.allocationsByNode[node], id)
			}
			if len(c.allocationsByNode[node]) == 0 {
				delete(c.allocationsByNode, node)
			}

			// And to be safe, remove from confirmed leaks just in case.
			delete(c.confirmedLeaks, id)
		}
	}

	// Finally, update the raw storage.
	c.allBlocks[blockCIDR] = kvp
}

func (c *ipamController) onBlockDeleted(key model.BlockKey) {
	blockCIDR := key.CIDR.String()
	log.WithField("block", blockCIDR).Info("Received block delete")

	// Remove allocations that were contributed by this block.
	allocations := c.allocationsByBlock[blockCIDR]
	for id, alloc := range allocations {
		node := alloc.node()
		if node != "" {
			delete(c.allocationsByNode[node], id)
		}
		if len(c.allocationsByNode[node]) == 0 {
			delete(c.allocationsByNode, node)
		}
	}
	delete(c.allocationsByBlock, blockCIDR)

	// Remove from raw block storage.
	if n := c.nodesByBlock[blockCIDR]; n != "" {
		// The block was assigned to a node, make sure to update internal cache.
		delete(c.blocksByNode[n], blockCIDR)
	}
	delete(c.allBlocks, blockCIDR)
	delete(c.nodesByBlock, blockCIDR)
	delete(c.emptyBlocks, blockCIDR)
}

func (c *ipamController) updateMetrics() {
	log.Debug("Gathering latest IPAM state for metrics")

	// Keep track of various counts so that we can report them as metrics.
	blocksByNode := map[string]int{}
	borrowedIPsByNode := map[string]int{}

	// Iterate blocks to determine the correct metric values.
	for _, kvp := range c.allBlocks {
		b := kvp.Value.(*model.AllocationBlock)
		if b.Affinity != nil {
			n := strings.TrimPrefix(*b.Affinity, "host:")
			blocksByNode[n]++
		} else {
			// Count blocks with no affinity as a pseudo-node.
			blocksByNode["no_affinity"]++
		}

		// Go through each IPAM allocation, check its attributes for the node it is assigned to.
		for _, idx := range b.Allocations {
			if idx == nil {
				// Not allocated.
				continue
			}
			attr := b.Attributes[*idx]

			// Track nodes based on IP allocations.
			if node, ok := attr.AttrSecondary[ipam.AttributeNode]; ok {
				// Update metrics maps with this allocation.
				if b.Affinity == nil || node != strings.TrimPrefix(*b.Affinity, "host:") {
					// If the allocations node doesn't match the block's, then this is borrowed.
					borrowedIPsByNode[node]++
				}
			}
		}
	}

	// Update prometheus metrics.
	ipsGauge.Reset()
	for node, allocations := range c.allocationsByNode {
		ipsGauge.WithLabelValues(node).Set(float64(len(allocations)))
	}
	blocksGauge.Reset()
	for node, num := range blocksByNode {
		blocksGauge.WithLabelValues(node).Set(float64(num))
	}
	borrowedGauge.Reset()
	for node, num := range borrowedIPsByNode {
		borrowedGauge.WithLabelValues(node).Set(float64(num))
	}
	log.Debug("IPAM metrics updated")
}

// checkEmptyBlocks looks at known empty blocks, and releases their affinity
// if appropriate. A block is a candidate for having its affinity released if:
// - The block is empty.
// - The block's node has at least one other affine block.
// - The other blocks on the node are not at capacity.
// - The node is not currently undergoing a migration from Flannel
func (c *ipamController) checkEmptyBlocks() error {
	for blockCIDR, node := range c.emptyBlocks {
		logc := log.WithFields(log.Fields{"blockCIDR": blockCIDR, "node": node})
		nodeBlocks := c.blocksByNode[node]
		if len(nodeBlocks) <= 1 {
			continue
		}

		// The node has more than one block. Check that the other blocks allocated to this node
		// are not at capacity. We only release blocks when there's room in the other affine blocks,
		// otherwise the next IP allocation will just assign a new block to this node anyway.
		numAddressesAvailableOnNode := 0
		for b := range nodeBlocks {
			if b == blockCIDR {
				// Skip the known empty block.
				continue
			}

			// Sum the number of unallocated addresses across the other blocks.
			kvp := c.allBlocks[b]
			numAddressesAvailableOnNode += len(kvp.Value.(*model.AllocationBlock).Unallocated)
		}

		// Make sure there are some addresses available before releasing.
		if numAddressesAvailableOnNode < 3 {
			logc.Debug("Block is still needed, skip release")
			continue
		}

		// During a Flannel migration, we can only migrate blocks affined to nodes that have already undergone the migration
		migrating, err := c.nodeIsBeingMigrated(node)
		if err != nil {
			logc.WithError(err).Warn("Failed to check if node is being migrated from Flannel, skipping affinity release")
			continue
		}
		if migrating {
			logc.Info("Node affined to block is currently undergoing a migration from Flannel, skipping affinity release")
			continue
		}

		// Find the actual block object.
		block, ok := c.allBlocks[blockCIDR]
		if !ok {
			logc.Warn("Couldn't find empty block in cache, skipping affinity release")
			continue
		}

		// We can release the empty one.
		logc.Infof("Releasing affinity for empty block (node has %d total blocks)", len(nodeBlocks))
		err = c.client.IPAM().ReleaseBlockAffinity(context.TODO(), block.Value.(*model.AllocationBlock), true)
		if err != nil {
			logc.WithError(err).Warn("unable or unwilling to release affinity for block")
			continue
		}

		// Update internal state. We released affinity on an empty block, and so
		// it will have been deleted. It's important that we update blocksByNode here
		// in case there are other empty blocks allocated to the node so that we don't
		// accidentally release all of the node's blocks.
		delete(c.emptyBlocks, blockCIDR)
		delete(c.blocksByNode[node], blockCIDR)
		delete(c.nodesByBlock, blockCIDR)
		delete(c.allBlocks, blockCIDR)
	}
	return nil
}

// checkAllocations scans Calico IPAM and determines if any IPs appear to be leaks, and if any nodes should have their
// block affinities released.
//
// An IP allocation is a candidate for GC when:
// - The referenced pod does not exist in the k8s API.
// - The referenced pod exists, but has a mismatched IP.
//
// An IP allocation is confirmed for GC when:
// - It has been a leak candidate for >= the grace period.
// - It is a leak candidate and it's node has been deleted.
//
// A node's affinities should be released when:
// - The node no longer exists in the Kubernetes API, AND
// - There are no longer any IP allocations on the node, OR
// - The remaining IP allocations on the node are all determined to be leaked IP addresses.
// TODO: We're effectively iterating every allocation in the cluster on every execution. Can we optimize? Or at least rate-limit?
func (c *ipamController) checkAllocations() ([]string, error) {
	// For each node present in IPAM, if it doesn't exist in the Kubernetes API then we
	// should consider it a candidate for cleanup.
	nodesAndAllocations := map[string]map[string]*allocation{}
	for _, node := range c.nodesByBlock {
		// For each affine block, add an entry. This makes sure we consider them even
		// if they have no allocations.
		nodesAndAllocations[node] = nil
	}
	for node, allocations := range c.allocationsByNode {
		// For each allocation, add an entry. This make sure we consider them even
		// if the node has no affine blocks.
		nodesAndAllocations[node] = allocations
	}
	nodesToRelease := []string{}
	for cnode, allocations := range nodesAndAllocations {
		// Lookup the corresponding Kubernetes node for each Calico node we found in IPAM.
		// In KDD mode, these are identical. However, in etcd mode its possible that the Calico node has a
		// different name from the Kubernetes node.
		// In KDD mode, if the Node has been deleted from the Kubernetes API, this may be an empty string.
		knode, err := c.kubernetesNodeForCalico(cnode)
		if err != nil {
			if _, ok := err.(*ErrorNotKubernetes); !ok {
				log.Debug("Skipping non-kubernetes node")
			} else {
				log.WithError(err).Warnf("Failed to lookup corresponding node, skipping %s", cnode)
			}
			continue
		}
		logc := log.WithFields(log.Fields{"calicoNode": cnode, "k8sNode": knode})

		// If we found a corresponding k8s node name, check to make sure it is gone. If we
		// found no corresponding node, then we're good to clean up any allocations.
		// We'll check each allocation to make sure it comes from Kubernetes (or is a tunnel address)
		// before cleaning it up below.
		kubernetesNodeExists := false
		if knode != "" && c.nodeExists(knode) {
			logc.Debug("Node still exists")
			kubernetesNodeExists = true
		}
		logc.Debug("Checking node")

		// Tunnel addresses are special - they should only be marked as a leak if the node itself
		// is deleted, and there are no other valid allocations on the node. Keep track of them
		// in this slice so we can mark them for GC when we decide if the node should be cleaned up
		// or not.
		tunnelAddresses := []*allocation{}

		// To increase our confidence, go through each IP address and
		// check to see if the pod it references exists. If all the pods on that node are gone,
		// we can delete it. If any pod still exists, we skip this node. We want to be
		// extra sure that the node is gone before we clean it up.
		canDelete := true
		for _, a := range allocations {
			// Set the Kubernetes node field now that we know the kubernetes node name
			// for this allocation.
			a.knode = knode

			logc = log.WithFields(a.fields())
			if a.isWindowsReserved() {
				// Windows reserved IPs don't need garbage collection. They get released automatically when
				// the block is released.
				logc.Debug("Skipping Windows reserved IP address")
				continue
			}

			if !a.isPodIP() && !a.isTunnelAddress() {
				// Skip any allocations which are not either a Kubernetes pod, or a node's
				// IPIP, VXLAN or Wireguard address. In practice, we don't expect these, but they might exist.
				// When they do, they will need to be released outside of this controller in order for
				// the block to be cleaned up.
				logc.Info("IP allocation on node is from an unknown source. Will be unable to cleanup block until it is removed.")
				canDelete = false
				continue
			}

			if a.isTunnelAddress() {
				// Handle tunnel addresses below.
				tunnelAddresses = append(tunnelAddresses, a)
				continue
			}

			if c.allocationIsValid(a, true) {
				// Allocation is still valid. We can't cleanup the node yet, even
				// if it appears to be deleted, because the allocation's validity breaks
				// our confidence.
				canDelete = false
				a.markValid()
				continue
			} else if !kubernetesNodeExists {
				// The allocation is NOT valid, we can skip the candidacy stage.
				// We know this with confidence because:
				// - The node the allocation belongs to no longer exists.
				// - There pod owning this allocation no longer exists.
				a.markConfirmedLeak()
			} else if c.config.LeakGracePeriod != nil {
				// The allocation is NOT valid, but the Kubernetes node still exists, so our confidence is lower.
				// Mark as a candidate leak. If this state remains, it will switch
				// to confirmed after the grace period.
				a.markLeak(c.config.LeakGracePeriod.Duration)
			}

			if a.isConfirmedLeak() {
				// If the address is determined to be a confirmed leak, add it to the index.
				c.confirmedLeaks[a.id()] = a
			} else if _, ok := c.confirmedLeaks[a.id()]; ok {
				// Address used to be a leak, but is no longer.
				logc.Info("Leaked IP has been resurrected")
				delete(c.confirmedLeaks, a.id())
			}
		}

		if !kubernetesNodeExists {
			if !canDelete {
				// There are still valid allocations on the node.
				logc.Infof("Can't cleanup node yet - IPs still in use on this node")
				continue
			}

			// Mark the node's tunnel addresses for GC.
			for _, a := range tunnelAddresses {
				a.markConfirmedLeak()
				c.confirmedLeaks[a.id()] = a
			}

			// The node is ready have its IPAM affinities released. It exists in Calico IPAM, but
			// not in the Kubernetes API. Additionally, we've checked that there are no
			// outstanding valid allocations on the node.
			nodesToRelease = append(nodesToRelease, cnode)
		}
	}
	return nodesToRelease, nil
}

// allocationIsValid returns true if the allocation is still in use, and false if the allocation
// appears to be leaked.
func (c *ipamController) allocationIsValid(a *allocation, preferCache bool) bool {
	ns := a.attrs[ipam.AttributeNamespace]
	pod := a.attrs[ipam.AttributePod]
	logc := log.WithFields(a.fields())

	if a.isTunnelAddress() {
		// Tunnel addresses are only valid if the hosting node still exists.
		return a.knode != ""
	}

	if ns == "" || pod == "" {
		// Allocation is either not a pod address, or it pre-dates the use of these
		// attributes. Assume it's a valid allocation since we can't perform our
		// confidence checks below.
		logc.Debug("IP allocation is missing metadata, cannot confirm or deny validity. Assume valid.")
		return true
	}

	// Query the pod referenced by this allocation. If preferCache is true, then check the cache first.
	var err error
	var p *v1.Pod
	key := fmt.Sprintf("%s/%s", ns, pod)
	if preferCache {
		logc.Debug("Checking cache for pod")
		p = c.podCache[key]
	}
	if p == nil {
		logc.Debug("Querying Kubernetes API for pod")
		p, err = c.clientset.CoreV1().Pods(ns).Get(context.Background(), pod, metav1.GetOptions{})
		if err != nil {
			if !errors.IsNotFound(err) {
				log.WithError(err).Warn("Failed to query pod, assume it exists and allocation is valid")
				return true
			}
			// Pod not found. Assume this is a leak.
			logc.Debug("Pod not found, assume it's a leak")
			return false
		}

		// Proactively keep our cache up-to-date.
		c.podCache[key] = p
	}

	// The pod exists - check if it is still on the original node.
	// TODO: Do we need this check?
	if p.Spec.NodeName != "" && a.knode != "" && p.Spec.NodeName != a.knode {
		// If the pod has been rescheduled to a new node, we can treat the old allocation as
		// gone and clean it up.
		fields := log.Fields{"old": a.knode, "new": p.Spec.NodeName}
		logc.WithFields(fields).Info("Pod rescheduled on new node. Allocation no longer valid")
		return false
	}

	// Check to see if the pod actually has the IP in question. Gate based on the presence of the
	// status field, which is populated by kubelet.
	if p.Status.PodIP == "" || len(p.Status.PodIPs) == 0 {
		// The pod hasn't received an IP yet.
		log.Debugf("Pod IP has not yet been reported, consider allocation valid")
		return true
	}

	// Convert the pod to a workload endpoint. This takes advantage of the IP
	// gathering logic already implemented in the converter, and handles exceptional cases like
	// additional WEPs attached to Multus networks.
	conv := conversion.NewConverter()
	kvps, err := conv.PodToWorkloadEndpoints(p)
	if err != nil {
		log.WithError(err).Warn("Failed to parse pod into WEP, consider allocation valid.")
		return true
	}

	for _, kvp := range kvps {
		if kvp == nil || kvp.Value == nil {
			// Shouldn't hit this branch, but better safe than sorry.
			logc.Warn("Pod converted to nil WorkloadEndpoint")
			continue
		}
		wep := kvp.Value.(*libapiv3.WorkloadEndpoint)
		for _, nw := range wep.Spec.IPNetworks {
			ip, _, err := net.ParseCIDR(nw)
			if err != nil {
				logc.WithError(err).Error("Failed to parse WEP IP, assume allocation is valid")
				return true
			}
			allocIP := net.ParseIP(a.ip)
			if allocIP == nil {
				logc.WithField("ip", a.ip).Error("Failed to parse IP, assume allocation is valid")
				return true
			}

			if allocIP.Equal(ip) {
				// Found a match.
				logc.Debugf("Pod has matching IP, allocation is valid")
				return true
			}
		}
	}

	logc.Debugf("Allocated IP no longer in-use by pod")
	return false
}

func (c *ipamController) syncIPAM() error {
	if !c.datastoreReady {
		log.Warn("datastore is locked, skipping ipam sync")
		return nil
	}

	// Skip if not InSync yet.
	if c.syncStatus != bapi.InSync {
		log.WithField("status", c.syncStatus).Debug("Have not yet received InSync notification, skipping IPAM sync.")
		return nil
	}

	// Check if any nodes in IPAM need to have affinities released.
	log.Debug("Synchronizing IPAM data")
	nodesToRelease, err := c.checkAllocations()
	if err != nil {
		return err
	}

	// Release all confirmed leaks.
	err = c.garbageCollectIPs()
	if err != nil {
		return err
	}

	// Check if any empty blocks should be removed.
	err = c.checkEmptyBlocks()
	if err != nil {
		return err
	}

	// Delete any nodes that we determined can be removed above.
	var storedErr error
	for _, cnode := range nodesToRelease {
		logc := log.WithField("node", cnode)

		// Potentially rate limit node cleanup.
		time.Sleep(c.rl.When(RateLimitCalicoDelete))
		logc.Info("Cleaning up IPAM resources for deleted node")
		if err := c.cleanupNode(cnode); err != nil {
			// Store the error, but continue. Storing the error ensures we'll retry.
			logc.WithError(err).Warnf("Error cleaning up node")
			storedErr = err
			continue
		}
		c.rl.Forget(RateLimitCalicoDelete)
	}
	if storedErr != nil {
		return storedErr
	}

	log.Debug("IPAM sync completed")
	return nil
}

// garbageCollectIPs checks all known allocations and garbage collects any confirmed leaks.
func (c *ipamController) garbageCollectIPs() error {
	for id, a := range c.confirmedLeaks {
		logc := log.WithFields(a.fields())

		// Final check that the allocation is leaked, this time ignoring our cache
		// to make sure we're working with up-to-date information.
		if c.allocationIsValid(a, false) {
			logc.Info("Leaked IP has been resurrected after querying latest state")
			delete(c.confirmedLeaks, id)
			a.markValid()
			continue
		}

		// Ensure that all of the IPs with this handle are in fact leaked.
		if !c.handleTracker.isConfirmedLeak(a.handle) {
			logc.Debug("Some IPs with this handle are still valid, skipping")
			continue
		}

		logc.Info("Garbage collecting leaked IP address")
		unallocated, err := c.client.IPAM().ReleaseIPs(context.TODO(), a.ReleaseOptions())
		if _, ok := err.(cerrors.ErrorResourceDoesNotExist); ok || len(unallocated) == 1 {
			logc.WithField("handle", a.handle).Debug("IP already released")
			continue
		} else if err != nil {
			logc.WithError(err).WithField("handle", a.handle).Warning("Failed to release leaked IP")
			return err
		}

		// No longer a leak. Remove it from the map here so we're not dependent on receiving
		// the update from the syncer (which we will do eventually, this is just cleaner).
		delete(c.allocationsByNode[a.node()], id)
		if len(c.allocationsByNode[a.node()]) == 0 {
			delete(c.allocationsByNode, a.node())
		}
		delete(c.confirmedLeaks, id)
	}
	return nil
}

func (c *ipamController) cleanupNode(cnode string) error {
	// At this point, we've verified that the node isn't in Kubernetes and that all the allocations
	// are tied to pods which don't exist any more. Clean up any allocations which may still be laying around.
	logc := log.WithField("calicoNode", cnode)

	// Release the affinities for this node, requiring that the blocks are empty.
	if err := c.client.IPAM().ReleaseHostAffinities(context.TODO(), cnode, true); err != nil {
		logc.WithError(err).Errorf("Failed to release block affinities for node")
		return err
	}

	logc.Debug("Released all affinities for node")
	return nil
}

// nodeExists returns true if the given node still exists in the Kubernetes API.
func (c *ipamController) nodeExists(knode string) bool {
	_, err := c.clientset.CoreV1().Nodes().Get(context.Background(), knode, metav1.GetOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			return false
		}
		log.WithError(err).Warn("Failed to query node, assume it exists")
	}
	return true
}

// nodeIsBeingMigrated looks up a Kubernetes node for a Calico node and checks,
// if it is marked by the flannel-migration controller to undergo migration.
func (c *ipamController) nodeIsBeingMigrated(name string) (bool, error) {
	// Find the Kubernetes node referenced by the Calico node
	kname, err := c.kubernetesNodeForCalico(name)
	if err != nil {
		return false, err
	}
	// Get node to inspect labels
	obj, ok, err := c.nodeIndexer.GetByKey(kname)
	if !ok {
		// Node doesn't exist, so isn't being migrated.
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("failed to check node for migration status: %w", err)
	}
	node, ok := obj.(*v1.Node)
	if !ok {
		return false, fmt.Errorf("failed to check node for migration status: unexpected error: object is not a node")
	}

	for labelName, labelVal := range node.ObjectMeta.Labels {
		// Check against labels used by the migration controller
		for migrationLabelName, migrationLabelValue := range flannelmigration.NodeNetworkCalico {
			// Only the label value "calico" specifies a migrated node where we can release the affinity
			if labelName == migrationLabelName && labelVal != migrationLabelValue {
				return true, nil
			}
		}
	}

	return false, nil
}

// kubernetesNodeForCalico returns the name of the Kubernetes node that corresponds to this Calico node.
// This function returns an empty string if no corresponding node could be found.
// Returns ErrorNotKubernetes if the given Calico node is not a Kubernetes node.
func (c *ipamController) kubernetesNodeForCalico(cnode string) (string, error) {
	// Check if we have the node name cached.
	if kn, ok := c.kubernetesNodesByCalicoName[cnode]; ok {
		return kn, nil
	}
	log.WithField("cnode", cnode).Debug("Node not in cache, look it up in the API")

	// If we can't find a matching Kubernetes node, try looking up the Calico node explicitly,
	// since it's theoretically possible the kubernetesNodesByCalicoName is just running behind the actual state of the
	// data store.
	calicoNode, err := c.client.Nodes().Get(context.TODO(), cnode, options.GetOptions{})
	if err != nil {
		if _, ok := err.(cerrors.ErrorResourceDoesNotExist); ok {
			log.WithError(err).Info("Calico Node referenced in IPAM data does not exist")
			return "", nil
		}
		log.WithError(err).Warn("failed to query Calico Node referenced in IPAM data")
		return "", err
	}

	// Try to pull the k8s name from the retrieved Calico node object. If there is no match,
	// this will return an ErrorNotKubernetes, indicating the node should be ignored.
	return getK8sNodeName(*calicoNode)
}

func ordinalToIP(b *model.AllocationBlock, ord int) net.IP {
	return b.OrdinalToIP(ord).IP
}

// podUpdate is an internal struct used to send information about new, updated,
// or deleted pods to the main worker goroutine in response to calls from the
// informer.
type podUpdate struct {
	key string
	pod *v1.Pod
}

// pauseRequest is used internally for testing.
type pauseRequest struct {
	// pauseConfirmed is sent a signal when the main loop is paused.
	pauseConfirmed chan struct{}

	// doneChan can be used to resume the main loop.
	doneChan chan struct{}
}

// pause pauses the controller's main loop until the returned function is called.
// this function is for TESTING PURPOSES ONLY, allowing the tests to safely access
// the controller's data caches without races.
func (c *ipamController) pause() func() {
	doneChan := make(chan struct{})
	pauseConfirmed := make(chan struct{})
	c.pauseRequestChannel <- pauseRequest{doneChan: doneChan, pauseConfirmed: pauseConfirmed}
	<-pauseConfirmed
	return func() {
		doneChan <- struct{}{}
	}
}
