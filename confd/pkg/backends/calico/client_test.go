// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package calico

import (
	"testing"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/libcalico-go/lib/apis/internalapi"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/syncersv1/updateprocessors"
)

func TestKeyUpdated_LogLevel(t *testing.T) {
	const nodeLogKey = "/calico/bgp/v1/host/node1/loglevel"

	tests := []struct {
		name              string
		revisionsByPrefix map[string]uint64
		cache             map[string]string
		key               string
		expectedLevel     log.Level
	}{
		{
			// The stock templates no longer watch /calico/bgp/v1/global, but confd should
			// still follow the global log level.
			name: "global log level, no watched prefix covers the key",
			revisionsByPrefix: map[string]uint64{
				"/calico/bgpconfig":   0,
				"/calico/bgp/v1/host": 0,
			},
			cache:         map[string]string{globalLogging: "debug"},
			key:           globalLogging,
			expectedLevel: log.DebugLevel,
		},
		{
			// An earlier key in the same batch, e.g. listen_port from the same per-node
			// BGPConfiguration, has already bumped the prefix covering the log level key.
			name: "node log level, covering prefix already bumped in this batch",
			revisionsByPrefix: map[string]uint64{
				"/calico/bgp/v1/host": 7,
			},
			cache:         map[string]string{nodeLogKey: "debug"},
			key:           nodeLogKey,
			expectedLevel: log.DebugLevel,
		},
	}

	// Note, the cached log level values are only ever "debug", "info" or "none", because
	// getLogSeverityKVPair maps every other BGPConfiguration LogSeverityScreen value to "none".
	// Each test starts at info level, so uses "debug" to show that the log level was updated.

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("BGP_LOGSEVERITYSCREEN", "")
			origLevel := log.GetLevel()
			defer log.SetLevel(origLevel)
			log.SetLevel(log.InfoLevel)

			c := &client{
				cache:             tt.cache,
				revisionsByPrefix: tt.revisionsByPrefix,
				cacheRevision:     7,
				nodeLogKey:        nodeLogKey,
			}
			c.keyUpdated(tt.key)

			assert.Equal(t, tt.expectedLevel, log.GetLevel())
		})
	}
}

func newTriggerTestClient() *client {
	return &client{
		cache:             map[string]string{},
		nodeListenPorts:   map[string]uint16{},
		revisionsByPrefix: map[string]uint64{"/calico/bgpconfig": 0},
		cacheRevision:     1,
	}
}

// bgpConfigUpdated returns whether /calico/bgpconfig has been marked updated at the current
// revision, and then moves on to a new revision.
func bgpConfigUpdated(c *client) bool {
	updated := c.revisionsByPrefix["/calico/bgpconfig"] == c.cacheRevision
	c.cacheRevision++
	return updated
}

func TestUpdateBGPConfigCache_PerNode(t *testing.T) {
	originalNodeName := NodeName
	NodeName = "node1"
	defer func() { NodeName = originalNodeName }()

	c := newTriggerTestClient()
	update := func(name string, spec apiv3.BGPConfigurationSpec) (updatePeersV1 bool) {
		res := apiv3.NewBGPConfiguration()
		res.Name = name
		res.Spec = spec
		svcAdvertisement := false
		var reasons []string
		c.updateBGPConfigCache(name, res, &svcAdvertisement, &updatePeersV1, &reasons)
		return
	}

	// A new listen port, for any node, affects the emitted peerings, and also the mesh peering to
	// that node, which GetBirdBGPConfig builds directly.
	assert.True(t, update("node.node2", apiv3.BGPConfigurationSpec{ListenPort: 1790}))
	assert.True(t, bgpConfigUpdated(c))

	// The same listen port again does not.
	assert.False(t, update("node.node2", apiv3.BGPConfigurationSpec{ListenPort: 1790}))
	assert.False(t, bgpConfigUpdated(c))

	// A log level change for another node affects nothing that we render.
	assert.False(t, update("node.node2", apiv3.BGPConfigurationSpec{ListenPort: 1790, LogSeverityScreen: "Debug"}))
	assert.False(t, bgpConfigUpdated(c))

	// A log level change for this node affects GetBirdBGPConfig, but not the emitted peerings.
	assert.False(t, update("node.node1", apiv3.BGPConfigurationSpec{LogSeverityScreen: "Debug"}))
	assert.True(t, bgpConfigUpdated(c))
	assert.False(t, update("node.node1", apiv3.BGPConfigurationSpec{LogSeverityScreen: "Debug"}))
	assert.False(t, bgpConfigUpdated(c))

	// Likewise a prefix advertisement change for this node.
	prefixes := []apiv3.PrefixAdvertisement{{CIDR: "10.0.0.0/24", Communities: []string{"100:200"}}}
	assert.False(t, update("node.node1", apiv3.BGPConfigurationSpec{LogSeverityScreen: "Debug", PrefixAdvertisements: prefixes}))
	assert.True(t, bgpConfigUpdated(c))
}

func TestUpdateBGPConfigCache_Global(t *testing.T) {
	c := newTriggerTestClient()
	update := func(spec apiv3.BGPConfigurationSpec) (updatePeersV1 bool) {
		res := apiv3.NewBGPConfiguration()
		res.Name = globalConfigName
		res.Spec = spec
		svcAdvertisement := false
		var reasons []string
		c.updateBGPConfigCache(globalConfigName, res, &svcAdvertisement, &updatePeersV1, &reasons)
		return
	}

	// A new global AS number affects the emitted peerings.
	asNum := numorstring.ASNumber(64513)
	assert.True(t, update(apiv3.BGPConfigurationSpec{ASNumber: &asNum}))
	// Don't assert bgpConfigUpdated here, because a peering change will always trigger
	// keyUpdated("/calico/bgpconfig") at the next level up.  But still call it in order to bump
	// the cache revision.
	bgpConfigUpdated(c)

	// The same AS number again does not affect the emitted peerings, but a LogSeverityScreen
	// change impacts GetBirdBGPConfig.
	assert.False(t, update(apiv3.BGPConfigurationSpec{ASNumber: &asNum, LogSeverityScreen: "Debug"}))
	assert.True(t, bgpConfigUpdated(c))
}

func newPeeringTestClient() *client {
	c := newTriggerTestClient()
	c.peeringCache = map[string]string{}
	c.bgpPeers = map[string]*apiv3.BGPPeer{}
	c.nodeIPs = map[string]struct{}{}
	c.nodeLabelManager = newNodeLabelManager()
	c.nodeV1Processor = updateprocessors.NewBGPNodeUpdateProcessor(false)
	return c
}

func TestOnUpdates_BGPConfigUpdatedOnlyIfPeeringsChange(t *testing.T) {
	c := newPeeringTestClient()
	updateNode := func(labels map[string]string, rrClusterID string) {
		node := internalapi.NewNode()
		node.Name = "node1"
		node.Labels = labels
		node.Spec.BGP = &internalapi.NodeBGPSpec{IPv4Address: "10.0.0.1/24", RouteReflectorClusterID: rrClusterID}
		c.onUpdates([]api.Update{{
			KVPair: model.KVPair{
				Key:   model.ResourceKey{Kind: internalapi.KindNode, Name: node.Name},
				Value: node,
			},
			UpdateType: api.UpdateTypeKVUpdated,
		}}, false)
	}
	updatePeer := func() {
		peer := apiv3.NewBGPPeer()
		peer.Name = "peer1"
		peer.Spec = apiv3.BGPPeerSpec{NodeSelector: "rack == 'a'", PeerIP: "192.0.2.1", ASNumber: 64512}
		c.onUpdates([]api.Update{{
			KVPair: model.KVPair{
				Key:   model.ResourceKey{Kind: apiv3.KindBGPPeer, Name: peer.Name},
				Value: peer,
			},
			UpdateType: api.UpdateTypeKVUpdated,
		}}, false)
	}

	// Don't assert bgpConfigUpdated for the new node, because its per-node BGP keys (such as
	// network_v4) are new and are read by GetBirdBGPConfig.
	updateNode(map[string]string{"rack": "a"}, "")
	bgpConfigUpdated(c)

	// A new BGPPeer that selects the node adds a peering.
	updatePeer()
	assert.True(t, bgpConfigUpdated(c))
	assert.Len(t, c.peeringCache, 1)

	// Re-applying the same BGPPeer recomputes the peerings, but they are unchanged.
	updatePeer()
	assert.False(t, bgpConfigUpdated(c))

	// Likewise a node label change that does not affect which nodes the BGPPeer selects.
	updateNode(map[string]string{"rack": "a", "zone": "z"}, "")
	assert.False(t, bgpConfigUpdated(c))

	// Likewise a triggered recheck, when nothing has changed.
	c.onUpdates(nil, true)
	assert.False(t, bgpConfigUpdated(c))

	// A change to a node BGP field that affects peerings does not change the explicit peerings
	// here, but GetBirdBGPConfig also reads it directly for the mesh peerings.
	updateNode(map[string]string{"rack": "a", "zone": "z"}, "224.0.0.1")
	assert.True(t, bgpConfigUpdated(c))
	assert.Len(t, c.peeringCache, 1)

	// A node label change that stops the BGPPeer selecting the node removes the peering.
	updateNode(map[string]string{"rack": "b", "zone": "z"}, "224.0.0.1")
	assert.True(t, bgpConfigUpdated(c))
	assert.Empty(t, c.peeringCache)
}

func TestOnUpdates_BGPConfigUpdatedIfMeshPasswordChanges(t *testing.T) {
	c := newPeeringTestClient()
	secret := func(name, password string) *secretWatchData {
		return &secretWatchData{
			stopCh: make(chan struct{}),
			secret: &v1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: "kube-system", Name: name},
				Data:       map[string][]byte{"password": []byte(password)},
			},
		}
	}
	sw := &secretWatcher{
		client:    c,
		namespace: "kube-system",
		watches: map[string]*secretWatchData{
			"mesh1": secret("mesh1", "pass1"),
		},
	}
	c.secretWatcher = sw
	setMeshSecret := func(name string) {
		res := apiv3.NewBGPConfiguration()
		res.Name = globalConfigName
		res.Spec.NodeMeshPassword = &apiv3.BGPPassword{
			SecretKeyRef: &v1.SecretKeySelector{
				LocalObjectReference: v1.LocalObjectReference{Name: name},
				Key:                  "password",
			},
		}
		svcAdvertisement, updatePeersV1 := false, false
		var reasons []string
		c.updateBGPConfigCache(globalConfigName, res, &svcAdvertisement, &updatePeersV1, &reasons)
	}

	// A BGPConfiguration change always bumps /calico/bgpconfig.
	setMeshSecret("mesh1")
	assert.True(t, bgpConfigUpdated(c))

	// A triggered recheck, e.g. for a change to some other secret, does not.
	c.onUpdates(nil, true)
	assert.False(t, bgpConfigUpdated(c))

	// A change to the mesh password's secret does, even though the mesh peerings are not in
	// peeringCache and so the peerings appear unchanged.
	sw.watches["mesh1"].secret.Data["password"] = []byte("pass1b")
	c.onUpdates(nil, true)
	assert.True(t, bgpConfigUpdated(c))

	// After switching the mesh password to a different secret, a change to that secret is
	// compared against its own password, not the first secret's.  (Add the watch for the new
	// secret here, because the triggered rechecks above would sweep it as unreferenced.)
	sw.watches["mesh2"] = secret("mesh2", "pass2")
	setMeshSecret("mesh2")
	assert.True(t, bgpConfigUpdated(c))
	sw.watches["mesh2"].secret.Data["password"] = []byte("pass1b")
	c.onUpdates(nil, true)
	assert.True(t, bgpConfigUpdated(c))
}

func TestNodeKeyAffectsPeers(t *testing.T) {
	for name, expected := range map[string]bool{
		"ip_addr_v4":        true,
		"ip_addr_v6":        true,
		"as_num":            true,
		"rr_cluster_id":     true,
		"network_v4":        false,
		"network_v6":        false,
		"wireguard_addr_v4": false,
		"wireguard_addr_v6": false,
	} {
		assert.Equal(t, expected, nodeKeyAffectsPeers(model.NodeBGPConfigKey{Nodename: "node1", Name: name}), name)
	}
	assert.False(t, nodeKeyAffectsPeers(model.BlockAffinityKey{Host: "node1"}))
}

func TestAffectsBirdBGPConfig(t *testing.T) {
	assert.True(t, affectsBirdBGPConfig(model.IPPoolKey{}))
	assert.True(t, affectsBirdBGPConfig(model.ResourceKey{Kind: apiv3.KindBGPFilter, Name: "f1"}))
	assert.False(t, affectsBirdBGPConfig(model.ResourceKey{Kind: apiv3.KindBGPPeer, Name: "p1"}))
	assert.False(t, affectsBirdBGPConfig(model.BlockAffinityKey{}))
}
