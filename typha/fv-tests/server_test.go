// Copyright (c) 2017-2018,2021 Tigera, Inc. All rights reserved.
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

package fvtests_test

import (
	"context"
	"crypto/x509"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/prometheus/client_golang/prometheus"
	io_prometheus_client "github.com/prometheus/client_model/go"
	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	libapiv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/encap"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	calinet "github.com/projectcalico/calico/libcalico-go/lib/net"
	. "github.com/projectcalico/calico/typha/fv-tests"
	"github.com/projectcalico/calico/typha/pkg/calc"
	"github.com/projectcalico/calico/typha/pkg/discovery"
	"github.com/projectcalico/calico/typha/pkg/snapcache"
	"github.com/projectcalico/calico/typha/pkg/syncclient"
	"github.com/projectcalico/calico/typha/pkg/syncproto"
	"github.com/projectcalico/calico/typha/pkg/syncserver"
	"github.com/projectcalico/calico/typha/pkg/tlsutils"
)

var (
	configFoobarBazzBiff = api.Update{
		KVPair: model.KVPair{
			Key:      model.GlobalConfigKey{Name: "foobar"},
			Value:    "bazzbiff",
			Revision: "1234",
			TTL:      12,
		},
		UpdateType: api.UpdateTypeKVNew,
	}
	configFoobarDeleted = api.Update{
		KVPair: model.KVPair{
			Key:      model.GlobalConfigKey{Name: "foobar"},
			Revision: "1235",
		},
		UpdateType: api.UpdateTypeKVDeleted,
	}
	configFoobar2BazzBiff = api.Update{
		KVPair: model.KVPair{
			Key:      model.GlobalConfigKey{Name: "foobar2"},
			Value:    "bazzbiff",
			Revision: "1237",
		},
		UpdateType: api.UpdateTypeKVNew,
	}
	// Simulates an invalid key, which we treat as a deletion.
	configFoobar2Invalid = api.Update{
		KVPair: model.KVPair{
			Key:      model.GlobalConfigKey{Name: "foobar2"},
			Revision: "1238",
		},
		UpdateType: api.UpdateTypeKVUpdated,
	}

	// The updates below contain all the datatypes that the BGP syncer can emit.
	ipPoolCIDR = calinet.MustParseCIDR("10.0.1.0/24")
	ipPool1    = api.Update{
		KVPair: model.KVPair{
			Key: model.IPPoolKey{CIDR: ipPoolCIDR},
			Value: &model.IPPool{
				CIDR:          ipPoolCIDR,
				IPIPInterface: "tunl0",
				IPIPMode:      encap.Always,
				Masquerade:    true,
				IPAM:          true,
				Disabled:      true,
			},
			Revision: "1234",
		},
		UpdateType: api.UpdateTypeKVNew,
	}
	nodeBGPConfNode = api.Update{
		KVPair: model.KVPair{
			Key:      model.NodeBGPConfigKey{Nodename: "node1", Name: "foo"},
			Value:    "nodeBGPConfNode",
			Revision: "1235",
		},
		UpdateType: api.UpdateTypeKVNew,
	}
	nodeBGPConfGlobal = api.Update{
		KVPair: model.KVPair{
			Key:      model.GlobalBGPConfigKey{Name: "bar"},
			Value:    "nodeBGPConfGlobal",
			Revision: "1236",
		},
		UpdateType: api.UpdateTypeKVNew,
	}
	v3Node = api.Update{
		KVPair: model.KVPair{
			Key: model.ResourceKey{Name: "node1", Kind: libapiv3.KindNode},
			Value: &libapiv3.Node{
				ObjectMeta: metav1.ObjectMeta{
					ResourceVersion: "1237",
				},
			},
			Revision: "1237",
		},
		UpdateType: api.UpdateTypeKVNew,
	}
	v3BGPPeer = api.Update{
		KVPair: model.KVPair{
			Key: model.ResourceKey{Name: "peer1", Kind: apiv3.KindBGPPeer},
			Value: &apiv3.BGPPeer{
				ObjectMeta: metav1.ObjectMeta{
					ResourceVersion: "1238",
				},
			},
			Revision: "1238",
		},
		UpdateType: api.UpdateTypeKVNew,
	}
	blockAffCIDR = calinet.MustParseCIDR("10.0.1.0/26")
	blockAff1    = api.Update{
		KVPair: model.KVPair{
			Key:      model.BlockAffinityKey{CIDR: blockAffCIDR, AffinityType: model.IPAMAffinityTypeHost, Host: "node1"},
			Value:    &model.BlockAffinity{State: model.StateConfirmed},
			Revision: "1239",
		},
		UpdateType: api.UpdateTypeKVNew,
	}
)

var _ = Describe("With an in-process Server", func() {
	// We'll create this pipeline for updates to flow through:
	//
	//    This goroutine -> callback -chan-> validation -> snapshot -> server
	//                      decoupler        filter        cache
	//
	var (
		h *ServerHarness
	)

	BeforeEach(func() {
		// Default to debug but some more aggressive tests override this below.
		log.SetLevel(log.DebugLevel)
		h = NewHarness()
		h.Start()
	})

	AfterEach(func() {
		h.Stop()
	})

	It("should choose a port", func() {
		Expect(h.Server.Port()).ToNot(BeZero())
	})

	Describe("with a client connection", func() {
		var clientCancel context.CancelFunc
		var recorder *StateRecorder

		BeforeEach(func() {
			h.CreateClients(1)
			clientCancel = h.ClientStates[0].clientCancel
			recorder = h.ClientStates[0].recorder
		})

		// expectFelixClientState asserts that the client eventually reaches the given state.  Then, it
		// simulates a second connection and check that that also converges to the given state.
		expectClientState := func(c *ClientState, status api.SyncStatus, kvs map[string]api.Update) {
			// Wait until we reach that state.
			EventuallyWithOffset(1, c.recorder.Status).Should(Equal(status), "Unexpected sync status")
			EventuallyWithOffset(1, c.recorder.KVs).Should(Equal(kvs), "Unexpected KVs")

			// Now, a newly-connecting client should also reach the same state.
			log.Info("Starting transient client to read snapshot.")

			transientClient := h.CreateClient("transient", c.syncerType)
			defer func() {
				log.Info("Stopping transient client.")
				transientClient.clientCancel()
				transientClient.client.Finished.Wait()
				log.Info("Stopped transient client.")
			}()
			Eventually(transientClient.recorder.Status).Should(Equal(status))
			Eventually(transientClient.recorder.KVs).Should(Equal(kvs))
		}

		expectFelixClientState := func(status api.SyncStatus, kvs map[string]api.Update) {
			expectClientState(h.ClientStates[0], status, kvs)
		}

		It("should drop a bad KV", func() {
			// Bypass the validation filter (which also converts Nodes to HostIPs).
			h.FelixCache.OnStatusUpdated(api.ResyncInProgress)
			h.FelixCache.OnUpdates([]api.Update{{
				KVPair: model.KVPair{
					// NodeKeys can't be serialized right now.
					Key:      model.NodeKey{Hostname: "foobar"},
					Value:    "bazzbiff",
					Revision: "1234",
					TTL:      12,
				},
				UpdateType: api.UpdateTypeKVNew,
			}})
			h.FelixCache.OnStatusUpdated(api.InSync)
			expectFelixClientState(api.InSync, map[string]api.Update{})
		})

		It("validation should drop a bad Node", func() {
			h.ValFilter.OnStatusUpdated(api.ResyncInProgress)
			h.ValFilter.OnUpdates([]api.Update{{
				KVPair: model.KVPair{
					Key:      model.NodeKey{Hostname: "foobar"},
					Value:    "bazzbiff",
					Revision: "1234",
					TTL:      12,
				},
				UpdateType: api.UpdateTypeKVNew,
			}})
			h.ValFilter.OnStatusUpdated(api.InSync)
			expectFelixClientState(api.InSync, map[string]api.Update{})
		})

		It("validation should convert a valid Node", func() {
			h.ValFilter.OnStatusUpdated(api.ResyncInProgress)
			h.ValFilter.OnUpdates([]api.Update{{
				KVPair: model.KVPair{
					Key: model.NodeKey{Hostname: "foobar"},
					Value: &model.Node{
						FelixIPv4: calinet.ParseIP("10.0.0.1"),
					},
					Revision: "1234",
				},
				UpdateType: api.UpdateTypeKVNew,
			}})
			h.ValFilter.OnStatusUpdated(api.InSync)
			expectFelixClientState(api.InSync, map[string]api.Update{
				"/calico/v1/host/foobar/bird_ip": {
					KVPair: model.KVPair{
						Key:      model.HostIPKey{Hostname: "foobar"},
						Value:    &calinet.IP{IP: net.ParseIP("10.0.0.1")},
						Revision: "1234",
					},
					UpdateType: api.UpdateTypeKVNew,
				},
			})
		})

		It("should pass through a KV and status", func() {
			h.Decoupler.OnStatusUpdated(api.ResyncInProgress)
			h.Decoupler.OnUpdates([]api.Update{configFoobarBazzBiff})
			h.Decoupler.OnStatusUpdated(api.InSync)
			Eventually(recorder.Status).Should(Equal(api.InSync))
			expectFelixClientState(
				api.InSync,
				map[string]api.Update{
					"/calico/v1/config/foobar": configFoobarBazzBiff,
				},
			)
		})

		Describe("with a BGP client", func() {
			var bgpClient *ClientState

			BeforeEach(func() {
				bgpClient = h.CreateClient("bgp", syncproto.SyncerTypeBGP)
			})

			DescribeTable("should pass through BGP KV pairs",
				func(update api.Update, v1key string) {
					h.BGPDecoupler.OnStatusUpdated(api.ResyncInProgress)
					h.BGPDecoupler.OnUpdates([]api.Update{update})
					h.BGPDecoupler.OnStatusUpdated(api.InSync)
					Eventually(bgpClient.recorder.Status).Should(Equal(api.InSync))
					expectClientState(
						bgpClient,
						api.InSync,
						map[string]api.Update{
							v1key: update,
						},
					)
					// Our updates shouldn't affect the felix syncer.
					expectFelixClientState(api.ResyncInProgress, map[string]api.Update{})
				},
				Entry("IP pool", ipPool1, "/calico/v1/ipam/v4/pool/10.0.1.0-24"),
				Entry("Node conf", nodeBGPConfNode, "/calico/bgp/v1/host/node1/foo"),
				Entry("Global conf", nodeBGPConfGlobal, "/calico/bgp/v1/global/bar"),
				Entry("Node", v3Node, "/calico/resources/v3/projectcalico.org/nodes/node1"),
				Entry("BGP peer", v3BGPPeer, "/calico/resources/v3/projectcalico.org/bgppeers/peer1"),
				Entry("Block affinity", blockAff1, "/calico/ipam/v2/host/node1/ipv4/block/10.0.1.0-26"),
			)

			It("should handle a felix and BGP client at same time", func() {
				h.BGPDecoupler.OnStatusUpdated(api.ResyncInProgress)
				h.Decoupler.OnStatusUpdated(api.ResyncInProgress)
				h.BGPDecoupler.OnUpdates([]api.Update{ipPool1})
				h.Decoupler.OnUpdates([]api.Update{configFoobarBazzBiff})
				h.Decoupler.OnStatusUpdated(api.InSync)
				h.BGPDecoupler.OnStatusUpdated(api.InSync)

				expectClientState(bgpClient, api.InSync, map[string]api.Update{
					"/calico/v1/ipam/v4/pool/10.0.1.0-24": ipPool1,
				})
				expectFelixClientState(api.InSync, map[string]api.Update{
					"/calico/v1/config/foobar": configFoobarBazzBiff,
				})
			})
		})

		It("should handle deletions", func() {
			// Create two keys, then delete them.  One of the keys happens to have a
			// default path that is the prefix of the other, just to make sure the Ctrie
			// doesn't accidentally delete the whole prefix.
			h.Decoupler.OnUpdates([]api.Update{configFoobarBazzBiff})
			h.Decoupler.OnUpdates([]api.Update{configFoobar2BazzBiff})
			h.Decoupler.OnStatusUpdated(api.InSync)
			expectFelixClientState(api.InSync, map[string]api.Update{
				"/calico/v1/config/foobar":  configFoobarBazzBiff,
				"/calico/v1/config/foobar2": configFoobar2BazzBiff,
			})
			h.Decoupler.OnUpdates([]api.Update{configFoobarDeleted})
			expectFelixClientState(api.InSync, map[string]api.Update{
				"/calico/v1/config/foobar2": configFoobar2BazzBiff,
			})
			h.Decoupler.OnUpdates([]api.Update{configFoobar2Invalid})
			expectFelixClientState(api.InSync, map[string]api.Update{})
		})

		It("after adding many keys and deleting half, should give correct state", func() {
			// This test is a regression test for https://github.com/projectcalico/typha/issues/28.  That
			// issue was caused by a bug in the Ctrie datastructure that we use: if there was an internal
			// node of that trie that contained exactly two values and we delete one of them, then the
			// other value would be skipped on subsequent iterations over the trie.  I've verified that,
			// without the fix, this test fails (but setting numKeys=1000 wasn't enough to trigger the bug).
			rev := 100
			expectedState := map[string]api.Update{}
			const numKeys = 10000
			const halfNumKeys = numKeys / 2
			for i := 0; i < numKeys; i++ {
				upd := api.Update{
					KVPair: model.KVPair{
						Key:      model.GlobalConfigKey{Name: fmt.Sprintf("foobar%d", i)},
						Value:    fmt.Sprintf("biff%d", i),
						Revision: fmt.Sprintf("%d", rev),
					},
					UpdateType: api.UpdateTypeKVNew,
				}
				h.Decoupler.OnUpdates([]api.Update{upd})
				rev++
				if i >= halfNumKeys {
					expectedState[fmt.Sprintf("/calico/v1/config/foobar%d", i)] = upd
				}
			}
			for i := 0; i < halfNumKeys; i++ {
				h.Decoupler.OnUpdates([]api.Update{{
					KVPair: model.KVPair{
						Key:      model.GlobalConfigKey{Name: fmt.Sprintf("foobar%d", i)},
						Revision: fmt.Sprintf("%d", rev),
					},
					UpdateType: api.UpdateTypeKVDeleted,
				}})
				rev++
			}
			h.Decoupler.OnStatusUpdated(api.InSync)
			expectFelixClientState(api.InSync, expectedState)
		})

		It("should pass through many KVs", func() {
			expectedEndState := h.SendInitialSnapshotPods(1000)
			expectFelixClientState(api.InSync, expectedEndState)
		})

		It("should report the correct number of connections", func() {
			expectGlobalGaugeValue("typha_connections_active", 1.0)
		})

		It("should report the correct number of connections after killing the client", func() {
			clientCancel()
			expectGlobalGaugeValue("typha_connections_active", 0.0)
		})
	})

	// Simulate an old client.
	Describe("with a client that doesn't support decoder restart", func() {
		BeforeEach(func() {
			h.CreateClientNoDecodeRestart("no decoder restart", syncproto.SyncerTypeFelix)
		})

		It("should handle the initial snapshot", func() {
			expState := h.SendInitialSnapshotPods(10)
			h.ExpectAllClientsToReachState(api.InSync, expState)
			expState2 := h.SendPodUpdates(10)
			for k, v := range expState2 {
				expState[k] = v
			}
			h.ExpectAllClientsToReachState(api.InSync, expState)
		})
	})

	Describe("with big starting snapshot and ~10 clients", func() {
		var expectedEndState map[string]api.Update
		BeforeEach(func() {
			log.SetLevel(log.InfoLevel)
			// Using simulated Pods to give more realistic picture of JSON encoding/decoding overheads
			// (this test is a good one to profile).
			expectedEndState = h.SendInitialSnapshotPods(200000)
			// The snapshot is huge, so we only create one real client (which records the
			// keys/values that it sees) and a bunch of no-op clients, which run the protocol
			// but don't record anything.
			h.CreateNoOpClients(10)
			h.CreateClients(1)
		})

		It("should pass through many KVs", func() {
			h.ExpectAllClientsToReachState(api.InSync, expectedEndState)
		})
	})

	Describe("with 100 client connections", func() {
		BeforeEach(func() {
			log.SetLevel(log.InfoLevel) // Debug too verbose with 100 clients.
			h.CreateClients(100)
		})

		It("should drop expected number of connections", func() {
			// Start a goroutine to watch each client and send us a message on the channel when it stops.
			finishedC := make(chan int)
			for _, s := range h.ClientStates {
				go func(s *ClientState) {
					s.client.Finished.Wait()
					finishedC <- 1
				}(s)
			}

			// We start with 100 connections, set the max to 60 so we kill 40 connections.
			h.Server.SetMaxConns(60)

			// We set the drop interval to 50ms so it should take 2-2.2 seconds (due to jitter) to drop the
			// connections.  Wait 3 seconds so that we verify that the server doesn't go on to kill any
			// more than the target.
			timeout := time.NewTimer(3 * time.Second)
			oneSec := time.NewTimer(1 * time.Second)
			numFinished := 0
		loop:
			for {
				select {
				case <-timeout.C:
					break loop
				case <-oneSec.C:
					// Check the rate is in the right ballpark: after one second we should have
					// dropped approximately 20 clients.
					Expect(numFinished).To(BeNumerically(">", 10))
					Expect(numFinished).To(BeNumerically("<", 30))
				case c := <-finishedC:
					numFinished += c
				}
			}
			// After the timeout we should have dropped exactly the right number of connections.
			Expect(numFinished).To(Equal(40))
			expectGlobalGaugeValue("typha_connections_active", 60.0)
		})

		It("should pass through a KV and status", func() {
			h.Decoupler.OnStatusUpdated(api.ResyncInProgress)
			h.Decoupler.OnUpdates([]api.Update{configFoobarBazzBiff})
			h.Decoupler.OnStatusUpdated(api.InSync)
			h.ExpectAllClientsToReachState(
				api.InSync,
				map[string]api.Update{
					"/calico/v1/config/foobar": configFoobarBazzBiff,
				},
			)
		})

		It("should pass through many KVs", func() {
			expectedEndState := h.SendInitialSnapshotPods(1000)
			h.ExpectAllClientsToReachState(api.InSync, expectedEndState)
		})

		It("should report the correct number of connections", func() {
			expectGlobalGaugeValue("typha_connections_active", 100.0)
			expectPerSyncerGaugeValue(syncproto.SyncerTypeFelix, "typha_connections_streaming", 100.0)
		})

		It("should report the correct number of connections after killing the clients", func() {
			for _, c := range h.ClientStates {
				c.clientCancel()
			}
			expectGlobalGaugeValue("typha_connections_active", 0.0)
			expectPerSyncerGaugeValue(syncproto.SyncerTypeFelix, "typha_connections_streaming", 0.0)
		})

		It("with churn, it should report the correct number of connections after killing the clients", func() {
			// Generate some churn while we disconnect the clients.
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				h.SendInitialSnapshotPods(1000)
				wg.Done()
			}()
			defer wg.Wait()
			for _, c := range h.ClientStates {
				c.clientCancel()
				time.Sleep(100 * time.Microsecond)
			}
			expectGlobalGaugeValue("typha_connections_active", 0.0)
		})
	})
})

var _ = Describe("with no client connections", func() {
	var h *ServerHarness

	BeforeEach(func() {
		log.SetLevel(log.InfoLevel) // Debug too verbose for tests with a few clients.
		h = NewHarness()
	})

	AfterEach(func() {
		h.Stop()
	})

	JustBeforeEach(func() {
		h.Start()
	})

	Describe("300s shutdown timer and 1s max drop interval", func() {
		It("should shut drop 1 client per second", func() {
			Expect(h.Server.NumActiveConnections()).To(Equal(0))

			h.Server.ShutDownGracefully()
			finishedC := make(chan struct{})
			go func() {
				defer close(finishedC)
				h.Server.Finished.Wait()
			}()
			Eventually(finishedC).Should(BeClosed())
		})
	})
})

var _ = Describe("with 5 client connections", func() {
	const numClients = 5

	var h *ServerHarness

	BeforeEach(func() {
		log.SetLevel(log.InfoLevel) // Debug too verbose for tests with a few clients.
		h = NewHarness()
	})

	AfterEach(func() {
		h.Stop()
	})

	JustBeforeEach(func() {
		h.Start()
		h.CreateClients(numClients)
	})

	Describe("300s shutdown timer and 1s max drop interval", func() {
		It("should shut drop 1 client per second", func() {
			Eventually(h.Server.NumActiveConnections).Should(Equal(numClients))

			h.Server.ShutDownGracefully()
			finishedC := make(chan struct{})
			go func() {
				defer close(finishedC)
				h.Server.Finished.Wait()
			}()

			for n := numClients - 1; n >= 0; n-- {
				if n > 0 {
					Expect(finishedC).ToNot(BeClosed())
				}
				Eventually(h.Server.NumActiveConnections, "1500ms", "10ms").Should(BeNumerically("==", n))
				Consistently(h.Server.NumActiveConnections, "500ms", "10ms").Should(BeNumerically("==", n))
			}

			Eventually(finishedC).Should(BeClosed())
		})
	})

	Describe("2.5s shutdown timer and 1s max drop interval", func() {
		BeforeEach(func() {
			h.Config.ShutdownTimeout = 2500 * time.Millisecond
		})

		It("should shut drop 1 client every half second", func() {
			Eventually(h.Server.NumActiveConnections).Should(Equal(numClients))

			h.Server.ShutDownGracefully()
			finishedC := make(chan struct{})
			go func() {
				defer close(finishedC)
				h.Server.Finished.Wait()
			}()

			for n := numClients - 1; n >= 0; n-- {
				if n > 0 {
					Expect(finishedC).ToNot(BeClosed())
				}
				Eventually(h.Server.NumActiveConnections, "750ms", "10ms").Should(BeNumerically("==", n))
				Consistently(h.Server.NumActiveConnections, "250ms", "10ms").Should(BeNumerically("==", n))
			}

			Eventually(finishedC).Should(BeClosed())
		})
	})
})

var _ = Describe("With an in-process Server with short ping timeout", func() {
	// We'll create this pipeline for updates to flow through:
	//
	//    This goroutine -> callback -chan-> validation -> snapshot -> server
	//                      decoupler        filter        cache
	//
	var (
		h *ServerHarness
	)

	BeforeEach(func() {
		// Default to debug but some more aggressive tests override this below.
		log.SetLevel(log.DebugLevel)
		h = NewHarness()
		h.Config = syncserver.Config{
			PingInterval: 100 * time.Millisecond,
			PongTimeout:  500 * time.Millisecond,
			Port:         syncserver.PortRandom,
			DropInterval: 50 * time.Millisecond,
		}
		h.Start()
	})

	AfterEach(func() {
		h.Stop()
	})

	It("should not disconnect a responsive client", func() {
		// Start a real client, which will respond correctly to pings.
		clientCxt, clientCancel := context.WithCancel(context.Background())
		recorder := NewRecorder()
		client := syncclient.New(
			h.Discoverer(),
			"test-version",
			"test-host",
			"test-info",
			recorder,
			nil,
		)
		err := client.Start(clientCxt)
		Expect(err).NotTo(HaveOccurred())
		recorderCtx, recorderCancel := context.WithCancel(context.Background())
		defer recorderCancel()
		go recorder.Loop(recorderCtx)
		defer func() {
			clientCancel()
			client.Finished.Wait()
		}()

		// Wait until we should have been dropped if we were unresponsive.  I.e. 1 pong timeout + 1 ping
		// interval for the check to take place.
		time.Sleep(1 * time.Second)

		// Then send an update.
		h.FelixCache.OnStatusUpdated(api.InSync)
		Eventually(recorder.Status).Should(Equal(api.InSync))
	})

	Describe("with a raw connection", func() {
		var rawConn net.Conn
		var w *gob.Encoder
		var r *gob.Decoder

		BeforeEach(func() {
			var err error
			rawConn, err = net.DialTimeout("tcp", h.Addr(), 10*time.Second)
			Expect(err).NotTo(HaveOccurred())

			w = gob.NewEncoder(rawConn)
			r = gob.NewDecoder(rawConn)
		})

		AfterEach(func() {
			err := rawConn.Close()
			if err != nil {
				log.WithError(err).Info("Error recorded while closing conn.")
			}
		})

		expectDisconnection := func(after time.Duration) {
			var envelope syncproto.Envelope
			disconnected := make(chan struct{})

			go func() {
				defer close(disconnected)
				for {
					err := r.Decode(&envelope)
					if err != nil {
						return // Success!
					}
				}
			}()

			select {
			case <-time.After(after):
				Fail("client wasn't disconnected within expected time")
			case <-disconnected:
			}
			expectGlobalGaugeValue("typha_connections_active", 0.0)
		}

		It("should clean up if the hello doesn't get sent", func() {
			expectGlobalGaugeValue("typha_connections_active", 1.0)
			err := rawConn.Close()
			Expect(err).ToNot(HaveOccurred())
			expectGlobalGaugeValue("typha_connections_active", 0.0)
		})

		Describe("After sending Hello with bad syncer type", func() {
			BeforeEach(func() {
				err := w.Encode(syncproto.Envelope{
					Message: syncproto.MsgClientHello{
						Hostname:                 "me",
						Version:                  "test",
						Info:                     "test info",
						SyncerType:               syncproto.SyncerType("garbage"),
						SupportsModernPolicyKeys: true,
					},
				})
				Expect(err).NotTo(HaveOccurred())
			})

			It("should disconnect the client", func() {
				expectDisconnection(100 * time.Millisecond)
				expectGlobalGaugeValue("typha_connections_active", 0.0)
			})
		})

		Describe("After sending Hello with no policy key support", func() {
			BeforeEach(func() {
				err := w.Encode(syncproto.Envelope{
					Message: syncproto.MsgClientHello{
						Hostname:                 "me",
						Version:                  "test",
						Info:                     "test info",
						SyncerType:               syncproto.SyncerTypeFelix,
						SupportsModernPolicyKeys: false,
					},
				})
				Expect(err).NotTo(HaveOccurred())
			})

			It("should disconnect the client", func() {
				expectDisconnection(100 * time.Millisecond)
				expectGlobalGaugeValue("typha_connections_active", 0.0)
			})
		})

		Describe("After sending unexpected message", func() {
			BeforeEach(func() {
				err := w.Encode(syncproto.Envelope{
					Message: syncproto.MsgSyncStatus{
						SyncStatus: api.InSync,
					},
				})
				Expect(err).NotTo(HaveOccurred())
			})

			It("should disconnect the client", func() {
				expectDisconnection(100 * time.Millisecond)
				expectGlobalGaugeValue("typha_connections_active", 0.0)
			})
		})

		Describe("After sending Hello", func() {
			BeforeEach(func() {
				err := w.Encode(syncproto.Envelope{
					Message: syncproto.MsgClientHello{
						Hostname:                 "me",
						Version:                  "test",
						Info:                     "test info",
						SupportsModernPolicyKeys: true,
					},
				})
				Expect(err).NotTo(HaveOccurred())
			})

			It("should disconnect a client that sends a nil update", func() {
				var envelope syncproto.Envelope
				err := w.Encode(envelope)
				Expect(err).NotTo(HaveOccurred())
				expectDisconnection(100 * time.Millisecond)
			})

			It("should disconnect a client that sends an unexpected update", func() {
				var envelope syncproto.Envelope
				envelope.Message = 42
				err := w.Encode(envelope)
				Expect(err).NotTo(HaveOccurred())
				expectDisconnection(100 * time.Millisecond)
			})

			It("should disconnect a client that sends a garbage update", func() {
				_, err := rawConn.Write([]byte("dsjfkldjsklfajdskjfk;dajskfjaoirefmuweioufijsdkfjkdsjkfjasd;"))
				log.WithError(err).Info("Sent garbage to server")
				// We don't get dropped as quickly as above because the gob decoder doesn't raise an
				// error for the above data (presumably, it's still waiting for more data to decode).
				// We should still get dropped by the ping timeout though...
				expectDisconnection(time.Second)
			})

			It("should disconnect an unresponsive client", func() {
				done := make(chan struct{})
				pings := make(chan *syncproto.MsgPing)
				go func() {
					defer close(done)
					defer close(pings)
					for {
						var envelope syncproto.Envelope
						err := r.Decode(&envelope)
						if err != nil {
							return
						}
						if m, ok := envelope.Message.(syncproto.MsgPing); ok {
							pings <- &m
						}
					}
				}()
				timeout := time.NewTimer(1 * time.Second)
				startTime := time.Now()
				gotPing := false
				for {
					select {
					case m := <-pings:
						if m == nil {
							pings = nil
							continue
						}
						Expect(time.Since(m.Timestamp)).To(BeNumerically("<", time.Second))
						gotPing = true
					case <-done:
						// Check we didn't get dropped too soon.
						Expect(gotPing).To(BeTrue())
						Expect(time.Since(startTime)).To(BeNumerically(">=", 500*time.Millisecond))
						timeout.Stop()
						return
					case <-timeout.C:
						Fail("timed out waiting for unresponsive client to be dropped")
					}
				}
			})
		})
	})
})

var _ = Describe("With an in-process Server with long ping interval", func() {
	// We'll create this pipeline for updates to flow through:
	//
	//    This goroutine -> callback -chan-> validation -> snapshot -> server
	//                      decoupler        filter        cache
	//
	var (
		h *ServerHarness
	)

	BeforeEach(func() {
		// Default to debug but some more aggressive tests override this below.
		log.SetLevel(log.DebugLevel)
		h = NewHarness()
		h.Config = syncserver.Config{
			// Effectively disable pings so that we can test the non-ping timeouts.
			PingInterval: 10000 * time.Second,
			PongTimeout:  50000 * time.Second,
			Port:         syncserver.PortRandom,
			DropInterval: 1 * time.Second,
		}
		h.Start()
	})

	AfterEach(func() {
		h.Stop()
	})

	It("client should disconnect after read timeout", func() {
		clientCxt, clientCancel := context.WithCancel(context.Background())
		recorder := NewRecorder()
		client := syncclient.New(
			h.Discoverer(),
			"test-version",
			"test-host",
			"test-info",
			recorder,
			&syncclient.Options{
				ReadTimeout:  1 * time.Second,
				WriteTimeout: 10 * time.Second,
			},
		)
		err := client.Start(clientCxt)
		recorderCtx, recorderCancel := context.WithCancel(context.Background())
		defer recorderCancel()
		go recorder.Loop(recorderCtx)
		Expect(err).NotTo(HaveOccurred())
		defer func() {
			clientCancel()
			client.Finished.Wait()
		}()

		finishedC := make(chan struct{})
		go func() {
			client.Finished.Wait()
			close(finishedC)
		}()

		timeout := time.After(2 * time.Second)
		startTime := time.Now()
		select {
		case <-finishedC:
			Expect(time.Since(startTime)).To(BeNumerically(">=", 900*time.Millisecond))
		case <-timeout:
			Fail("Timed out waiting for client to have a read timeout.")
		}
	})
})

var _ = Describe("With an in-process Server with short grace period", func() {
	var h *ServerHarness

	BeforeEach(func() {
		h = NewHarness()

		// Effectively disable pings, so we can hit the grace period timers.
		h.Config.PingInterval = 10000 * time.Second
		h.Config.PongTimeout = 50000 * time.Second

		// Short timeouts so we can hit them quickly.
		h.Config.MaxFallBehind = time.Second
		h.Config.NewClientFallBehindGracePeriod = time.Second

		// The snapshot is >10MB; set the write buffer to something much less than that since these
		// tests need to cause backpressure on Typha.
		h.Config.WriteBufferSize = 1024 * 256
		// Since we rely on back-pressure, it's really handy to have a log of exactly what writes
		// happen and when.
		h.Config.DebugLogWrites = true

		h.Start()
	})

	AfterEach(func() {
		h.Stop()
	})

	Describe("with lots of KVs", func() {
		const initialSnapshotSize = 10000

		logStats := func(note string) {
			for _, stat := range []string{
				"typha_snapshots_generated",
			} {
				value, _ := getPerSyncerCounter(syncproto.SyncerTypeFelix, stat)
				log.Infof("%s: counter: %s =  %v", note, stat, int(value))
			}
			for _, stat := range []string{
				"typha_snapshot_raw_bytes",
				"typha_snapshot_compressed_bytes",
			} {
				value, _ := getPerSyncerGauge(syncproto.SyncerTypeFelix, stat)
				log.Infof("%s: gauge: %s =  %v", note, stat, int(value))
			}
		}

		BeforeEach(func() {
			// These tests use a lot of KVs so debug is too aggressive.
			log.SetLevel(log.InfoLevel)
			logStats("Start of test")
			h.SendInitialSnapshotConfigs(initialSnapshotSize)

			// Make sure we don't start a client until the initial snapshot
			// flows through to the cache.
			Eventually(func() int {
				return h.FelixCache.CurrentBreadcrumb().KVs.Len()
			}).Should(Equal(initialSnapshotSize))
		})

		AfterEach(func() {
			logStats("End of test")
		})

		It("client should get a grace period after reading the snapshot", func() {
			clientCxt, clientCancel := context.WithCancel(context.Background())
			recorder := NewRecorderChanSize(0) // Need a small channel so we can give back pressure.

			origGaugeValue, err := getPerSyncerCounter(syncproto.SyncerTypeFelix, "typha_connections_grace_used")
			Expect(err).NotTo(HaveOccurred())

			// Make the client block after it reads the first update.  This means the server will have started
			// streaming the snapshot but it shouldn't be able to finish streaming the snapshot.  Blocking for
			// >1s wastes the MaxFallBehind timeout so this client will need to rely on the
			// NewClientFallBehindGracePeriod, which should kick in only once we've finished reading the snapshot.
			recorder.BlockAfterNUpdates(1, 2500*time.Millisecond)

			client := syncclient.New(
				h.Discoverer(),
				"test-version",
				"test-host",
				"test-info",
				recorder,
				&syncclient.Options{
					// The snapshot is >10MB; set the read buffer to something much less than that since these
					// tests need to cause backpressure on Typha.
					ReadBufferSize: 1024 * 256,
					// Enable logging of every read since these tests depend on read and write timings.
					DebugLogReads: true,
				},
			)

			err = client.Start(clientCxt)
			recorderCtx, recorderCancel := context.WithCancel(context.Background())
			defer recorderCancel()
			go recorder.Loop(recorderCtx)
			Expect(err).NotTo(HaveOccurred())
			defer func() {
				clientCancel()
				client.Finished.Wait()
			}()

			// Wait until the client reads its first KV so that we know the server has started streaming the
			// first breadcrumb before we create a new one...
			Eventually(recorder.Len, time.Second).Should(BeNumerically(">", 0))

			log.SetLevel(log.DebugLevel)

			// Make a breadcrumb 1s later.
			log.Info("Sleeping 1s")
			time.Sleep(time.Second)
			log.Info("Sending 1 update")
			h.SendConfigUpdates(1)
			log.Info("Sent 1 update")
			// Make a breadcrumb 1s later.
			log.Info("Sleeping 1s")
			time.Sleep(time.Second)
			log.Info("Sending 1 update")
			h.SendConfigUpdates(1)
			log.Info("Sent 1 update")

			// Client should wake up around now and start catching up.

			// Make a breadcrumb 1s later.
			log.Info("Sleeping 1s")
			time.Sleep(time.Second)
			log.Info("Sending 1 update")
			h.SendConfigUpdates(1)
			log.Info("Sent 1 update")

			Eventually(recorder.Len, 2*time.Second).Should(BeNumerically("==", initialSnapshotSize+3))
			Expect(getPerSyncerCounter(syncproto.SyncerTypeFelix, "typha_connections_grace_used")).To(BeNumerically("==", origGaugeValue+1))
		})

		It("client should get disconnected if it falls behind after the grace period", func() {
			clientCxt, clientCancel := context.WithCancel(context.Background())
			recorder := NewRecorderChanSize(0)

			origGaugeValue, err := getPerSyncerCounter(syncproto.SyncerTypeFelix, "typha_connections_grace_used")
			Expect(err).NotTo(HaveOccurred())

			// Make the client block after it reads the first update _after_ the snapshot.  This means it will
			// Quickly read hte snapshot, then catch up to the latest breadcrumb and _then_ start to fall behind.
			// This invalidates the grace period so it will only get the normal "max fall behind" timeout.
			recorder.BlockAfterNUpdates(initialSnapshotSize+1, 2500*time.Millisecond)

			client := syncclient.New(
				h.Discoverer(),
				"test-version",
				"test-host",
				"test-info",
				recorder,
				nil,
			)
			err = client.Start(clientCxt)
			recorderCtx, recorderCancel := context.WithCancel(context.Background())
			defer recorderCancel()
			go recorder.Loop(recorderCtx)
			Expect(err).NotTo(HaveOccurred())
			defer func() {
				clientCancel()
				client.Finished.Wait()
			}()

			// Wait until the snapshot is read.
			Eventually(recorder.Len, time.Second).Should(BeNumerically("==", initialSnapshotSize))

			// Send a lot of updates.

			log.Info("Sleeping 1s")
			time.Sleep(time.Second)
			log.Info("Send many updates...")
			h.SendConfigUpdates(initialSnapshotSize)

			// Client should read the first update from the above and then block.

			// Make a breadcrumb 1s later.
			log.Info("Sleeping 1s")
			time.Sleep(time.Second)
			log.SetLevel(log.DebugLevel)
			log.Info("Sending one update")
			h.SendConfigUpdates(1)

			// Make a breadcrumb 1s later.
			log.Info("Sleeping 1s")
			time.Sleep(time.Second)
			log.Info("Sending one update")
			h.SendConfigUpdates(1)

			// Client should wake up around now but be too far behind and get disconnected.

			log.Info("Waiting for client to be killed...")
			finishedC := make(chan struct{})
			go func() {
				client.Finished.Wait()
				close(finishedC)
			}()

			Eventually(finishedC, 5*time.Second).Should(BeClosed())

			// Should only have received at most the first two chunks.
			Expect(recorder.Len()).To(BeNumerically(">", initialSnapshotSize))
			Expect(recorder.Len()).To(BeNumerically("<=", initialSnapshotSize*2))

			// Should not use the grace period at all.
			Expect(getPerSyncerCounter(syncproto.SyncerTypeFelix, "typha_connections_grace_used")).To(BeNumerically("==", origGaugeValue))
		})
	})
})

var _ = Describe("With an in-process Server with short write timeout", func() {
	var h *ServerHarness

	BeforeEach(func() {
		// Default to debug but some more aggressive tests override this below.
		log.SetLevel(log.InfoLevel)
		h = NewHarness()

		// Effectively disable pings, so we can hit the other timeouts reliably.
		h.Config.PingInterval = 10000 * time.Second
		h.Config.PongTimeout = 50000 * time.Second

		// Short timeouts so we can hit them quickly.
		h.Config.WriteTimeout = 250 * time.Millisecond

		// The snapshot is >10MB; set the write buffer to something much less than that since these
		// tests need to cause backpressure on Typha.
		h.Config.WriteBufferSize = 1024 * 256
		// Since we rely on back-pressure, it's really handy to have a log of exactly what writes
		// happen and when.
		h.Config.DebugLogWrites = true

		h.Start()
	})

	AfterEach(func() {
		h.Stop()
	})

	Describe("with lots of KVs", func() {
		const initialSnapshotSize = 10000

		logStats := func(note string) {
			for _, stat := range []string{
				"typha_snapshots_generated",
			} {
				value, _ := getPerSyncerCounter(syncproto.SyncerTypeFelix, stat)
				log.Infof("%s: counter: %s =  %v", note, stat, int(value))
			}
			for _, stat := range []string{
				"typha_snapshot_raw_bytes",
				"typha_snapshot_compressed_bytes",
			} {
				value, _ := getPerSyncerGauge(syncproto.SyncerTypeFelix, stat)
				log.Infof("%s: gauge: %s =  %v", note, stat, int(value))
			}
		}

		BeforeEach(func() {
			logStats("Start of test")
			h.SendInitialSnapshotConfigs(initialSnapshotSize)
		})

		AfterEach(func() {
			logStats("End of test")
		})

		for _, disabledDecoderRestart := range []bool{true, false} {
			disabledDecoderRestart := disabledDecoderRestart
			It(fmt.Sprintf("client (DisabledDecoderRestart=%v) that blocks while reading snapshot should get disconnected", disabledDecoderRestart),
				func() {
					clientCxt, clientCancel := context.WithCancel(context.Background())
					defer clientCancel()
					recorder := NewRecorderChanSize(0) // Need a small channel so we can give back pressure.

					// Make the client block after it reads the first update.
					recorder.BlockAfterNUpdates(1, 1*time.Second)

					client := syncclient.New(
						h.Discoverer(),
						"test-version",
						"test-host",
						"test-info",
						recorder,
						&syncclient.Options{
							// The snapshot is >10MB; set the read buffer to something much less than that since these
							// tests need to cause backpressure on Typha.
							ReadBufferSize: 1024 * 256,
							// Enable logging of every read since these tests depend on read and write timings.
							DebugLogReads:         true,
							DisableDecoderRestart: disabledDecoderRestart,
						},
					)

					err := client.Start(clientCxt)
					recorderCtx, recorderCancel := context.WithCancel(context.Background())
					defer recorderCancel()
					go recorder.Loop(recorderCtx)
					Expect(err).NotTo(HaveOccurred())
					defer func() {
						clientCancel()
						log.Info("Waiting for client to stop...")
						client.Finished.Wait()
						log.Info("Client stopped.")
					}()

					// We should get at least the first KV...
					Eventually(recorder.Len, time.Second).Should(BeNumerically(">", 0))

					// But then get disconnected.
					finishedC := make(chan struct{})
					go func() {
						client.Finished.Wait()
						close(finishedC)
					}()

					Eventually(finishedC, 5*time.Second).Should(BeClosed())
					expectGlobalGaugeValue("typha_connections_active", 0.0)
				},
			)
		}
	})
})

func getGlobalGauge(name string) (float64, error) {
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		return 0, err
	}
	for _, mf := range mfs {
		if mf.GetName() == name {
			return mf.Metric[0].GetGauge().GetValue(), nil
		}
	}
	return 0, errors.New("not found")
}

func expectGlobalGaugeValue(name string, value float64) {
	EventuallyWithOffset(1, func() (float64, error) {
		return getGlobalGauge(name)
	}).Should(Equal(value))
}

func getPerSyncerCounter(syncer syncproto.SyncerType, name string) (float64, error) {
	m, err := getPerSyncerMetric(name, syncer)
	if err != nil {
		return 0, err
	}
	if m == nil {
		return 0, nil
	}
	return m.GetCounter().GetValue(), nil
}

func expectPerSyncerGaugeValue(syncer syncproto.SyncerType, name string, value float64) {
	EventuallyWithOffset(1, func() (float64, error) {
		return getPerSyncerGauge(syncer, name)
	}).Should(Equal(value))
}

func getPerSyncerGauge(syncer syncproto.SyncerType, name string) (float64, error) {
	m, err := getPerSyncerMetric(name, syncer)
	if err != nil {
		return 0, err
	}
	if m == nil {
		return 0, nil
	}
	return m.GetGauge().GetValue(), nil
}

func getPerSyncerMetric(name string, syncer syncproto.SyncerType) (*io_prometheus_client.Metric, error) {
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		return nil, err
	}
	for _, mf := range mfs {
		if mf.GetName() == name {
			for _, m := range mf.Metric {
				for _, l := range m.Label {
					if l.GetName() == "syncer" && l.GetValue() == string(syncer) {
						return m, nil
					}
				}
			}
			// Found the metric but no value for that syncer yet.
			return nil, nil
		}
	}
	return nil, errors.New("metric not found")
}

// TLS connection tests.

const (
	clientCN     = "typha-client"
	serverCN     = "typha-server"
	clientURISAN = "spiffe://k8s.example.com/typha-client"
	serverURISAN = "spiffe://k8s.example.com/typha-server"
)

var _ = Describe("with server requiring TLS", func() {
	var certDir string

	BeforeEach(func() {
		// Generating certs is expensive, so we defer it until this BeforeEach and then reuse the certs for all the
		// tests.
		if certDir != "" {
			return
		}

		// Create a temporary directory for certificates.
		var err error
		certDir, err = os.MkdirTemp("", "typhafv")
		tlsutils.PanicIfErr(err)

		// Trusted CA.
		caCert, caKey := tlsutils.MakeCACert("trustedCA")
		tlsutils.WriteCert(caCert.Raw, filepath.Join(certDir, "ca.crt"))

		// An untrusted CA.
		untrustedCert, untrustedKey := tlsutils.MakeCACert("untrustedCA")
		tlsutils.WriteCert(untrustedCert.Raw, filepath.Join(certDir, "untrusted.crt"))

		// Typha server.
		serverCert, serverKey := tlsutils.MakePeerCert(serverCN, serverURISAN, x509.ExtKeyUsageServerAuth, caCert, caKey)
		tlsutils.WriteKey(serverKey, filepath.Join(certDir, "server.key"))
		tlsutils.WriteCert(serverCert, filepath.Join(certDir, "server.crt"))

		// Typha server using untrusted CA.
		serverCert, serverKey = tlsutils.MakePeerCert(serverCN, serverURISAN, x509.ExtKeyUsageServerAuth, untrustedCert, untrustedKey)
		tlsutils.WriteKey(serverKey, filepath.Join(certDir, "server-untrusted.key"))
		tlsutils.WriteCert(serverCert, filepath.Join(certDir, "server-untrusted.crt"))

		// Typha client with good CN.
		clientCert, clientKey := tlsutils.MakePeerCert(clientCN, "", x509.ExtKeyUsageClientAuth, caCert, caKey)
		tlsutils.WriteKey(clientKey, filepath.Join(certDir, "goodcn.key"))
		tlsutils.WriteCert(clientCert, filepath.Join(certDir, "goodcn.crt"))

		// Typha client with good URI.
		clientCert, clientKey = tlsutils.MakePeerCert("", clientURISAN, x509.ExtKeyUsageClientAuth, caCert, caKey)
		tlsutils.WriteKey(clientKey, filepath.Join(certDir, "gooduri.key"))
		tlsutils.WriteCert(clientCert, filepath.Join(certDir, "gooduri.crt"))

		// Typha client with good CN and URI.
		clientCert, clientKey = tlsutils.MakePeerCert(clientCN, clientURISAN, x509.ExtKeyUsageClientAuth, caCert, caKey)
		tlsutils.WriteKey(clientKey, filepath.Join(certDir, "goodcnuri.key"))
		tlsutils.WriteCert(clientCert, filepath.Join(certDir, "goodcnuri.crt"))

		// Typha client with bad CN and URI.
		clientCert, clientKey = tlsutils.MakePeerCert(clientCN+"bad", clientURISAN+"bad", x509.ExtKeyUsageClientAuth, caCert, caKey)
		tlsutils.WriteKey(clientKey, filepath.Join(certDir, "badcnuri.key"))
		tlsutils.WriteCert(clientCert, filepath.Join(certDir, "badcnuri.crt"))

		// Typha client using untrusted CA.
		clientCert, clientKey = tlsutils.MakePeerCert(clientCN, clientURISAN, x509.ExtKeyUsageClientAuth, untrustedCert, untrustedKey)
		tlsutils.WriteKey(clientKey, filepath.Join(certDir, "client-untrusted.key"))
		tlsutils.WriteCert(clientCert, filepath.Join(certDir, "client-untrusted.crt"))
	})

	_ = AfterSuite(func() {
		// Remove TLS keys and certificates.
		if certDir != "" {
			_ = os.RemoveAll(certDir)
		}
	})

	// We'll create this pipeline for updates to flow through:
	//
	//    This goroutine -> callback -chan-> validation -> snapshot -> server
	//                      decoupler        filter        cache
	//
	var (
		decoupler    *calc.SyncerCallbacksDecoupler
		valFilter    *calc.ValidationFilter
		cacheCxt     context.Context
		cacheCancel  context.CancelFunc
		cache        *snapcache.Cache
		server       *syncserver.Server
		serverCxt    context.Context
		serverCancel context.CancelFunc
	)

	var (
		requiredClientCN     string
		requiredClientURISAN string
		serverCertName       string
	)

	// Each client we create gets recorded here for cleanup.
	type clientState struct {
		clientCxt      context.Context
		clientCancel   context.CancelFunc
		recorderCancel context.CancelFunc
		client         *syncclient.SyncerClient
		recorder       *StateRecorder
		startErr       error
	}

	createClient := func(options *syncclient.Options) clientState {
		clientCxt, clientCancel := context.WithCancel(context.Background())
		recorderCxt, recorderCancel := context.WithCancel(context.Background())
		recorder := NewRecorder()
		serverAddr := fmt.Sprintf("127.0.0.1:%d", server.Port())
		client := syncclient.New(
			discovery.New(discovery.WithAddrOverride(serverAddr)),
			"test-version",
			"test-host-1",
			"test-info",
			recorder,
			options,
		)

		err := client.Start(clientCxt)
		go recorder.Loop(recorderCxt)

		cs := clientState{
			clientCxt:      clientCxt,
			client:         client,
			clientCancel:   clientCancel,
			recorderCancel: recorderCancel,
			recorder:       recorder,
			startErr:       err,
		}
		return cs
	}

	JustBeforeEach(func() {
		// Set up a pipeline:
		//
		//    This goroutine -> callback -chan-> validation -> snapshot -> server
		//                      decoupler        filter        cache
		//
		decoupler = calc.NewSyncerCallbacksDecoupler()
		cache = snapcache.New(snapcache.Config{
			// Set the batch size small so we can force new Breadcrumbs easily.
			MaxBatchSize: 10,
			// Reduce the wake up interval from the default to give us faster tear down.
			WakeUpInterval: 50 * time.Millisecond,
		})
		cacheCxt, cacheCancel = context.WithCancel(context.Background())
		valFilter = calc.NewValidationFilter(cache)
		go decoupler.SendToContext(cacheCxt, valFilter)
		server = syncserver.New(
			map[syncproto.SyncerType]syncserver.BreadcrumbProvider{syncproto.SyncerTypeFelix: cache},
			syncserver.Config{
				PingInterval: 10 * time.Second,
				Port:         syncserver.PortRandom,
				DropInterval: 50 * time.Millisecond,
				KeyFile:      filepath.Join(certDir, serverCertName+".key"),
				CertFile:     filepath.Join(certDir, serverCertName+".crt"),
				CAFile:       filepath.Join(certDir, "ca.crt"),
				ClientCN:     requiredClientCN,
				ClientURISAN: requiredClientURISAN,
			})
		cache.Start(cacheCxt)
		serverCxt, serverCancel = context.WithCancel(context.Background())
		server.Start(serverCxt)
	})

	AfterEach(func() {
		serverCancel()
		log.Info("Waiting for server to shut down")
		server.Finished.Wait()
		log.Info("Done waiting for server to shut down")
		cacheCancel()
	})

	testConnection := func(clientCertName string, expectConnection bool) {
		var options *syncclient.Options = nil
		if clientCertName != "" {
			options = &syncclient.Options{
				KeyFile:      filepath.Join(certDir, clientCertName+".key"),
				CertFile:     filepath.Join(certDir, clientCertName+".crt"),
				CAFile:       filepath.Join(certDir, "ca.crt"),
				ServerCN:     serverCN,
				ServerURISAN: serverURISAN,
			}
			// Client config's CAFile must be the CA that signed its CertFile;
			// otherwise it appears that the golang TLS client-side code does not even
			// send its certificate to the server.
			if clientCertName == "client-untrusted" {
				options.CAFile = filepath.Join(certDir, "untrusted.crt")
			}
		}
		// Connect with specified TLS options.
		clientState := createClient(options)
		defer clientState.recorderCancel()
		if clientCertName == "" || expectConnection {
			// Expecting this connection to succeed so there should be no error from Start().
			Expect(clientState.startErr).NotTo(HaveOccurred())
		}

		// Prepare channel that will be unblocked when the client connection is closed.
		connectionClosed := make(chan struct{})
		go func() {
			defer close(connectionClosed)
			log.Info("Waiting for client to shut down")
			clientState.client.Finished.Wait()
			log.Info("Done waiting for client to shut down")
		}()

		// Generate a state change on the Typha server.
		decoupler.OnStatusUpdated(api.ResyncInProgress)
		decoupler.OnUpdates([]api.Update{configFoobarBazzBiff})
		decoupler.OnStatusUpdated(api.InSync)
		if expectConnection {
			// Client should be connected, so should see that state.
			Eventually(clientState.recorder.Status).Should(Equal(api.InSync))
			Eventually(clientState.recorder.KVs).Should(Equal(map[string]api.Update{
				"/calico/v1/config/foobar": configFoobarBazzBiff,
			}))
			// Now get the client to disconnect.
			clientState.clientCancel()
		}

		// For successful connections we just told the client to stop.  For unsuccessful connections
		// it should detect the failure and stop on its own.
		Eventually(connectionClosed).Should(BeClosed())

		if !expectConnection {
			// Client connection should have failed, so should not have got any updates.
			Consistently(clientState.recorder.KVs).Should(Equal(map[string]api.Update{}))
		}
	}

	testNonTLS := func() {
		testConnection("", false)
	}

	testTLSUntrusted := func() {
		testConnection("client-untrusted", false)
	}

	testTLSGoodCN := func(expectConnection bool) func() {
		return func() {
			testConnection("goodcn", expectConnection)
		}
	}

	testTLSGoodURI := func(expectConnection bool) func() {
		return func() {
			testConnection("gooduri", expectConnection)
		}
	}

	testTLSGoodCNURI := func(expectConnection bool) func() {
		return func() {
			testConnection("goodcnuri", expectConnection)
		}
	}

	testTLSBadCNURI := func(expectConnection bool) func() {
		return func() {
			testConnection("badcnuri", expectConnection)
		}
	}

	Describe("and CN or URI SAN", func() {
		BeforeEach(func() {
			requiredClientCN = clientCN
			requiredClientURISAN = clientURISAN
			serverCertName = "server"
		})

		It("should reject non-TLS connection", testNonTLS)

		It("should reject TLS untrusted", testTLSUntrusted)

		It("should allow TLS with good CN", testTLSGoodCN(true))

		It("should allow TLS with good URI", testTLSGoodURI(true))

		It("should allow TLS with good CN and URI", testTLSGoodCNURI(true))

		It("should reject TLS with bad CN and URI", testTLSBadCNURI(false))
	})

	Describe("and CN", func() {
		BeforeEach(func() {
			requiredClientCN = clientCN
			requiredClientURISAN = ""
			serverCertName = "server"
		})

		It("should reject non-TLS connection", testNonTLS)

		It("should reject TLS untrusted", testTLSUntrusted)

		It("should allow TLS with good CN", testTLSGoodCN(true))

		It("should reject TLS with good URI", testTLSGoodURI(false))

		It("should allow TLS with good CN and URI", testTLSGoodCNURI(true))

		It("should reject TLS with bad CN and URI", testTLSBadCNURI(false))
	})

	Describe("and URI SAN", func() {
		BeforeEach(func() {
			requiredClientCN = ""
			requiredClientURISAN = clientURISAN
			serverCertName = "server"
		})

		It("should reject non-TLS connection", testNonTLS)

		It("should reject TLS untrusted", testTLSUntrusted)

		It("should reject TLS with good CN", testTLSGoodCN(false))

		It("should allow TLS with good URI", testTLSGoodURI(true))

		It("should allow TLS with good CN and URI", testTLSGoodCNURI(true))

		It("should reject TLS with bad CN and URI", testTLSBadCNURI(false))
	})

	Describe("using untrusted certificate", func() {
		BeforeEach(func() {
			requiredClientCN = ""
			requiredClientURISAN = clientURISAN
			serverCertName = "server-untrusted"
		})

		It("non-TLS connection should fail", testNonTLS)

		It("TLS connection with good CN should fail", testTLSGoodCN(false))

		It("TLS connection with good URI should fail", testTLSGoodURI(false))

		It("TLS connection with good CN and URI should fail", testTLSGoodCNURI(false))
	})

	Describe("handshake", func() {
		BeforeEach(func() {
			requiredClientCN = clientCN
			requiredClientURISAN = clientURISAN
			serverCertName = "server"
		})

		It("should timeout after 10 seconds for TCP half open connections", func() {
			serverAddr := fmt.Sprintf("127.0.0.1:%d", server.Port())
			expectedDisconnectTime := time.Now().Add(10 * time.Second)
			tcpConn, err := net.Dial("tcp", serverAddr)
			Expect(err).NotTo(HaveOccurred())
			defer func() {
				_ = tcpConn.Close()
			}()
			err = tcpConn.SetDeadline(time.Now().Add(15 * time.Second))
			Expect(err).NotTo(HaveOccurred())

			// Client sends a few valid bytes of a Client hello but then stops...
			_, err = tcpConn.Write([]byte{16, 3, 01})
			Expect(err).NotTo(HaveOccurred())

			// Start a read that we don't expect to complete.
			received := make([]byte, 1024)
			_, err = tcpConn.Read(received)

			// io.EOF means the server closed the connection (we'd get
			// a timeout error if the deadline we set was reached.
			Expect(err).Should(Equal(io.EOF))
			// Should get disconnected at approximately the right time.
			Expect(time.Now()).Should(
				BeTemporally("~", expectedDisconnectTime, 2*time.Second),
				"Expected to be disconnected at approx 10s")
		})

		It("should allow connections while another connection is half-open", func() {
			// Set up a raw connection that just blocks at the handshake.
			log.Info("Sending blocking connection")
			serverAddr := fmt.Sprintf("127.0.0.1:%d", server.Port())
			conn, err := net.Dial("tcp", serverAddr)
			Expect(err).NotTo(HaveOccurred())
			tcpConn := conn.(*net.TCPConn)
			defer func() {
				_ = tcpConn.Close()
			}()
			log.Info("Blocking connection source:", tcpConn.LocalAddr())
			_, err = tcpConn.Write([]byte{16, 3, 01})
			Expect(err).NotTo(HaveOccurred())
			Eventually(server.NumActiveConnections).Should(Equal(1))

			// Set up a normal, valid connection.
			log.Info("Sending valid connection")
			startTime := time.Now()
			testConnection("gooduri", true)
			Expect(time.Now()).To(BeTemporally("<", startTime.Add(time.Second)))
			log.Info("Done")

			// The normal client closes its own connection.
			Eventually(server.NumActiveConnections).Should(Equal(1))

			// Closing the blocked one should get through to the server.
			_ = tcpConn.Close()
			Eventually(server.NumActiveConnections).Should(Equal(0))
		})
	})
})
