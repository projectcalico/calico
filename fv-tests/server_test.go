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

package fvtests_test

import (
	"context"
	"crypto/x509"
	"encoding/gob"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	. "github.com/onsi/ginkgo/extensions/table"

	v3 "github.com/projectcalico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/backend/encap"
	"github.com/projectcalico/libcalico-go/lib/backend/model"
	calinet "github.com/projectcalico/libcalico-go/lib/net"
	. "github.com/projectcalico/typha/fv-tests"
	"github.com/projectcalico/typha/pkg/calc"
	"github.com/projectcalico/typha/pkg/snapcache"
	"github.com/projectcalico/typha/pkg/syncclient"
	"github.com/projectcalico/typha/pkg/syncproto"
	"github.com/projectcalico/typha/pkg/syncserver"
	"github.com/projectcalico/typha/pkg/tlsutils"
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
			Key:      model.ResourceKey{Name: "node1", Kind: v3.KindNode},
			Value:    &v3.Node{},
			Revision: "1237",
		},
		UpdateType: api.UpdateTypeKVNew,
	}
	v3BGPPeer = api.Update{
		KVPair: model.KVPair{
			Key:      model.ResourceKey{Name: "peer1", Kind: v3.KindBGPPeer},
			Value:    &v3.BGPPeer{},
			Revision: "1238",
		},
		UpdateType: api.UpdateTypeKVNew,
	}
	blockAffCIDR = calinet.MustParseCIDR("10.0.1.0/26")
	blockAff1    = api.Update{
		KVPair: model.KVPair{
			Key:      model.BlockAffinityKey{CIDR: blockAffCIDR, Host: "node1"},
			Value:    &model.BlockAffinity{State: model.StateConfirmed},
			Revision: "1239",
		},
		UpdateType: api.UpdateTypeKVNew,
	}
)

// Tests that rely on starting a real Typha syncserver.Server (on a real TCP port) in this process.
// We drive the server via a real snapshot cache using the snapshot cache's function API.
var _ = Describe("With an in-process Server", func() {
	// We'll create this pipeline for updates to flow through:
	//
	//    This goroutine -> callback -chan-> validation -> snapshot -> server
	//                      decoupler        filter        cache
	//
	var (
		decoupler, bgpDecoupler *calc.SyncerCallbacksDecoupler
		valFilter               *calc.ValidationFilter
		cacheCxt                context.Context
		cacheCancel             context.CancelFunc
		felixCache, bgpCache    *snapcache.Cache
		server                  *syncserver.Server
		serverCxt               context.Context
		serverCancel            context.CancelFunc
	)

	// Each client we create gets recorded here for cleanup.
	type clientState struct {
		clientCxt    context.Context
		clientCancel context.CancelFunc
		client       *syncclient.SyncerClient
		recorder     *StateRecorder
		syncerType   syncproto.SyncerType
	}
	var clientStates []clientState

	createClient := func(id interface{}, syncType syncproto.SyncerType) clientState {
		clientCxt, clientCancel := context.WithCancel(context.Background())
		recorder := NewRecorder()
		client := syncclient.New(
			fmt.Sprintf("127.0.0.1:%d", server.Port()),
			"test-version",
			fmt.Sprintf("test-host-%v", id),
			"test-info",
			recorder,
			&syncclient.Options{
				SyncerType: syncType,
			},
		)

		err := client.Start(clientCxt)
		Expect(err).NotTo(HaveOccurred())

		cs := clientState{
			clientCxt:    clientCxt,
			client:       client,
			clientCancel: clientCancel,
			recorder:     recorder,
			syncerType:   syncType,
		}
		return cs
	}

	createClients := func(n int) {
		clientStates = nil
		for i := 0; i < n; i++ {
			cs := createClient(i, syncproto.SyncerTypeFelix)
			clientStates = append(clientStates, cs)
		}
	}

	BeforeEach(func() {
		// Set up a pipeline:
		//
		//    This goroutine -> callback -chan-> validation -> snapshot -> server
		//                      decoupler        filter        cache
		//
		decoupler = calc.NewSyncerCallbacksDecoupler()
		felixCache = snapcache.New(snapcache.Config{
			// Set the batch size small so we can force new Breadcrumbs easily.
			MaxBatchSize: 10,
			// Reduce the wake up interval from the default to give us faster tear down.
			WakeUpInterval: 50 * time.Millisecond,
		})
		bgpDecoupler = calc.NewSyncerCallbacksDecoupler()
		bgpCache = snapcache.New(snapcache.Config{
			// Set the batch size small so we can force new Breadcrumbs easily.
			MaxBatchSize: 10,
			// Reduce the wake up interval from the default to give us faster tear down.
			WakeUpInterval: 50 * time.Millisecond,
		})
		cacheCxt, cacheCancel = context.WithCancel(context.Background())
		valFilter = calc.NewValidationFilter(felixCache)
		go decoupler.SendToContext(cacheCxt, valFilter)
		go bgpDecoupler.SendToContext(cacheCxt, bgpCache)
		server = syncserver.New(
			map[syncproto.SyncerType]syncserver.BreadcrumbProvider{
				syncproto.SyncerTypeFelix: felixCache,
				syncproto.SyncerTypeBGP:   bgpCache,
			},
			syncserver.Config{
				PingInterval: 10 * time.Second,
				Port:         syncserver.PortRandom,
				DropInterval: 50 * time.Millisecond,
			})
		felixCache.Start(cacheCxt)
		bgpCache.Start(cacheCxt)
		serverCxt, serverCancel = context.WithCancel(context.Background())
		server.Start(serverCxt)
	})

	AfterEach(func() {
		for _, c := range clientStates {
			c.clientCancel()
			if c.client != nil {
				log.Info("Waiting for client to shut down.")
				c.client.Finished.Wait()
				log.Info("Done waiting for client to shut down.")
			}
		}

		serverCancel()
		log.Info("Waiting for server to shut down")
		server.Finished.Wait()
		log.Info("Done waiting for server to shut down")
		cacheCancel()
	})

	It("should choose a port", func() {
		Expect(server.Port()).ToNot(BeZero())
	})

	sendNUpdatesThenInSync := func(n int) map[string]api.Update {
		expectedEndState := map[string]api.Update{}
		decoupler.OnStatusUpdated(api.ResyncInProgress)
		for i := 0; i < n; i++ {
			update := api.Update{
				KVPair: model.KVPair{
					Key: model.GlobalConfigKey{
						Name: fmt.Sprintf("foo%v", i),
					},
					Value:    fmt.Sprintf("baz%v", i),
					Revision: fmt.Sprintf("%v", i),
				},
				UpdateType: api.UpdateTypeKVNew,
			}
			path, err := model.KeyToDefaultPath(update.Key)
			Expect(err).NotTo(HaveOccurred())
			expectedEndState[path] = update
			decoupler.OnUpdates([]api.Update{update})
		}
		decoupler.OnStatusUpdated(api.InSync)
		return expectedEndState
	}

	Describe("with a client connection", func() {
		var clientCancel context.CancelFunc
		var recorder *StateRecorder

		BeforeEach(func() {
			createClients(1)
			clientCancel = clientStates[0].clientCancel
			recorder = clientStates[0].recorder
		})

		// expectFelixClientState asserts that the client eventually reaches the given state.  Then, it
		// simulates a second connection and check that that also converges to the given state.
		expectClientState := func(c clientState, status api.SyncStatus, kvs map[string]api.Update) {
			// Wait until we reach that state.
			Eventually(c.recorder.Status).Should(Equal(status))
			Eventually(c.recorder.KVs).Should(Equal(kvs))

			// Now, a newly-connecting client should also reach the same state.
			log.Info("Starting transient client to read snapshot.")

			transientClient := createClient("transient", c.syncerType)
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
			expectClientState(clientStates[0], status, kvs)
		}

		It("should drop a bad KV", func() {
			// Bypass the validation filter (which also converts Nodes to HostIPs).
			felixCache.OnStatusUpdated(api.ResyncInProgress)
			felixCache.OnUpdates([]api.Update{{
				KVPair: model.KVPair{
					// NodeKeys can't be serialized right now.
					Key:      model.NodeKey{Hostname: "foobar"},
					Value:    "bazzbiff",
					Revision: "1234",
					TTL:      12,
				},
				UpdateType: api.UpdateTypeKVNew,
			}})
			felixCache.OnStatusUpdated(api.InSync)
			expectFelixClientState(api.InSync, map[string]api.Update{})
		})

		It("validation should drop a bad Node", func() {
			valFilter.OnStatusUpdated(api.ResyncInProgress)
			valFilter.OnUpdates([]api.Update{{
				KVPair: model.KVPair{
					Key:      model.NodeKey{Hostname: "foobar"},
					Value:    "bazzbiff",
					Revision: "1234",
					TTL:      12,
				},
				UpdateType: api.UpdateTypeKVNew,
			}})
			valFilter.OnStatusUpdated(api.InSync)
			expectFelixClientState(api.InSync, map[string]api.Update{})
		})

		It("validation should convert a valid Node", func() {
			valFilter.OnStatusUpdated(api.ResyncInProgress)
			valFilter.OnUpdates([]api.Update{{
				KVPair: model.KVPair{
					Key: model.NodeKey{Hostname: "foobar"},
					Value: &model.Node{
						FelixIPv4: calinet.ParseIP("10.0.0.1"),
					},
					Revision: "1234",
				},
				UpdateType: api.UpdateTypeKVNew,
			}})
			valFilter.OnStatusUpdated(api.InSync)
			expectFelixClientState(api.InSync, map[string]api.Update{
				"/calico/v1/host/foobar/bird_ip": {
					KVPair: model.KVPair{
						Key:      model.HostIPKey{Hostname: "foobar"},
						Value:    &calinet.IP{net.ParseIP("10.0.0.1")},
						Revision: "1234",
					},
					UpdateType: api.UpdateTypeKVNew,
				}})
		})

		It("should pass through a KV and status", func() {
			decoupler.OnStatusUpdated(api.ResyncInProgress)
			decoupler.OnUpdates([]api.Update{configFoobarBazzBiff})
			decoupler.OnStatusUpdated(api.InSync)
			Eventually(recorder.Status).Should(Equal(api.InSync))
			expectFelixClientState(
				api.InSync,
				map[string]api.Update{
					"/calico/v1/config/foobar": configFoobarBazzBiff,
				},
			)
		})

		Describe("with a BGP client", func() {
			var bgpClient clientState

			BeforeEach(func() {
				bgpClient = createClient("bgp", syncproto.SyncerTypeBGP)
			})

			DescribeTable("should pass through BGP KV pairs",
				func(update api.Update, v1key string) {
					bgpDecoupler.OnStatusUpdated(api.ResyncInProgress)
					bgpDecoupler.OnUpdates([]api.Update{update})
					bgpDecoupler.OnStatusUpdated(api.InSync)
					Eventually(bgpClient.recorder.Status).Should(Equal(api.InSync))
					expectClientState(
						bgpClient,
						api.InSync,
						map[string]api.Update{
							v1key: update,
						},
					)
					// Our updates shouldn't affect the felix syncer.
					expectFelixClientState(api.WaitForDatastore, map[string]api.Update{})
				},
				Entry("IP pool", ipPool1, "/calico/v1/ipam/v4/pool/10.0.1.0-24"),
				Entry("Node conf", nodeBGPConfNode, "/calico/bgp/v1/host/node1/foo"),
				Entry("Global conf", nodeBGPConfGlobal, "/calico/bgp/v1/global/bar"),
				Entry("Node", v3Node, "/calico/resources/v3/projectcalico.org/nodes/node1"),
				Entry("BGP peer", v3BGPPeer, "/calico/resources/v3/projectcalico.org/bgppeers/peer1"),
				Entry("Block affinity", blockAff1, "/calico/ipam/v2/host/node1/ipv4/block/10.0.1.0-26"),
			)

			It("should handle a felix and BGP client at same time", func() {
				bgpDecoupler.OnStatusUpdated(api.ResyncInProgress)
				decoupler.OnStatusUpdated(api.ResyncInProgress)
				bgpDecoupler.OnUpdates([]api.Update{ipPool1})
				decoupler.OnUpdates([]api.Update{configFoobarBazzBiff})
				decoupler.OnStatusUpdated(api.InSync)
				bgpDecoupler.OnStatusUpdated(api.InSync)

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
			decoupler.OnUpdates([]api.Update{configFoobarBazzBiff})
			decoupler.OnUpdates([]api.Update{configFoobar2BazzBiff})
			decoupler.OnStatusUpdated(api.InSync)
			expectFelixClientState(api.InSync, map[string]api.Update{
				"/calico/v1/config/foobar":  configFoobarBazzBiff,
				"/calico/v1/config/foobar2": configFoobar2BazzBiff,
			})
			decoupler.OnUpdates([]api.Update{configFoobarDeleted})
			expectFelixClientState(api.InSync, map[string]api.Update{
				"/calico/v1/config/foobar2": configFoobar2BazzBiff,
			})
			decoupler.OnUpdates([]api.Update{configFoobar2Invalid})
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
				decoupler.OnUpdates([]api.Update{upd})
				rev++
				if i >= halfNumKeys {
					expectedState[fmt.Sprintf("/calico/v1/config/foobar%d", i)] = upd
				}
			}
			for i := 0; i < halfNumKeys; i++ {
				decoupler.OnUpdates([]api.Update{{
					KVPair: model.KVPair{
						Key:      model.GlobalConfigKey{Name: fmt.Sprintf("foobar%d", i)},
						Revision: fmt.Sprintf("%d", rev),
					},
					UpdateType: api.UpdateTypeKVDeleted,
				}})
				rev++
			}
			decoupler.OnStatusUpdated(api.InSync)
			expectFelixClientState(api.InSync, expectedState)
		})

		It("should pass through many KVs", func() {
			expectedEndState := sendNUpdatesThenInSync(1000)
			expectFelixClientState(api.InSync, expectedEndState)
		})

		It("should report the correct number of connections", func() {
			expectGaugeValue("typha_connections_active", 1.0)
		})

		It("should report the correct number of connections after killing the client", func() {
			clientCancel()
			expectGaugeValue("typha_connections_active", 0.0)
		})
	})

	Describe("with 100 client connections", func() {
		BeforeEach(func() {
			createClients(100)
		})

		// expectClientState asserts that every client eventually reaches the given state.
		expectClientStates := func(status api.SyncStatus, kvs map[string]api.Update) {
			for _, s := range clientStates {
				// Wait until we reach that state.
				Eventually(s.recorder.Status, 10*time.Second, 200*time.Millisecond).Should(Equal(status))
				Eventually(s.recorder.KVs, 10*time.Second).Should(Equal(kvs))
			}
		}

		It("should drop expected number of connections", func() {
			// Start a goroutine to watch each client and send us a message on the channel when it stops.
			finishedC := make(chan int)
			for _, s := range clientStates {
				go func(s clientState) {
					s.client.Finished.Wait()
					finishedC <- 1
				}(s)
			}

			// We start with 100 connections, set the max to 60 so we kill 40 connections.
			server.SetMaxConns(60)

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
			expectGaugeValue("typha_connections_active", 60.0)
		})

		It("should pass through a KV and status", func() {
			decoupler.OnStatusUpdated(api.ResyncInProgress)
			decoupler.OnUpdates([]api.Update{configFoobarBazzBiff})
			decoupler.OnStatusUpdated(api.InSync)
			expectClientStates(
				api.InSync,
				map[string]api.Update{
					"/calico/v1/config/foobar": configFoobarBazzBiff,
				},
			)
		})

		It("should pass through many KVs", func() {
			expectedEndState := sendNUpdatesThenInSync(1000)
			expectClientStates(api.InSync, expectedEndState)
		})

		It("should report the correct number of connections", func() {
			expectGaugeValue("typha_connections_active", 100.0)
		})

		It("should report the correct number of connections after killing the clients", func() {
			for _, c := range clientStates {
				c.clientCancel()
			}
			expectGaugeValue("typha_connections_active", 0.0)
		})

		It("with churn, it should report the correct number of connections after killing the clients", func() {
			// Generate some churn while we disconnect the clients.
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				sendNUpdatesThenInSync(1000)
				wg.Done()
			}()
			defer wg.Wait()
			for _, c := range clientStates {
				c.clientCancel()
				time.Sleep(100 * time.Microsecond)
			}
			expectGaugeValue("typha_connections_active", 0.0)
		})
	})
})

var _ = Describe("With an in-process Server with short ping timeout", func() {
	var (
		cacheCxt        context.Context
		cacheCancel     context.CancelFunc
		cache, bgpCache *snapcache.Cache
		server          *syncserver.Server
		serverCxt       context.Context
		serverCancel    context.CancelFunc
		serverAddr      string
	)

	BeforeEach(func() {
		cache = snapcache.New(snapcache.Config{
			// Set the batch size small so we can force new Breadcrumbs easily.
			MaxBatchSize: 10,
			// Reduce the wake up interval from the default to give us faster tear down.
			WakeUpInterval: 50 * time.Millisecond,
		})
		bgpCache = snapcache.New(snapcache.Config{
			// Set the batch size small so we can force new Breadcrumbs easily.
			MaxBatchSize: 10,
			// Reduce the wake up interval from the default to give us faster tear down.
			WakeUpInterval: 50 * time.Millisecond,
		})
		server = syncserver.New(
			map[syncproto.SyncerType]syncserver.BreadcrumbProvider{
				syncproto.SyncerTypeFelix: cache,
				syncproto.SyncerTypeBGP:   bgpCache,
			},
			syncserver.Config{
				PingInterval: 100 * time.Millisecond,
				PongTimeout:  500 * time.Millisecond,
				Port:         syncserver.PortRandom,
				DropInterval: 50 * time.Millisecond,
			})
		cacheCxt, cacheCancel = context.WithCancel(context.Background())
		cache.Start(cacheCxt)
		bgpCache.Start(cacheCxt)
		serverCxt, serverCancel = context.WithCancel(context.Background())
		server.Start(serverCxt)
		serverAddr = fmt.Sprintf("127.0.0.1:%d", server.Port())
	})

	AfterEach(func() {
		if server != nil {
			serverCancel()
			log.Info("Waiting for server to shut down")
			server.Finished.Wait()
			log.Info("Done waiting for server to shut down")
		}
		if cache != nil {
			cacheCancel()
		}
	})

	It("should not disconnect a responsive client", func() {
		// Start a real client, which will respond correctly to pings.
		clientCxt, clientCancel := context.WithCancel(context.Background())
		recorder := NewRecorder()
		client := syncclient.New(
			serverAddr,
			"test-version",
			"test-host",
			"test-info",
			recorder,
			nil,
		)
		err := client.Start(clientCxt)
		Expect(err).NotTo(HaveOccurred())
		defer func() {
			clientCancel()
			client.Finished.Wait()
		}()

		// Wait until we should have been dropped if we were unresponsive.  I.e. 1 pong timeout + 1 ping
		// interval for the check to take place.
		time.Sleep(1 * time.Second)

		// Then send an update.
		cache.OnStatusUpdated(api.InSync)
		Eventually(recorder.Status).Should(Equal(api.InSync))
	})

	Describe("with a raw connection", func() {
		var rawConn net.Conn
		var w *gob.Encoder
		var r *gob.Decoder

		BeforeEach(func() {
			var err error
			rawConn, err = net.DialTimeout("tcp", serverAddr, 10*time.Second)
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
			expectGaugeValue("typha_connections_active", 0.0)
		}

		It("should clean up if the hello doesn't get sent", func() {
			expectGaugeValue("typha_connections_active", 1.0)
			err := rawConn.Close()
			Expect(err).ToNot(HaveOccurred())
			expectGaugeValue("typha_connections_active", 0.0)
		})

		Describe("After sending Hello with bad syncer type", func() {
			BeforeEach(func() {
				err := w.Encode(syncproto.Envelope{
					Message: syncproto.MsgClientHello{
						Hostname:   "me",
						Version:    "test",
						Info:       "test info",
						SyncerType: syncproto.SyncerType("garbage"),
					},
				})
				Expect(err).NotTo(HaveOccurred())
			})

			It("should disconnect the client", func() {
				expectDisconnection(100 * time.Millisecond)
			})
		})

		Describe("After sending Hello", func() {
			BeforeEach(func() {
				err := w.Encode(syncproto.Envelope{
					Message: syncproto.MsgClientHello{
						Hostname: "me",
						Version:  "test",
						Info:     "test info",
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
	var (
		cacheCxt     context.Context
		cacheCancel  context.CancelFunc
		cache        *snapcache.Cache
		server       *syncserver.Server
		serverCxt    context.Context
		serverCancel context.CancelFunc
		serverAddr   string
	)

	BeforeEach(func() {
		cache = snapcache.New(snapcache.Config{
			// Set the batch size small so we can force new Breadcrumbs easily.
			MaxBatchSize: 10,
			// Reduce the wake up interval from the default to give us faster tear down.
			WakeUpInterval: 50 * time.Millisecond,
		})
		server = syncserver.New(
			map[syncproto.SyncerType]syncserver.BreadcrumbProvider{syncproto.SyncerTypeFelix: cache},
			syncserver.Config{
				PingInterval: 10000 * time.Second,
				PongTimeout:  50000 * time.Second,
				Port:         syncserver.PortRandom,
				DropInterval: 1 * time.Second,
			})
		cacheCxt, cacheCancel = context.WithCancel(context.Background())
		cache.Start(cacheCxt)
		serverCxt, serverCancel = context.WithCancel(context.Background())
		server.Start(serverCxt)
		serverAddr = fmt.Sprintf("127.0.0.1:%d", server.Port())
	})

	AfterEach(func() {
		if server != nil {
			serverCancel()
			log.Info("Waiting for server to shut down")
			server.Finished.Wait()
			log.Info("Done waiting for server to shut down")
		}
		if cache != nil {
			cacheCancel()
		}
	})

	It("client should disconnect after read timeout", func() {
		clientCxt, clientCancel := context.WithCancel(context.Background())
		recorder := NewRecorder()
		client := syncclient.New(
			serverAddr,
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

func getGauge(name string) (float64, error) {
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

func expectGaugeValue(name string, value float64) {
	Eventually(func() (float64, error) {
		return getGauge(name)
	}).Should(Equal(value))
}

// TLS connection tests.

const (
	clientCN     = "typha-client"
	serverCN     = "typha-server"
	clientURISAN = "spiffe://k8s.example.com/typha-client"
	serverURISAN = "spiffe://k8s.example.com/typha-server"
)

var certDir string

var _ = BeforeSuite(func() {
	// Create a temporary directory for certificates.
	var err error
	certDir, err = ioutil.TempDir("", "typhafv")
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

var _ = AfterSuite(func() {
	// Remove TLS keys and certificates.
	os.RemoveAll(certDir)
})

var _ = Describe("with server requiring TLS", func() {
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
		clientCxt    context.Context
		clientCancel context.CancelFunc
		client       *syncclient.SyncerClient
		recorder     *StateRecorder
		startErr     error
	}

	createClient := func(options *syncclient.Options) clientState {
		clientCxt, clientCancel := context.WithCancel(context.Background())
		recorder := NewRecorder()
		client := syncclient.New(
			fmt.Sprintf("127.0.0.1:%d", server.Port()),
			"test-version",
			"test-host-1",
			"test-info",
			recorder,
			options,
		)

		err := client.Start(clientCxt)

		cs := clientState{
			clientCxt:    clientCxt,
			client:       client,
			clientCancel: clientCancel,
			recorder:     recorder,
			startErr:     err,
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
		if clientCertName != "" && !expectConnection {
			// We're attempting a TLS connection but expecting it to fail.  That shows
			// up as Start() returning an error.
			Expect(clientState.startErr).To(HaveOccurred())
		} else {
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
		} else {
			// Client connection should have failed, so should not see that state.
			Consistently(clientState.recorder.Status).Should(Equal(api.SyncStatus(0)))
			Consistently(clientState.recorder.KVs).Should(Equal(map[string]api.Update{}))
		}

		// Synchronize with the client connection being closed.
		Eventually(connectionClosed).Should(BeClosed())
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
})
