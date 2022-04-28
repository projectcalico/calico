// Copyright (c) 2017-2018,2020 Tigera, Inc. All rights reserved.
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

package daemon_test

import (
	"errors"
	"strconv"
	"sync"
	"time"

	. "github.com/projectcalico/calico/typha/pkg/daemon"
	"github.com/projectcalico/calico/typha/pkg/discovery"

	"context"
	"fmt"
	"io/ioutil"
	"os"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	bapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam"
	fvtests "github.com/projectcalico/calico/typha/fv-tests"
	"github.com/projectcalico/calico/typha/pkg/config"
	"github.com/projectcalico/calico/typha/pkg/syncclient"
	"github.com/projectcalico/calico/typha/pkg/syncserver"
)

var configContents = []byte(`[default]
LogFilePath=none
`)

var _ = Describe("Daemon", func() {
	var d *TyphaDaemon
	var datastore *mockDatastore
	var newClientErr error
	var flagMutex sync.Mutex
	var earlyLoggingConfigured, loggingConfigured bool

	BeforeEach(func() {
		d = New()
		datastore = &mockDatastore{}
		d.NewClientV3 = func(config apiconfig.CalicoAPIConfig) (c DatastoreClient, err error) {
			return datastore, newClientErr
		}
		earlyLoggingConfigured = false
		loggingConfigured = false
		d.ConfigureEarlyLogging = func() {
			earlyLoggingConfigured = true
		}
		d.ConfigureLogging = func(config *config.Config) {
			Expect(config).ToNot(BeNil())
			flagMutex.Lock()
			defer flagMutex.Unlock()
			loggingConfigured = true
		}
	})

	It("shouldn't panic when DoEarlyRuntimeSetup is called", func() {
		d.DoEarlyRuntimeSetup()
		Expect(earlyLoggingConfigured).To(BeTrue())
	})

	It("should parse the config file path", func() {
		d.ParseCommandLineArgs([]string{"-c", "/tmp/config.cfg"})
		Expect(d.ConfigFilePath).To(Equal("/tmp/config.cfg"))
	})

	It("should parse the config file path", func() {
		d.ParseCommandLineArgs([]string{"--config", "/tmp/config.cfg"})
		Expect(d.ConfigFilePath).To(Equal("/tmp/config.cfg"))
	})

	It("should default the config file path", func() {
		d.ParseCommandLineArgs([]string{})
		Expect(d.ConfigFilePath).To(Equal("/etc/calico/typha.cfg"))
	})

	Describe("with a config file loaded", func() {
		var configFile *os.File
		var cxt context.Context
		var cancelFunc context.CancelFunc

		BeforeEach(func() {
			var err error
			configFile, err = ioutil.TempFile("", "typha")
			Expect(err).NotTo(HaveOccurred())

			_, err = configFile.Write(configContents)
			Expect(err).NotTo(HaveOccurred())
			err = configFile.Close()
			Expect(err).NotTo(HaveOccurred())

			d.ParseCommandLineArgs([]string{"-c", configFile.Name()})

			cxt, cancelFunc = context.WithTimeout(context.Background(), 10*time.Second)
		})

		AfterEach(func() {
			cancelFunc()
			err := os.Remove(configFile.Name())
			Expect(err).NotTo(HaveOccurred())
		})

		const (
			downSecs  = 2
			checkTime = "2s"
		)

		Describe("with datastore up", func() {
			JustBeforeEach(func() {
				err := d.LoadConfiguration(cxt)
				Expect(err).ToNot(HaveOccurred())
				Expect(loggingConfigured).To(BeTrue())
			})

			It("should load the configuration and connect to the datastore", func() {
				Eventually(datastore.getNumInitCalls).Should(Equal(1))
				Consistently(datastore.getNumInitCalls, checkTime, "1s").Should(Equal(1))
			})

			It("should create the server components", func() {
				d.CreateServer()
				Expect(d.SyncerPipelines).To(HaveLen(4))
				for _, p := range d.SyncerPipelines {
					Expect(p.SyncerToValidator).ToNot(BeNil())
					Expect(p.Syncer).ToNot(BeNil())
					Expect(p.SyncerToValidator).ToNot(BeNil())
					Expect(p.ValidatorToCache).ToNot(BeNil())
					Expect(p.Validator).ToNot(BeNil())
					Expect(p.Cache).ToNot(BeNil())
				}
				Expect(d.Server).ToNot(BeNil())
				Expect(datastore.bgpSyncerCalled).To(BeTrue())
				Expect(datastore.felixSyncerCalled).To(BeTrue())
				Expect(datastore.allocateTunnelIpSyncerCalled).To(BeTrue())
				Expect(datastore.nodestatusSyncerCalled).To(BeTrue())
			})

			It("should start a working server", func() {
				// Bypass the config validation to tell the server to pick a random port (so we won't clash)
				d.ConfigParams.ServerPort = syncserver.PortRandom
				d.CreateServer()

				// Start the server with a context that we can cancel.
				cxt, cancelFn := context.WithCancel(context.Background())
				defer cancelFn()
				d.Start(cxt)

				// Get the chosen port then start a real client in a context we can cancel.
				port := d.Server.Port()
				addr := fmt.Sprintf("127.0.0.1:%d", port)
				cbs := fvtests.NewRecorder()
				client := syncclient.New(
					[]discovery.Typha{{Addr: addr}},
					"",
					"",
					"",
					cbs,
					nil,
				)
				clientCxt, clientCancelFn := context.WithCancel(context.Background())
				defer func() {
					clientCancelFn()
					client.Finished.Wait()
				}()
				err := client.Start(clientCxt)
				Expect(err).NotTo(HaveOccurred())

				// Send in an update at the top of the processing pipeline.
				d.SyncerPipelines[0].SyncerToValidator.OnStatusUpdated(bapi.InSync)
				// It should make it all the way through to our recorder.
				Eventually(cbs.Status).Should(Equal(bapi.InSync))
			})
		})

		downSecsStr := strconv.Itoa(downSecs)

		Describe("with datastore down for "+downSecsStr+"s", func() {
			BeforeEach(func() {
				datastore.mutex.Lock()
				defer datastore.mutex.Unlock()
				datastore.failInit = true
			})

			JustBeforeEach(func() {
				// Kick off LoadConfiguration in a background thread since it will block trying to initialize the
				// datastore.
				go func() {
					defer GinkgoRecover()
					defer cancelFunc()
					_ = d.LoadConfiguration(cxt)
				}()
				Eventually(func() bool {
					flagMutex.Lock()
					defer flagMutex.Unlock()
					return loggingConfigured
				}).Should(BeTrue())

				time.Sleep(downSecs * time.Second)
			})

			It("should try >="+downSecsStr+" times to initialize the datastore", func() {
				Eventually(datastore.getNumInitCalls).Should(BeNumerically(">=", downSecs))
			})

			Describe("with datastore now available", func() {
				var numFailedInitCalls int

				JustBeforeEach(func() {
					datastore.mutex.Lock()
					defer datastore.mutex.Unlock()
					datastore.failInit = false
					numFailedInitCalls = datastore.initCalled
				})

				It("should initialize the datastore", func() {
					Eventually(datastore.getNumInitCalls, checkTime).Should(Equal(numFailedInitCalls + 1))
					Consistently(datastore.getNumInitCalls, checkTime, "1s").Should(Equal(numFailedInitCalls + 1))
				})
			})
		})
	})
})

type mockDatastore struct {
	mutex                        sync.Mutex
	allocateTunnelIpSyncerCalled bool
	bgpSyncerCalled              bool
	felixSyncerCalled            bool
	nodestatusSyncerCalled       bool
	initCalled                   int
	failInit                     bool
}

func (b *mockDatastore) FelixSyncerByIface(callbacks bapi.SyncerCallbacks) bapi.Syncer {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	b.felixSyncerCalled = true
	return &dummySyncer{}
}

func (b *mockDatastore) TunnelIPAllocationSyncerByIface(callbacks bapi.SyncerCallbacks) bapi.Syncer {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	b.allocateTunnelIpSyncerCalled = true
	return &dummySyncer{}
}

func (b *mockDatastore) BGPSyncerByIface(callbacks bapi.SyncerCallbacks) bapi.Syncer {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	b.bgpSyncerCalled = true
	return &dummySyncer{}
}

func (b *mockDatastore) NodeStatusSyncerByIface(callbacks bapi.SyncerCallbacks) bapi.Syncer {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	b.nodestatusSyncerCalled = true
	return &dummySyncer{}
}

func (b *mockDatastore) EnsureInitialized(ctx context.Context, version, clusterType string) error {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	b.initCalled++
	if b.failInit {
		return errors.New("Failure simulated by test code")
	}
	return nil
}

// Nodes returns an interface for managing node resources.
func (b *mockDatastore) Nodes() clientv3.NodeInterface {
	panic("not implemented")
}

// GlobalNetworkPolicies returns an interface for managing global network policy resources.
func (b *mockDatastore) GlobalNetworkPolicies() clientv3.GlobalNetworkPolicyInterface {
	panic("not implemented")
}

// GlobalNetworkPolicies returns an interface for managing global network policy resources.
func (b *mockDatastore) GlobalNetworkSets() clientv3.GlobalNetworkSetInterface {
	panic("not implemented")
}

// NetworkPolicies returns an interface for managing namespaced network policy resources.
func (b *mockDatastore) NetworkPolicies() clientv3.NetworkPolicyInterface {
	panic("not implemented")
}

// IPPools returns an interface for managing IP pool resources.
func (b *mockDatastore) IPPools() clientv3.IPPoolInterface {
	panic("not implemented")
}

// Profiles returns an interface for managing profile resources.
func (b *mockDatastore) Profiles() clientv3.ProfileInterface {
	panic("not implemented")
}

// HostEndpoints returns an interface for managing host endpoint resources.
func (b *mockDatastore) HostEndpoints() clientv3.HostEndpointInterface {
	panic("not implemented")
}

// WorkloadEndpoints returns an interface for managing workload endpoint resources.
func (b *mockDatastore) WorkloadEndpoints() clientv3.WorkloadEndpointInterface {
	panic("not implemented")
}

// BGPPeers returns an interface for managing BGP peer resources.
func (b *mockDatastore) BGPPeers() clientv3.BGPPeerInterface {
	panic("not implemented")
}

// IPAM returns an interface for managing IP address assignment and releasing.
func (b *mockDatastore) IPAM() ipam.Interface {
	panic("not implemented")
}

// BGPConfigurations returns an interface for managing the BGP configuration resources.
func (b *mockDatastore) BGPConfigurations() clientv3.BGPConfigurationInterface {
	panic("not implemented")
}

// FelixConfigurations returns an interface for managing the Felix configuration resources.
func (b *mockDatastore) FelixConfigurations() clientv3.FelixConfigurationInterface {
	panic("not implemented")
}

// ClusterInformation returns an interface for managing the cluster information resource.
func (b *mockDatastore) ClusterInformation() clientv3.ClusterInformationInterface {
	panic("not implemented")
}

// NetworkSets returns an interface for managing the networkSet resources.
func (b *mockDatastore) NetworkSets() clientv3.NetworkSetInterface {
	panic("not implemented")
}

// KubeControllersConfiguration returns an interface for managing the kubecontrollers configuration resources.
func (b *mockDatastore) KubeControllersConfiguration() clientv3.KubeControllersConfigurationInterface {
	panic("not implemented")
}

// CalicoNodeStatus returns an interface for managing the Calico node status resources.
func (b *mockDatastore) CalicoNodeStatus() clientv3.CalicoNodeStatusInterface {
	panic("not implemented")
}

func (b *mockDatastore) Backend() bapi.Client {
	panic("not implemented")
}

func (m *mockDatastore) IPReservations() clientv3.IPReservationInterface {
	panic("not implemented") // TODO: Implement
}

func (b *mockDatastore) getNumInitCalls() int {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	return b.initCalled
}

var _ RealClientV3 = (*mockDatastore)(nil)

type dummySyncer struct {
}

func (*dummySyncer) Start() {

}

func (*dummySyncer) Stop() {

}
