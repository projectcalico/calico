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

package daemon_test

import (
	"errors"
	"strconv"
	"sync"
	"time"

	. "github.com/projectcalico/typha/pkg/daemon"

	"context"
	"fmt"
	"io/ioutil"
	"os"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/rand"

	"github.com/projectcalico/libcalico-go/lib/apiconfig"
	bapi "github.com/projectcalico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/libcalico-go/lib/health"
	"github.com/projectcalico/libcalico-go/lib/ipam"
	"github.com/projectcalico/typha/fv-tests"
	"github.com/projectcalico/typha/pkg/config"
	"github.com/projectcalico/typha/pkg/syncclient"
	"github.com/projectcalico/typha/pkg/syncserver"
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
				Expect(d.SyncerToValidator).ToNot(BeNil())
				Expect(d.Syncer).ToNot(BeNil())
				Expect(d.SyncerToValidator).ToNot(BeNil())
				Expect(d.ValidatorToCache).ToNot(BeNil())
				Expect(d.Validator).ToNot(BeNil())
				Expect(d.Cache).ToNot(BeNil())
				Expect(d.Server).ToNot(BeNil())
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
				cbs := fvtests.NewRecorder()
				client := syncclient.New(
					fmt.Sprintf("127.0.0.1:%d", port),
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
				d.SyncerToValidator.OnStatusUpdated(bapi.InSync)
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
					d.LoadConfiguration(cxt)
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

var _ = Context("Healthcheck command", func() {
	var d *TyphaDaemon
	var h *health.HealthAggregator
	var port int

	healthcheckRC := func(kind string) int {
		d.ParseCommandLineArgs([]string{
			"check", kind, fmt.Sprintf("--port=%d", port),
		})
		return d.CalculateHealthRC()
	}

	BeforeEach(func() {
		d = New()
		logrus.SetOutput(GinkgoWriter)
		logrus.SetLevel(logrus.DebugLevel)

		h = health.NewHealthAggregator()
		port = 19000 + GinkgoParallelNode()*1000 + rand.IntnRange(0, 1000)
		h.ServeHTTP(true, "127.0.0.1", port)
		h.RegisterReporter("test", &health.HealthReport{Live: true, Ready: true}, 10*time.Second)

		// Wait for the health server to start...
		Eventually(func() int {
			return healthcheckRC("liveness")
		}).Should(Equal(0))
	})

	Context("with live and ready", func() {
		BeforeEach(func() {
			h.Report("test", &health.HealthReport{Live: true, Ready: true})
		})

		It("should report ready", func() {
			Expect(healthcheckRC("readiness")).To(Equal(0))
		})
		It("should report live", func() {
			Expect(healthcheckRC("liveness")).To(Equal(0))
		})
	})

	Context("with live only", func() {
		BeforeEach(func() {
			h.Report("test", &health.HealthReport{Live: true, Ready: false})
		})

		It("should not report ready", func() {
			Expect(healthcheckRC("readiness")).NotTo(Equal(0))
		})
		It("should report live", func() {
			Expect(healthcheckRC("liveness")).To(Equal(0))
		})
	})

	Context("with neither ready or live", func() {
		BeforeEach(func() {
			h.Report("test", &health.HealthReport{Live: false, Ready: false})
		})

		It("should not report ready", func() {
			Expect(healthcheckRC("readiness")).NotTo(Equal(0))
		})
		It("should report live", func() {
			Expect(healthcheckRC("liveness")).NotTo(Equal(0))
		})
	})

	AfterEach(func() {
		h.ServeHTTP(false, "127.0.0.1", port)
	})
})

type mockDatastore struct {
	mutex        sync.Mutex
	syncerCalled bool
	initCalled   int
	failInit     bool
}

func (b *mockDatastore) SyncerByIface(callbacks bapi.SyncerCallbacks) bapi.Syncer {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	b.syncerCalled = true
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

func (b *mockDatastore) Backend() bapi.Client {
	panic("not implemented")
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
