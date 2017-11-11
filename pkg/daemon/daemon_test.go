// Copyright (c) 2017 Tigera, Inc. All rights reserved.
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

	"github.com/projectcalico/libcalico-go/lib/apiconfig"
	bapi "github.com/projectcalico/libcalico-go/lib/backend/api"
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

		BeforeEach(func() {
			var err error
			configFile, err = ioutil.TempFile("", "typha")
			Expect(err).NotTo(HaveOccurred())

			_, err = configFile.Write(configContents)
			Expect(err).NotTo(HaveOccurred())
			err = configFile.Close()
			Expect(err).NotTo(HaveOccurred())

			d.ParseCommandLineArgs([]string{"-c", configFile.Name()})
		})
		JustBeforeEach(func() {
			d.LoadConfiguration()
			Expect(loggingConfigured).To(BeTrue())
		})
		AfterEach(func() {
			err := os.Remove(configFile.Name())
			Expect(err).NotTo(HaveOccurred())
		})

		const (
			downSecs  = 2
			checkTime = "2s"
		)
		downSecsStr := strconv.Itoa(downSecs)

		It("should load the configuration and connect to the datastore", func() {
			Eventually(datastore.getNumInitCalls).Should(Equal(1))
			Consistently(datastore.getNumInitCalls, checkTime, "1s").Should(Equal(1))
		})

		Describe("with datastore down for "+downSecsStr+"s", func() {
			BeforeEach(func() {
				datastore.mutex.Lock()
				defer datastore.mutex.Unlock()
				datastore.failInit = true
			})
			JustBeforeEach(func() {
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
					Eventually(datastore.getNumInitCalls).Should(Equal(numFailedInitCalls + 1))
					Consistently(datastore.getNumInitCalls, checkTime, "1s").Should(Equal(numFailedInitCalls + 1))
				})
			})
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
})

type mockDatastore struct {
	mutex        sync.Mutex
	syncerCalled bool
	initCalled   int
	failInit     bool
}

func (b *mockDatastore) Syncer(callbacks bapi.SyncerCallbacks) bapi.Syncer {
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

func (b *mockDatastore) getNumInitCalls() int {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	return b.initCalled
}

type dummySyncer struct {
}

func (*dummySyncer) Start() {

}
