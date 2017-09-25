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
	"sync"

	. "github.com/projectcalico/typha/pkg/daemon"

	"context"
	"fmt"
	"io/ioutil"
	"os"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/libcalico-go/lib/api"
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
	var backend *mockBackend
	var newClientErr error
	var earlyLoggingConfigured, loggingConfigured bool

	BeforeEach(func() {
		d = New()
		backend = &mockBackend{}
		d.NewBackendClient = func(config api.CalicoAPIConfig) (c BackendClient, err error) {
			return backend, newClientErr
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
			d.LoadConfiguration()
			Expect(loggingConfigured).To(BeTrue())
		})
		AfterEach(func() {
			err := os.Remove(configFile.Name())
			Expect(err).NotTo(HaveOccurred())
		})

		It("should load the configuration and connect to the datastore", func() {
			Eventually(func() bool {
				backend.mutex.Lock()
				defer backend.mutex.Unlock()
				return backend.initCalled
			}).Should(BeTrue())
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

type mockBackend struct {
	mutex        sync.Mutex
	syncerCalled bool
	initCalled   bool
}

func (b *mockBackend) Syncer(callbacks bapi.SyncerCallbacks) bapi.Syncer {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	b.syncerCalled = true
	return &dummySyncer{}
}

func (b *mockBackend) EnsureInitialized() error {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	b.initCalled = true
	return nil
}

type dummySyncer struct {
}

func (*dummySyncer) Start() {

}
