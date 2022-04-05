// Copyright (c) 2021 Tigera, Inc. All rights reserved.
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
// limitations under the License.package util

package integration

import (
	"crypto/tls"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"testing"
	"time"

	"k8s.io/klog/v2"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	genericoptions "k8s.io/apiserver/pkg/server/options"
	restclient "k8s.io/client-go/rest"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	calicoclient "github.com/projectcalico/api/pkg/client/clientset_generated/clientset"

	"github.com/projectcalico/calico/apiserver/cmd/apiserver/server"
	"github.com/projectcalico/calico/apiserver/pkg/apiserver"
)

const defaultEtcdPathPrefix = ""

func init() {
	rand.Seed(time.Now().UnixNano())
}

type TestServerConfig struct {
	etcdServerList []string
	emptyObjFunc   func() runtime.Object
}

// NewTestServerConfig is a default constructor for the standard test-apiserver setup
func NewTestServerConfig() *TestServerConfig {
	return &TestServerConfig{
		etcdServerList: []string{"http://localhost:2379"},
	}
}

func withConfigGetFreshApiserverServerAndClient(
	t *testing.T,
	serverConfig *TestServerConfig,
) (*apiserver.ProjectCalicoServer,
	calicoclient.Interface,
	*restclient.Config,
	func(),
) {
	securePort := rand.Intn(31743) + 1024
	secureAddr := fmt.Sprintf("https://localhost:%d", securePort)
	stopCh := make(chan struct{})
	serverFailed := make(chan struct{})
	shutdownServer := func() {
		t.Logf("Shutting down server on port: %d", securePort)
		close(stopCh)
	}

	t.Logf("Starting server on port: %d", securePort)
	ro := genericoptions.NewRecommendedOptions(defaultEtcdPathPrefix, apiserver.Codecs.LegacyCodec(v3.SchemeGroupVersion))
	ro.Etcd.StorageConfig.Transport.ServerList = serverConfig.etcdServerList
	options := &server.CalicoServerOptions{
		RecommendedOptions: ro,
		DisableAuth:        true,
		StopCh:             stopCh,
	}
	options.RecommendedOptions.SecureServing.BindPort = securePort
	options.RecommendedOptions.CoreAPI.CoreAPIKubeconfigPath = os.Getenv("KUBECONFIG")

	var err error
	pcs, err := server.PrepareServer(options)
	if err != nil {
		close(serverFailed)
		t.Fatalf("Error preparing the server: %v", err)
	}

	// Run the server in the background
	go func() {
		err := server.RunServer(options, pcs)
		if err != nil {
			close(serverFailed)
		}
	}()

	if err := waitForApiserverUp(secureAddr, serverFailed); err != nil {
		t.Fatalf("%v", err)
	}
	if pcs == nil {
		t.Fatal("Calico server is nil")
	}

	cfg := &restclient.Config{}
	cfg.Host = secureAddr
	cfg.Insecure = true
	clientset, err := calicoclient.NewForConfig(cfg)
	if nil != err {
		t.Fatal("can't make the client from the config", err)
	}

	return pcs, clientset, cfg, shutdownServer
}

func getFreshApiserverServerAndClient(
	t *testing.T,
	newEmptyObj func() runtime.Object,
) (*apiserver.ProjectCalicoServer, calicoclient.Interface, func()) {
	serverConfig := &TestServerConfig{
		etcdServerList: []string{"http://localhost:2379"},
		emptyObjFunc:   newEmptyObj,
	}
	pcs, client, _, shutdownFunc := withConfigGetFreshApiserverServerAndClient(t, serverConfig)
	return pcs, client, shutdownFunc
}

func getFreshApiserverAndClient(
	t *testing.T,
	newEmptyObj func() runtime.Object,
) (calicoclient.Interface, func()) {
	serverConfig := &TestServerConfig{
		etcdServerList: []string{"http://localhost:2379"},
		emptyObjFunc:   newEmptyObj,
	}
	_, client, _, shutdownFunc := withConfigGetFreshApiserverServerAndClient(t, serverConfig)
	return client, shutdownFunc
}

func customizeFreshApiserverAndClient(
	t *testing.T,
	serverConfig *TestServerConfig,
) (calicoclient.Interface, func()) {
	_, client, _, shutdownFunc := withConfigGetFreshApiserverServerAndClient(t, serverConfig)
	return client, shutdownFunc
}

func waitForApiserverUp(serverURL string, stopCh <-chan struct{}) error {
	interval := 1 * time.Second
	timeout := 30 * time.Second
	startWaiting := time.Now()
	tries := 0
	return wait.PollImmediate(interval, timeout,
		func() (bool, error) {
			select {
			// we've been told to stop, so no reason to keep going
			case <-stopCh:
				return true, fmt.Errorf("apiserver failed")
			default:
				klog.Infof("Waiting for : %#v", serverURL)
				tr := &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				}
				c := &http.Client{Transport: tr}
				_, err := c.Get(serverURL)
				if err == nil {
					klog.Infof("Found server after %v tries and duration %v",
						tries, time.Since(startWaiting))
					return true, nil
				}
				tries++
				return false, nil
			}
		},
	)
}
