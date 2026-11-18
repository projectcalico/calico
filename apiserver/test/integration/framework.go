// Copyright (c) 2021-2026 Tigera, Inc. All rights reserved.
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
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	calicoclient "github.com/projectcalico/api/pkg/client/clientset_generated/clientset"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	genericoptions "k8s.io/apiserver/pkg/server/options"
	restclient "k8s.io/client-go/rest"

	"github.com/projectcalico/calico/apiserver/cmd/apiserver/server"
	"github.com/projectcalico/calico/apiserver/pkg/apiserver"
)

const defaultEtcdPathPrefix = ""

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

// testServer is a Calico API server started for one test, with a client for it and the outcome of its RunServer call.
type testServer struct {
	server *apiserver.ProjectCalicoServer
	client calicoclient.Interface
	config *restclient.Config
	port   int
	stopCh chan struct{}

	// exited closes when RunServer returns, and runErr holds what it returned once exited is closed.
	exited chan struct{}
	runErr error
}

func withConfigGetFreshAPIServerServerAndClient(
	t *testing.T,
	serverConfig *TestServerConfig,
) (*apiserver.ProjectCalicoServer,
	calicoclient.Interface,
	*restclient.Config,
	func(),
) {
	apiServer := startTestServer(t, serverConfig, nil)
	return apiServer.server, apiServer.client, apiServer.config, apiServer.stop
}

// startTestServer prepares and runs a Calico API server against the test etcd and KUBECONFIG, and waits for it to
// serve. beforeRun, if not nil, gets the prepared server before RunServer starts, so a test can register hooks.
func startTestServer(t *testing.T, serverConfig *TestServerConfig, beforeRun func(*apiserver.ProjectCalicoServer)) *testServer {
	// A port the kernel picks cannot be one something else already holds, such as
	// the etcd the tests run against, and handing over the open listener leaves
	// no gap for anything to take it.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Error opening a listener for the server: %v", err)
	}
	addr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		if err := listener.Close(); err != nil {
			t.Logf("Closing the listener: %v", err)
		}
		t.Fatalf("Listener address %v is not a TCP address", listener.Addr())
	}
	apiServer := &testServer{
		port:   addr.Port,
		stopCh: make(chan struct{}),
		exited: make(chan struct{}),
	}
	secureAddr := fmt.Sprintf("https://localhost:%d", apiServer.port)

	t.Logf("Starting server on port: %d", apiServer.port)
	ro := genericoptions.NewRecommendedOptions(defaultEtcdPathPrefix, apiserver.Codecs.LegacyCodec(v3.SchemeGroupVersion))
	ro.Etcd.StorageConfig.Transport.ServerList = serverConfig.etcdServerList
	ro.Features.EnablePriorityAndFairness = false
	options := &server.CalicoServerOptions{
		RecommendedOptions: ro,
		DisableAuth:        true,
		StopCh:             apiServer.stopCh,
	}
	options.RecommendedOptions.SecureServing.Listener = listener
	options.RecommendedOptions.CoreAPI.CoreAPIKubeconfigPath = os.Getenv("KUBECONFIG")

	apiServer.server, err = server.PrepareServer(options)
	if err != nil {
		_ = listener.Close()
		t.Fatalf("Error preparing the server: %v", err)
	}
	if beforeRun != nil {
		beforeRun(apiServer.server)
	}

	// Run the server in the background.
	go func() {
		defer close(apiServer.exited)
		apiServer.runErr = server.RunServer(options, apiServer.server)
		logrus.WithError(apiServer.runErr).Infof("Server on port %d exited", apiServer.port)
	}()

	if err := waitForAPIServerUp(secureAddr, apiServer.exited); err != nil {
		t.Fatalf("%v", err)
	}

	// Build a client that talks to the server.
	apiServer.config = &restclient.Config{}
	apiServer.config.Host = secureAddr
	apiServer.config.Insecure = true
	apiServer.client, err = calicoclient.NewForConfig(apiServer.config)
	if nil != err {
		t.Fatal("can't make the client from the config", err)
	}
	return apiServer
}

// stop closes the server's stop channel, which starts its graceful shutdown. Call it once.
func (s *testServer) stop() {
	logrus.Infof("Shutting down server on port: %d", s.port)
	close(s.stopCh)
}

// waitForExit waits for RunServer to return and gives its error, failing the test if that takes longer than timeout.
func (s *testServer) waitForExit(t *testing.T, timeout time.Duration) error {
	select {
	case <-s.exited:
		return s.runErr
	case <-time.After(timeout):
		t.Fatalf("Server on port %d did not exit within %v", s.port, timeout)
		return nil
	}
}

func getFreshAPIServerAndClient(t *testing.T, newEmptyObj func() runtime.Object) (calicoclient.Interface, func()) {
	serverConfig := &TestServerConfig{
		etcdServerList: []string{"http://localhost:2379"},
		emptyObjFunc:   newEmptyObj,
	}
	_, client, _, shutdownFunc := withConfigGetFreshAPIServerServerAndClient(t, serverConfig)
	return client, shutdownFunc
}

func waitForAPIServerUp(serverURL string, exited <-chan struct{}) error {
	interval := 1 * time.Second
	timeout := 30 * time.Second
	startWaiting := time.Now()
	tries := 0
	return wait.PollUntilContextTimeout(context.Background(), interval, timeout, true,
		func(ctx context.Context) (bool, error) {
			select {
			case <-exited:
				return true, fmt.Errorf("apiserver exited before it was up")
			default:
				logrus.Infof("Waiting for : %#v", serverURL)
				tr := &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				}
				c := &http.Client{Transport: tr}
				_, err := c.Get(serverURL)
				if err == nil {
					logrus.Tracef("Found server after %v tries and duration %v",
						tries, time.Since(startWaiting))
					return true, nil
				}
				tries++
				return false, nil
			}
		},
	)
}
