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

package k8sapiserver

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"

	"github.com/projectcalico/felix/fv/containers"
	"github.com/projectcalico/felix/fv/utils"
	"github.com/projectcalico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/libcalico-go/lib/clientv3"
)

var (
	// This transport is based on  http.DefaultTransport, with InsecureSkipVerify set.
	insecureTransport = &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		ExpectContinueTimeout: 1 * time.Second,
	}
	insecureHTTPClient = http.Client{
		Transport: insecureTransport,
	}
)

type Server struct {
	etcdContainer      *containers.Container
	apiServerContainer *containers.Container

	Endpoint     string
	BadEndpoint  string
	CertFileName string
	Client       *kubernetes.Clientset
	CalicoClient client.Interface
}

var theServer *Server

func SetUp() *Server {
	var err error

	// Return existing server if we already have one.
	if theServer != nil {
		return theServer
	}

	// Set up a new server.  We'll store this in 'theServer' if the setup is completely
	// successful.
	server := &Server{}

	// Start etcd, which will back the k8s API server.
	server.etcdContainer = containers.RunEtcd()
	Expect(server.etcdContainer).NotTo(BeNil())

	// Start the k8s API server.
	//
	// The clients in this test - Felix, Typha and the test code itself - all connect
	// anonymously to the API server, because (a) they aren't running in pods in a proper
	// Kubernetes cluster, and (b) they don't provide client TLS certificates, and (c) they
	// don't use any of the other non-anonymous mechanisms that Kubernetes supports.  But, as of
	// 1.6, the API server doesn't allow anonymous users with the default "AlwaysAllow"
	// authorization mode.  So we specify the "RBAC" authorization mode instead, and create a
	// ClusterRoleBinding that gives the "system:anonymous" user unlimited power (aka the
	// "cluster-admin" role).
	server.apiServerContainer = containers.Run("apiserver",
		containers.RunOpts{AutoRemove: true},
		utils.Config.K8sImage,
		"/hyperkube", "apiserver",
		fmt.Sprintf("--etcd-servers=http://%s:2379", server.etcdContainer.IP),
		"--service-cluster-ip-range=10.101.0.0/16",
		//"-v=10",
		"--authorization-mode=RBAC",
	)
	Expect(server.apiServerContainer).NotTo(BeNil())

	// Allow anonymous connections to the API server.  We also use this command to wait
	// for the API server to be up.
	Eventually(func() (err error) {
		err = server.apiServerContainer.ExecMayFail(
			"kubectl", "create", "clusterrolebinding",
			"anonymous-admin",
			"--clusterrole=cluster-admin",
			"--user=system:anonymous",
		)
		if err != nil {
			log.Info("Waiting for API server to accept cluster role binding")
		}
		return
	}, "60s", "2s").ShouldNot(HaveOccurred())

	// Copy CRD registration manifest into the API server container, and apply it.
	err = server.apiServerContainer.CopyFileIntoContainer("../vendor/github.com/projectcalico/libcalico-go/test/crds.yaml", "/crds.yaml")
	Expect(err).NotTo(HaveOccurred())
	err = server.apiServerContainer.ExecMayFail("kubectl", "apply", "-f", "/crds.yaml")
	Expect(err).NotTo(HaveOccurred())

	server.Endpoint = fmt.Sprintf("https://%s:6443", server.apiServerContainer.IP)
	server.BadEndpoint = fmt.Sprintf("https://%s:1234", server.apiServerContainer.IP)
	Eventually(func() (err error) {
		var resp *http.Response
		resp, err = insecureHTTPClient.Get(server.Endpoint + "/apis/crd.projectcalico.org/v1/globalfelixconfigs")
		if resp.StatusCode != 200 {
			err = errors.New(fmt.Sprintf("Bad status (%v) for CRD GET request", resp.StatusCode))
		}
		if err != nil || resp.StatusCode != 200 {
			log.WithError(err).WithField("status", resp.StatusCode).Warn("Waiting for API server to respond to requests")
		}
		resp.Body.Close()
		return
	}, "60s", "2s").ShouldNot(HaveOccurred())
	log.Info("API server is up.")

	// Get the API server's cert, which we need to pass to Felix/Typha
	server.CertFileName = "/tmp/" + server.apiServerContainer.Name + ".crt"
	Eventually(func() (err error) {
		cmd := utils.Command("docker", "cp",
			server.apiServerContainer.Name+":/var/run/kubernetes/apiserver.crt",
			server.CertFileName,
		)
		err = cmd.Run()
		if err != nil {
			log.WithError(err).Warn("Waiting for API cert to appear")
		}
		return
	}, "60s", "2s").ShouldNot(HaveOccurred())

	Eventually(func() (err error) {
		server.CalicoClient, err = client.New(apiconfig.CalicoAPIConfig{
			Spec: apiconfig.CalicoAPIConfigSpec{
				DatastoreType: apiconfig.Kubernetes,
				KubeConfig: apiconfig.KubeConfig{
					K8sAPIEndpoint:           server.Endpoint,
					K8sInsecureSkipTLSVerify: true,
				},
			},
		})
		if err != nil {
			log.WithError(err).Warn("Waiting to create Calico client")
			return
		}

		ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
		err = server.CalicoClient.EnsureInitialized(
			ctx,
			"v3.0.0-test",
			"felix-fv,typha", // Including typha in clusterType to prevent config churn
		)

		return
	}, "60s", "2s").ShouldNot(HaveOccurred())

	Eventually(func() (err error) {
		server.Client, err = kubernetes.NewForConfig(&rest.Config{
			Transport: insecureTransport,
			Host:      "https://" + server.apiServerContainer.IP + ":6443",
		})
		if err != nil {
			log.WithError(err).Warn("Waiting to create k8s client")
		}
		return
	}, "60s", "2s").ShouldNot(HaveOccurred())

	theServer = server
	return theServer
}

func TearDown(server *Server) {
	server.apiServerContainer.Stop()
	server.etcdContainer.Stop()
}

var _ = AfterSuite(func() {
	if theServer != nil {
		TearDown(theServer)
		theServer = nil
	}
})
