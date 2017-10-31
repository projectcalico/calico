// +build fvtests

// Copyright (c) 2017 Tigera, Inc. All rights reserved.

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

package fv_test

// The tests in this file test Felix's and Typha's health endpoints, http://.../liveness and
// http://.../readiness.
//
// Felix should report itself as live, so long as its calc_graph and int_dataplane loops have not
// died or hung; and as ready, so long as it has completed its initial dataplane programming, is
// connected to its datastore, and is not doing a resync (either the initial resync, or a subsequent
// one).
//
// Typha should report itself as live, so long as its Felix-serving loop has not died or hung; and
// as ready, so long as it is connected to its datastore, and is not doing a resync (either the
// initial resync, or a subsequent one).
//
// (These reports are useful because k8s can detect and handle a pod that is consistently non-live,
// by killing and restarting it; and can adjust for a pod that is non-ready, by (a) not routing
// Service traffic to it (when that pod is otherwise one of the possible backends for a Service),
// and (b) not moving on to the next pod, in a rolling upgrade process, until the just-upgraded pod
// says that it is ready.)

import (
	"crypto/tls"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/types"
	log "github.com/sirupsen/logrus"
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/projectcalico/felix/fv/containers"
	"github.com/projectcalico/felix/fv/utils"
	"github.com/projectcalico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/libcalico-go/lib/clientv2"
	"github.com/projectcalico/libcalico-go/lib/health"
)

var etcdContainer *containers.Container
var apiServerContainer *containers.Container
var k8sAPIEndpoint string
var badK8sAPIEndpoint string
var k8sCertFilename string
var calicoClient client.Interface
var k8sClient *kubernetes.Clientset

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

var _ = BeforeSuite(func() {
	log.Info(">>> BeforeSuite <<<")
	var err error

	// Start etcd, which will back the k8s API server.
	etcdContainer = containers.RunEtcd()
	Expect(etcdContainer).NotTo(BeNil())

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
	apiServerContainer = containers.Run("apiserver",
		"gcr.io/google_containers/hyperkube-amd64:v"+utils.Config.K8sVersion,
		"/hyperkube", "apiserver",
		fmt.Sprintf("--etcd-servers=http://%s:2379", etcdContainer.IP),
		"--service-cluster-ip-range=10.101.0.0/16",
		//"-v=10",
		"--authorization-mode=RBAC",
	)
	Expect(apiServerContainer).NotTo(BeNil())

	// Allow anonymous connections to the API server.  We also use this command to wait
	// for the API server to be up.
	Eventually(func() (err error) {
		err = apiServerContainer.ExecMayFail(
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
	err = apiServerContainer.CopyFileIntoContainer("../vendor/github.com/projectcalico/libcalico-go/test/crds.yaml", "/crds.yaml")
	Expect(err).NotTo(HaveOccurred())
	err = apiServerContainer.ExecMayFail("kubectl", "apply", "-f", "/crds.yaml")
	Expect(err).NotTo(HaveOccurred())

	k8sAPIEndpoint = fmt.Sprintf("https://%s:6443", apiServerContainer.IP)
	badK8sAPIEndpoint = fmt.Sprintf("https://%s:1234", apiServerContainer.IP)
	Eventually(func() (err error) {
		var resp *http.Response
		resp, err = insecureHTTPClient.Get(k8sAPIEndpoint + "/apis/crd.projectcalico.org/v1/globalfelixconfigs")
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
	k8sCertFilename = "/tmp/" + apiServerContainer.Name + ".crt"
	Eventually(func() (err error) {
		cmd := utils.Command("docker", "cp",
			apiServerContainer.Name+":/var/run/kubernetes/apiserver.crt",
			k8sCertFilename,
		)
		err = cmd.Run()
		if err != nil {
			log.WithError(err).Warn("Waiting for API cert to appear")
		}
		return
	}, "60s", "2s").ShouldNot(HaveOccurred())

	Eventually(func() (err error) {
		calicoClient, err = client.New(apiconfig.CalicoAPIConfig{
			Spec: apiconfig.CalicoAPIConfigSpec{
				DatastoreType: apiconfig.Kubernetes,
				KubeConfig: apiconfig.KubeConfig{
					K8sAPIEndpoint:           k8sAPIEndpoint,
					K8sInsecureSkipTLSVerify: true,
				},
			},
		})
		if err != nil {
			log.WithError(err).Warn("Waiting to create Calico client")
		}
		return
	}, "60s", "2s").ShouldNot(HaveOccurred())

	Eventually(func() (err error) {
		k8sClient, err = kubernetes.NewForConfig(&rest.Config{
			Transport: insecureTransport,
			Host:      "https://" + apiServerContainer.IP + ":6443",
		})
		if err != nil {
			log.WithError(err).Warn("Waiting to create k8s client")
		}
		return
	}, "60s", "2s").ShouldNot(HaveOccurred())
})

var _ = AfterSuite(func() {
	apiServerContainer.Stop()
	etcdContainer.Stop()
})

var _ = Describe("health tests", func() {
	var felixContainer *containers.Container
	var felixReady, felixLiveness func() int

	// describeCommonFelixTests creates specs for Felix tests that are common between the
	// two scenarios below (with and without Typha).
	describeCommonFelixTests := func() {
		var podsToCleanUp []string

		Describe("with normal Felix startup", func() {

			It("should become ready and stay ready", func() {
				Eventually(felixReady, "5s", "100ms").Should(BeGood())
				Consistently(felixReady, "10s", "1s").Should(BeGood())
			})

			It("should become live and stay live", func() {
				Eventually(felixLiveness, "5s", "100ms").Should(BeGood())
				Consistently(felixLiveness, "10s", "1s").Should(BeGood())
			})
		})

		createLocalPod := func() {
			testPodName := fmt.Sprintf("test-pod-%x", rand.Uint32())
			pod := &v1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: testPodName},
				Spec: v1.PodSpec{Containers: []v1.Container{{
					Name:  fmt.Sprintf("container-foo"),
					Image: "ignore",
				}},
					NodeName: felixContainer.Hostname,
				},
				Status: v1.PodStatus{
					Phase: v1.PodRunning,
					Conditions: []v1.PodCondition{{
						Type:   v1.PodScheduled,
						Status: v1.ConditionTrue,
					}},
					PodIP: "10.0.0.1",
				},
			}
			_, err := k8sClient.CoreV1().Pods("default").Create(pod)
			Expect(err).NotTo(HaveOccurred())
			podsToCleanUp = append(podsToCleanUp, testPodName)
		}

		AfterEach(func() {
			for _, name := range podsToCleanUp {
				err := k8sClient.CoreV1().Pods("default").Delete(name, &metav1.DeleteOptions{})
				Expect(err).NotTo(HaveOccurred())
			}
			podsToCleanUp = nil
		})

		Describe("after removing iptables-restore", func() {
			BeforeEach(func() {
				// Wait until felix gets into steady state.
				Eventually(felixReady, "5s", "100ms").Should(BeGood())

				// Then remove iptables-restore.
				err := felixContainer.ExecMayFail("rm", "/sbin/iptables-restore")
				Expect(err).NotTo(HaveOccurred())

				// Make an update that will force felix to run iptables-restore.
				createLocalPod()
			})

			It("should become unready, then die", func() {
				Eventually(felixReady, "120s", "10s").ShouldNot(BeGood())
				Eventually(felixContainer.Stopped, "5s").Should(BeTrue())
			})
		})

		Describe("after replacing iptables with a slow version", func() {
			BeforeEach(func() {
				// Wait until felix gets into steady state.
				Eventually(felixReady, "5s", "100ms").Should(BeGood())

				// Then replace iptables-restore with the bad version:

				// We need to delete the file first since it's a symlink and "docker cp"
				// follows the link and overwrites the wrong file if we don't.
				err := felixContainer.ExecMayFail("rm", "/sbin/iptables-restore")
				Expect(err).NotTo(HaveOccurred())

				// Copy in the nobbled iptables command.
				err = felixContainer.CopyFileIntoContainer("slow-iptables-restore",
					"/sbin/iptables-restore")
				Expect(err).NotTo(HaveOccurred())

				// Make it executable.
				err = felixContainer.ExecMayFail("chmod", "+x", "/sbin/iptables-restore")
				Expect(err).NotTo(HaveOccurred())

				// Make an update that will force felix to run iptables-restore.
				createLocalPod()
			})

			It("should detect dataplane pause and become non-ready", func() {
				Eventually(felixReady, "120s", "10s").ShouldNot(BeGood())
			})
		})
	}

	var typhaContainer *containers.Container
	var typhaReady, typhaLiveness func() int

	startTypha := func(endpoint string) {
		typhaContainer = containers.Run("typha",
			"--privileged",
			"-e", "CALICO_DATASTORE_TYPE=kubernetes",
			"-e", "TYPHA_HEALTHENABLED=true",
			"-e", "TYPHA_LOGSEVERITYSCREEN=info",
			"-e", "TYPHA_DATASTORETYPE=kubernetes",
			"-e", "TYPHA_PROMETHEUSMETRICSENABLED=true",
			"-e", "TYPHA_USAGEREPORTINGENABLED=false",
			"-e", "TYPHA_DEBUGMEMORYPROFILEPATH=\"heap-<timestamp>\"",
			"-e", "K8S_API_ENDPOINT="+endpoint,
			"-e", "K8S_INSECURE_SKIP_TLS_VERIFY=true",
			"-v", k8sCertFilename+":/tmp/apiserver.crt",
			"calico/typha:"+utils.Config.TyphaVersion,
			"calico-typha")
		Expect(typhaContainer).NotTo(BeNil())
		typhaReady = getHealthStatus(typhaContainer.IP, "9098", "readiness")
		typhaLiveness = getHealthStatus(typhaContainer.IP, "9098", "liveness")
	}

	startFelix := func(typhaAddr string, calcGraphHangTime string, dataplaneHangTime string) {
		felixContainer = containers.Run("felix",
			"--privileged",
			"-e", "CALICO_DATASTORE_TYPE=kubernetes",
			"-e", "FELIX_IPV6SUPPORT=false",
			"-e", "FELIX_HEALTHENABLED=true",
			"-e", "FELIX_LOGSEVERITYSCREEN=info",
			"-e", "FELIX_DATASTORETYPE=kubernetes",
			"-e", "FELIX_PROMETHEUSMETRICSENABLED=true",
			"-e", "FELIX_USAGEREPORTINGENABLED=false",
			"-e", "FELIX_DEBUGMEMORYPROFILEPATH=\"heap-<timestamp>\"",
			"-e", "FELIX_DebugSimulateCalcGraphHangAfter="+calcGraphHangTime,
			"-e", "FELIX_DebugSimulateDataplaneHangAfter="+dataplaneHangTime,
			"-e", "K8S_API_ENDPOINT="+k8sAPIEndpoint,
			"-e", "K8S_INSECURE_SKIP_TLS_VERIFY=true",
			"-e", "FELIX_TYPHAADDR="+typhaAddr,
			"-v", k8sCertFilename+":/tmp/apiserver.crt",
			"calico/felix", // TODO Felix version
			"calico-felix")
		Expect(felixContainer).NotTo(BeNil())

		felixReady = getHealthStatus(felixContainer.IP, "9099", "readiness")
		felixLiveness = getHealthStatus(felixContainer.IP, "9099", "liveness")
	}

	Describe("with Felix running (no Typha)", func() {
		BeforeEach(func() {
			startFelix("", "", "")
		})

		AfterEach(func() {
			felixContainer.Stop()
		})

		describeCommonFelixTests()
	})

	Describe("with Felix (no Typha) and Felix calc graph set to hang", func() {
		BeforeEach(func() {
			startFelix("", "5", "")
		})

		AfterEach(func() {
			felixContainer.Stop()
		})

		It("should report live initially, then become non-live", func() {
			Eventually(felixLiveness, "10s", "100ms").Should(BeGood())
			Eventually(felixLiveness, "30s", "100ms").Should(BeBad())
			Consistently(felixLiveness, "10s", "100ms").Should(BeBad())
		})
	})

	Describe("with Felix (no Typha) and Felix dataplane set to hang", func() {
		BeforeEach(func() {
			startFelix("", "", "5")
		})

		AfterEach(func() {
			felixContainer.Stop()
		})

		It("should report live initially, then become non-live", func() {
			Eventually(felixLiveness, "10s", "100ms").Should(BeGood())
			Eventually(felixLiveness, "30s", "100ms").Should(BeBad())
			Consistently(felixLiveness, "10s", "100ms").Should(BeBad())
		})
	})

	Describe("with Felix and Typha running", func() {
		BeforeEach(func() {
			startTypha(k8sAPIEndpoint)
			startFelix(typhaContainer.IP+":5473", "", "")
		})

		AfterEach(func() {
			felixContainer.Stop()
			typhaContainer.Stop()
		})

		describeCommonFelixTests()

		It("typha should report ready", func() {
			Eventually(typhaReady, "5s", "100ms").Should(BeGood())
			Consistently(typhaReady, "10s", "1s").Should(BeGood())
		})

		It("typha should report live", func() {
			Eventually(typhaLiveness, "5s", "100ms").Should(BeGood())
			Consistently(typhaLiveness, "10s", "1s").Should(BeGood())
		})
	})

	Describe("with typha connected to bad API endpoint", func() {
		BeforeEach(func() {
			startTypha(badK8sAPIEndpoint)
		})

		AfterEach(func() {
			typhaContainer.Stop()
		})

		It("typha should not report ready", func() {
			Consistently(typhaReady, "10s", "1s").ShouldNot(BeGood())
		})

		It("typha should report live", func() {
			Eventually(typhaLiveness, "5s", "100ms").Should(BeGood())
			Consistently(typhaLiveness, "10s", "1s").Should(BeGood())
		})
	})
})

const statusErr = -1

func getHealthStatus(ip, port, endpoint string) func() int {
	return func() int {
		resp, err := http.Get("http://" + ip + ":" + port + "/" + endpoint)
		if err != nil {
			log.WithError(err).WithField("resp", resp).Warn("HTTP GET failed")
			return statusErr
		}
		defer resp.Body.Close()
		log.WithField("resp", resp).Info("Health response")
		return resp.StatusCode
	}
}

func BeErr() types.GomegaMatcher {
	return BeNumerically("==", statusErr)
}

func BeBad() types.GomegaMatcher {
	return BeNumerically("==", health.StatusBad)
}

func BeGood() types.GomegaMatcher {
	return BeNumerically("==", health.StatusGood)
}
