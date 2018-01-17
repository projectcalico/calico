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
	"context"
	"fmt"
	"math/rand"
	"net/http"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/types"
	log "github.com/sirupsen/logrus"
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"time"

	"github.com/projectcalico/felix/fv/containers"
	"github.com/projectcalico/felix/fv/k8sapiserver"
	"github.com/projectcalico/felix/fv/utils"
	"github.com/projectcalico/libcalico-go/lib/health"
	"github.com/projectcalico/libcalico-go/lib/options"
)

var _ = Describe("health tests", func() {

	var k8sAPIServer *k8sapiserver.Server

	BeforeEach(func() {
		k8sAPIServer = k8sapiserver.SetUp()
	})

	JustBeforeEach(func() {
		// Felix can now flap ready/non-ready while loading its config.  Delay until that
		// is done.
		time.Sleep(1 * time.Second)
	})

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
			var err error
			pod, err = k8sAPIServer.Client.CoreV1().Pods("default").Create(pod)
			Expect(err).NotTo(HaveOccurred())
			pod.Status.PodIP = "10.0.0.1"
			_, err = k8sAPIServer.Client.CoreV1().Pods("default").UpdateStatus(pod)
			Expect(err).NotTo(HaveOccurred())
			podsToCleanUp = append(podsToCleanUp, testPodName)
		}

		AfterEach(func() {
			for _, name := range podsToCleanUp {
				err := k8sAPIServer.Client.CoreV1().Pods("default").Delete(name, &metav1.DeleteOptions{})
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
			containers.RunOpts{AutoRemove: true},
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
			"-v", k8sAPIServer.CertFileName+":/tmp/apiserver.crt",
			utils.Config.TyphaImage,
			"calico-typha")
		Expect(typhaContainer).NotTo(BeNil())
		typhaReady = getHealthStatus(typhaContainer.IP, "9098", "readiness")
		typhaLiveness = getHealthStatus(typhaContainer.IP, "9098", "liveness")
	}

	startFelix := func(typhaAddr string, calcGraphHangTime string, dataplaneHangTime string) {
		felixContainer = containers.Run("felix",
			containers.RunOpts{AutoRemove: true},
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
			"-e", "K8S_API_ENDPOINT="+k8sAPIServer.Endpoint,
			"-e", "K8S_INSECURE_SKIP_TLS_VERIFY=true",
			"-e", "FELIX_TYPHAADDR="+typhaAddr,
			"-v", k8sAPIServer.CertFileName+":/tmp/apiserver.crt",
			"calico/felix:latest",
		)
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
			startTypha(k8sAPIServer.Endpoint)
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
			startTypha(k8sAPIServer.BadEndpoint)
		})

		AfterEach(func() {
			typhaContainer.Stop()
		})

		It("typha should not report ready", func() {
			Consistently(typhaReady, "10s", "1s").ShouldNot(BeGood())
		})

		It("typha should not report live", func() {
			Consistently(typhaLiveness(), "10s", "1s").ShouldNot(BeGood())
		})
	})

	Describe("with datastore not ready", func() {
		BeforeEach(func() {
			info, err := k8sAPIServer.CalicoClient.ClusterInformation().Get(
				context.Background(),
				"default",
				options.GetOptions{},
			)
			Expect(err).NotTo(HaveOccurred())
			log.Infof("info = %#v", info)
			notReady := false
			info.Spec.DatastoreReady = &notReady
			_, err = k8sAPIServer.CalicoClient.ClusterInformation().Update(
				context.Background(),
				info,
				options.SetOptions{},
			)
			Expect(err).NotTo(HaveOccurred())
			startFelix("", "", "")
		})

		AfterEach(func() {
			felixContainer.Stop()
		})

		It("felix should report ready", func() {
			Eventually(felixReady, "5s", "100ms").Should(BeGood())
			Consistently(felixReady, "10s", "1s").Should(BeGood())
		})

		It("felix should report live", func() {
			Eventually(felixLiveness, "5s", "100ms").Should(BeGood())
			Consistently(felixLiveness, "10s", "1s").Should(BeGood())
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
