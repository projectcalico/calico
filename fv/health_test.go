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

import (
	"net/http"

	"github.com/kelseyhightower/envconfig"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/types"
	log "github.com/sirupsen/logrus"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/pkg/api/v1"

	"github.com/projectcalico/felix/fv/containers"
	"github.com/projectcalico/felix/fv/k8sapiserver"
	"github.com/projectcalico/libcalico-go/lib/health"
)

type EnvConfig struct {
	K8sVersion   string `default:"1.7.5"`
	TyphaVersion string `default:"latest"`
}

var config EnvConfig

var _ = BeforeSuite(func() {
	err := envconfig.Process("k8sfv", &config)
	Expect(err).NotTo(HaveOccurred())
	log.WithField("config", config).Info("Loaded config")

})

var _ = Describe("health tests", func() {

	var k8sAPIServer *k8sapiserver.Server

	BeforeEach(func() {
		k8sAPIServer = k8sapiserver.SetUp(config.K8sVersion)
	})

	var felixContainer *containers.Container
	var felixReady, felixLiveness func() int

	createPerNodeConfig := func() {
		// Make a k8s Node using the hostname of Felix's container.
		_, err := k8sAPIServer.Client.Nodes().Create(&v1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name: felixContainer.Hostname,
			},
			Spec: v1.NodeSpec{},
		})
		Expect(err).NotTo(HaveOccurred())
	}

	removePerNodeConfig := func() {
		err := k8sAPIServer.Client.Nodes().Delete(felixContainer.Hostname, nil)
		Expect(err).NotTo(HaveOccurred())
	}

	// describeCommonFelixTests creates specs for Felix tests that are common between the
	// two scenarios below (with and without Typha).
	describeCommonFelixTests := func() {
		Describe("with per-node config in datastore", func() {
			BeforeEach(createPerNodeConfig)
			AfterEach(removePerNodeConfig)

			It("should become ready and stay ready", func() {
				Eventually(felixReady, "5s", "100ms").Should(BeGood())
				Consistently(felixReady, "10s", "1s").Should(BeGood())
			})

			It("should become live and stay live", func() {
				Eventually(felixLiveness, "5s", "100ms").Should(BeGood())
				Consistently(felixLiveness, "10s", "1s").Should(BeGood())
			})
		})

		Describe("after removing iptables-restore", func() {
			BeforeEach(func() {
				// Delete iptables-restore in order to make the first apply() fail.
				err := felixContainer.ExecMayFail("rm", "/sbin/iptables-restore")
				Expect(err).NotTo(HaveOccurred())

				createPerNodeConfig()
			})
			AfterEach(removePerNodeConfig)

			It("should never be ready, then die", func() {
				Eventually(felixReady, "1s", "100ms").ShouldNot(BeGood())
				Consistently(felixReady, "5s", "100ms").ShouldNot(BeGood())
				Eventually(felixContainer.Stopped, "5s").Should(BeTrue())
			})
		})

		Describe("after replacing iptables with a slow version, with per-node config", func() {
			BeforeEach(func() {
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

				// Insert per-node config.  This will trigger felix to start up.
				createPerNodeConfig()
			})
			AfterEach(removePerNodeConfig)

			It("should delay readiness", func() {
				Consistently(felixReady, "5s", "100ms").ShouldNot(BeGood())
				Eventually(felixReady, "10s", "100ms").Should(BeGood())
				Consistently(felixReady, "10s", "1s").Should(BeGood())
			})

			It("should become live as normal", func() {
				Eventually(felixLiveness, "5s", "100ms").Should(BeGood())
				Consistently(felixLiveness, "10s", "1s").Should(BeGood())
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
			"-v", k8sAPIServer.CertFileName+":/tmp/apiserver.crt",
			"calico/typha:"+config.TyphaVersion,
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
			"-e", "K8S_API_ENDPOINT="+k8sAPIServer.Endpoint,
			"-e", "K8S_INSECURE_SKIP_TLS_VERIFY=true",
			"-e", "FELIX_TYPHAADDR="+typhaAddr,
			"-v", k8sAPIServer.CertFileName+":/tmp/apiserver.crt",
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
			createPerNodeConfig()
		})

		AfterEach(func() {
			felixContainer.Stop()
			removePerNodeConfig()
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
			createPerNodeConfig()
		})

		AfterEach(func() {
			felixContainer.Stop()
			removePerNodeConfig()
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

		// Pending because currently fails - investigation needed.
		PIt("typha should report live", func() {
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
