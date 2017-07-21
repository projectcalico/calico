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

package k8s

import (
	"os/exec"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/kelseyhightower/envconfig"
	"fmt"
	"os"
	"strings"
	"time"
	log "github.com/Sirupsen/logrus"
	"net/http"
)

type EnvConfig struct {
	FelixVersion string
	K8sVersion string `default:"1.6.4"`
	PromPGURL string
	CodeLevel string
	UseTypha bool
}

var config EnvConfig

var etcdName string
var etcdCmd *exec.Cmd
var etcdStopped chan struct{} = make(chan struct{})

var k8sName string
var k8sCmd *exec.Cmd
var k8sStopped chan struct{} = make(chan struct{})

var _ = BeforeSuite(func() {
	log.Info(">>> BeforeSuite <<<")
	err := envconfig.Process("k8sfv", &config)
	Expect(err).NotTo(HaveOccurred())
	log.WithField("config", config).Info("Loaded config")

	// Start etcd, which will back the k8s API server.
	etcdName = nameForContainer("etcd")
	log.WithField("name", etcdName).Info("Starting etcd")
	etcdCmd = exec.Command("docker", "run",
		"--rm",
		"--name", etcdName,
		"quay.io/coreos/etcd",
		"etcd",
		"--advertise-client-urls", "http://127.0.0.1:2379,http://127.0.0.1:4001",
		"--listen-client-urls", "http://0.0.0.0:2379,http://0.0.0.0:4001",
	)
	err = etcdCmd.Start()
	Expect(err).NotTo(HaveOccurred())
	go func() {
		defer close(etcdStopped)
		etcdCmd.Wait()
	}()
	waitForContainer(etcdName, etcdStopped)
	etcdIP := getContainerIP(etcdName)

	// Start the k8s API server.
	k8sName = nameForContainer("k8s-api")
	log.WithField("name", k8sName).Info("Starting k8s")
	k8sCmd = exec.Command("docker", "run",
		"--rm",
		"--name", k8sName,
		"gcr.io/google_containers/hyperkube-amd64:v" + config.K8sVersion,
		"/hyperkube", "apiserver",
		fmt.Sprintf("--etcd-servers=http://%s:2379", etcdIP),
		"--service-cluster-ip-range=10.101.0.0/16",
		"-v=10",
		"--authorization-mode=RBAC")
	k8sCmd.Stdout = os.Stdout
	k8sCmd.Stderr = os.Stderr
	err = k8sCmd.Start()
	Expect(err).NotTo(HaveOccurred())
	go func() {
		defer close(k8sStopped)
		k8sCmd.Wait()
	}()
	waitForContainer(k8sName, k8sStopped)
	k8sIP := getContainerIP(k8sName)

	// Allow anonymous connections to the API server.  We also use this command to wait
	// for the API server to be up.
	for {
		rbCmd := exec.Command("docker", "exec", k8sName,
			"kubectl", "create", "clusterrolebinding", "anonymous-admin",
			"--clusterrole=cluster-admin", "--user=system:anonymous")
		err = rbCmd.Run()
		if err != nil {
			log.Info("Waiting for API server to accept cluster role binding")
			time.Sleep(2 * time.Second)
			continue
		}
		break
	}

	http.Get(fmt.Sprintf("https://%s:6443/apis/extensions/v1beta1/thirdpartyresources", k8sIP))
})

var _ = AfterSuite(func() {
	stopContainer(k8sCmd)
	stopContainer(etcdCmd)
})

func stopContainer(cmd *exec.Cmd) {
	if cmd == nil {
		// Command was never started.
		return
	}
	if cmd.Process == nil {
		// Command didn't get as far as forking.
		return
	}
	// Use interrupt rather than kill or the container will detach and run in the
	// background.
	cmd.Process.Signal(os.Interrupt)
}

var _ = Describe("With a k8s API server", func() {
	It("should", func() {

	})
})

func waitForContainer(name string, stopChan chan struct{}) {
	for {
		Expect(stopChan).NotTo(BeClosed())
		out, err := exec.Command("docker", "inspect", name).CombinedOutput()
		if err == nil {
			return
		}
		if strings.Contains(string(out), "No such object") {
			log.Info("Waiting for ", name)
			time.Sleep(1 * time.Second)
			continue
		}
		Expect(err).NotTo(HaveOccurred())
	}
}

func getContainerIP(name string) string {
	out, err := exec.Command("docker", "inspect",
		"--format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", name).Output()
	Expect(err).NotTo(HaveOccurred())
	return string(out)
}

var containerIdx int

func nameForContainer(stem string) string {
	containerName := fmt.Sprintf("k8sfv-%s-%d-%d", stem, os.Getpid(), containerIdx)
	containerIdx++
	return containerName
}

//var _ = Describe("health", func() {
//
//	var (
//		clientset *kubernetes.Clientset
//	)
//
//	BeforeEach(func() {
//		log.Info(">>> BeforeEach <<<")
//		clientset = initialize(k8sServerEndpoint)
//	})
//
//	It("Felix should be not ready", func() {
//		// Because there is no config for the local node.
//		triggerFelixRestart()
//		for i := 0; i < 8; i++ {
//			Expect(getFelixStatus("readiness")()).To(BeBad())
//			time.Sleep(500 * time.Millisecond)
//		}
//	})
//
//	It("Felix should be not live", func() {
//		// Because there is no config for the local node.
//		triggerFelixRestart()
//		for i := 0; i < 8; i++ {
//			Expect(getFelixStatus("liveness")()).To(BeBad())
//			time.Sleep(500 * time.Millisecond)
//		}
//	})
//
//	It("Typha should be ready", func() {
//		skipIfNoTypha()
//		Eventually(getTyphaStatus("readiness"), "8s", "0.5s").Should(BeGood())
//	})
//
//	It("Typha should be live", func() {
//		skipIfNoTypha()
//		Eventually(getTyphaStatus("liveness"), "8s", "0.5s").Should(BeGood())
//	})
//
//	Context("with a local host", func() {
//		BeforeEach(func() {
//			log.Info(">>> BeforeEach with a local host <<<")
//			triggerFelixRestart()
//			_ = NewDeployment(clientset, 0, true)
//		})
//
//		It("Felix should be ready", func() {
//			Eventually(getFelixStatus("readiness"), "8s", "0.5s").Should(BeGood())
//		})
//
//		Context("with API server hidden", func() {
//			BeforeEach(func() {
//				log.Info(">>> BeforeEach hiding the API server <<<")
//				hideAPIServer()
//
//				// We need to restart the daemons here because the Syncer doesn't currently
//				// move to non-ready due to network failures.
//				triggerTyphaRestart()
//				triggerFelixRestart()
//			})
//
//			AfterEach(func() {
//				revealAPIServer()
//
//				// Restart the daemons again to leave them in a clean state.
//				triggerTyphaRestart()
//				triggerFelixRestart()
//			})
//
//			It("Felix should be non-ready", func() {
//				Eventually(getFelixStatus("readiness"), "60s", "5s").Should(BeBad())
//			})
//
//			It("Typha should be non-ready", func() {
//				skipIfNoTypha()
//				Eventually(getTyphaStatus("readiness"), "60s", "5s").Should(BeBad())
//			})
//		})
//
//		It("Felix should be live", func() {
//			Eventually(getFelixStatus("liveness"), "8s", "0.5s").Should(BeGood())
//		})
//
//		It("Typha should be ready", func() {
//			skipIfNoTypha()
//			Eventually(getTyphaStatus("readiness"), "8s", "0.5s").Should(BeGood())
//		})
//
//		It("Typha should be live", func() {
//			skipIfNoTypha()
//			Eventually(getTyphaStatus("liveness"), "8s", "0.5s").Should(BeGood())
//		})
//	})
//
//	AfterEach(func() {
//		log.Info(">>> AfterEach <<<")
//	})
//})
//
//func BeBad() types.GomegaMatcher {
//	return BeNumerically("==", health.StatusBad)
//}
//
//func BeGood() types.GomegaMatcher {
//	return BeNumerically("==", health.StatusGood)
//}
//
//func getHealthStatus(ip, port, endpoint string) func() int {
//	return func() int {
//		resp, err := http.Get("http://" + ip + ":" + port + "/" + endpoint)
//		if err != nil {
//			log.WithError(err).Error("HTTP GET failed")
//			return health.StatusBad
//		}
//		log.WithField("resp", resp).Info("Health response")
//		defer resp.Body.Close()
//		return resp.StatusCode
//	}
//}
//
//func getFelixStatus(endpoint string) func() int {
//	return getHealthStatus(felixIP, "9099", endpoint)
//}
//
//func getTyphaStatus(endpoint string) func() int {
//	return getHealthStatus(typhaIP, "9098", endpoint)
//}
//
//func triggerFelixRestart() {
//	log.Info("Killing felix")
//	exec.Command("pkill", "-TERM", "calico-felix").Run()
//	time.Sleep(1 * time.Second)
//}
//
//func triggerTyphaRestart() {
//	log.Info("Killing typha")
//	exec.Command("pkill", "-TERM", "calico-typha").Run()
//	time.Sleep(1 * time.Second)
//}
//
//func skipIfNoTypha() {
//	if typhaIP == "" {
//		Skip("No Typha in this test run")
//	}
//}
//
//func hideAPIServer() {
//	log.Info("Hiding API server")
//	err := exec.Command("iptables", "-A", "OUTPUT", "-p", "tcp", "-d", k8sServerIP, "-j", "REJECT", "--reject-with", "tcp-reset").Run()
//	Expect(err).NotTo(HaveOccurred())
//	exec.Command("conntrack", "-D", "-d", k8sServerIP).Run()
//}
//
//func revealAPIServer() {
//	log.Info("Revealing API server")
//	err := exec.Command("iptables", "-D", "OUTPUT",  "-p", "tcp", "-d", k8sServerIP, "-j", "REJECT", "--reject-with", "tcp-reset").Run()
//	Expect(err).NotTo(HaveOccurred())
//}
