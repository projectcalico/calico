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

package k8s

import (
	"os/exec"

	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"bufio"
	"crypto/tls"
	"io"
	"io/ioutil"
	"net"

	log "github.com/Sirupsen/logrus"
	"github.com/kelseyhightower/envconfig"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/types"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/pkg/api/v1"
	"k8s.io/client-go/rest"

	"github.com/projectcalico/libcalico-go/lib/api"
	"github.com/projectcalico/libcalico-go/lib/client"
	"github.com/projectcalico/libcalico-go/lib/health"
)

type EnvConfig struct {
	FelixVersion string
	K8sVersion   string `default:"1.6.4"`
	PromPGURL    string
	CodeLevel    string
	UseTypha     bool
}

var config EnvConfig

var etcdContainer *Container
var apiServerContainer *Container
var k8sAPIEndpoint string
var k8sCertFilename string
var calicoClient *client.Client
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
	err := envconfig.Process("k8sfv", &config)
	Expect(err).NotTo(HaveOccurred())
	log.WithField("config", config).Info("Loaded config")

	// Start etcd, which will back the k8s API server.

	etcdContainer, err = NewContainer("etcd",
		"quay.io/coreos/etcd",
		"etcd",
		"--advertise-client-urls", "http://127.0.0.1:2379,http://127.0.0.1:4001",
		"--listen-client-urls", "http://0.0.0.0:2379,http://0.0.0.0:4001",
	)
	Expect(err).NotTo(HaveOccurred())

	// Start the k8s API server.
	apiServerContainer, err = NewContainer("apiserver",
		"gcr.io/google_containers/hyperkube-amd64:v"+config.K8sVersion,
		"/hyperkube", "apiserver",
		fmt.Sprintf("--etcd-servers=http://%s:2379", etcdContainer.IP),
		"--service-cluster-ip-range=10.101.0.0/16",
		"-v=10",
		"--authorization-mode=RBAC",
	)
	Expect(err).NotTo(HaveOccurred())

	// Allow anonymous connections to the API server.  We also use this command to wait
	// for the API server to be up.
	for {
		err := apiServerContainer.RunInContainer(
			"kubectl", "create", "clusterrolebinding",
			"anonymous-admin",
			"--clusterrole=cluster-admin",
			"--user=system:anonymous",
		)
		if err != nil {
			log.Info("Waiting for API server to accept cluster role binding")
			time.Sleep(2 * time.Second)
			continue
		}
		break
	}

	k8sAPIEndpoint = fmt.Sprintf("https://%s:6443", apiServerContainer.IP)
	for {
		resp, err := insecureHTTPClient.Get(k8sAPIEndpoint + "/apis/extensions/v1beta1/thirdpartyresources")
		if err != nil {
			log.WithError(err).Info("Waiting for API server to respond to requests")
			continue
		}
		body, err := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			log.WithError(err).Info("Waiting for API server to respond to requests")
			continue
		}
		log.WithField("body", string(body)).Info("Response from API server")
		break
	}
	log.Info("API server is up.")

	// Get the API server's cert, which we need to pass to Felix/Typha
	k8sCertFilename = "/tmp/" + apiServerContainer.Name + ".crt"
	for {
		cmd := exec.Command("docker", "cp",
			apiServerContainer.Name+":/var/run/kubernetes/apiserver.crt",
			k8sCertFilename,
		)
		err := cmd.Run()
		if err != nil {
			log.WithError(err).Warn("Waiting for API cert to appear")
			continue
		}
		break
	}

	for {
		calicoClient, err = client.New(api.CalicoAPIConfig{
			Spec: api.CalicoAPIConfigSpec{
				DatastoreType: api.Kubernetes,
				KubeConfig: api.KubeConfig{
					K8sAPIEndpoint:           k8sAPIEndpoint,
					K8sInsecureSkipTLSVerify: true,
				},
			},
		})
		if err != nil {
			log.WithError(err).Warn("Failed to init datastore")
			continue
		}
		err = calicoClient.EnsureInitialized()
		if err != nil {
			log.WithError(err).Warn("Failed to init datastore")
			continue
		}
		break
	}

	for {
		k8sClient, err = kubernetes.NewForConfig(&rest.Config{
			Transport: insecureTransport,
			Host:      "https://" + apiServerContainer.IP + ":6443",
		})
		if err == nil {
			break
		}
	}
})

var _ = AfterSuite(func() {
	apiServerContainer.Stop()
	etcdContainer.Stop()
})

var _ = Describe("with Felix running", func() {
	var felixContainer *Container
	var felixReady, felixLiveness func() int

	BeforeEach(func() {
		var err error
		felixContainer, err = NewContainer("felix",
			"--privileged",
			//${typha_felix_args}",
			"-e", "CALICO_DATASTORE_TYPE=kubernetes",
			"-e", "FELIX_HEALTHENABLED=true",
			"-e", "FELIX_LOGSEVERITYSCREEN=info",
			"-e", "FELIX_DATASTORETYPE=kubernetes",
			"-e", "FELIX_PROMETHEUSMETRICSENABLED=true",
			"-e", "FELIX_USAGEREPORTINGENABLED=false",
			"-e", "FELIX_HEALTHENABLED=true",
			"-e", "FELIX_DEBUGMEMORYPROFILEPATH=\"heap-<timestamp>\"",
			"-e", "K8S_API_ENDPOINT="+k8sAPIEndpoint,
			"-e", "K8S_INSECURE_SKIP_TLS_VERIFY=true",
			"-v", k8sCertFilename+":/tmp/apiserver.crt",
			"calico/felix", // TODO Felix version
			"calico-felix")
		Expect(err).NotTo(HaveOccurred())

		felixReady = getHealthStatus(felixContainer.IP, "9099", "readiness")
		felixLiveness = getHealthStatus(felixContainer.IP, "9099", "liveness")
	})

	AfterEach(func() {
		felixContainer.Stop()
	})

	Describe("with no per-node config in datastore", func() {
		It("should not open port due to lack of config", func() {
			// With no config, Felix won't even open the socket.
			Consistently(felixReady, "5s", "1s").Should(BeErr())
		})
	})

	createPerNodeConfig := func() {
		// Make a k8s Node using the hostname of Felix's container.
		_, err := k8sClient.Nodes().Create(&v1.Node{
			ObjectMeta: metav1.ObjectMeta{
				Name: felixContainer.Hostname,
			},
			Spec: v1.NodeSpec{},
		})
		Expect(err).NotTo(HaveOccurred())
	}

	removePerNodeConfig := func() {
		err := k8sClient.Nodes().Delete(felixContainer.Hostname, nil)
		Expect(err).NotTo(HaveOccurred())
	}

	Describe("with per-node config in datastore", func() {
		BeforeEach(createPerNodeConfig)
		AfterEach(removePerNodeConfig)

		It("should become ready and stay ready", func() {
			Eventually(felixReady, "5s", "100ms").Should(BeGood())
			Consistently(felixReady, "30s", "1s").Should(BeGood())
		})

		It("should become live and stay live", func() {
			Eventually(felixLiveness, "5s", "100ms").Should(BeGood())
			Consistently(felixLiveness, "30s", "1s").Should(BeGood())
		})
	})

	Describe("after removing iptables-restore", func() {
		BeforeEach(func() {
			// Delete iptables-restore in order to make the first apply() fail.
			err := felixContainer.RunInContainer("rm", "/sbin/iptables-restore")
			Expect(err).NotTo(HaveOccurred())

			createPerNodeConfig()
		})
		AfterEach(removePerNodeConfig)

		It("should never be ready, then die", func() {
			Consistently(felixReady, "5s", "100ms").ShouldNot(BeGood())
			Eventually(felixContainer.Stopped, "5s").Should(BeTrue())
		})
	})

	Describe("after replacing iptables with a slow version, with per-node config", func() {
		BeforeEach(func() {
			// We need to delete the file first since it's a symlink and "docker cp"
			// follows the link and overwrites the wrong file if we don't.
			err := felixContainer.RunInContainer("rm", "/sbin/iptables-restore")
			Expect(err).NotTo(HaveOccurred())

			// Copy in the nobbled iptables command.
			err = felixContainer.CopyFileIntoContainer("slow-iptables-restore",
				"/sbin/iptables-restore")
			Expect(err).NotTo(HaveOccurred())
			// Make it executable.
			err = felixContainer.RunInContainer("chmod", "+x", "/sbin/iptables-restore")
			Expect(err).NotTo(HaveOccurred())

			// Insert per-node config.  This will trigger felix to start up.
			createPerNodeConfig()
		})
		AfterEach(removePerNodeConfig)

		It("should delay readiness", func() {
			Consistently(felixReady, "5s", "100ms").ShouldNot(BeGood())
			Eventually(felixReady, "10s", "100ms").Should(BeGood())
			Consistently(felixReady, "20s", "1s").Should(BeGood())
		})

		It("should become live as normal", func() {
			Eventually(felixLiveness, "5s", "100ms").Should(BeGood())
			Consistently(felixLiveness, "30s", "1s").Should(BeGood())
		})
	})
})

type Container struct {
	Name     string
	Cmd      *exec.Cmd
	IP       string
	Hostname string
	stopped  chan struct{}
}

func NewContainer(nameStem string, dockerRunArgs ...string) (*Container, error) {
	name := nameForContainer(nameStem)
	args := []string{"run", "--rm", "--name", name, "--hostname", name}
	args = append(args, dockerRunArgs...)

	cmd := command("docker", args...)

	stdout, err := cmd.StdoutPipe()
	Expect(err).NotTo(HaveOccurred())
	stderr, err := cmd.StderrPipe()
	Expect(err).NotTo(HaveOccurred())

	err = cmd.Start()
	if err != nil {
		return nil, err
	}

	go copyOutputToLog(nameStem, "stdout", stdout)
	go copyOutputToLog(nameStem, "stderr", stderr)

	stoppedChan := make(chan struct{})
	go func() {
		defer close(stoppedChan)
		err := cmd.Wait()
		log.WithError(err).WithField("name", name).Info("Container stopped")
	}()
	waitForContainer(name, stoppedChan)
	return &Container{
		Name:     name,
		Cmd:      cmd,
		stopped:  stoppedChan,
		IP:       getContainerIP(name),
		Hostname: name,
	}, nil
}

func (c *Container) RunInContainer(args ...string) error {
	dockerArgs := append([]string{"exec", c.Name}, args...)
	cmd := exec.Command("docker", dockerArgs...)
	return cmd.Run()
}

func (c *Container) CopyFileIntoContainer(hostPath, containerPath string) error {
	cmd := exec.Command("docker", "cp", hostPath, c.Name+":"+containerPath)
	return cmd.Run()
}

func copyOutputToLog(name string, streamName string, stream io.Reader) {
	scanner := bufio.NewScanner(stream)
	for scanner.Scan() {
		log.Info(name, "[", streamName, "] ", scanner.Text())
	}
	logCxt := log.WithFields(log.Fields{
		"name":   name,
		"stream": stream,
	})
	if scanner.Err() != nil {
		logCxt.WithError(scanner.Err()).Warn("Error reading container stream")
	}
	logCxt.Info("Stream finished")
}

func (c *Container) Stop() {
	if c == nil {
		return
	}
	if c.Cmd == nil {
		// Command was never started.
		return
	}
	if c.Cmd.Process == nil {
		// Command didn't get as far as forking.
		return
	}
	// Use interrupt rather than kill or the container will detach and run in the
	// background.
	c.Cmd.Process.Signal(os.Interrupt)
	timeout := time.NewTimer(10 * time.Second)
	select {
	case <-timeout.C:
		c.Cmd.Process.Kill()
	case <-c.stopped:
		timeout.Stop()
	}
}

func (c *Container) Stopped() bool {
	select {
	case <-c.stopped:
		return true
	default:
		return false
	}
}

func waitForContainer(name string, stopChan chan struct{}) error {
	for {
		Expect(stopChan).NotTo(BeClosed())
		out, err := exec.Command("docker", "inspect", name).CombinedOutput()
		if err == nil {
			return nil
		}
		if strings.Contains(string(out), "No such") {
			log.Info("Waiting for ", name)
			time.Sleep(1 * time.Second)
			continue
		}
		return err
	}
}

func getContainerIP(name string) string {
	out, err := exec.Command("docker", "inspect",
		"--format={{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", name).Output()
	Expect(err).NotTo(HaveOccurred())
	return strings.TrimSpace(string(out))
}

var containerIdx int

func nameForContainer(stem string) string {
	containerName := fmt.Sprintf("k8sfv-%s-%d-%d", stem, os.Getpid(), containerIdx)
	containerIdx++
	return containerName
}

func command(name string, args ...string) *exec.Cmd {
	log.WithFields(log.Fields{
		"command":     name,
		"commandArgs": args,
	}).Info("Creating Command.")

	return exec.Command(name, args...)
}

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

//
//func getTyphaStatus(endpoint string) func() int {
//	return getHealthStatus(typhaIP, "9098", endpoint)
//}

func BeErr() types.GomegaMatcher {
	return BeNumerically("==", statusErr)
}

func BeBad() types.GomegaMatcher {
	return BeNumerically("==", health.StatusBad)
}

func BeGood() types.GomegaMatcher {
	return BeNumerically("==", health.StatusGood)
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
//
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
