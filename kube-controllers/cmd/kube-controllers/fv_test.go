// Copyright (c) 2017-2022 Tigera, Inc. All rights reserved.
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

package main_test

import (
	"context"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/projectcalico/calico/felix/fv/containers"
	"github.com/projectcalico/calico/kube-controllers/tests/testutils"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

var _ = Describe("[etcd] kube-controllers health check FV tests", func() {
	var (
		etcd              *containers.Container
		kubeControllers   *containers.Container
		apiserver         *containers.Container
		calicoClient      client.Interface
		k8sClient         *kubernetes.Clientset
		controllerManager *containers.Container
		err               error
		kconfigfile       string
		removeKubeconfig  func()
	)

	BeforeEach(func() {
		// Run etcd.
		etcd = testutils.RunEtcd()
		calicoClient = testutils.GetCalicoClient(apiconfig.EtcdV3, etcd.IP, "")

		// Run apiserver.
		apiserver = testutils.RunK8sApiserver(etcd.IP)

		kconfigfile, removeKubeconfig = testutils.BuildKubeconfig(apiserver.IP)

		// Run the controller.
		kubeControllers = testutils.RunKubeControllers(apiconfig.EtcdV3, etcd.IP, kconfigfile, "")

		k8sClient, err = testutils.GetK8sClient(kconfigfile)
		Expect(err).NotTo(HaveOccurred())

		// Wait for the apiserver to be available.
		Eventually(func() error {
			_, err := k8sClient.CoreV1().Namespaces().List(context.Background(), metav1.ListOptions{})
			return err
		}, 30*time.Second, 1*time.Second).Should(BeNil())

		// Run controller manager.  Empirically it can take around 10s until the
		// controller manager is ready to create default service accounts, even
		// when the k8s image has already been downloaded to run the API
		// server.  We use Eventually to allow for possible delay when doing
		// initial pod creation below.
		controllerManager = testutils.RunK8sControllerManager(apiserver.IP)
	})

	AfterEach(func() {
		_ = calicoClient.Close()
		controllerManager.Stop()
		kubeControllers.Stop()
		apiserver.Stop()
		etcd.Stop()
		removeKubeconfig()
	})

	It("should initialize the datastore at start-of-day", func() {
		var info *v3.ClusterInformation
		Eventually(func() *v3.ClusterInformation {
			info, _ = calicoClient.ClusterInformation().Get(context.Background(), "default", options.GetOptions{})
			return info
		}, 10*time.Second).ShouldNot(BeNil())

		Expect(info.Spec.ClusterGUID).To(MatchRegexp("^[a-f0-9]{32}$"))
		Expect(info.Spec.ClusterType).To(Equal("k8s"))
		Expect(*info.Spec.DatastoreReady).To(BeTrue())
	})

	Context("Healthcheck FV tests", func() {
		It("should pass health check", func() {
			By("Waiting for an initial readiness report")
			Eventually(func() []byte {
				cmd := exec.Command("docker", "exec", kubeControllers.Name, "/usr/bin/check-status", "-r")
				stdoutStderr, _ := cmd.CombinedOutput()

				return stdoutStderr
			}, 20*time.Second, 500*time.Millisecond).ShouldNot(ContainSubstring("initialized to false"))

			By("Waiting for the controller to be ready")
			Eventually(func() string {
				cmd := exec.Command("docker", "exec", kubeControllers.Name, "/usr/bin/check-status", "-r")
				stdoutStderr, _ := cmd.CombinedOutput()

				return strings.TrimSpace(string(stdoutStderr))
			}, 20*time.Second, 500*time.Millisecond).Should(Equal("Ready"))
		})

		It("should fail health check if apiserver is not running", func() {
			By("Waiting for an initial readiness report")
			Eventually(func() []byte {
				cmd := exec.Command("docker", "exec", kubeControllers.Name, "/usr/bin/check-status", "-r")
				stdoutStderr, _ := cmd.CombinedOutput()

				return stdoutStderr
			}, 20*time.Second, 500*time.Millisecond).ShouldNot(ContainSubstring("initialized to false"))

			By("Stopping the apiserver")
			apiserver.Stop()

			By("Waiting for the readiness to change")
			Eventually(func() []byte {
				cmd := exec.Command("docker", "exec", kubeControllers.Name, "/usr/bin/check-status", "-r")
				stdoutStderr, _ := cmd.CombinedOutput()

				return stdoutStderr
			}, 20*time.Second, 500*time.Millisecond).Should(ContainSubstring("Error reaching apiserver"))
		})

		It("should fail health check if etcd not running", func() {
			By("Waiting for an initial readiness report")
			Eventually(func() []byte {
				cmd := exec.Command("docker", "exec", kubeControllers.Name, "/usr/bin/check-status", "-r")
				stdoutStderr, _ := cmd.CombinedOutput()

				return stdoutStderr
			}, 20*time.Second, 500*time.Millisecond).ShouldNot(ContainSubstring("initialized to false"))

			By("Stopping etcd")
			etcd.Stop()

			By("Waiting for the readiness to change")
			Eventually(func() []byte {
				cmd := exec.Command("docker", "exec", kubeControllers.Name, "/usr/bin/check-status", "-r")
				stdoutStderr, _ := cmd.CombinedOutput()

				return stdoutStderr
			}, 20*time.Second, 500*time.Millisecond).Should(ContainSubstring("Error verifying datastore"))
		})
	})
})

var _ = Describe("kube-controllers metrics and pprof FV tests", func() {
	var (
		etcd             *containers.Container
		kubectrls        *containers.Container
		apiserver        *containers.Container
		kconfigfile      string
		removeKubeconfig func()
	)

	BeforeEach(func() {
		// Run etcd.
		etcd = testutils.RunEtcd()

		// Run apiserver.
		apiserver = testutils.RunK8sApiserver(etcd.IP)

		// Write out a kubeconfig file
		kconfigfile, removeKubeconfig = testutils.BuildKubeconfig(apiserver.IP)

		// Create some clients.
		client := testutils.GetCalicoClient(apiconfig.Kubernetes, "", kconfigfile)
		k8sClient, err := testutils.GetK8sClient(kconfigfile)
		Expect(err).NotTo(HaveOccurred())

		// Wait for the apiserver to be available.
		Eventually(func() error {
			_, err := k8sClient.CoreV1().Namespaces().List(context.Background(), metav1.ListOptions{})
			return err
		}, 30*time.Second, 1*time.Second).Should(BeNil())

		// Apply the necessary CRDs. There can sometimes be a delay between starting
		// the API server and when CRDs are apply-able, so retry here.
		testutils.ApplyCRDs(apiserver)

		// Enable metrics and pprof ports for these tests.
		Eventually(func() error {
			kcfg := v3.NewKubeControllersConfiguration()
			kcfg.Name = "default"
			metricsPort := 9094
			kcfg.Spec.PrometheusMetricsPort = &metricsPort
			profilePort := int32(9095)
			kcfg.Spec.DebugProfilePort = &profilePort
			_, err = client.KubeControllersConfiguration().Create(context.Background(), kcfg, options.SetOptions{})
			return err
		}, 10*time.Second).Should(Succeed())

		// Run the controller. We don't need to run any controllers for these tests, but
		// we do need to run something, so just run the node controller.
		kubectrls = testutils.RunKubeControllers(apiconfig.Kubernetes, etcd.IP, kconfigfile, "node")
	})

	AfterEach(func() {
		kubectrls.Stop()
		apiserver.Stop()
		etcd.Stop()
		removeKubeconfig()
	})

	get := func(server, path string) error {
		httpClient := http.Client{Timeout: 2 * time.Second}
		url := server + path
		resp, err := httpClient.Get(url)
		if err != nil {
			return err
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != 200 {
			return fmt.Errorf("bad status code for %q: %d", url, resp.StatusCode)
		}
		return nil
	}

	It("should not expose pprof endpoints on the prometheus port", func() {
		// By checking that prometheus metrics are available on the default port.
		metricsEndpoint := fmt.Sprintf("http://%s:9094", kubectrls.IP)
		Expect(get(metricsEndpoint, "/metrics")).To(Succeed())

		// By checking that pprof endpoints are not available on the prometheus port.
		Expect(get(metricsEndpoint, "/debug/pprof/profile?seconds=1")).NotTo(Succeed())

		// By checking that pprof endpoints are available on the pprof port.
		pprofEndpoint := fmt.Sprintf("http://%s:9095", kubectrls.IP)
		Expect(get(pprofEndpoint, "/debug/pprof/profile?seconds=1")).To(Succeed())
	})
})

var _ = Describe("[kdd] kube-controllers health check FV tests", func() {
	var (
		etcd              *containers.Container
		kubeControllers   *containers.Container
		apiserver         *containers.Container
		calicoClient      client.Interface
		k8sClient         *kubernetes.Clientset
		controllerManager *containers.Container
		err               error
		kconfigfile       string
		removeKubeconfig  func()
	)

	BeforeEach(func() {
		// Run etcd.
		etcd = testutils.RunEtcd()

		// Run apiserver.
		apiserver = testutils.RunK8sApiserver(etcd.IP)

		// Write out a kubeconfig file
		kconfigfile, removeKubeconfig = testutils.BuildKubeconfig(apiserver.IP)

		// Make the kubeconfig readable by the container.
		k8sClient, err = testutils.GetK8sClient(kconfigfile)
		Expect(err).NotTo(HaveOccurred())
		// Wait for the apiserver to be available.
		Eventually(func() error {
			_, err := k8sClient.CoreV1().Namespaces().List(context.Background(), metav1.ListOptions{})
			return err
		}, 30*time.Second, 1*time.Second).Should(BeNil())
		Consistently(func() error {
			_, err := k8sClient.CoreV1().Namespaces().List(context.Background(), metav1.ListOptions{})
			return err
		}, 10*time.Second, 1*time.Second).Should(BeNil())

		// Apply the necessary CRDs. There can sometimes be a delay between starting
		// the API server and when CRDs are apply-able, so retry here.
		testutils.ApplyCRDs(apiserver)

		calicoClient = testutils.GetCalicoClient(apiconfig.Kubernetes, "", kconfigfile)

		// In KDD mode, we only support the node controller right now.
		kubeControllers = testutils.RunKubeControllers(apiconfig.Kubernetes, "", kconfigfile, "node")

		// Run controller manager.
		controllerManager = testutils.RunK8sControllerManager(apiserver.IP)
	})

	AfterEach(func() {
		_ = calicoClient.Close()
		controllerManager.Stop()
		kubeControllers.Stop()
		apiserver.Stop()
		etcd.Stop()
		removeKubeconfig()
	})

	It("should initialize the datastore at start-of-day", func() {
		var info *v3.ClusterInformation
		Eventually(func() *v3.ClusterInformation {
			info, _ = calicoClient.ClusterInformation().Get(context.Background(), "default", options.GetOptions{})
			return info
		}, 10*time.Second).ShouldNot(BeNil())

		Expect(info.Spec.ClusterGUID).To(MatchRegexp("^[a-f0-9]{32}$"))
		Expect(info.Spec.ClusterType).To(Equal("k8s,kdd"))
		Expect(*info.Spec.DatastoreReady).To(BeTrue())
	})

	Context("Healthcheck FV tests", func() {
		It("should pass health check", func() {
			By("Waiting for an initial readiness report")
			Eventually(func() []byte {
				cmd := exec.Command("docker", "exec", kubeControllers.Name, "/usr/bin/check-status", "-r")
				stdoutStderr, _ := cmd.CombinedOutput()

				return stdoutStderr
			}, 20*time.Second, 500*time.Millisecond).ShouldNot(ContainSubstring("initialized to false"))

			By("Waiting for the controller to be ready")
			Eventually(func() string {
				cmd := exec.Command("docker", "exec", kubeControllers.Name, "/usr/bin/check-status", "-r")
				stdoutStderr, _ := cmd.CombinedOutput()

				return strings.TrimSpace(string(stdoutStderr))
			}, 20*time.Second, 500*time.Millisecond).Should(Equal("Ready"))
		})

		It("should fail health check if apiserver is not running", func() {
			By("Waiting for an initial readiness report")
			Eventually(func() []byte {
				cmd := exec.Command("docker", "exec", kubeControllers.Name, "/usr/bin/check-status", "-r")
				stdoutStderr, _ := cmd.CombinedOutput()

				return stdoutStderr
			}, 20*time.Second, 500*time.Millisecond).ShouldNot(ContainSubstring("initialized to false"))

			By("Stopping the apiserver")
			apiserver.Stop()

			By("Waiting for the readiness to change")
			Eventually(func() []byte {
				cmd := exec.Command("docker", "exec", kubeControllers.Name, "/usr/bin/check-status", "-r")
				stdoutStderr, _ := cmd.CombinedOutput()

				return stdoutStderr
			}, 60*time.Second, 500*time.Millisecond).Should(ContainSubstring("Error"))
		})
	})
})
