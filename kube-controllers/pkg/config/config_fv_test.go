// Copyright (c) 2020 Tigera, Inc. All rights reserved.
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

package config_test

import (
	"context"
	"os"
	"time"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/calico/libcalico-go/lib/options"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/fv/containers"
	"github.com/projectcalico/calico/kube-controllers/tests/testutils"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
)

var _ = Describe("KubeControllersConfiguration FV tests", func() {
	var (
		etcd              *containers.Container
		uut               *containers.Container
		apiserver         *containers.Container
		c                 client.Interface
		k8sClient         *kubernetes.Clientset
		controllerManager *containers.Container
		kconfigFile       *os.File
	)

	BeforeEach(func() {
		// Run etcd.
		etcd = testutils.RunEtcd()
		c = testutils.GetCalicoClient(apiconfig.EtcdV3, etcd.IP, "")

		// Run apiserver.
		apiserver = testutils.RunK8sApiserver(etcd.IP)

		// Write out a kubeconfig file
		var err error
		kconfigFile, err = os.CreateTemp("", "ginkgo-nodecontroller")
		Expect(err).NotTo(HaveOccurred())
		data := testutils.BuildKubeconfig(apiserver.IP)
		_, err = kconfigFile.Write([]byte(data))
		Expect(err).NotTo(HaveOccurred())

		// Make the kubeconfig readable by the container.
		Expect(kconfigFile.Chmod(os.ModePerm)).NotTo(HaveOccurred())

		k8sClient, err = testutils.GetK8sClient(kconfigFile.Name())
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
		os.Remove(kconfigFile.Name())
		controllerManager.Stop()
		uut.Stop()
		apiserver.Stop()
		etcd.Stop()
	})

	Context("with no KubeControllersConfig at start of day", func() {
		BeforeEach(func() {
			uut = testutils.RunKubeControllerWithEnv(apiconfig.EtcdV3, etcd.IP, kconfigFile.Name(), nil)
		})

		It("should create default config", func() {
			var out *v3.KubeControllersConfiguration
			Eventually(func() *v3.KubeControllersConfiguration {
				out, _ = c.KubeControllersConfiguration().Get(context.Background(), "default", options.GetOptions{})
				return out
			}, time.Second*10, time.Millisecond*500).ShouldNot(BeNil())

			// Spot check the status to make sure it's set.
			Expect(out.Status.RunningConfig.HealthChecks).To(Equal(v3.Enabled))
		})

		It("should recreate status if overwritten", func() {
			var out *v3.KubeControllersConfiguration
			Eventually(func() *v3.KubeControllersConfiguration {
				out, _ = c.KubeControllersConfiguration().Get(context.Background(), "default", options.GetOptions{})
				return out
			}, time.Second*10, time.Millisecond*500).ShouldNot(BeNil())

			// overwrite the status back to empty value
			out.Status = v3.KubeControllersConfigurationStatus{}
			out, err := c.KubeControllersConfiguration().Update(context.Background(), out, options.SetOptions{})
			Expect(err).ToNot(HaveOccurred())

			// status is recreated
			Eventually(func() string {
				out, err := c.KubeControllersConfiguration().Get(context.Background(), "default", options.GetOptions{})
				if err != nil {
					return ""
				}
				return out.Status.RunningConfig.HealthChecks
			}, time.Second*5).Should(Equal(v3.Enabled))
		})

		It("should restart if config is changed", func() {
			var out *v3.KubeControllersConfiguration
			Eventually(func() *v3.KubeControllersConfiguration {
				out, _ = c.KubeControllersConfiguration().Get(context.Background(), "default", options.GetOptions{})
				return out
			}, time.Second*10, time.Millisecond*500).ShouldNot(BeNil())

			// disable the namespace controller
			out.Spec.Controllers.Namespace = nil
			out, err := c.KubeControllersConfiguration().Update(context.Background(), out, options.SetOptions{})
			Expect(err).ToNot(HaveOccurred())

			// container stops
			Eventually(uut.Stopped, time.Second*30, time.Second).Should(BeTrue())

			// Clear the status, so we know when the new system comes up
			out, err = c.KubeControllersConfiguration().Get(context.Background(), "default", options.GetOptions{})
			Expect(err).ToNot(HaveOccurred())
			out.Status = v3.KubeControllersConfigurationStatus{}
			out, err = c.KubeControllersConfiguration().Update(context.Background(), out, options.SetOptions{})
			Expect(err).ToNot(HaveOccurred())

			// restart the container (in a real system, Kubernetes restarts it)
			uut = testutils.RunKubeControllerWithEnv(apiconfig.EtcdV3, etcd.IP, kconfigFile.Name(), nil)

			// Wait for status to get set again, by checking a field for non-empty value
			Eventually(func() bool {
				out, err = c.KubeControllersConfiguration().Get(context.Background(), "default", options.GetOptions{})
				Expect(err).ToNot(HaveOccurred())
				return out.Status.RunningConfig.HealthChecks != ""
			}, time.Second*10, time.Millisecond*500).Should(BeTrue())

			// Namespace controller should be disabled as our original update set
			Expect(out.Status.RunningConfig.Controllers.Namespace).To(BeNil())
		})
	})

	Context("with KubeControllersConfig at start of day", func() {
		BeforeEach(func() {
			kcc := v3.NewKubeControllersConfiguration()
			kcc.Name = "default"
			kcc.Spec = v3.KubeControllersConfigurationSpec{Controllers: v3.ControllersConfig{
				Namespace: &v3.NamespaceControllerConfig{
					ReconcilerPeriod: &metav1.Duration{Duration: time.Minute * 6},
				},
			}}
			_, err := c.KubeControllersConfiguration().Create(context.Background(), kcc, options.SetOptions{})
			Expect(err).ToNot(HaveOccurred())

			uut = testutils.RunKubeControllerWithEnv(apiconfig.EtcdV3, etcd.IP, kconfigFile.Name(), nil)
		})

		It("should set status matching config with defaults for unset values", func() {
			var out *v3.KubeControllersConfiguration
			Eventually(func() *v3.NamespaceControllerConfig {
				var err error
				out, err = c.KubeControllersConfiguration().Get(context.Background(), "default", options.GetOptions{})
				Expect(err).ToNot(HaveOccurred())
				return out.Status.RunningConfig.Controllers.Namespace
			}, time.Second*10, time.Millisecond*500).ShouldNot(BeNil())
			Expect(out.Status.RunningConfig.Controllers.Node).To(BeNil())
			Expect(out.Status.RunningConfig.Controllers.Policy).To(BeNil())
			Expect(out.Status.RunningConfig.Controllers.WorkloadEndpoint).To(BeNil())
			Expect(out.Status.RunningConfig.Controllers.ServiceAccount).To(BeNil())

			// These fields are defaulted
			Expect(out.Status.RunningConfig.HealthChecks).To(Equal(v3.Enabled))
			Expect(out.Status.RunningConfig.LogSeverityScreen).To(Equal("Info"))
			Expect(out.Status.RunningConfig.EtcdV3CompactionPeriod).To(Equal(&metav1.Duration{Duration: time.Minute * 10}))
		})
	})

	Context("with environment overrides", func() {
		BeforeEach(func() {
			kcc := v3.NewKubeControllersConfiguration()
			kcc.Name = "default"
			kcc.Spec = v3.KubeControllersConfigurationSpec{Controllers: v3.ControllersConfig{
				Namespace: &v3.NamespaceControllerConfig{
					ReconcilerPeriod: &metav1.Duration{Duration: time.Minute * 6},
				},
			}}
			_, err := c.KubeControllersConfiguration().Create(context.Background(), kcc, options.SetOptions{})
			Expect(err).ToNot(HaveOccurred())

			uut = testutils.RunKubeControllerWithEnv(apiconfig.EtcdV3, etcd.IP, kconfigFile.Name(), map[string]string{
				"ENABLED_CONTROLLERS": "node",
			})
		})

		It("should not restart after change that is overridden", func() {
			// Wait until controller is up and has set status
			var kcc *v3.KubeControllersConfiguration
			Eventually(func() map[string]string {
				var err error
				kcc, err = c.KubeControllersConfiguration().Get(context.Background(), "default", options.GetOptions{})
				Expect(err).ToNot(HaveOccurred())
				return kcc.Status.EnvironmentVars
			}, time.Second*10, time.Millisecond*500).Should(Equal(map[string]string{"ENABLED_CONTROLLERS": "node"}))

			// Enable the policy controller, which isn't specified in the ENABLED_CONTROLLERS env.
			kcc.Spec.Controllers.Policy = &v3.PolicyControllerConfig{}

			// Also delete the status so we can see it is reset
			kcc.Status = v3.KubeControllersConfigurationStatus{}
			var err error
			kcc, err = c.KubeControllersConfiguration().Update(context.Background(), kcc, options.SetOptions{})
			Expect(err).ToNot(HaveOccurred())

			// Since enabled controllers environment variable supersedes the API
			// the controller should not restart
			Consistently(uut.Stopped, time.Second*10, time.Millisecond*500).Should(BeFalse())

			// Should have recreated status with only the node controller enabled.
			kcc, err = c.KubeControllersConfiguration().Get(context.Background(), "default", options.GetOptions{})
			Expect(err).ToNot(HaveOccurred())
			Expect(kcc.Status.EnvironmentVars).To(Equal(map[string]string{"ENABLED_CONTROLLERS": "node"}))
		})
	})
})
