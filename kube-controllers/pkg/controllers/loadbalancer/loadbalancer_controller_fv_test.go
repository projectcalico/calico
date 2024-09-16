// Copyright (c) 2024 Tigera, Inc. All rights reserved.
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

package loadbalancer_test

import (
	"context"
	"fmt"
	"os"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/calico/felix/fv/containers"
	"github.com/projectcalico/calico/kube-controllers/tests/testutils"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/json"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
)

var _ = Describe("Calico loadbalancer controller FV tests (etcd mode)", func() {
	var (
		etcd                   *containers.Container
		loadbalancercontroller *containers.Container
		apiserver              *containers.Container
		calicoClient           client.Interface
		k8sClient              *kubernetes.Clientset
		controllerManager      *containers.Container
	)

	const testNamespace = "test-loadbalancer-ns"

	basicIpPool := v3.IPPool{
		ObjectMeta: metav1.ObjectMeta{
			Name: "loadbalancer-ippool",
		},
		Spec: v3.IPPoolSpec{
			CIDR:         "1.2.3.0/24",
			BlockSize:    26,
			NodeSelector: "all()",
			AllowedUses:  []v3.IPPoolAllowedUse{v3.IPPoolAllowedUseLoadBalancer},
		},
	}

	specificIpPool := v3.IPPool{
		ObjectMeta: metav1.ObjectMeta{
			Name: "loadbalancer-ippool-specific",
		},
		Spec: v3.IPPoolSpec{
			CIDR:           "4.4.4.4/32",
			BlockSize:      32,
			NodeSelector:   "all()",
			AllowedUses:    []v3.IPPoolAllowedUse{v3.IPPoolAllowedUseLoadBalancer},
			AssignmentMode: v3.Manual,
		},
	}

	basicService := v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name: "basic-service",
		},
		Spec: v1.ServiceSpec{
			Type: v1.ServiceTypeLoadBalancer,
			Ports: []v1.ServicePort{
				{
					Port:       8787,
					Name:       "default",
					TargetPort: intstr.FromInt32(9797),
				},
			},
			Selector: map[string]string{"app": "my-app"},
		},
	}

	serviceIpv4PoolSpecified := v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name: "basic-ipv4-pool-specified",
			Annotations: map[string]string{
				"projectcalico.org/ipv4pools": fmt.Sprintf("[\"%s\"]", specificIpPool.Name),
			},
		},
		Spec: v1.ServiceSpec{
			Type: v1.ServiceTypeLoadBalancer,
			Ports: []v1.ServicePort{
				{
					Port:       8787,
					Name:       "default",
					TargetPort: intstr.FromInt32(9797),
				},
			},
			Selector: map[string]string{"app": "my-app"},
		},
	}

	serviceIpAddressSpecified := v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name: "basic-ip-address-specified",
			Annotations: map[string]string{
				"projectcalico.org/loadBalancerIPs": "[\"1.2.3.100\"]",
			},
		},
		Spec: v1.ServiceSpec{
			Type: v1.ServiceTypeLoadBalancer,
			Ports: []v1.ServicePort{
				{
					Port:       8787,
					Name:       "default",
					TargetPort: intstr.FromInt32(9797),
				},
			},
			Selector: map[string]string{"app": "my-app"},
		},
	}

	BeforeEach(func() {
		// Run etcd.
		etcd = testutils.RunEtcd()
		calicoClient = testutils.GetCalicoClient(apiconfig.EtcdV3, etcd.IP, "")

		// Run apiserver.
		apiserver = testutils.RunK8sApiserver(etcd.IP)

		// Write out a kubeconfig file
		kconfigfile, err := os.CreateTemp("", "ginkgo-loadbalancercontroller")
		Expect(err).NotTo(HaveOccurred())
		defer os.Remove(kconfigfile.Name())
		data := testutils.BuildKubeconfig(apiserver.IP)
		_, err = kconfigfile.Write([]byte(data))
		Expect(err).NotTo(HaveOccurred())

		// Make the kubeconfig readable by the container.
		Expect(kconfigfile.Chmod(os.ModePerm)).NotTo(HaveOccurred())

		loadbalancercontroller = testutils.RunLoadBalancerController(apiconfig.EtcdV3, etcd.IP, kconfigfile.Name(), "")

		k8sClient, err = testutils.GetK8sClient(kconfigfile.Name())
		Expect(err).NotTo(HaveOccurred())

		// Wait for the apiserver to be available.
		Eventually(func() error {
			_, err := k8sClient.CoreV1().Services(testNamespace).List(context.Background(), metav1.ListOptions{})
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
		controllerManager.Stop()
		loadbalancercontroller.Stop()
		apiserver.Stop()
		etcd.Stop()
	})

	Context("Service LoadBalancer FV tests - LoadBalancer AllServices mode", func() {
		BeforeEach(func() {
			nsName := testNamespace
			ns := &v1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: nsName,
				},
				Spec: v1.NamespaceSpec{},
			}
			_, err := k8sClient.CoreV1().Namespaces().Create(context.Background(), ns, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			_, err = calicoClient.IPPools().Create(context.Background(), &basicIpPool, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())

			_, err = calicoClient.IPPools().Create(context.Background(), &specificIpPool, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())
		})

		It("Should assign IP from available IP pool", func() {
			_, err := k8sClient.CoreV1().Services(testNamespace).Create(context.Background(), &basicService, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			Eventually(func() []v1.LoadBalancerIngress {
				service, _ := k8sClient.CoreV1().Services(testNamespace).Get(context.Background(), basicService.Name, metav1.GetOptions{})
				return service.Status.LoadBalancer.Ingress
			}, time.Second*15, 500*time.Millisecond).ShouldNot(BeEmpty())
		})

		It("Should assign IP from specified IP pool", func() {
			_, err := k8sClient.CoreV1().Services(testNamespace).Create(context.Background(), &serviceIpv4PoolSpecified, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			Eventually(func() []v1.LoadBalancerIngress {
				service, _ := k8sClient.CoreV1().Services(testNamespace).Get(context.Background(), serviceIpv4PoolSpecified.Name, metav1.GetOptions{})
				return service.Status.LoadBalancer.Ingress
			}, time.Second*15, 500*time.Millisecond).Should(Not(BeEmpty()))

			service, _ := k8sClient.CoreV1().Services(testNamespace).Get(context.Background(), serviceIpv4PoolSpecified.Name, metav1.GetOptions{})
			Expect(service.Status.LoadBalancer.Ingress[0].IP).Should(Equal("4.4.4.4"))
		})

		It("Should assign specific IP address", func() {
			_, err := k8sClient.CoreV1().Services(testNamespace).Create(context.Background(), &serviceIpAddressSpecified, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			Eventually(func() []v1.LoadBalancerIngress {
				service, _ := k8sClient.CoreV1().Services(testNamespace).Get(context.Background(), serviceIpAddressSpecified.Name, metav1.GetOptions{})
				return service.Status.LoadBalancer.Ingress
			}, time.Second*15, 500*time.Millisecond).Should(Not(BeEmpty()))

			service, _ := k8sClient.CoreV1().Services(testNamespace).Get(context.Background(), serviceIpAddressSpecified.Name, metav1.GetOptions{})
			Expect(service.Status.LoadBalancer.Ingress[0].IP).Should(Equal("1.2.3.100"))
		})

		It("Should remove IP assignment when Service type is changed from LoadBalancer to NodePort", func() {
			_, err := k8sClient.CoreV1().Services(testNamespace).Create(context.Background(), &serviceIpv4PoolSpecified, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			Eventually(func() []v1.LoadBalancerIngress {
				service, _ := k8sClient.CoreV1().Services(testNamespace).Get(context.Background(), serviceIpv4PoolSpecified.Name, metav1.GetOptions{})
				return service.Status.LoadBalancer.Ingress
			}, time.Second*15, 500*time.Millisecond).Should(Not(BeEmpty()))

			service, err := k8sClient.CoreV1().Services(testNamespace).Get(context.Background(), serviceIpv4PoolSpecified.Name, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(service.Status.LoadBalancer.Ingress[0].IP).Should(Equal("4.4.4.4"))

			svcPatch := map[string]interface{}{}
			spec := map[string]interface{}{}
			svcPatch["spec"] = spec
			spec["type"] = v1.ServiceTypeNodePort
			patch, err := json.Marshal(svcPatch)
			Expect(err).NotTo(HaveOccurred())

			service, err = k8sClient.CoreV1().Services(testNamespace).Patch(context.Background(), service.Name, types.StrategicMergePatchType, patch, metav1.PatchOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(service.Spec.Type).To(Equal(v1.ServiceTypeNodePort))
			Expect(service.Status.LoadBalancer.Ingress).Should(BeEmpty())
		})

		It("Should not assign IP if there is no LoadBalancer IP pool", func() {
			_, err := calicoClient.IPPools().Delete(context.Background(), specificIpPool.Name, options.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())

			_, err = calicoClient.IPPools().Delete(context.Background(), basicIpPool.Name, options.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())

			_, err = k8sClient.CoreV1().Services(testNamespace).Create(context.Background(), &basicService, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			Eventually(func() []v1.LoadBalancerIngress {
				service, _ := k8sClient.CoreV1().Services(testNamespace).Get(context.Background(), basicService.Name, metav1.GetOptions{})
				return service.Status.LoadBalancer.Ingress
			}, time.Second*15, 500*time.Millisecond).Should(BeEmpty())
		})

		It("Should assign IP after LoadBalancer IP pool is created", func() {
			_, err := calicoClient.IPPools().Delete(context.Background(), specificIpPool.Name, options.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())

			_, err = calicoClient.IPPools().Delete(context.Background(), basicIpPool.Name, options.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())

			_, err = k8sClient.CoreV1().Services(testNamespace).Create(context.Background(), &basicService, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			Eventually(func() []v1.LoadBalancerIngress {
				service, _ := k8sClient.CoreV1().Services(testNamespace).Get(context.Background(), basicService.Name, metav1.GetOptions{})
				return service.Status.LoadBalancer.Ingress
			}, time.Second*15, 500*time.Millisecond).Should(BeEmpty())

			_, err = calicoClient.IPPools().Create(context.Background(), &basicIpPool, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())

			Eventually(func() []v1.LoadBalancerIngress {
				service, _ := k8sClient.CoreV1().Services(testNamespace).Get(context.Background(), basicService.Name, metav1.GetOptions{})
				return service.Status.LoadBalancer.Ingress
			}, time.Second*15, 500*time.Millisecond).ShouldNot(BeEmpty())
		})

		It("Should assign IP after LoadBalancer IP pool is created", func() {
			_, err := calicoClient.IPPools().Delete(context.Background(), specificIpPool.Name, options.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())

			_, err = calicoClient.IPPools().Delete(context.Background(), basicIpPool.Name, options.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())

			_, err = k8sClient.CoreV1().Services(testNamespace).Create(context.Background(), &basicService, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			Eventually(func() []v1.LoadBalancerIngress {
				service, _ := k8sClient.CoreV1().Services(testNamespace).Get(context.Background(), basicService.Name, metav1.GetOptions{})
				return service.Status.LoadBalancer.Ingress
			}, time.Second*15, 500*time.Millisecond).Should(BeEmpty())

			_, err = calicoClient.IPPools().Create(context.Background(), &basicIpPool, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())

			Eventually(func() []v1.LoadBalancerIngress {
				service, _ := k8sClient.CoreV1().Services(testNamespace).Get(context.Background(), basicService.Name, metav1.GetOptions{})
				return service.Status.LoadBalancer.Ingress
			}, time.Second*15, 500*time.Millisecond).ShouldNot(BeEmpty())
		})
	})
})
