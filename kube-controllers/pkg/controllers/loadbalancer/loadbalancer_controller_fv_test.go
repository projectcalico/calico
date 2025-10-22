// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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

package loadbalancer

import (
	"context"
	"fmt"
	"os"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"

	"github.com/projectcalico/calico/felix/fv/containers"
	"github.com/projectcalico/calico/kube-controllers/tests/testutils"
	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/json"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
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

	v4poolManualIP := "1.1.1.1"
	specificIpFromAutomaticPool := "1.2.3.100"
	v4poolManualSpecifcIP := "4.4.4.4"
	automatic := v3.Automatic
	manual := v3.Manual

	v4poolManual := v3.IPPool{
		ObjectMeta: metav1.ObjectMeta{
			Name: "v4pool-manual",
		},
		Spec: v3.IPPoolSpec{
			CIDR:           fmt.Sprintf("%s/32", v4poolManualIP),
			BlockSize:      32,
			NodeSelector:   "all()",
			AllowedUses:    []v3.IPPoolAllowedUse{v3.IPPoolAllowedUseLoadBalancer},
			AssignmentMode: &manual,
		},
	}

	v4poolAutomatic := v3.IPPool{
		ObjectMeta: metav1.ObjectMeta{
			Name: "v4pool-automatic",
		},
		Spec: v3.IPPoolSpec{
			CIDR:           "1.2.3.0/24",
			BlockSize:      26,
			NodeSelector:   "all()",
			AllowedUses:    []v3.IPPoolAllowedUse{v3.IPPoolAllowedUseLoadBalancer},
			AssignmentMode: &automatic,
		},
	}

	v4poolManualSpecific := v3.IPPool{
		ObjectMeta: metav1.ObjectMeta{
			Name: "loadbalancer-ippool-specific",
		},
		Spec: v3.IPPoolSpec{
			CIDR:           fmt.Sprintf("%s/32", v4poolManualSpecifcIP),
			BlockSize:      32,
			NodeSelector:   "all()",
			AllowedUses:    []v3.IPPoolAllowedUse{v3.IPPoolAllowedUseLoadBalancer},
			AssignmentMode: &manual,
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
				"projectcalico.org/ipv4pools": fmt.Sprintf("[\"%s\"]", v4poolManualSpecific.Name),
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
				"projectcalico.org/loadBalancerIPs": fmt.Sprintf("[\"%s\"]", specificIpFromAutomaticPool),
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
		defer func() { _ = os.Remove(kconfigfile.Name()) }()
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
		_ = calicoClient.Close()
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

			_, err = calicoClient.IPPools().Create(context.Background(), &v4poolAutomatic, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())

			_, err = calicoClient.IPPools().Create(context.Background(), &v4poolManual, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())

			_, err = calicoClient.IPPools().Create(context.Background(), &v4poolManualSpecific, options.SetOptions{})
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

		It("Should remove previously assigned IP when all IPPools are deleted", func() {
			_, err := k8sClient.CoreV1().Services(testNamespace).Create(context.Background(), &basicService, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			Eventually(func() []v1.LoadBalancerIngress {
				service, _ := k8sClient.CoreV1().Services(testNamespace).Get(context.Background(), basicService.Name, metav1.GetOptions{})
				return service.Status.LoadBalancer.Ingress
			}, time.Second*15, 500*time.Millisecond).ShouldNot(BeEmpty())

			_, err = calicoClient.IPPools().Delete(context.Background(), v4poolManual.Name, options.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())

			_, err = calicoClient.IPPools().Delete(context.Background(), v4poolManualSpecific.Name, options.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())

			// We delete the automatic pool last, ensuring that the service will not be reassigned IP before last pool is deleted
			_, err = calicoClient.IPPools().Delete(context.Background(), v4poolAutomatic.Name, options.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())

			Eventually(func() []v1.LoadBalancerIngress {
				service, _ := k8sClient.CoreV1().Services(testNamespace).Get(context.Background(), basicService.Name, metav1.GetOptions{})
				return service.Status.LoadBalancer.Ingress
			}, time.Second*15, 500*time.Millisecond).Should(BeEmpty())
		})

		It("Should assign IP from specified IP pool", func() {
			_, err := k8sClient.CoreV1().Services(testNamespace).Create(context.Background(), &serviceIpv4PoolSpecified, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			Eventually(func() []v1.LoadBalancerIngress {
				service, _ := k8sClient.CoreV1().Services(testNamespace).Get(context.Background(), serviceIpv4PoolSpecified.Name, metav1.GetOptions{})
				return service.Status.LoadBalancer.Ingress
			}, time.Second*15, 500*time.Millisecond).Should(Not(BeEmpty()))

			service, err := k8sClient.CoreV1().Services(testNamespace).Get(context.Background(), serviceIpv4PoolSpecified.Name, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(service.Status.LoadBalancer.Ingress[0].IP).Should(Equal("4.4.4.4"))
		})

		It("Should assign specific IP address", func() {
			_, err := k8sClient.CoreV1().Services(testNamespace).Create(context.Background(), &serviceIpAddressSpecified, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			Eventually(func() []v1.LoadBalancerIngress {
				service, _ := k8sClient.CoreV1().Services(testNamespace).Get(context.Background(), serviceIpAddressSpecified.Name, metav1.GetOptions{})
				return service.Status.LoadBalancer.Ingress
			}, time.Second*15, 500*time.Millisecond).Should(Not(BeEmpty()))

			service, err := k8sClient.CoreV1().Services(testNamespace).Get(context.Background(), serviceIpAddressSpecified.Name, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(service.Status.LoadBalancer.Ingress[0].IP).Should(Equal(specificIpFromAutomaticPool))
		})

		It("Should remove IP assignment when Service type is changed from LoadBalancer to NodePort", func() {
			_, err := k8sClient.CoreV1().Services(testNamespace).Create(context.Background(), &basicService, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			Eventually(func() []v1.LoadBalancerIngress {
				service, _ := k8sClient.CoreV1().Services(testNamespace).Get(context.Background(), basicService.Name, metav1.GetOptions{})
				return service.Status.LoadBalancer.Ingress
			}, time.Second*15, 500*time.Millisecond).Should(Not(BeEmpty()))

			_, err = k8sClient.CoreV1().Services(testNamespace).Create(context.Background(), &serviceIpv4PoolSpecified, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			Eventually(func() []v1.LoadBalancerIngress {
				service, _ := k8sClient.CoreV1().Services(testNamespace).Get(context.Background(), serviceIpv4PoolSpecified.Name, metav1.GetOptions{})
				return service.Status.LoadBalancer.Ingress
			}, time.Second*15, 500*time.Millisecond).Should(Not(BeEmpty()))

			serviceSpecific, err := k8sClient.CoreV1().Services(testNamespace).Get(context.Background(), serviceIpv4PoolSpecified.Name, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(serviceSpecific.Status.LoadBalancer.Ingress[0].IP).Should(Equal(v4poolManualSpecifcIP))

			// Update the service type to NodePort, LoadBalancer controller should release the IP
			svcPatch := map[string]interface{}{}
			spec := map[string]interface{}{}
			svcPatch["spec"] = spec
			spec["type"] = v1.ServiceTypeNodePort
			patch, err := json.Marshal(svcPatch)
			Expect(err).NotTo(HaveOccurred())

			serviceSpecific, err = k8sClient.CoreV1().Services(testNamespace).Patch(context.Background(), serviceSpecific.Name, types.StrategicMergePatchType, patch, metav1.PatchOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(serviceSpecific.Spec.Type).To(Equal(v1.ServiceTypeNodePort))
			Expect(serviceSpecific.Status.LoadBalancer.Ingress).Should(BeEmpty())

			// Update annotation for the basic service, we should be able to assign the IP from specific service that was released
			serviceBasic, err := k8sClient.CoreV1().Services(testNamespace).Get(context.Background(), basicService.Name, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			serviceBasic.Annotations = map[string]string{
				"projectcalico.org/loadBalancerIPs": fmt.Sprintf("[\"%s\"]", v4poolManualSpecifcIP),
			}

			_, err = k8sClient.CoreV1().Services(testNamespace).Update(context.Background(), serviceBasic, metav1.UpdateOptions{})
			Expect(err).NotTo(HaveOccurred())

			Eventually(func() string {
				service, _ := k8sClient.CoreV1().Services(testNamespace).Get(context.Background(), basicService.Name, metav1.GetOptions{})
				if len(service.Status.LoadBalancer.Ingress) == 0 {
					return ""
				}
				return service.Status.LoadBalancer.Ingress[0].IP
			}, time.Second*15, 500*time.Millisecond).Should(Equal(v4poolManualSpecifcIP))
		})

		It("Should not assign IP if there is no LoadBalancer IP pool", func() {
			_, err := calicoClient.IPPools().Delete(context.Background(), v4poolManualSpecific.Name, options.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())

			_, err = calicoClient.IPPools().Delete(context.Background(), v4poolAutomatic.Name, options.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())

			_, err = k8sClient.CoreV1().Services(testNamespace).Create(context.Background(), &basicService, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			Eventually(func() []v1.LoadBalancerIngress {
				service, _ := k8sClient.CoreV1().Services(testNamespace).Get(context.Background(), basicService.Name, metav1.GetOptions{})
				return service.Status.LoadBalancer.Ingress
			}, time.Second*15, 500*time.Millisecond).Should(BeEmpty())
		})

		It("Should assign IP after LoadBalancer IP pool is created", func() {
			_, err := calicoClient.IPPools().Delete(context.Background(), v4poolManualSpecific.Name, options.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())

			_, err = calicoClient.IPPools().Delete(context.Background(), v4poolAutomatic.Name, options.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())

			_, err = k8sClient.CoreV1().Services(testNamespace).Create(context.Background(), &basicService, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			Eventually(func() []v1.LoadBalancerIngress {
				service, _ := k8sClient.CoreV1().Services(testNamespace).Get(context.Background(), basicService.Name, metav1.GetOptions{})
				return service.Status.LoadBalancer.Ingress
			}, time.Second*15, 500*time.Millisecond).Should(BeEmpty())

			_, err = calicoClient.IPPools().Create(context.Background(), &v4poolAutomatic, options.SetOptions{})
			Expect(err).NotTo(HaveOccurred())

			Eventually(func() []v1.LoadBalancerIngress {
				service, _ := k8sClient.CoreV1().Services(testNamespace).Get(context.Background(), basicService.Name, metav1.GetOptions{})
				return service.Status.LoadBalancer.Ingress
			}, time.Second*15, 500*time.Millisecond).ShouldNot(BeEmpty())
		})

		It("Should update service IP after pool annotation has been added", func() {
			_, err := k8sClient.CoreV1().Services(testNamespace).Create(context.Background(), &basicService, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			Eventually(func() []v1.LoadBalancerIngress {
				service, _ := k8sClient.CoreV1().Services(testNamespace).Get(context.Background(), basicService.Name, metav1.GetOptions{})
				return service.Status.LoadBalancer.Ingress
			}, time.Second*15, 500*time.Millisecond).Should(Not(BeEmpty()))

			service, err := k8sClient.CoreV1().Services(testNamespace).Get(context.Background(), basicService.Name, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())

			service.Annotations = map[string]string{
				"projectcalico.org/ipv4pools": "[\"v4pool-manual\"]",
			}

			_, err = k8sClient.CoreV1().Services(testNamespace).Update(context.Background(), service, metav1.UpdateOptions{})
			Expect(err).NotTo(HaveOccurred())

			Eventually(func() string {
				service, _ := k8sClient.CoreV1().Services(testNamespace).Get(context.Background(), basicService.Name, metav1.GetOptions{})
				return service.Status.LoadBalancer.Ingress[0].IP
			}, time.Second*15, 500*time.Millisecond).Should(Equal(v4poolManualIP))
		})

		It("Should update service IP after ip annotation has been added", func() {
			_, err := k8sClient.CoreV1().Services(testNamespace).Create(context.Background(), &basicService, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			Eventually(func() []v1.LoadBalancerIngress {
				service, _ := k8sClient.CoreV1().Services(testNamespace).Get(context.Background(), basicService.Name, metav1.GetOptions{})
				return service.Status.LoadBalancer.Ingress
			}, time.Second*15, 500*time.Millisecond).Should(Not(BeEmpty()))

			service, err := k8sClient.CoreV1().Services(testNamespace).Get(context.Background(), basicService.Name, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())

			service.Annotations = map[string]string{
				"projectcalico.org/loadBalancerIPs": fmt.Sprintf("[\"%s\"]", specificIpFromAutomaticPool),
			}

			_, err = k8sClient.CoreV1().Services(testNamespace).Update(context.Background(), service, metav1.UpdateOptions{})
			Expect(err).NotTo(HaveOccurred())

			Eventually(func() string {
				service, _ := k8sClient.CoreV1().Services(testNamespace).Get(context.Background(), basicService.Name, metav1.GetOptions{})
				return service.Status.LoadBalancer.Ingress[0].IP
			}, time.Second*15, 500*time.Millisecond).Should(Equal(specificIpFromAutomaticPool))
		})

		It("Should update service IP after the address has been released from another service", func() {
			// Create service with IP annotation
			_, err := k8sClient.CoreV1().Services(testNamespace).Create(context.Background(), &serviceIpAddressSpecified, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			Eventually(func() []v1.LoadBalancerIngress {
				service, _ := k8sClient.CoreV1().Services(testNamespace).Get(context.Background(), serviceIpAddressSpecified.Name, metav1.GetOptions{})
				return service.Status.LoadBalancer.Ingress
			}, time.Second*15, 500*time.Millisecond).Should(Not(BeEmpty()))

			// Check that the assigned IP is the one specified in the annotation
			service, err := k8sClient.CoreV1().Services(testNamespace).Get(context.Background(), serviceIpAddressSpecified.Name, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(service.Status.LoadBalancer.Ingress[0].IP).Should(Equal(specificIpFromAutomaticPool))

			// Create a service with no annotation
			_, err = k8sClient.CoreV1().Services(testNamespace).Create(context.Background(), &serviceIpv4PoolSpecified, metav1.CreateOptions{})
			Expect(err).NotTo(HaveOccurred())

			Eventually(func() []v1.LoadBalancerIngress {
				service, _ := k8sClient.CoreV1().Services(testNamespace).Get(context.Background(), serviceIpv4PoolSpecified.Name, metav1.GetOptions{})
				return service.Status.LoadBalancer.Ingress
			}, time.Second*15, 500*time.Millisecond).Should(Not(BeEmpty()))

			service, err = k8sClient.CoreV1().Services(testNamespace).Get(context.Background(), serviceIpv4PoolSpecified.Name, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())

			// Update the service to have the same IP as the service we have created above
			service.Annotations = map[string]string{
				"projectcalico.org/loadBalancerIPs": fmt.Sprintf("[\"%s\"]", specificIpFromAutomaticPool),
			}

			_, err = k8sClient.CoreV1().Services(testNamespace).Update(context.Background(), service, metav1.UpdateOptions{})
			Expect(err).NotTo(HaveOccurred())

			// The service ingress should be empty
			Eventually(func() []v1.LoadBalancerIngress {
				service, _ := k8sClient.CoreV1().Services(testNamespace).Get(context.Background(), serviceIpv4PoolSpecified.Name, metav1.GetOptions{})
				return service.Status.LoadBalancer.Ingress
			}, time.Second*15, 500*time.Millisecond).Should(BeEmpty())

			err = k8sClient.CoreV1().Services(testNamespace).Delete(context.Background(), serviceIpAddressSpecified.Name, metav1.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())

			// After we deleted the other service we should be able to have the IP assigned to this one
			Eventually(func() []v1.LoadBalancerIngress {
				service, _ := k8sClient.CoreV1().Services(testNamespace).Get(context.Background(), serviceIpv4PoolSpecified.Name, metav1.GetOptions{})
				return service.Status.LoadBalancer.Ingress
			}, time.Second*15, 500*time.Millisecond).Should(Not(BeEmpty()))

			service, err = k8sClient.CoreV1().Services(testNamespace).Get(context.Background(), serviceIpv4PoolSpecified.Name, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(service.Status.LoadBalancer.Ingress).NotTo(BeEmpty(), "saw service.Status.LoadBalancer.Ingress non-empty and then empty again!")
			Expect(service.Status.LoadBalancer.Ingress[0].IP).Should(Equal(specificIpFromAutomaticPool))
		})
	})
})
