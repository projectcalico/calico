// Copyright (c) 2023-2026 Tigera, Inc. All rights reserved.

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

package convert

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	kscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/apis"
	ctrlrfake "github.com/tigera/operator/pkg/ctrlruntime/client/fake"
)

func int32Ptr(x int32) *int32 {
	return &x
}

var _ = Describe("Convert network tests", func() {
	ctx := context.Background()
	var v4pool *v3.IPPool
	var v6pool *v3.IPPool
	var scheme *runtime.Scheme
	var falseValue bool

	BeforeEach(func() {
		scheme = kscheme.Scheme
		err := apis.AddToScheme(scheme, false)
		Expect(err).NotTo(HaveOccurred())

		v4pool = v3.NewIPPool()
		v4pool.Name = "test-ipv4-pool"
		v4pool.Spec = v3.IPPoolSpec{
			CIDR:        "192.168.4.0/24",
			IPIPMode:    v3.IPIPModeAlways,
			NATOutgoing: true,
		}

		v6pool = v3.NewIPPool()
		v6pool.Name = "test-ipv6-pool"
		v6pool.Spec = v3.IPPoolSpec{
			CIDR:        "2001:db8::1/120",
			NATOutgoing: true,
		}
		falseValue = false
	})

	Describe("handle alternate CNI migration", func() {
		DescribeTable("non-calico plugins", func(envs []corev1.EnvVar, plugin operatorv1.CNIPluginType) {
			ds := emptyNodeSpec()
			ds.Spec.Template.Spec.InitContainers = nil
			ds.Spec.Template.Spec.Containers[0].Env = append(envs, corev1.EnvVar{
				Name:  "CALICO_NETWORKING_BACKEND",
				Value: "none",
			})

			c := ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(ds, emptyKubeControllerSpec(), v4pool, emptyFelixConfig()).Build()
			cfg, err := Convert(ctx, c)
			Expect(err).ToNot(HaveOccurred())
			Expect(cfg).ToNot(BeNil())
			Expect(cfg.Spec.CNI.Type).To(Equal(plugin))
		},
			Entry("AzureVNET", []corev1.EnvVar{{Name: "FELIX_INTERFACEPREFIX", Value: "azv"}}, operatorv1.PluginAzureVNET),
			Entry("AmazonVPC", []corev1.EnvVar{
				{Name: "FELIX_INTERFACEPREFIX", Value: "eni"},
				{Name: "FELIX_IPTABLESMANGLEALLOWACTION", Value: "Return"},
			}, operatorv1.PluginAmazonVPC),
			Entry("GKE", []corev1.EnvVar{
				{Name: "FELIX_INTERFACEPREFIX", Value: "gke"},
				{Name: "FELIX_IPTABLESMANGLEALLOWACTION", Value: "Return"},
				{Name: "FELIX_IPTABLESFILTERALLOWACTION", Value: "Return"},
			}, operatorv1.PluginGKE),
		)
		It("should convert AWS CNI install", func() {
			c := ctrlrfake.DefaultFakeClientBuilder(scheme).WithRuntimeObjects(append([]runtime.Object{v4pool, emptyFelixConfig(), getK8sNodes(6)}, awsCNIPolicyOnlyConfig()...)...).Build()
			_, err := Convert(ctx, c)
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Describe("handle Calico CNI migration", func() {
		It("migrate default", func() {
			c := ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(emptyNodeSpec(), emptyKubeControllerSpec(), v4pool, emptyFelixConfig()).Build()
			cfg, err := Convert(ctx, c)
			Expect(err).ToNot(HaveOccurred())
			Expect(cfg).ToNot(BeNil())
			Expect(cfg.Spec.CNI.Type).To(Equal(operatorv1.PluginCalico))
			Expect(cfg.Spec.CNI.IPAM.Type).To(Equal(operatorv1.IPAMPluginCalico))
			Expect(*cfg.Spec.CalicoNetwork.BGP).To(Equal(operatorv1.BGPEnabled))
			Expect(cfg.Spec.CalicoNetwork.ContainerIPForwarding).To(BeNil())
		})
		It("should convert Calico v3.15 manifest", func() {
			c := ctrlrfake.DefaultFakeClientBuilder(scheme).WithRuntimeObjects(append([]runtime.Object{v4pool, emptyFelixConfig()}, calicoDefaultConfig()...)...).Build()
			cfg, err := Convert(ctx, c)
			Expect(err).NotTo(HaveOccurred())
			var _1440 int32 = 1440
			_1intstr := intstr.FromInt(1)
			Expect(*cfg).To(Equal(operatorv1.Installation{Spec: operatorv1.InstallationSpec{
				CNI: &operatorv1.CNISpec{
					Type: operatorv1.PluginCalico,
					IPAM: &operatorv1.IPAMSpec{Type: operatorv1.IPAMPluginCalico},
				},
				CalicoNetwork: &operatorv1.CalicoNetworkSpec{
					BGP:       operatorv1.BGPOptionPtr(operatorv1.BGPEnabled),
					MTU:       &_1440,
					HostPorts: operatorv1.HostPortsTypePtr(operatorv1.HostPortsEnabled),
					IPPools: []operatorv1.IPPool{{
						CIDR:             "192.168.4.0/24",
						Encapsulation:    operatorv1.EncapsulationIPIP,
						NATOutgoing:      operatorv1.NATOutgoingEnabled,
						DisableBGPExport: &falseValue,
					}},
				},
				FlexVolumePath: "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/nodeagent~uds",
				NodeUpdateStrategy: appsv1.DaemonSetUpdateStrategy{
					Type: "RollingUpdate",
					RollingUpdate: &appsv1.RollingUpdateDaemonSet{
						MaxUnavailable: &_1intstr,
					},
				},
				ComponentResources: []operatorv1.ComponentResource{
					{
						ComponentName: operatorv1.ComponentNameNode,
						ResourceRequirements: &corev1.ResourceRequirements{
							Requests: corev1.ResourceList{
								corev1.ResourceCPU: resource.MustParse("250m"),
							},
						},
					},
				},
			}}))
		})
		It("migrate cloud route config", func() {
			ds := emptyNodeSpec()
			ds.Spec.Template.Spec.InitContainers[0].Env = []corev1.EnvVar{{
				Name:  "CNI_NETWORK_CONFIG",
				Value: `{"type": "calico", "name": "k8s-pod-network", "ipam": {"type": "host-local"}}`,
			}}
			ds.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{{
				Name:  "CALICO_NETWORKING_BACKEND",
				Value: "none",
			}}
			c := ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(ds, emptyKubeControllerSpec(), v4pool, emptyFelixConfig()).Build()
			cfg, err := Convert(ctx, c)
			Expect(err).ToNot(HaveOccurred())
			Expect(cfg).ToNot(BeNil())
			Expect(cfg.Spec.CNI.Type).To(Equal(operatorv1.PluginCalico))
			Expect(cfg.Spec.CNI.IPAM.Type).To(Equal(operatorv1.IPAMPluginHostLocal))
			Expect(*cfg.Spec.CalicoNetwork.BGP).To(Equal(operatorv1.BGPDisabled))
		})
		It("migrate calico-ipam and vxlan config", func() {
			ds := emptyNodeSpec()
			ds.Spec.Template.Spec.InitContainers[0].Env = []corev1.EnvVar{{
				Name:  "CNI_NETWORK_CONFIG",
				Value: `{"type": "calico", "name": "k8s-pod-network", "ipam": {"type": "calico-ipam"}}`,
			}}
			ds.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{{
				Name:  "CALICO_NETWORKING_BACKEND",
				Value: "vxlan",
			}}
			c := ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(ds, emptyKubeControllerSpec(), v4pool, emptyFelixConfig()).Build()
			cfg, err := Convert(ctx, c)
			Expect(err).ToNot(HaveOccurred())
			Expect(cfg).ToNot(BeNil())
			Expect(cfg.Spec.CNI.Type).To(Equal(operatorv1.PluginCalico))
			Expect(cfg.Spec.CNI.IPAM.Type).To(Equal(operatorv1.IPAMPluginCalico))
			Expect(*cfg.Spec.CalicoNetwork.BGP).To(Equal(operatorv1.BGPDisabled))
		})
		It("migrate default with IPv6 explicitly disabled", func() {
			ds := emptyNodeSpec()
			ds.Spec.Template.Spec.Containers[0].Env = append(ds.Spec.Template.Spec.Containers[0].Env,
				corev1.EnvVar{
					Name:  "IP6",
					Value: "none",
				},
				corev1.EnvVar{
					Name:  "FELIX_IPV6SUPPORT",
					Value: "false",
				},
			)
			c := ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(ds, emptyKubeControllerSpec(), v4pool, emptyFelixConfig()).Build()
			cfg, err := Convert(ctx, c)
			Expect(err).ToNot(HaveOccurred())
			Expect(cfg).ToNot(BeNil())
			Expect(cfg.Spec.CNI.Type).To(Equal(operatorv1.PluginCalico))
			Expect(cfg.Spec.CNI.IPAM.Type).To(Equal(operatorv1.IPAMPluginCalico))
			Expect(*cfg.Spec.CalicoNetwork.BGP).To(Equal(operatorv1.BGPEnabled))

			expectedV4pool, err := convertPool(*v4pool)
			Expect(err).ToNot(HaveOccurred())
			Expect(cfg.Spec.CalicoNetwork.IPPools).To(ContainElements(expectedV4pool))
		})
		It("migrate default with IPv6 and Autodetection method explicitly disabled", func() {
			ds := emptyNodeSpec()
			ds.Spec.Template.Spec.Containers[0].Env = append(ds.Spec.Template.Spec.Containers[0].Env,
				corev1.EnvVar{
					Name:  "IP6",
					Value: "none",
				},
				corev1.EnvVar{
					Name:  "IP6_AUTODETECTION_METHOD",
					Value: "none",
				},
				corev1.EnvVar{
					Name:  "FELIX_IPV6SUPPORT",
					Value: "false",
				},
			)
			c := ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(ds, emptyKubeControllerSpec(), v4pool, emptyFelixConfig()).Build()
			cfg, err := Convert(ctx, c)
			Expect(err).ToNot(HaveOccurred())
			Expect(cfg).ToNot(BeNil())
			Expect(cfg.Spec.CNI.Type).To(Equal(operatorv1.PluginCalico))
			Expect(cfg.Spec.CNI.IPAM.Type).To(Equal(operatorv1.IPAMPluginCalico))
			Expect(*cfg.Spec.CalicoNetwork.BGP).To(Equal(operatorv1.BGPEnabled))

			expectedV4pool, err := convertPool(*v4pool)
			Expect(err).ToNot(HaveOccurred())
			Expect(cfg.Spec.CalicoNetwork.IPPools).To(ContainElements(expectedV4pool))
		})

		It("migrate default dual stack config", func() {
			// This is the minimal dual stack config as outlined in our docs.
			ds := emptyNodeSpec()
			ds.Spec.Template.Spec.InitContainers[0].Env = []corev1.EnvVar{{
				Name:  "CNI_NETWORK_CONFIG",
				Value: `{"type": "calico", "name": "k8s-pod-network", "ipam": {"type": "calico-ipam", "assign_ipv4":"true", "assign_ipv6":"true"}}`,
			}}

			ds.Spec.Template.Spec.Containers[0].Env = append(ds.Spec.Template.Spec.Containers[0].Env,
				corev1.EnvVar{
					Name:  "IP6",
					Value: "autodetect",
				},
				corev1.EnvVar{
					Name:  "FELIX_IPV6SUPPORT",
					Value: "true",
				},
			)

			c := ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(v4pool, v6pool, ds, emptyKubeControllerSpec(), emptyFelixConfig()).Build()
			cfg, err := Convert(ctx, c)
			Expect(err).ToNot(HaveOccurred())
			Expect(cfg).ToNot(BeNil())
			Expect(cfg.Spec.CNI.Type).To(Equal(operatorv1.PluginCalico))
			Expect(cfg.Spec.CNI.IPAM.Type).To(Equal(operatorv1.IPAMPluginCalico))
			Expect(*cfg.Spec.CalicoNetwork.BGP).To(Equal(operatorv1.BGPEnabled))

			expectedV4pool, err := convertPool(*v4pool)
			Expect(err).ToNot(HaveOccurred())
			expectedV6pool, err := convertPool(*v6pool)
			Expect(err).ToNot(HaveOccurred())
			Expect(cfg.Spec.CalicoNetwork.IPPools).To(ContainElements(expectedV4pool, expectedV6pool))
		})
		It("fails migrating default dual stack config if missing pools", func() {
			// This is the minimal dual stack config as outlined in our docs.
			ds := emptyNodeSpec()
			ds.Spec.Template.Spec.InitContainers[0].Env = []corev1.EnvVar{{
				Name:  "CNI_NETWORK_CONFIG",
				Value: `{"type": "calico", "name": "k8s-pod-network", "ipam": {"type": "calico-ipam", "assign_ipv4":"true", "assign_ipv6":"true"}}`,
			}}

			ds.Spec.Template.Spec.Containers[0].Env = append(ds.Spec.Template.Spec.Containers[0].Env,
				corev1.EnvVar{
					Name:  "IP6",
					Value: "autodetect",
				},
				corev1.EnvVar{
					Name:  "FELIX_IPV6SUPPORT",
					Value: "true",
				},
			)

			c := ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(v6pool, ds, emptyKubeControllerSpec(), emptyFelixConfig()).Build()
			cfg, err := Convert(ctx, c)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("CNI config indicates assign_ipv4=true but there were no valid IPv4 pools found. To fix it, create an IPv4 pool or set assign_ipv4=false on cni-config"))
			Expect(cfg).To(BeNil())

			c = ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(v4pool, ds, emptyKubeControllerSpec(), emptyFelixConfig()).Build()
			cfg, err = Convert(ctx, c)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("CNI config indicates assign_ipv6=true but there were no valid IPv6 pools found. To fix it, create an IPv6 pool or set assign_ipv6=false on cni-config"))
			Expect(cfg).To(BeNil())
		})
		It("migrate default IPv6 only config", func() {
			ds := emptyNodeSpec()
			ds.Spec.Template.Spec.InitContainers[0].Env = []corev1.EnvVar{{
				Name:  "CNI_NETWORK_CONFIG",
				Value: `{"type": "calico", "name": "k8s-pod-network", "ipam": {"type": "calico-ipam", "assign_ipv4":"false", "assign_ipv6":"true"}}`,
			}}

			ds.Spec.Template.Spec.Containers[0].Env = append(ds.Spec.Template.Spec.Containers[0].Env,
				corev1.EnvVar{
					Name:  "IP6",
					Value: "autodetect",
				},
				corev1.EnvVar{
					Name:  "FELIX_IPV6SUPPORT",
					Value: "true",
				},
			)

			runTest := func(c client.WithWatch) {
				cfg, err := Convert(ctx, c)
				Expect(err).ToNot(HaveOccurred())
				Expect(cfg).ToNot(BeNil())
				Expect(cfg.Spec.CNI.Type).To(Equal(operatorv1.PluginCalico))
				Expect(cfg.Spec.CNI.IPAM.Type).To(Equal(operatorv1.IPAMPluginCalico))
				Expect(*cfg.Spec.CalicoNetwork.BGP).To(Equal(operatorv1.BGPEnabled))

				expectedV6pool, err := convertPool(*v6pool)
				Expect(err).ToNot(HaveOccurred())
				Expect(cfg.Spec.CalicoNetwork.IPPools).To(ContainElements(expectedV6pool))
			}

			// Run test with both pools. calico-node will create a v4 pool by default.
			// But the operator migration will remove the v4 pool from the installation cr.
			bothPools := ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(v4pool, v6pool, ds, emptyKubeControllerSpec(), emptyFelixConfig()).Build()
			runTest(bothPools)

			// Run test but with only v6 pool
			ipv6Only := ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(v6pool, ds, emptyKubeControllerSpec(), emptyFelixConfig()).Build()
			runTest(ipv6Only)
		})
		It("fails migrating default IPv6 only config if missing pool", func() {
			ds := emptyNodeSpec()
			ds.Spec.Template.Spec.InitContainers[0].Env = []corev1.EnvVar{{
				Name:  "CNI_NETWORK_CONFIG",
				Value: `{"type": "calico", "name": "k8s-pod-network", "ipam": {"type": "calico-ipam", "assign_ipv4":"false", "assign_ipv6":"true"}}`,
			}}

			ds.Spec.Template.Spec.Containers[0].Env = append(ds.Spec.Template.Spec.Containers[0].Env,
				corev1.EnvVar{
					Name:  "IP6",
					Value: "autodetect",
				},
				corev1.EnvVar{
					Name:  "FELIX_IPV6SUPPORT",
					Value: "true",
				},
			)

			// no pools at all
			c := ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(ds, emptyKubeControllerSpec(), emptyFelixConfig()).Build()
			cfg, err := Convert(ctx, c)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("CNI config indicates assign_ipv6=true but there were no valid IPv6 pools found. To fix it, create an IPv6 pool or set assign_ipv6=false on cni-config"))
			Expect(cfg).To(BeNil())

			// IPv4 pool only
			c = ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(ds, v4pool, emptyKubeControllerSpec(), emptyFelixConfig()).Build()
			cfg, err = Convert(ctx, c)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("CNI config indicates assign_ipv6=true but there were no valid IPv6 pools found. To fix it, create an IPv6 pool or set assign_ipv6=false on cni-config"))
			Expect(cfg).To(BeNil())
		})
		It("migrate default IPv6 only config with IPv4 disabled", func() {
			ds := emptyNodeSpec()
			ds.Spec.Template.Spec.InitContainers[0].Env = []corev1.EnvVar{{
				Name:  "CNI_NETWORK_CONFIG",
				Value: `{"type": "calico", "name": "k8s-pod-network", "ipam": {"type": "calico-ipam", "assign_ipv4":"false", "assign_ipv6":"true"}}`,
			}}

			ds.Spec.Template.Spec.Containers[0].Env = append(ds.Spec.Template.Spec.Containers[0].Env,
				corev1.EnvVar{
					Name:  "IP",
					Value: "none",
				},
				corev1.EnvVar{
					Name:  "IP6",
					Value: "autodetect",
				},
				corev1.EnvVar{
					Name:  "CALICO_ROUTER_ID",
					Value: "hash",
				},
				corev1.EnvVar{
					Name:  "FELIX_IPV6SUPPORT",
					Value: "true",
				},
			)

			runTest := func(c client.WithWatch) {
				cfg, err := Convert(ctx, c)
				Expect(err).ToNot(HaveOccurred())
				Expect(cfg).ToNot(BeNil())
				Expect(cfg.Spec.CNI.Type).To(Equal(operatorv1.PluginCalico))
				Expect(cfg.Spec.CNI.IPAM.Type).To(Equal(operatorv1.IPAMPluginCalico))
				Expect(*cfg.Spec.CalicoNetwork.BGP).To(Equal(operatorv1.BGPEnabled))

				expectedV6pool, err := convertPool(*v6pool)
				Expect(err).ToNot(HaveOccurred())
				Expect(cfg.Spec.CalicoNetwork.IPPools).To(ContainElements(expectedV6pool))
			}

			// Run test with both pools. calico-node will create a v4 pool by default.
			// But the operator migration will remove the v4 pool from the installation cr.
			bothPools := ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(v4pool, v6pool, ds, emptyKubeControllerSpec(), emptyFelixConfig()).Build()
			runTest(bothPools)

			// Run test but with only v6 pool
			ipv6Only := ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(v6pool, ds, emptyKubeControllerSpec(), emptyFelixConfig()).Build()
			runTest(ipv6Only)
		})
		It("migrate IPv6-only config with VXLAN", func() {
			// This is the minimal dual stack config as outlined in our docs.
			ds := emptyNodeSpec()
			ds.Spec.Template.Spec.InitContainers[0].Env = []corev1.EnvVar{{
				Name:  "CNI_NETWORK_CONFIG",
				Value: `{"type": "calico", "name": "k8s-pod-network", "ipam": {"type": "calico-ipam", "assign_ipv4":"false", "assign_ipv6":"true"}}`,
			}}
			ds.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{{
				Name:  "CALICO_NETWORKING_BACKEND",
				Value: "vxlan",
			}}

			ds.Spec.Template.Spec.Containers[0].Env = append(ds.Spec.Template.Spec.Containers[0].Env,
				corev1.EnvVar{
					Name:  "IP6",
					Value: "autodetect",
				},
				corev1.EnvVar{
					Name:  "FELIX_IPV6SUPPORT",
					Value: "true",
				},
			)

			v6pool.Spec.IPIPMode = v3.IPIPModeNever
			v6pool.Spec.VXLANMode = v3.VXLANModeAlways
			c := ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(v6pool, ds, emptyKubeControllerSpec(), emptyFelixConfig()).Build()
			cfg, err := Convert(ctx, c)
			Expect(err).ToNot(HaveOccurred())
			Expect(cfg).ToNot(BeNil())
			Expect(cfg.Spec.CNI.Type).To(Equal(operatorv1.PluginCalico))
			Expect(cfg.Spec.CNI.IPAM.Type).To(Equal(operatorv1.IPAMPluginCalico))
			Expect(*cfg.Spec.CalicoNetwork.BGP).To(Equal(operatorv1.BGPDisabled))

			expectedV6pool, err := convertPool(*v6pool)
			Expect(err).ToNot(HaveOccurred())
			Expect(cfg.Spec.CalicoNetwork.IPPools).To(ContainElements(expectedV6pool))
		})
		It("migrate dual stack config with VXLAN", func() {
			// This is the minimal dual stack config as outlined in our docs.
			ds := emptyNodeSpec()
			ds.Spec.Template.Spec.InitContainers[0].Env = []corev1.EnvVar{{
				Name:  "CNI_NETWORK_CONFIG",
				Value: `{"type": "calico", "name": "k8s-pod-network", "ipam": {"type": "calico-ipam", "assign_ipv4":"true", "assign_ipv6":"true"}}`,
			}}
			ds.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{{
				Name:  "CALICO_NETWORKING_BACKEND",
				Value: "vxlan",
			}}

			ds.Spec.Template.Spec.Containers[0].Env = append(ds.Spec.Template.Spec.Containers[0].Env,
				corev1.EnvVar{
					Name:  "IP6",
					Value: "autodetect",
				},
				corev1.EnvVar{
					Name:  "FELIX_IPV6SUPPORT",
					Value: "true",
				},
			)

			v4pool.Spec.IPIPMode = v3.IPIPModeNever
			v4pool.Spec.VXLANMode = v3.VXLANModeAlways
			v6pool.Spec.IPIPMode = v3.IPIPModeNever
			v6pool.Spec.VXLANMode = v3.VXLANModeAlways
			c := ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(v4pool, v6pool, ds, emptyKubeControllerSpec(), emptyFelixConfig()).Build()
			cfg, err := Convert(ctx, c)
			Expect(err).ToNot(HaveOccurred())
			Expect(cfg).ToNot(BeNil())
			Expect(cfg.Spec.CNI.Type).To(Equal(operatorv1.PluginCalico))
			Expect(cfg.Spec.CNI.IPAM.Type).To(Equal(operatorv1.IPAMPluginCalico))
			Expect(*cfg.Spec.CalicoNetwork.BGP).To(Equal(operatorv1.BGPDisabled))

			expectedV4pool, err := convertPool(*v4pool)
			Expect(err).ToNot(HaveOccurred())
			expectedV6pool, err := convertPool(*v6pool)
			Expect(err).ToNot(HaveOccurred())
			Expect(cfg.Spec.CalicoNetwork.IPPools).To(ContainElements(expectedV4pool, expectedV6pool))
		})
		It("migrate allow_ip_forwarding=true container setting", func() {
			ds := emptyNodeSpec()
			ds.Spec.Template.Spec.InitContainers[0].Env = []corev1.EnvVar{{
				Name:  "CNI_NETWORK_CONFIG",
				Value: `{"type": "calico", "name": "k8s-pod-network", "ipam": {"type": "host-local"}, "container_settings": {"allow_ip_forwarding": true}}`,
			}}
			c := ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(ds, emptyKubeControllerSpec(), v4pool, emptyFelixConfig()).Build()
			cfg, err := Convert(ctx, c)
			Expect(err).ToNot(HaveOccurred())
			Expect(cfg).ToNot(BeNil())
			Expect(cfg.Spec.CalicoNetwork.ContainerIPForwarding).ToNot(BeNil())
			Expect(*cfg.Spec.CalicoNetwork.ContainerIPForwarding).To(Equal(operatorv1.ContainerIPForwardingEnabled))
		})
		It("migrate allow_ip_forwarding=false container setting", func() {
			ds := emptyNodeSpec()
			ds.Spec.Template.Spec.InitContainers[0].Env = []corev1.EnvVar{{
				Name:  "CNI_NETWORK_CONFIG",
				Value: `{"type": "calico", "name": "k8s-pod-network", "ipam": {"type": "host-local"}, "container_settings": {"allow_ip_forwarding": false}}`,
			}}
			c := ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(ds, emptyKubeControllerSpec(), v4pool, emptyFelixConfig()).Build()
			cfg, err := Convert(ctx, c)
			Expect(err).ToNot(HaveOccurred())
			Expect(cfg.Spec.CalicoNetwork.ContainerIPForwarding).To(BeNil())
		})

		DescribeTable("test invalid ipam and backend",
			func(ipam, backend string) {
				ds := emptyNodeSpec()
				ds.Spec.Template.Spec.InitContainers[0].Env = []corev1.EnvVar{{
					Name:  "CNI_NETWORK_CONFIG",
					Value: fmt.Sprintf(`{"type": "calico", "name": "k8s-pod-network", "ipam": {"type": "%s"}}`, ipam),
				}}
				ds.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{{
					Name:  "CALICO_NETWORKING_BACKEND",
					Value: backend,
				}}
				c := ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(ds, emptyKubeControllerSpec(), v4pool, emptyFelixConfig()).Build()
				_, err := Convert(ctx, c)
				Expect(err).To(HaveOccurred())
			},
			Entry("host-local and vxlan", "host-local", "vxlan"),
			Entry("calico and none", "calico-ipam", "none"),
		)
		It("test unknown ipam plugin", func() {
			ds := emptyNodeSpec()
			ds.Spec.Template.Spec.InitContainers[0].Env = []corev1.EnvVar{{
				Name:  "CNI_NETWORK_CONFIG",
				Value: `{"type": "calico", "name": "k8s-pod-network", "ipam": {"type": "unknown"}}`,
			}}
			ds.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{{
				Name:  "CALICO_NETWORKING_BACKEND",
				Value: "none",
			}}
			c := ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(ds, emptyKubeControllerSpec(), v4pool, emptyFelixConfig()).Build()
			_, err := Convert(ctx, c)
			Expect(err).To(HaveOccurred())
		})
		Context("HostLocal IPAM", func() {
			DescribeTable("migrate HostLocal BGP config",
				func(backend string) {
					ds := emptyNodeSpec()
					ds.Spec.Template.Spec.InitContainers[0].Env = []corev1.EnvVar{{
						Name:  "CNI_NETWORK_CONFIG",
						Value: `{"type": "calico", "name": "k8s-pod-network", "ipam": {"type": "host-local"}}`,
					}}
					ds.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{{
						Name:  "CALICO_NETWORKING_BACKEND",
						Value: backend,
					}}
					c := ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(ds, emptyKubeControllerSpec(), v4pool, emptyFelixConfig()).Build()
					cfg, err := Convert(ctx, c)
					Expect(err).ToNot(HaveOccurred())
					Expect(cfg).ToNot(BeNil())
					Expect(cfg.Spec.CNI.Type).To(Equal(operatorv1.PluginCalico))
					Expect(cfg.Spec.CNI.IPAM.Type).To(Equal(operatorv1.IPAMPluginHostLocal))
					Expect(*cfg.Spec.CalicoNetwork.BGP).To(Equal(operatorv1.BGPEnabled))
				},
				Entry("bird backend", "bird"),
				Entry("<empty> backend", ""),
			)
			DescribeTable("test CNI config name",
				func(cni string) {
					ds := emptyNodeSpec()
					ds.Spec.Template.Spec.InitContainers[0].Env = []corev1.EnvVar{{
						Name:  "CNI_NETWORK_CONFIG",
						Value: cni,
					}}
					ds.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{{
						Name:  "CALICO_NETWORKING_BACKEND",
						Value: "bird",
					}}
					c := ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(ds, emptyKubeControllerSpec(), v4pool, emptyFelixConfig()).Build()
					_, err := Convert(ctx, c)
					Expect(err).NotTo(HaveOccurred())
				},
				Entry("name in conflist", `{"name": "k8s-pod-network",
	"plugins": [
	  {
		"type": "calico",
		"datastore_type": "kubernetes",
		"nodename": "__KUBERNETES_NODE_NAME__",
		"ipam": {"type": "host-local"},
		"policy": {"type": "k8s"}
	  }
	]
  }`),
				Entry("name in single conf", `{"name": "k8s-pod-network",
		"type": "calico",
		"datastore_type": "kubernetes",
		"nodename": "__KUBERNETES_NODE_NAME__",
		"ipam": {"type": "host-local"},
		"policy": {"type": "k8s"}
  }`),
			)
			DescribeTable("test bad CNI config name",
				func(cni string) {
					ds := emptyNodeSpec()
					ds.Spec.Template.Spec.InitContainers[0].Env = []corev1.EnvVar{{
						Name:  "CNI_NETWORK_CONFIG",
						Value: cni,
					}}
					ds.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{{
						Name:  "CALICO_NETWORKING_BACKEND",
						Value: "bird",
					}}
					c := ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(ds, emptyKubeControllerSpec(), v4pool, emptyFelixConfig()).Build()
					_, err := Convert(ctx, c)
					Expect(err).To(HaveOccurred())
				},
				Entry("no name in conflist", `{
	"plugins": [
	  {
		"type": "calico",
		"datastore_type": "kubernetes",
		"nodename": "__KUBERNETES_NODE_NAME__",
		"ipam": {"type": "host-local"},
		"policy": {"type": "k8s"}
	  }
	]
  }`),
				Entry("no name in single conf", `{
		"type": "calico",
		"datastore_type": "kubernetes",
		"nodename": "__KUBERNETES_NODE_NAME__",
		"ipam": {"type": "host-local"},
		"policy": {"type": "k8s"}
  }`),
				Entry("wrong name in conflist", `{"name": "wrong-name",
	"plugins": [
	  {
		"type": "calico",
		"datastore_type": "kubernetes",
		"nodename": "__KUBERNETES_NODE_NAME__",
		"ipam": {"type": "host-local"},
		"policy": {"type": "k8s"}
	  }
	]
  }`),
				Entry("wrong name in single conf", `{"name": "wrong-name",
		"type": "calico",
		"datastore_type": "kubernetes",
		"nodename": "__KUBERNETES_NODE_NAME__",
		"ipam": {"type": "host-local"},
		"policy": {"type": "k8s"}
  }`),
			)
			DescribeTable("test unsupported CNI config",
				func(ipamExtra string) {
					ds := emptyNodeSpec()
					ds.Spec.Template.Spec.InitContainers[0].Env = []corev1.EnvVar{{
						Name: "CNI_NETWORK_CONFIG",
						Value: fmt.Sprintf(`{
	"name": "k8s-pod-network",
	"cniVersion": "0.3.1",
	"plugins": [
	  {
		"type": "calico",
		"log_level": "info",
		"datastore_type": "kubernetes",
		"nodename": "__KUBERNETES_NODE_NAME__",
		"mtu": __CNI_MTU__,
		"ipam": {
			"type": "host-local",
			%s
		},
		"policy": {
			"type": "k8s"
		},
		"kubernetes": {
			"kubeconfig": "__KUBECONFIG_FILEPATH__"
		}
	  }
	]
  }`, ipamExtra),
					}}
					ds.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{{
						Name:  "CALICO_NETWORKING_BACKEND",
						Value: "bird",
					}}
					c := ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(ds, emptyKubeControllerSpec(), v4pool, emptyFelixConfig()).Build()
					_, err := Convert(ctx, c)
					Expect(err).To(HaveOccurred())
				},
				Entry("unsupported ranges", `"ranges": [[{ "subnet": "usePodCidr" }],[{ "subnet": "2001:db8::/96" }]]`),
				Entry("routes", `"routes": [{ "dst": "0.0.0.0/0" },{ "dst": "2001:db8::/96" }]`),
				Entry("dataDir", `"dataDir": "/some/path/i/think/would/be/here"`),
				Entry("unknown field", `"unknownField": "something"`),
			)
			DescribeTable("test valid HostLocal config with usePodCidr configs",
				func(ipamExtra string) {
					ds := emptyNodeSpec()
					ds.Spec.Template.Spec.InitContainers[0].Env = []corev1.EnvVar{{
						Name: "CNI_NETWORK_CONFIG",
						Value: fmt.Sprintf(`{
	"name": "k8s-pod-network",
	"cniVersion": "0.3.1",
	"plugins": [
	  {
		"type": "calico",
		"log_level": "info",
		"datastore_type": "kubernetes",
		"nodename": "__KUBERNETES_NODE_NAME__",
		"mtu": __CNI_MTU__,
		"ipam": {
			"type": "host-local",
			%s
		},
		"policy": {
			"type": "k8s"
		},
		"kubernetes": {
			"kubeconfig": "__KUBECONFIG_FILEPATH__"
		}
	  }
	]
  }`, ipamExtra),
					}}
					ds.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{{
						Name:  "CALICO_NETWORKING_BACKEND",
						Value: "bird",
					}}
					c := ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(ds, emptyKubeControllerSpec(), v4pool, emptyFelixConfig()).Build()
					_, err := Convert(ctx, c)
					Expect(err).NotTo(HaveOccurred())
				},
				Entry("subnet in ipam section", `"subnet": "usePodCidr"`),
				Entry("subnet in ranges section under ipam", `"ranges": [[{ "subnet": "usePodCidr" }]]`),
				Entry("dual-stack subnets in ranges section", `"ranges": [[{ "subnet": "usePodCidr" }], [{ "subnet": "usePodCidrIPv6" }]]`),
			)
		})

		Context("Calico CNI config flags", func() {
			Describe("migrate tuning setting", func() {
				It("sysctl tuning in config", func() {
					ds := emptyNodeSpec()
					ds.Spec.Template.Spec.InitContainers[0].Env = []corev1.EnvVar{{
						Name: "CNI_NETWORK_CONFIG",
						Value: `{
"name": "k8s-pod-network",
"cniVersion": "0.3.1",
"plugins": [
  {
	"type": "calico",
	"log_level": "info",
	"datastore_type": "kubernetes",
	"nodename": "__KUBERNETES_NODE_NAME__",
	"mtu": __CNI_MTU__,
	"ipam": {
		"type": "host-local"
	},
	"policy": {
		"type": "k8s"
	},
	"kubernetes": {
		"kubeconfig": "__KUBECONFIG_FILEPATH__"
	}
  },
  {
	"type": "tuning",
	"sysctl": {
		"net.ipv4.tcp_keepalive_intvl": "15",
		"net.ipv4.tcp_keepalive_probes": "6",
		"net.ipv4.tcp_keepalive_time": "40"
	}
  }
  ]
}`,
					}}
					c := ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(ds, emptyKubeControllerSpec(), v4pool, emptyFelixConfig()).Build()
					cfg, err := Convert(ctx, c)
					Expect(err).ToNot(HaveOccurred())
					Expect(cfg).ToNot(BeNil())
					Expect(cfg.Spec.CalicoNetwork.Sysctl).ToNot(BeNil())
					Expect(cfg.Spec.CalicoNetwork.Sysctl).To(ConsistOf(
						operatorv1.Sysctl{
							Key:   "net.ipv4.tcp_keepalive_intvl",
							Value: "15",
						},
						operatorv1.Sysctl{
							Key:   "net.ipv4.tcp_keepalive_probes",
							Value: "6",
						},
						operatorv1.Sysctl{
							Key:   "net.ipv4.tcp_keepalive_time",
							Value: "40",
						},
					))
				})

				It("not allowed sysctl tuning in config", func() {
					ds := emptyNodeSpec()
					ds.Spec.Template.Spec.InitContainers[0].Env = []corev1.EnvVar{{
						Name: "CNI_NETWORK_CONFIG",
						Value: `{
"name": "k8s-pod-network",
"cniVersion": "0.3.1",
"plugins": [
{
"type": "calico",
"log_level": "info",
"datastore_type": "kubernetes",
"nodename": "__KUBERNETES_NODE_NAME__",
"mtu": __CNI_MTU__,
"ipam": {
	"type": "host-local"
},
"policy": {
	"type": "k8s"
},
"kubernetes": {
	"kubeconfig": "__KUBECONFIG_FILEPATH__"
}
},
{
	"type": "tuning",
	"sysctl": {
		"net.ipv4.not_allowed": "40"
	}
}
]
}`,
					}}
					c := ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(ds, emptyKubeControllerSpec(), v4pool, emptyFelixConfig()).Build()
					cfg, err := Convert(ctx, c)
					Expect(err).To(HaveOccurred())
					Expect(cfg).To(BeNil())
				})

				It("no sysctl tuning in config, cfg must be nil", func() {
					ds := emptyNodeSpec()
					ds.Spec.Template.Spec.InitContainers[0].Env = []corev1.EnvVar{{
						Name: "CNI_NETWORK_CONFIG",
						Value: `{
"name": "k8s-pod-network",
"cniVersion": "0.3.1",
"plugins": [
{
"type": "calico",
"log_level": "info",
"datastore_type": "kubernetes",
"nodename": "__KUBERNETES_NODE_NAME__",
"mtu": __CNI_MTU__,
"ipam": {
	"type": "host-local"
},
"policy": {
	"type": "k8s"
},
"kubernetes": {
	"kubeconfig": "__KUBECONFIG_FILEPATH__"
}
}
]
}`,
					}}
					c := ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(ds, emptyKubeControllerSpec(), v4pool, emptyFelixConfig()).Build()
					cfg, err := Convert(ctx, c)
					Expect(err).ToNot(HaveOccurred())
					Expect(cfg).ToNot(BeNil())
					Expect(cfg.Spec.CalicoNetwork.Sysctl).To(BeNil())
				})
			})

			Describe("migrate portmap setting", func() {
				It("no portmap in config", func() {
					ds := emptyNodeSpec()
					ds.Spec.Template.Spec.InitContainers[0].Env = []corev1.EnvVar{{
						Name: "CNI_NETWORK_CONFIG",
						Value: `{
"name": "k8s-pod-network",
"cniVersion": "0.3.1",
"plugins": [
  {
	"type": "calico",
	"log_level": "info",
	"datastore_type": "kubernetes",
	"nodename": "__KUBERNETES_NODE_NAME__",
	"mtu": __CNI_MTU__,
	"ipam": {
		"type": "host-local"
	},
	"policy": {
		"type": "k8s"
	},
	"kubernetes": {
		"kubeconfig": "__KUBECONFIG_FILEPATH__"
	}
  }
  ]
}`,
					}}
					ds.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{{
						Name:  "CALICO_NETWORKING_BACKEND",
						Value: "bird",
					}}
					c := ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(ds, emptyKubeControllerSpec(), v4pool, emptyFelixConfig()).Build()
					cfg, err := Convert(ctx, c)
					Expect(err).ToNot(HaveOccurred())
					Expect(cfg).ToNot(BeNil())
					Expect(cfg.Spec.CNI.Type).To(Equal(operatorv1.PluginCalico))
					Expect(cfg.Spec.CNI.IPAM.Type).To(Equal(operatorv1.IPAMPluginHostLocal))
					Expect(*cfg.Spec.CalicoNetwork.BGP).To(Equal(operatorv1.BGPEnabled))
					Expect(*cfg.Spec.CalicoNetwork.HostPorts).To(Equal(operatorv1.HostPortsDisabled))
				})
				It("portmap in config", func() {
					ds := emptyNodeSpec()
					ds.Spec.Template.Spec.InitContainers[0].Env = []corev1.EnvVar{{
						Name: "CNI_NETWORK_CONFIG",
						Value: `{
"name": "k8s-pod-network",
"cniVersion": "0.3.1",
"plugins": [
  {
	"type": "calico",
	"log_level": "info",
	"datastore_type": "kubernetes",
	"nodename": "__KUBERNETES_NODE_NAME__",
	"mtu": __CNI_MTU__,
	"ipam": {
		"type": "host-local"
	},
	"policy": {
		"type": "k8s"
	},
	"kubernetes": {
		"kubeconfig": "__KUBECONFIG_FILEPATH__"
	}
  },
  {
    "type": "portmap",
    "snat": true,
    "capabilities": {"portMappings": true}
    }
  ]
}`,
					}}
					ds.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{{
						Name:  "CALICO_NETWORKING_BACKEND",
						Value: "bird",
					}}
					c := ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(ds, emptyKubeControllerSpec(), v4pool, emptyFelixConfig()).Build()
					cfg, err := Convert(ctx, c)
					Expect(err).ToNot(HaveOccurred())
					Expect(cfg).ToNot(BeNil())
					Expect(cfg.Spec.CNI.Type).To(Equal(operatorv1.PluginCalico))
					Expect(cfg.Spec.CNI.IPAM.Type).To(Equal(operatorv1.IPAMPluginHostLocal))
					Expect(*cfg.Spec.CalicoNetwork.BGP).To(Equal(operatorv1.BGPEnabled))
					Expect(*cfg.Spec.CalicoNetwork.HostPorts).To(Equal(operatorv1.HostPortsEnabled))
				})
			})
			DescribeTable("block on IPAM flags", func(ipam string) {
				ds := emptyNodeSpec()
				ds.Spec.Template.Spec.InitContainers[0].Env = []corev1.EnvVar{{
					Name: "CNI_NETWORK_CONFIG",
					Value: fmt.Sprintf(`{
"name": "k8s-pod-network",
"cniVersion": "0.3.1",
"plugins": [
  {
	"type": "calico",
	"log_level": "info",
	"datastore_type": "kubernetes",
	"nodename": "__KUBERNETES_NODE_NAME__",
	"mtu": __CNI_MTU__,
	"ipam": { "type": "calico-ipam", %s },
	"policy": {
		"type": "k8s"
	},
	"kubernetes": {
		"kubeconfig": "__KUBECONFIG_FILEPATH__"
	}
  }
  ]
}`, ipam),
				}}
				ds.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{{
					Name:  "CALICO_NETWORKING_BACKEND",
					Value: "bird",
				}}
				c := ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(ds, emptyKubeControllerSpec(), v4pool, emptyFelixConfig()).Build()
				_, err := Convert(ctx, c)
				Expect(err).To(HaveOccurred())
			},
				Entry("subnet", `"subnet": "usePodCidr"`),
				Entry("ipv4_pools", `"ipv4_pools": ["10.0.0.0/24"]`),
				Entry("ipv6_pools", `"ipv6_pools": ["2001:db8::1/120"]`),
				Entry("both pools", `"ipv4_pools": ["10.0.0.0/24"], "ipv6_pools": ["2001:db8::1/120"]`),
			)
		})
	})

	DescribeTable("handle IPv6 config errors", func(envVars []corev1.EnvVar, errorExpected bool) {
		ds := emptyNodeSpec()
		ds.Spec.Template.Spec.Containers[0].Env = append(ds.Spec.Template.Spec.Containers[0].Env, envVars...)
		// The calico-node ds has a v4 pool to satisfy the migration controller.
		// The tests here are only testing the IPv6-related env var migration
		// validation so the defined pools don't matter.
		c := ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(ds, emptyKubeControllerSpec(), v4pool, emptyFelixConfig()).Build()
		cfg, err := Convert(ctx, c)
		if errorExpected {
			Expect(err).To(HaveOccurred())
			Expect(cfg).To(BeNil())
		} else {
			Expect(err).ToNot(HaveOccurred())
			Expect(cfg).ToNot(BeNil())
		}
	},
		Entry("should error if implicitly IPv4 only and FELIX_IPV6SUPPORT=true", []corev1.EnvVar{{Name: "FELIX_IPV6SUPPORT", Value: "true"}}, true),
		Entry("should error if explicitlyIPv4 only and FELIX_IPV6SUPPORT=true", []corev1.EnvVar{
			{Name: "IP", Value: "autodetect"},
			{Name: "FELIX_IPV6SUPPORT", Value: "true"},
		}, true),
		Entry("should error if IP6=none but FELIX_IPV6SUPPORT=true", []corev1.EnvVar{
			{Name: "IP6", Value: "none"},
			{Name: "FELIX_IPV6SUPPORT", Value: "true"},
		}, true),
		Entry("should not error if IP6=none and FELIX_IPV6SUPPORT is undefined", []corev1.EnvVar{{Name: "IP6", Value: "none"}}, false),
		Entry("should error if IPv4 only and FELIX_IPV6SUPPORT=true", []corev1.EnvVar{{Name: "FELIX_IPV6SUPPORT", Value: "true"}}, true),
		Entry("should error if IPv6 only with bird and CALICO_ROUTER_ID != `hash`",
			[]corev1.EnvVar{
				{Name: "IP", Value: "none"},
				{Name: "IP6", Value: "autodetect"},
				{Name: "FELIX_IPV6SUPPORT", Value: "true"},
				{Name: "CALICO_NETWORKING_BACKEND", Value: "bird"},
				{Name: "CALICO_ROUTER_ID", Value: "not hash"},
			}, true),
		Entry("should error if IPv6 only with vxlan and CALICO_ROUTER_ID == `hash`",
			[]corev1.EnvVar{
				{Name: "IP", Value: "none"},
				{Name: "IP6", Value: "autodetect"},
				{Name: "FELIX_IPV6SUPPORT", Value: "true"},
				{Name: "CALICO_NETWORKING_BACKEND", Value: "vxlan"},
				{Name: "CALICO_ROUTER_ID", Value: "hash"},
			}, true),
	)

	It("handle both IP_AUTODETECTION_METHOD and IP6_AUTODETECTION_METHOD", func() {
		ds := emptyNodeSpec()
		ds.Spec.Template.Spec.InitContainers[0].Env = []corev1.EnvVar{{
			Name:  "CNI_NETWORK_CONFIG",
			Value: `{"type": "calico", "name": "k8s-pod-network", "ipam": {"type": "calico-ipam", "assign_ipv4":"true", "assign_ipv6":"true"}}`,
		}}

		ds.Spec.Template.Spec.Containers[0].Env = append(ds.Spec.Template.Spec.Containers[0].Env,
			corev1.EnvVar{
				Name:  "IP",
				Value: "autodetect",
			},
			corev1.EnvVar{
				Name:  "IP6",
				Value: "autodetect",
			},
			corev1.EnvVar{
				Name:  "FELIX_IPV6SUPPORT",
				Value: "true",
			},
		)

		ds.Spec.Template.Spec.Containers[0].Env = append(ds.Spec.Template.Spec.Containers[0].Env, corev1.EnvVar{
			Name:  "IP_AUTODETECTION_METHOD",
			Value: "can-reach=8.8.8.8",
		})

		ds.Spec.Template.Spec.Containers[0].Env = append(ds.Spec.Template.Spec.Containers[0].Env, corev1.EnvVar{
			Name:  "IP6_AUTODETECTION_METHOD",
			Value: "interface=ens*",
		})

		c := ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(v4pool, v6pool, ds, emptyKubeControllerSpec(), emptyFelixConfig()).Build()
		cfg, err := Convert(ctx, c)
		Expect(err).ToNot(HaveOccurred())
		Expect(cfg).ToNot(BeNil())
		Expect(cfg.Spec.CalicoNetwork.NodeAddressAutodetectionV4).NotTo(BeNil())
		Expect(cfg.Spec.CalicoNetwork.NodeAddressAutodetectionV4.CanReach).To(Equal("8.8.8.8"))
		Expect(cfg.Spec.CalicoNetwork.NodeAddressAutodetectionV6).NotTo(BeNil())
		Expect(cfg.Spec.CalicoNetwork.NodeAddressAutodetectionV6.Interface).To(Equal("ens*"))
	})

	Describe("handle IP_AUTODETECTION_METHOD env", func() {
		var ds *appsv1.DaemonSet

		BeforeEach(func() {
			ds = emptyNodeSpec()
			ds.Spec.Template.Spec.InitContainers[0].Env = []corev1.EnvVar{{
				Name:  "CNI_NETWORK_CONFIG",
				Value: `{"type": "calico", "name": "k8s-pod-network", "ipam": {"type": "calico-ipam", "assign_ipv4":"true"}}`,
			}}
		})

		It("migrate cidr=", func() {
			ds.Spec.Template.Spec.Containers[0].Env = append(ds.Spec.Template.Spec.Containers[0].Env, corev1.EnvVar{
				Name:  "IP_AUTODETECTION_METHOD",
				Value: "cidr=10.0.0.0/24,10.0.1.0/24",
			})

			c := ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(v4pool, ds, emptyKubeControllerSpec(), emptyFelixConfig()).Build()
			cfg, err := Convert(ctx, c)
			Expect(err).ToNot(HaveOccurred())
			Expect(cfg).ToNot(BeNil())
			Expect(cfg.Spec.CalicoNetwork.NodeAddressAutodetectionV4).NotTo(BeNil())
			Expect(cfg.Spec.CalicoNetwork.NodeAddressAutodetectionV4.CIDRS).To(Equal([]string{"10.0.0.0/24", "10.0.1.0/24"}))
		})
		It("migrate first-found", func() {
			ds.Spec.Template.Spec.Containers[0].Env = append(ds.Spec.Template.Spec.Containers[0].Env, corev1.EnvVar{
				Name:  "IP_AUTODETECTION_METHOD",
				Value: "first-found",
			})

			c := ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(v4pool, ds, emptyKubeControllerSpec(), emptyFelixConfig()).Build()
			cfg, err := Convert(ctx, c)
			Expect(err).ToNot(HaveOccurred())
			Expect(cfg).ToNot(BeNil())
			Expect(cfg.Spec.CalicoNetwork.NodeAddressAutodetectionV4).NotTo(BeNil())
			Expect(cfg.Spec.CalicoNetwork.NodeAddressAutodetectionV4.FirstFound).NotTo(BeNil())
			Expect(*cfg.Spec.CalicoNetwork.NodeAddressAutodetectionV4.FirstFound).To(Equal(true))
		})
		It("migrate can-reach=", func() {
			ds.Spec.Template.Spec.Containers[0].Env = append(ds.Spec.Template.Spec.Containers[0].Env, corev1.EnvVar{
				Name:  "IP_AUTODETECTION_METHOD",
				Value: "can-reach=8.8.8.8",
			})

			c := ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(v4pool, ds, emptyKubeControllerSpec(), emptyFelixConfig()).Build()
			cfg, err := Convert(ctx, c)
			Expect(err).ToNot(HaveOccurred())
			Expect(cfg).ToNot(BeNil())
			Expect(cfg.Spec.CalicoNetwork.NodeAddressAutodetectionV4).NotTo(BeNil())
			Expect(cfg.Spec.CalicoNetwork.NodeAddressAutodetectionV4.CanReach).To(Equal("8.8.8.8"))
		})
		It("migrate interface=", func() {
			ds.Spec.Template.Spec.Containers[0].Env = append(ds.Spec.Template.Spec.Containers[0].Env, corev1.EnvVar{
				Name:  "IP_AUTODETECTION_METHOD",
				Value: "interface=ens*",
			})

			c := ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(v4pool, ds, emptyKubeControllerSpec(), emptyFelixConfig()).Build()
			cfg, err := Convert(ctx, c)
			Expect(err).ToNot(HaveOccurred())
			Expect(cfg).ToNot(BeNil())
			Expect(cfg.Spec.CalicoNetwork.NodeAddressAutodetectionV4).NotTo(BeNil())
			Expect(cfg.Spec.CalicoNetwork.NodeAddressAutodetectionV4.Interface).To(Equal("ens*"))
		})
		It("migrate skip-interface=", func() {
			ds.Spec.Template.Spec.Containers[0].Env = append(ds.Spec.Template.Spec.Containers[0].Env, corev1.EnvVar{
				Name:  "IP_AUTODETECTION_METHOD",
				Value: "skip-interface=eth1",
			})

			c := ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(v4pool, ds, emptyKubeControllerSpec(), emptyFelixConfig()).Build()
			cfg, err := Convert(ctx, c)
			Expect(err).ToNot(HaveOccurred())
			Expect(cfg).ToNot(BeNil())
			Expect(cfg.Spec.CalicoNetwork.NodeAddressAutodetectionV4).NotTo(BeNil())
			Expect(cfg.Spec.CalicoNetwork.NodeAddressAutodetectionV4.SkipInterface).To(Equal("eth1"))
		})
		It("migrate kubernetes-internal-ip", func() {
			ds.Spec.Template.Spec.Containers[0].Env = append(ds.Spec.Template.Spec.Containers[0].Env, corev1.EnvVar{
				Name:  "IP_AUTODETECTION_METHOD",
				Value: "kubernetes-internal-ip",
			})

			c := ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(v4pool, ds, emptyKubeControllerSpec(), emptyFelixConfig()).Build()
			cfg, err := Convert(ctx, c)
			Expect(err).ToNot(HaveOccurred())
			Expect(cfg).ToNot(BeNil())
			Expect(cfg.Spec.CalicoNetwork.NodeAddressAutodetectionV4).NotTo(BeNil())
			Expect(cfg.Spec.CalicoNetwork.NodeAddressAutodetectionV4.Kubernetes).NotTo(BeNil())
		})
		It("return error if method is invalid", func() {
			ds.Spec.Template.Spec.Containers[0].Env = append(ds.Spec.Template.Spec.Containers[0].Env, corev1.EnvVar{
				Name:  "IP_AUTODETECTION_METHOD",
				Value: "invalid",
			})

			c := ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(v4pool, ds, emptyKubeControllerSpec(), emptyFelixConfig()).Build()
			cfg, err := Convert(ctx, c)
			Expect(err).To(HaveOccurred())
			Expect(cfg).To(BeNil())
		})
	})

	Describe("handle IP6_AUTODETECTION_METHOD env", func() {
		var ds *appsv1.DaemonSet

		BeforeEach(func() {
			ds = emptyNodeSpec()
			ds.Spec.Template.Spec.InitContainers[0].Env = []corev1.EnvVar{{
				Name:  "CNI_NETWORK_CONFIG",
				Value: `{"type": "calico", "name": "k8s-pod-network", "ipam": {"type": "calico-ipam", "assign_ipv4":"false", "assign_ipv6":"true"}}`,
			}}

			ds.Spec.Template.Spec.Containers[0].Env = append(ds.Spec.Template.Spec.Containers[0].Env,
				corev1.EnvVar{
					Name:  "IP",
					Value: "none",
				},
				corev1.EnvVar{
					Name:  "IP6",
					Value: "autodetect",
				},
				corev1.EnvVar{
					Name:  "FELIX_IPV6SUPPORT",
					Value: "true",
				},
			)
		})

		It("migrate cidr=", func() {
			ds.Spec.Template.Spec.Containers[0].Env = append(ds.Spec.Template.Spec.Containers[0].Env,
				corev1.EnvVar{
					Name:  "IP6_AUTODETECTION_METHOD",
					Value: "cidr=2001:20::8/64",
				},
			)
			c := ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(v4pool, v6pool, ds, emptyKubeControllerSpec(), emptyFelixConfig()).Build()
			cfg, err := Convert(ctx, c)
			Expect(err).ToNot(HaveOccurred())
			Expect(cfg).ToNot(BeNil())
			Expect(cfg.Spec.CalicoNetwork.NodeAddressAutodetectionV6).NotTo(BeNil())
			Expect(cfg.Spec.CalicoNetwork.NodeAddressAutodetectionV6.CIDRS).To(Equal([]string{"2001:20::8/64"}))
		})
		It("migrate first-found", func() {
			ds.Spec.Template.Spec.Containers[0].Env = append(ds.Spec.Template.Spec.Containers[0].Env,
				corev1.EnvVar{
					Name:  "IP6_AUTODETECTION_METHOD",
					Value: "first-found",
				})

			c := ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(v4pool, v6pool, ds, emptyKubeControllerSpec(), emptyFelixConfig()).Build()
			cfg, err := Convert(ctx, c)
			Expect(err).ToNot(HaveOccurred())
			Expect(cfg).ToNot(BeNil())
			Expect(cfg.Spec.CalicoNetwork.NodeAddressAutodetectionV6).NotTo(BeNil())
			Expect(cfg.Spec.CalicoNetwork.NodeAddressAutodetectionV6.FirstFound).NotTo(BeNil())
			Expect(*cfg.Spec.CalicoNetwork.NodeAddressAutodetectionV6.FirstFound).To(Equal(true))
		})
		It("migrate can-reach=", func() {
			ds.Spec.Template.Spec.Containers[0].Env = append(ds.Spec.Template.Spec.Containers[0].Env,
				corev1.EnvVar{
					Name:  "IP6_AUTODETECTION_METHOD",
					Value: "can-reach=2001:4860:4860::8888",
				},
			)

			c := ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(v4pool, v6pool, ds, emptyKubeControllerSpec(), emptyFelixConfig()).Build()
			cfg, err := Convert(ctx, c)
			Expect(err).ToNot(HaveOccurred())
			Expect(cfg).ToNot(BeNil())
			Expect(cfg.Spec.CalicoNetwork.NodeAddressAutodetectionV6).NotTo(BeNil())
			Expect(cfg.Spec.CalicoNetwork.NodeAddressAutodetectionV6.CanReach).To(Equal("2001:4860:4860::8888"))
		})
		It("migrate interface=", func() {
			ds.Spec.Template.Spec.Containers[0].Env = append(ds.Spec.Template.Spec.Containers[0].Env,
				corev1.EnvVar{
					Name:  "IP6_AUTODETECTION_METHOD",
					Value: "interface=ens*",
				},
			)

			c := ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(v4pool, v6pool, ds, emptyKubeControllerSpec(), emptyFelixConfig()).Build()
			cfg, err := Convert(ctx, c)
			Expect(err).ToNot(HaveOccurred())
			Expect(cfg).ToNot(BeNil())
			Expect(cfg.Spec.CalicoNetwork.NodeAddressAutodetectionV6).NotTo(BeNil())
			Expect(cfg.Spec.CalicoNetwork.NodeAddressAutodetectionV6.Interface).To(Equal("ens*"))
		})
		It("migrate skip-interface=", func() {
			ds.Spec.Template.Spec.Containers[0].Env = append(ds.Spec.Template.Spec.Containers[0].Env,
				corev1.EnvVar{
					Name:  "IP6_AUTODETECTION_METHOD",
					Value: "skip-interface=eth1",
				},
			)

			c := ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(v4pool, v6pool, ds, emptyKubeControllerSpec(), emptyFelixConfig()).Build()
			cfg, err := Convert(ctx, c)
			Expect(err).ToNot(HaveOccurred())
			Expect(cfg).ToNot(BeNil())
			Expect(cfg.Spec.CalicoNetwork.NodeAddressAutodetectionV6).NotTo(BeNil())
			Expect(cfg.Spec.CalicoNetwork.NodeAddressAutodetectionV6.SkipInterface).To(Equal("eth1"))
		})
		It("migrate kubernetes-internal-ip", func() {
			ds.Spec.Template.Spec.Containers[0].Env = append(ds.Spec.Template.Spec.Containers[0].Env,
				corev1.EnvVar{
					Name:  "IP6_AUTODETECTION_METHOD",
					Value: "kubernetes-internal-ip",
				},
			)

			c := ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(v4pool, v6pool, ds, emptyKubeControllerSpec(), emptyFelixConfig()).Build()
			cfg, err := Convert(ctx, c)
			Expect(err).ToNot(HaveOccurred())
			Expect(cfg).ToNot(BeNil())
			Expect(cfg.Spec.CalicoNetwork.NodeAddressAutodetectionV6).NotTo(BeNil())
			Expect(cfg.Spec.CalicoNetwork.NodeAddressAutodetectionV6.Kubernetes).NotTo(BeNil())
		})
		It("return error if method is invalid", func() {
			ds.Spec.Template.Spec.Containers[0].Env = append(ds.Spec.Template.Spec.Containers[0].Env,
				corev1.EnvVar{
					Name:  "IP6_AUTODETECTION_METHOD",
					Value: "invalid",
				},
			)

			c := ctrlrfake.DefaultFakeClientBuilder(scheme).WithObjects(v4pool, v6pool, ds, emptyKubeControllerSpec(), emptyFelixConfig()).Build()
			cfg, err := Convert(ctx, c)
			Expect(err).To(HaveOccurred())
			Expect(cfg).To(BeNil())
		})
	})
})
