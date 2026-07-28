// Copyright (c) 2019-2026 Tigera, Inc. All rights reserved.

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

package installation

import (
	"path/filepath"

	"github.com/tigera/operator/pkg/render"

	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/utils/ptr"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"

	operator "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/controller/k8sapi"
)

var _ = Describe("Installation validation tests", func() {
	var instance *operator.Installation

	BeforeEach(func() {
		instance = &operator.Installation{
			Spec: operator.InstallationSpec{
				CalicoNetwork:  &operator.CalicoNetworkSpec{},
				FlexVolumePath: "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/",
				NodeUpdateStrategy: appsv1.DaemonSetUpdateStrategy{
					Type: appsv1.RollingUpdateDaemonSetStrategyType,
				},
				Variant: operator.Calico,
				CNI: &operator.CNISpec{
					Type: operator.PluginCalico,
					IPAM: &operator.IPAMSpec{Type: operator.IPAMPluginCalico},
				},
				ComponentResources:      []operator.ComponentResource{},
				KubeletVolumePluginPath: filepath.Clean("/var/lib/kubelet"),
			},
		}
	})

	It("should allow IPv6 if BPF is enabled", func() {
		bpf := operator.LinuxDataplaneBPF
		enabled := operator.BGPEnabled
		instance.Spec.CalicoNetwork.BGP = &enabled
		instance.Spec.CalicoNetwork.LinuxDataplane = &bpf
		instance.Spec.CalicoNetwork.IPPools = []operator.IPPool{
			{
				CIDR:          "1eef::/64",
				NATOutgoing:   operator.NATOutgoingEnabled,
				Encapsulation: operator.EncapsulationNone,
				NodeSelector:  "all()",
			},
		}
		instance.Spec.CalicoNetwork.NodeAddressAutodetectionV6 = &operator.NodeAddressAutodetection{
			CanReach: "2001:4860:4860::8888",
		}
		err := validateCustomResource(instance)
		Expect(err).To(BeNil())
	})

	It("should allow dual stack (both IPv4 and IPv6) if BPF is enabled", func() {
		instance.Spec.CalicoNetwork.BGP = ptr.To(operator.BGPEnabled)
		bpf := operator.LinuxDataplaneBPF
		instance.Spec.CalicoNetwork.LinuxDataplane = &bpf
		instance.Spec.CalicoNetwork.IPPools = []operator.IPPool{
			{
				CIDR:          "1eef::/64",
				NATOutgoing:   operator.NATOutgoingEnabled,
				Encapsulation: operator.EncapsulationNone,
				NodeSelector:  "all()",
			},
			{
				CIDR:          "192.168.0.0/27",
				Encapsulation: operator.EncapsulationNone,
				NATOutgoing:   operator.NATOutgoingEnabled,
				NodeSelector:  "all()",
			},
		}
		instance.Spec.CalicoNetwork.NodeAddressAutodetectionV6 = &operator.NodeAddressAutodetection{
			CanReach: "2001:4860:4860::8888",
		}
		instance.Spec.CalicoNetwork.NodeAddressAutodetectionV4 = &operator.NodeAddressAutodetection{
			CanReach: "8.8.8.8",
		}
		err := validateCustomResource(instance)
		Expect(err).To(BeNil())
	})

	It("should allow IPv6 VXLAN", func() {
		encaps := []operator.EncapsulationType{operator.EncapsulationVXLAN, operator.EncapsulationVXLANCrossSubnet}
		for _, vxlanMode := range encaps {
			instance.Spec.CalicoNetwork.IPPools = []operator.IPPool{
				{
					CIDR:          "1eef::/64",
					NATOutgoing:   operator.NATOutgoingEnabled,
					Encapsulation: vxlanMode,
					NodeSelector:  "all()",
				},
			}
			err := validateCustomResource(instance)
			Expect(err).To(BeNil())
		}
	})

	It("should prevent IPv6 if IPIP is enabled", func() {
		encaps := []operator.EncapsulationType{operator.EncapsulationIPIP, operator.EncapsulationIPIPCrossSubnet}
		for _, ipipMode := range encaps {
			instance.Spec.CalicoNetwork.IPPools = []operator.IPPool{
				{
					CIDR:          "1eef::/64",
					NATOutgoing:   operator.NATOutgoingEnabled,
					Encapsulation: ipipMode,
					NodeSelector:  "all()",
				},
			}
			err := validateCustomResource(instance)
			Expect(err).To(MatchError("IPIP encapsulation is not supported by IPv6 pools, but it is set for 1eef::/64"))
		}
	})

	It("should prevent multiple node address autodetection methods", func() {
		nodeIP := operator.NodeInternalIP
		instance.Spec.CalicoNetwork.NodeAddressAutodetectionV4 = &operator.NodeAddressAutodetection{
			CanReach:   "8.8.8.8",
			Kubernetes: &nodeIP,
		}
		err := validateCustomResource(instance)
		Expect(err).To(MatchError("no more than one node address autodetection method can be specified per-family"))
	})

	It("should allow autodetection based on Kubernetes node IP", func() {
		nodeIP := operator.NodeInternalIP
		instance.Spec.CalicoNetwork.NodeAddressAutodetectionV4 = &operator.NodeAddressAutodetection{
			Kubernetes: &nodeIP,
		}
		err := validateCustomResource(instance)
		Expect(err).NotTo(HaveOccurred())
	})

	It("should allow host ports if BPF is enabled", func() {
		bpf := operator.LinuxDataplaneBPF
		instance.Spec.CalicoNetwork.LinuxDataplane = &bpf
		hp := operator.HostPortsEnabled
		instance.Spec.CalicoNetwork.HostPorts = &hp
		instance.Spec.CalicoNetwork.NodeAddressAutodetectionV4 = &operator.NodeAddressAutodetection{
			CanReach: "8.8.8.8",
		}
		err := validateCustomResource(instance)
		Expect(err).NotTo(HaveOccurred())
	})

	It("should allow disabled host ports if BPF is enabled", func() {
		bpf := operator.LinuxDataplaneBPF
		instance.Spec.CalicoNetwork.LinuxDataplane = &bpf
		hp := operator.HostPortsDisabled
		instance.Spec.CalicoNetwork.HostPorts = &hp
		instance.Spec.CalicoNetwork.NodeAddressAutodetectionV4 = &operator.NodeAddressAutodetection{
			CanReach: "8.8.8.8",
		}
		err := validateCustomResource(instance)
		Expect(err).NotTo(HaveOccurred())
	})

	It("should not allow VPP to be used with a variant other than Calico", func() {
		vpp := operator.LinuxDataplaneVPP
		en := operator.BGPEnabled
		instance.Spec.CalicoNetwork.LinuxDataplane = &vpp
		instance.Spec.CalicoNetwork.BGP = &en
		instance.Spec.CNI.Type = operator.PluginCalico
		err := validateCustomResource(instance)
		Expect(err).NotTo(HaveOccurred())
		instance.Spec.Variant = operator.CalicoEnterprise
		err = validateCustomResource(instance)
		Expect(err).To(HaveOccurred())
	})

	It("should not allow VPP to be used with a CNI other than Calico", func() {
		vpp := operator.LinuxDataplaneVPP
		en := operator.BGPEnabled
		instance.Spec.CalicoNetwork.LinuxDataplane = &vpp
		instance.Spec.CalicoNetwork.BGP = &en
		instance.Spec.CNI.Type = operator.PluginAmazonVPC
		err := validateCustomResource(instance)
		Expect(err).To(HaveOccurred())
		instance.Spec.CNI.Type = operator.PluginCalico
		err = validateCustomResource(instance)
		Expect(err).NotTo(HaveOccurred())
	})

	It("should not allow VPP to be used if BGP is not enabled", func() {
		vpp := operator.LinuxDataplaneVPP
		en := operator.BGPEnabled
		dis := operator.BGPDisabled
		instance.Spec.CalicoNetwork.LinuxDataplane = &vpp
		instance.Spec.CNI.Type = operator.PluginCalico
		instance.Spec.CalicoNetwork.BGP = &dis
		err := validateCustomResource(instance)
		Expect(err).To(HaveOccurred())
		instance.Spec.CalicoNetwork.BGP = &en
		err = validateCustomResource(instance)
		Expect(err).NotTo(HaveOccurred())
	})

	It("should not allow HostPorts to be disabled with VPP", func() {
		vpp := operator.LinuxDataplaneVPP
		bgp := operator.BGPEnabled
		en := operator.HostPortsEnabled
		dis := operator.HostPortsDisabled
		instance.Spec.CalicoNetwork.LinuxDataplane = &vpp
		instance.Spec.CalicoNetwork.BGP = &bgp
		instance.Spec.CNI.Type = operator.PluginCalico
		instance.Spec.CalicoNetwork.HostPorts = &dis
		err := validateCustomResource(instance)
		Expect(err).To(HaveOccurred())
		instance.Spec.CalicoNetwork.HostPorts = &en
		err = validateCustomResource(instance)
		Expect(err).NotTo(HaveOccurred())
	})

	It("should allow HostPorts=Disabled when using the AmazonVPC plugin", func() {
		bpf := operator.LinuxDataplaneBPF
		bgp := operator.BGPDisabled
		dis := operator.HostPortsDisabled
		instance.Spec.CalicoNetwork.LinuxDataplane = &bpf
		instance.Spec.CalicoNetwork.BGP = &bgp
		instance.Spec.CNI.Type = operator.PluginAmazonVPC
		instance.Spec.CNI.IPAM.Type = operator.IPAMPluginAmazonVPC
		instance.Spec.CalicoNetwork.HostPorts = &dis
		err := validateCustomResource(instance)
		Expect(err).NotTo(HaveOccurred())
	})

	It("should allow specVersion with Calico CNI", func() {
		pinned := operator.CNISpecVersion100
		instance.Spec.CNI.SpecVersion = &pinned
		Expect(validateCustomResource(instance)).NotTo(HaveOccurred())
	})

	It("should reject specVersion when the CNI plugin is not Calico", func() {
		pinned := operator.CNISpecVersion100
		bgp := operator.BGPDisabled
		dis := operator.HostPortsDisabled
		instance.Spec.CalicoNetwork.BGP = &bgp
		instance.Spec.CalicoNetwork.HostPorts = &dis
		instance.Spec.CNI.Type = operator.PluginAmazonVPC
		instance.Spec.CNI.IPAM.Type = operator.IPAMPluginAmazonVPC
		instance.Spec.CNI.SpecVersion = &pinned
		err := validateCustomResource(instance)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("spec.cni.specVersion is only valid"))
	})

	It("should prevent IPIP with BGP disabled in BIRD cluster routing mode", func() {
		disabled := operator.BGPDisabled
		instance.Spec.CalicoNetwork.BGP = &disabled
		instance.Spec.CalicoNetwork.IPPools = []operator.IPPool{
			{
				CIDR:          "192.168.0.0/24",
				Encapsulation: operator.EncapsulationIPIP,
				NATOutgoing:   operator.NATOutgoingEnabled,
				NodeSelector:  "all()",
			},
		}
		err := validateCustomResource(instance)
		Expect(err).To(HaveOccurred())
	})

	It("should prevent IPIP cross-subnet with BGP disabled in BIRD cluster routing mode", func() {
		disabled := operator.BGPDisabled
		instance.Spec.CalicoNetwork.BGP = &disabled
		instance.Spec.CalicoNetwork.IPPools = []operator.IPPool{
			{
				CIDR:          "192.168.0.0/24",
				Encapsulation: operator.EncapsulationIPIPCrossSubnet,
				NATOutgoing:   operator.NATOutgoingEnabled,
				NodeSelector:  "all()",
			},
		}
		err := validateCustomResource(instance)
		Expect(err).To(HaveOccurred())
	})

	It("should prevent no-encap with BGP disabled in BIRD cluster routing mode", func() {
		disabled := operator.BGPDisabled
		instance.Spec.CalicoNetwork.BGP = &disabled
		instance.Spec.CalicoNetwork.IPPools = []operator.IPPool{
			{
				CIDR:          "192.168.0.0/24",
				Encapsulation: operator.EncapsulationNone,
				NATOutgoing:   operator.NATOutgoingEnabled,
				NodeSelector:  "all()",
			},
		}
		err := validateCustomResource(instance)
		Expect(err).To(HaveOccurred())
	})

	It("should allow IPIP with BGP disabled in Felix cluster routing mode", func() {
		disabled := operator.BGPDisabled
		instance.Spec.CalicoNetwork.BGP = &disabled
		clusterRoutingMode := operator.ClusterRoutingModeFelix
		instance.Spec.CalicoNetwork.ClusterRoutingMode = &clusterRoutingMode
		instance.Spec.CalicoNetwork.IPPools = []operator.IPPool{
			{
				CIDR:          "192.168.0.0/24",
				Encapsulation: operator.EncapsulationIPIP,
				NATOutgoing:   operator.NATOutgoingEnabled,
				NodeSelector:  "all()",
			},
		}
		err := validateCustomResource(instance)
		Expect(err).NotTo(HaveOccurred())
	})

	It("should allow IPIP cross-subnet with BGP disabled in Felix cluster routing mode", func() {
		disabled := operator.BGPDisabled
		instance.Spec.CalicoNetwork.BGP = &disabled
		clusterRoutingMode := operator.ClusterRoutingModeFelix
		instance.Spec.CalicoNetwork.ClusterRoutingMode = &clusterRoutingMode
		instance.Spec.CalicoNetwork.IPPools = []operator.IPPool{
			{
				CIDR:          "192.168.0.0/24",
				Encapsulation: operator.EncapsulationIPIPCrossSubnet,
				NATOutgoing:   operator.NATOutgoingEnabled,
				NodeSelector:  "all()",
			},
		}
		err := validateCustomResource(instance)
		Expect(err).NotTo(HaveOccurred())
	})

	It("should allow no-encap with BGP disabled in Felix cluster routing mode", func() {
		disabled := operator.BGPDisabled
		instance.Spec.CalicoNetwork.BGP = &disabled
		clusterRoutingMode := operator.ClusterRoutingModeFelix
		instance.Spec.CalicoNetwork.ClusterRoutingMode = &clusterRoutingMode
		instance.Spec.CalicoNetwork.IPPools = []operator.IPPool{
			{
				CIDR:          "192.168.0.0/24",
				Encapsulation: operator.EncapsulationNone,
				NATOutgoing:   operator.NATOutgoingEnabled,
				NodeSelector:  "all()",
			},
		}
		err := validateCustomResource(instance)
		Expect(err).NotTo(HaveOccurred())
	})

	It("should not error if CalicoNetwork is provided on EKS", func() {
		instance := &operator.Installation{}
		instance.Spec.CNI = &operator.CNISpec{Type: operator.PluginCalico}
		instance.Spec.Variant = operator.CalicoEnterprise
		instance.Spec.CalicoNetwork = &operator.CalicoNetworkSpec{}
		instance.Spec.KubernetesProvider = operator.ProviderEKS

		// Fill in defaults and validate the result.
		Expect(fillDefaults(instance, nil)).NotTo(HaveOccurred())
		Expect(validateCustomResource(instance)).NotTo(HaveOccurred())
	})

	It("should not allow a relative path in FlexVolumePath", func() {
		instance.Spec.FlexVolumePath = "foo/bar/baz"
		err := validateCustomResource(instance)
		Expect(err).To(HaveOccurred())
	})

	It("should allow arbitrary absolute path in KubeletVolumePluginPath", func() {
		instance.Spec.KubeletVolumePluginPath = "/some/abs/path"
		err := validateCustomResource(instance)
		Expect(err).NotTo(HaveOccurred())
	})

	It("should not allow a relative path in KubeletVolumePluginPath", func() {
		instance.Spec.KubeletVolumePluginPath = "relative/path"
		err := validateCustomResource(instance)
		Expect(err).To(HaveOccurred())
	})

	It("should allow 'None' value in KubeletVolumePluginPath", func() {
		instance.Spec.KubeletVolumePluginPath = "None"
		err := validateCustomResource(instance)
		Expect(err).NotTo(HaveOccurred())
	})

	It("should validate controlPlaneNodeSelector", func() {
		instance.Spec.ControlPlaneNodeSelector = map[string]string{
			"kubernetes.io/os": "windows",
		}
		Expect(validateCustomResource(instance)).To(HaveOccurred())
	})

	It("should validate ControlPlaneReplicas", func() {
		var replicas int32

		replicas = -1
		instance.Spec.ControlPlaneReplicas = &replicas
		Expect(validateCustomResource(instance)).To(HaveOccurred())

		replicas = 0
		instance.Spec.ControlPlaneReplicas = &replicas
		Expect(validateCustomResource(instance)).To(HaveOccurred())

		replicas = 1
		instance.Spec.ControlPlaneReplicas = &replicas
		Expect(validateCustomResource(instance)).NotTo(HaveOccurred())

		replicas = 2
		instance.Spec.ControlPlaneReplicas = &replicas
		Expect(validateCustomResource(instance)).NotTo(HaveOccurred())
	})

	It("should validate HostPorts", func() {
		instance.Spec.CalicoNetwork.HostPorts = nil
		err := validateCustomResource(instance)
		Expect(err).NotTo(HaveOccurred())

		hp := operator.HostPortsEnabled
		instance.Spec.CalicoNetwork.HostPorts = &hp
		err = validateCustomResource(instance)
		Expect(err).NotTo(HaveOccurred())

		hp = operator.HostPortsDisabled
		instance.Spec.CalicoNetwork.HostPorts = &hp
		err = validateCustomResource(instance)
		Expect(err).NotTo(HaveOccurred())

		hp = "NotValid"
		instance.Spec.CalicoNetwork.HostPorts = &hp
		err = validateCustomResource(instance)
		Expect(err).To(HaveOccurred())
	})

	It("should not allow Calico to run in non-privileged mode, since it's deprecated", func() {
		np := operator.NonPrivilegedEnabled
		instance.Spec.NonPrivileged = &np
		err := validateCustomResource(instance)
		Expect(err).To(HaveOccurred())
	})

	It("should pass on allowed CNI sysctl tuning plugin config", func() {
		instance.Spec.CalicoNetwork.Sysctl = []operator.Sysctl{
			{
				Key:   "net.ipv4.tcp_keepalive_intvl",
				Value: "15",
			},
			{
				Key:   "net.ipv4.tcp_keepalive_probes",
				Value: "6",
			},
			{
				Key:   "net.ipv4.tcp_keepalive_time",
				Value: "40",
			},
		}
		err := validateCustomResource(instance)
		Expect(err).ShouldNot(HaveOccurred())
	})

	It("should error on not-allowed CNI sysctl tuning plugin config", func() {
		instance.Spec.CalicoNetwork.Sysctl = []operator.Sysctl{
			{
				Key:   "net.ipv4.not_allowed_parameter",
				Value: "1",
			},
		}
		err := validateCustomResource(instance)
		Expect(err).To(HaveOccurred())
	})

	It("should allow Spec.Azure to be set for AKS provider", func() {
		instance.Spec.KubernetesProvider = operator.ProviderAKS
		instance.Spec.Azure = &operator.Azure{}
		err := validateCustomResource(instance)
		Expect(err).NotTo(HaveOccurred())
	})

	It("should not allow Spec.Azure to be set for non AKS provider", func() {
		instance.Spec.KubernetesProvider = operator.ProviderGKE
		instance.Spec.Azure = &operator.Azure{}
		err := validateCustomResource(instance)
		Expect(err).To(HaveOccurred())
	})

	Describe("validate Calico CNI plugin Type", func() {
		DescribeTable("test invalid IPAM",
			func(ipam operator.IPAMPluginType) {
				instance.Spec.CNI.Type = operator.PluginCalico
				instance.Spec.CNI.IPAM = &operator.IPAMSpec{Type: ipam}
				err := validateCustomResource(instance)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("valid IPAM values Calico,HostLocal"))
			},

			Entry("AmazonVPC", operator.IPAMPluginAmazonVPC),
			Entry("AzureVNET", operator.IPAMPluginAzureVNET),
		)
		DescribeTable("test valid IPAM",
			func(ipam operator.IPAMPluginType) {
				instance.Spec.CNI.Type = operator.PluginCalico
				instance.Spec.CNI.IPAM = &operator.IPAMSpec{Type: ipam}
				err := validateCustomResource(instance)
				Expect(err).NotTo(HaveOccurred())
			},

			Entry("Calico", operator.IPAMPluginCalico),
			Entry("HostLocal", operator.IPAMPluginHostLocal),
		)
		DescribeTable("with HostLocal IPAM",
			func(ipam operator.IPAMPluginType) {
				instance.Spec.CNI.Type = operator.PluginCalico
				instance.Spec.CNI.IPAM = &operator.IPAMSpec{Type: ipam}
				err := validateCustomResource(instance)
				Expect(err).NotTo(HaveOccurred())
			},

			Entry("Calico", operator.IPAMPluginCalico),
			Entry("HostLocal", operator.IPAMPluginHostLocal),
		)
		Describe("should validate HostLocal with IPPool", func() {
			BeforeEach(func() {
				instance.Spec.CNI.IPAM = &operator.IPAMSpec{Type: operator.IPAMPluginHostLocal}
				disabled := operator.BGPDisabled
				instance.Spec.CalicoNetwork.BGP = &disabled
			})

			It("with empty CalicoNetwork validates", func() {
				Expect(fillDefaults(instance, nil)).NotTo(HaveOccurred())
				err := validateCustomResource(instance)
				Expect(err).NotTo(HaveOccurred())
			})

			It("with IPPool with Encapsulation None validates", func() {
				instance.Spec.CalicoNetwork.IPPools = []operator.IPPool{
					{
						CIDR:          "192.168.0.0/24",
						Encapsulation: operator.EncapsulationNone,
						NATOutgoing:   operator.NATOutgoingEnabled,
						NodeSelector:  "all()",
					},
				}
				Expect(fillDefaults(instance, nil)).NotTo(HaveOccurred())
				err := validateCustomResource(instance)
				Expect(err).NotTo(HaveOccurred())
			})

			It("with BGP enabled validates", func() {
				enable := operator.BGPEnabled
				instance.Spec.CalicoNetwork.BGP = &enable
				Expect(fillDefaults(instance, nil)).NotTo(HaveOccurred())
				err := validateCustomResource(instance)
				Expect(err).NotTo(HaveOccurred())
			})

			It("With dual-stack enabled", func() {
				instance.Spec.CalicoNetwork.IPPools = []operator.IPPool{
					{
						CIDR:          "192.168.0.0/24",
						Encapsulation: operator.EncapsulationNone,
						NATOutgoing:   operator.NATOutgoingEnabled,
						NodeSelector:  "all()",
					},
					{
						CIDR:          "fe80:00::00/64",
						Encapsulation: operator.EncapsulationNone,
						NATOutgoing:   operator.NATOutgoingEnabled,
						NodeSelector:  "all()",
					},
				}
				Expect(fillDefaults(instance, nil)).NotTo(HaveOccurred())
				err := validateCustomResource(instance)
				Expect(err).NotTo(HaveOccurred())
			})
		})

		Describe("should validate CNILogging", func() {
			BeforeEach(func() {
				instance.Spec.Logging = &operator.Logging{
					CNI: &operator.CNILogging{},
				}
			})

			It("with nil LogSeverity", func() {
				Expect(fillDefaults(instance, nil)).NotTo(HaveOccurred())
				err := validateCustomResource(instance)
				Expect(err).NotTo(HaveOccurred())
				Expect(*instance.Spec.Logging.CNI.LogSeverity).To(Equal(operator.LogLevelInfo))
			})

			It("with nil LogFileMaxAgeDays", func() {
				Expect(fillDefaults(instance, nil)).NotTo(HaveOccurred())
				err := validateCustomResource(instance)
				Expect(err).NotTo(HaveOccurred())
				Expect(*instance.Spec.Logging.CNI.LogFileMaxAgeDays).To(Equal(uint32(30)))
			})

			It("with invalid LogFileMaxAgeDays", func() {
				instance.Spec.Logging.CNI.LogFileMaxAgeDays = new(uint32)
				*instance.Spec.Logging.CNI.LogFileMaxAgeDays = 0
				Expect(fillDefaults(instance, nil)).NotTo(HaveOccurred())
				err := validateCustomResource(instance)
				Expect(err).To(HaveOccurred())
				Expect(err).To(MatchError("spec.Logging.cni.logFileMaxAgeDays should be a positive non-zero integer"))
			})

			It("with nil LogFileMaxCount", func() {
				Expect(fillDefaults(instance, nil)).NotTo(HaveOccurred())
				err := validateCustomResource(instance)
				Expect(err).NotTo(HaveOccurred())
				Expect(*instance.Spec.Logging.CNI.LogFileMaxCount).To(Equal(uint32(10)))
			})

			It("with invalid LogFileMaxCount", func() {
				instance.Spec.Logging.CNI.LogFileMaxCount = new(uint32)
				*instance.Spec.Logging.CNI.LogFileMaxCount = 0
				Expect(fillDefaults(instance, nil)).NotTo(HaveOccurred())
				err := validateCustomResource(instance)
				Expect(err).To(HaveOccurred())
				Expect(err).To(MatchError("spec.loggingConfig.cni.logFileMaxCount value should be greater than zero"))
			})

			It("with nil LogFileMaxSize", func() {
				Expect(fillDefaults(instance, nil)).NotTo(HaveOccurred())
				err := validateCustomResource(instance)
				Expect(err).NotTo(HaveOccurred())
				Expect(*instance.Spec.Logging.CNI.LogFileMaxSize).To(Equal(resource.MustParse("100Mi")))
			})

			It("with invalid LogFileMaxSize", func() {
				instance.Spec.Logging.CNI.LogFileMaxSize = new(resource.Quantity)
				*instance.Spec.Logging.CNI.LogFileMaxSize = resource.MustParse("1")
				Expect(fillDefaults(instance, nil)).NotTo(HaveOccurred())
				err := validateCustomResource(instance)
				Expect(err).To(HaveOccurred())
				Expect(err).To(MatchError("spec.Logging.cni.logFileMaxSize format is not corrent. Suffix should be Ki | Mi | Gi | Ti | Pi | Ei"))

				*instance.Spec.Logging.CNI.LogFileMaxSize = resource.MustParse("0")
				Expect(fillDefaults(instance, nil)).NotTo(HaveOccurred())
				err = validateCustomResource(instance)
				Expect(err).To(HaveOccurred())
				Expect(err).To(MatchError("spec.Logging.cni.logFileMaxSize format is not corrent. Suffix should be Ki | Mi | Gi | Ti | Pi | Ei"))

				*instance.Spec.Logging.CNI.LogFileMaxSize = resource.MustParse("-1")
				Expect(fillDefaults(instance, nil)).NotTo(HaveOccurred())
				err = validateCustomResource(instance)
				Expect(err).To(HaveOccurred())
				Expect(err).To(MatchError("spec.Logging.cni.logFileMaxSize format is not corrent. Suffix should be Ki | Mi | Gi | Ti | Pi | Ei"))

				*instance.Spec.Logging.CNI.LogFileMaxSize = resource.MustParse("1M")
				Expect(fillDefaults(instance, nil)).NotTo(HaveOccurred())
				err = validateCustomResource(instance)
				Expect(err).To(HaveOccurred())
				Expect(err).To(MatchError("spec.Logging.cni.logFileMaxSize format is not corrent. Suffix should be Ki | Mi | Gi | Ti | Pi | Ei"))
			})
		})
	})
	Describe("validate non-calico CNI plugin Type", func() {
		BeforeEach(func() {
			instance.Spec.CNI = &operator.CNISpec{}
		})

		It("should not allow empty CNI", func() {
			err := validateCustomResource(instance)
			Expect(err).To(HaveOccurred())
		})

		It("should not allow invalid CNI Type", func() {
			instance.Spec.CNI.Type = "bad"
			err := validateCustomResource(instance)
			Expect(err).To(HaveOccurred())
		})
		nonCalicoCNIEntries := []TableEntry{
			Entry("GKE", operator.PluginGKE, operator.IPAMPluginHostLocal),
			Entry("AmazonVPC", operator.PluginAmazonVPC, operator.IPAMPluginAmazonVPC),
			Entry("AzureVNET", operator.PluginAzureVNET, operator.IPAMPluginAzureVNET),
		}
		DescribeTable("test allowed plugins", func(plugin operator.CNIPluginType, ipam operator.IPAMPluginType) {
			instance.Spec.CNI.Type = plugin
			instance.Spec.CNI.IPAM = &operator.IPAMSpec{Type: ipam}
			Expect(fillDefaults(instance, nil)).NotTo(HaveOccurred())
			err := validateCustomResource(instance)
			Expect(err).NotTo(HaveOccurred())
		}, nonCalicoCNIEntries)
		DescribeTable("test with no CalicoNetwork", func(plugin operator.CNIPluginType, ipam operator.IPAMPluginType) {
			instance.Spec.CalicoNetwork = nil
			instance.Spec.CNI.Type = plugin
			instance.Spec.CNI.IPAM = &operator.IPAMSpec{Type: ipam}
			err := validateCustomResource(instance)
			Expect(err).NotTo(HaveOccurred())
		}, nonCalicoCNIEntries)
		DescribeTable("test invalid CNI and IPAM combinations",
			func(plugin operator.CNIPluginType, allowedipam operator.IPAMPluginType) {
				instance.Spec.CNI.Type = plugin
				for _, x := range operator.IPAMPluginTypes {
					if allowedipam == x {
						continue
					}
					instance.Spec.CNI.IPAM = &operator.IPAMSpec{Type: x}
					err := validateCustomResource(instance)
					Expect(err).To(HaveOccurred())
					Expect(err.Error()).To(ContainSubstring("valid IPAM values " + allowedipam.String()))
				}
			},

			Entry("GKE", operator.PluginGKE, operator.IPAMPluginHostLocal),
			Entry("AmazonVPC", operator.PluginAmazonVPC, operator.IPAMPluginAmazonVPC),
			Entry("AzureVNET", operator.PluginAzureVNET, operator.IPAMPluginAzureVNET),
		)
		DescribeTable("should disallow Calico only fields",
			func(setField func(inst *operator.Installation)) {
				instance.Spec.CNI.Type = operator.PluginGKE
				instance.Spec.CNI.IPAM = &operator.IPAMSpec{Type: operator.IPAMPluginHostLocal}
				setField(instance)
				err := validateCustomResource(instance)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("supported only for Calico CNI"))
			},
			Entry("HostPorts", func(inst *operator.Installation) {
				hpe := operator.HostPortsEnabled
				inst.Spec.CalicoNetwork.HostPorts = &hpe
			}),
			Entry("MultiInterfaceMode", func(inst *operator.Installation) {
				mimm := operator.MultiInterfaceModeMultus
				inst.Spec.CalicoNetwork.MultiInterfaceMode = &mimm
			}),
			Entry("ContainerIPForwarding", func(inst *operator.Installation) {
				cipf := operator.ContainerIPForwardingEnabled
				inst.Spec.CalicoNetwork.ContainerIPForwarding = &cipf
			}),
			Entry("LinuxPodInterfaceType", func(inst *operator.Installation) {
				nk := operator.LinuxPodInterfaceNetkit
				inst.Spec.CalicoNetwork.LinuxPodInterfaceType = &nk
			}),
		)
		DescribeTable("should allow IPPool", func(plugin operator.CNIPluginType, ipam operator.IPAMPluginType) {
			instance.Spec.CNI.Type = plugin
			instance.Spec.CNI.IPAM = &operator.IPAMSpec{Type: ipam}
			instance.Spec.CalicoNetwork.IPPools = []operator.IPPool{
				{
					CIDR:          "192.168.0.0/24",
					Encapsulation: operator.EncapsulationNone,
					NATOutgoing:   operator.NATOutgoingEnabled,
					NodeSelector:  "all()",
				},
			}
			err := validateCustomResource(instance)
			Expect(err).NotTo(HaveOccurred())
		}, nonCalicoCNIEntries)
		DescribeTable("should disallow IPPool with IPIP", func(plugin operator.CNIPluginType, ipam operator.IPAMPluginType) {
			instance.Spec.CNI.Type = plugin
			instance.Spec.CNI.IPAM = &operator.IPAMSpec{Type: ipam}
			instance.Spec.CalicoNetwork.IPPools = []operator.IPPool{
				{
					CIDR:          "192.168.0.0/24",
					Encapsulation: operator.EncapsulationIPIP,
					NATOutgoing:   operator.NATOutgoingEnabled,
					NodeSelector:  "all()",
				},
			}
			err := validateCustomResource(instance)
			Expect(err).To(HaveOccurred())
		}, nonCalicoCNIEntries)
		DescribeTable("should disallow IPPool with non-all NodeSelector", func(plugin operator.CNIPluginType, ipam operator.IPAMPluginType) {
			instance.Spec.CNI.Type = plugin
			instance.Spec.CNI.IPAM = &operator.IPAMSpec{Type: ipam}
			instance.Spec.CalicoNetwork.IPPools = []operator.IPPool{
				{
					CIDR:          "192.168.0.0/24",
					Encapsulation: operator.EncapsulationIPIP,
					NATOutgoing:   operator.NATOutgoingEnabled,
					NodeSelector:  "anything()",
				},
			}
			err := validateCustomResource(instance)
			Expect(err).To(HaveOccurred())
		}, nonCalicoCNIEntries)
		DescribeTable("should not allow BGP", func(plugin operator.CNIPluginType, ipam operator.IPAMPluginType) {
			instance.Spec.CNI.Type = plugin
			instance.Spec.CNI.IPAM = &operator.IPAMSpec{Type: ipam}
			be := operator.BGPEnabled
			instance.Spec.CalicoNetwork.BGP = &be
			err := validateCustomResource(instance)
			Expect(err).NotTo(HaveOccurred())
		}, nonCalicoCNIEntries)
	})
	Describe("cross validate CNI.Type and kubernetesProvider", func() {
		BeforeEach(func() {
			instance.Spec.CalicoNetwork = nil
			instance.Spec.CNI = &operator.CNISpec{}
		})
		DescribeTable("test allowed plugins",
			func(kubeProvider operator.Provider, plugin operator.CNIPluginType, ipam operator.IPAMPluginType, success bool) {
				instance.Spec.KubernetesProvider = kubeProvider
				instance.Spec.CNI.Type = plugin
				instance.Spec.CNI.IPAM = &operator.IPAMSpec{Type: ipam}
				err := validateCustomResource(instance)
				if success {
					Expect(err).NotTo(HaveOccurred())
				} else {
					Expect(err).To(HaveOccurred())
				}
			},

			Entry("GKE plugin is not allowed on EKS", operator.ProviderEKS, operator.PluginGKE, operator.IPAMPluginHostLocal, false),
			Entry("AmazonVPC plugin is allowed on EKS", operator.ProviderEKS, operator.PluginAmazonVPC, operator.IPAMPluginAmazonVPC, true),
			Entry("AzureVNET plugin is not allowed on EKS", operator.ProviderEKS, operator.PluginAzureVNET, operator.IPAMPluginAzureVNET, false),
		)
	})
	Describe("validate ComponentResources", func() {
		It("should return nil when there are no ComponentResources to validate.", func() {
			Expect(validateCustomResource(instance)).To(BeNil())
		})

		It("should return nil when only supported ComponentNames are present.", func() {
			instance.Spec.ComponentResources = append(instance.Spec.ComponentResources, []operator.ComponentResource{
				{
					ComponentName: operator.ComponentNameTypha,
				},
				{
					ComponentName: operator.ComponentNameKubeControllers,
				},
				{
					ComponentName: operator.ComponentNameNode,
				},
			}...)
			Expect(validateCustomResource(instance)).To(BeNil())
		})

		It("should return an error when an invalid ComponentName is present", func() {
			instance.Spec.ComponentResources = append(instance.Spec.ComponentResources, operator.ComponentResource{
				ComponentName: "invalid-componentName",
			})
			Expect(validateCustomResource(instance)).ToNot(BeNil())
		})
	})

	Describe("validate CalicoNetwork LinuxPolicySetupTimeoutSeconds", func() {
		It("should return an error when LinuxPolicySetupTimeoutSeconds is negative", func() {
			negative := int32(-1)
			instance.Spec.CalicoNetwork.LinuxPolicySetupTimeoutSeconds = &negative
			err := validateCustomResource(instance)
			Expect(err).To(MatchError("spec.calicoNetwork.linuxPolicySetupTimeoutSeconds negative value is not valid"))
		})

		It("should return an error when LinuxPolicySetupTimeoutSeconds is set but no dataplane is specified", func() {
			tos := int32(10)
			instance.Spec.CalicoNetwork.LinuxPolicySetupTimeoutSeconds = &tos
			err := validateCustomResource(instance)
			Expect(err).To(MatchError("spec.calicoNetwork.linuxPolicySetupTimeoutSeconds requires the Iptables Linux dataplane to be set"))
		})

		It("should return an error when LinuxPolicySetupTimeoutSeconds is set for an unsupported dataplane", func() {
			dp := operator.LinuxDataplaneVPP
			// Enable BGP to pass VPP validation.
			bgp := operator.BGPEnabled
			tos := int32(10)
			instance.Spec.CalicoNetwork.LinuxDataplane = &dp
			instance.Spec.CalicoNetwork.LinuxPolicySetupTimeoutSeconds = &tos
			instance.Spec.CalicoNetwork.BGP = &bgp
			err := validateCustomResource(instance)
			Expect(err).To(MatchError("spec.calicoNetwork.linuxPolicySetupTimeoutSeconds is supported only for the Iptables, Nftables and BPF Linux dataplanes"))
		})

		It("should not error if LinuxPolicySetupTimeoutSeconds is set as a positive int32, with the Calico CNI plugin and Iptables dataplane", func() {
			tos := int32(10)
			cniType := operator.PluginCalico
			dp := operator.LinuxDataplaneIptables
			instance.Spec.CalicoNetwork.LinuxPolicySetupTimeoutSeconds = &tos
			instance.Spec.CNI.Type = cniType
			instance.Spec.CalicoNetwork.LinuxDataplane = &dp
		})
	})

	It("validate custom installation", func() {
		disabled := operator.BGPDisabled
		ipfw := operator.ContainerIPForwardingEnabled
		var twentyEight int32 = 28
		instance = &operator.Installation{
			Spec: operator.InstallationSpec{
				KubernetesProvider: operator.ProviderAKS,
				ImagePullSecrets:   []v1.LocalObjectReference{},
				CalicoNetwork: &operator.CalicoNetworkSpec{
					BGP:                   &disabled,
					ContainerIPForwarding: &ipfw,
					IPPools: []operator.IPPool{
						{
							CIDR:          "192.168.0.0/27",
							BlockSize:     &twentyEight,
							Encapsulation: operator.EncapsulationNone,
						},
					},
				},
				ServiceCIDRs: []string{"10.96.0.0/12"},
				CNI: &operator.CNISpec{
					Type: operator.PluginCalico,
					IPAM: &operator.IPAMSpec{Type: operator.IPAMPluginHostLocal},
				},
			},
		}
		// Populate the k8s service endpoint (required for windows)
		k8sapi.Endpoint = k8sapi.ServiceEndpoint{
			Host: "1.2.3.4",
			Port: "6443",
		}
		Expect(fillDefaults(instance, nil)).NotTo(HaveOccurred())
		err := validateCustomResource(instance)
		Expect(err).NotTo(HaveOccurred())
	})

	Describe("validate CalicoNodeDaemonSet", func() {
		It("should return nil when it is empty", func() {
			instance.Spec.CalicoNodeDaemonSet = &operator.CalicoNodeDaemonSet{}
			err := validateCustomResource(instance)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should return an error if it is invalid", func() {
			instance.Spec.CalicoNodeDaemonSet = &operator.CalicoNodeDaemonSet{
				Metadata: &operator.Metadata{
					Labels: map[string]string{
						"NoUppercaseOrSpecialCharsLike=Equals":    "b",
						"WowNoUppercaseOrSpecialCharsLike=Equals": "b",
					},
					Annotations: map[string]string{
						"AnnotNoUppercaseOrSpecialCharsLike=Equals": "bar",
					},
				},
			}
			err := validateCustomResource(instance)
			Expect(err).To(HaveOccurred())

			var invalidMinReadySeconds int32 = -1
			instance.Spec.CalicoNodeDaemonSet = &operator.CalicoNodeDaemonSet{
				Spec: &operator.CalicoNodeDaemonSetSpec{
					MinReadySeconds: &invalidMinReadySeconds,
				},
			}
			err = validateCustomResource(instance)
			Expect(err).To(HaveOccurred())

			instance.Spec.CalicoNodeDaemonSet = &operator.CalicoNodeDaemonSet{
				Spec: &operator.CalicoNodeDaemonSetSpec{
					Template: &operator.CalicoNodeDaemonSetPodTemplateSpec{
						Spec: &operator.CalicoNodeDaemonSetPodSpec{
							InitContainers: []operator.CalicoNodeDaemonSetInitContainer{
								{
									Name: "mount-bpffs",
									Resources: &v1.ResourceRequirements{
										Requests: v1.ResourceList{
											v1.ResourceCPU: resource.MustParse("100m"),
										},
									},
								},
								{
									Name: "ebpf-bootstrap",
									Resources: &v1.ResourceRequirements{
										Requests: v1.ResourceList{
											v1.ResourceMemory: resource.MustParse("100Mi"),
										},
									},
								},
							},
						},
					},
				},
			}
			err = validateCustomResource(instance)
			Expect(err).To(HaveOccurred())
		})
	})

	Describe("validate CalicoNodeWindowsDaemonSet", func() {
		It("should return nil when it is empty", func() {
			instance.Spec.CalicoNodeWindowsDaemonSet = &operator.CalicoNodeWindowsDaemonSet{}
			err := validateCustomResource(instance)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should return an error if it is invalid", func() {
			instance.Spec.CalicoNodeWindowsDaemonSet = &operator.CalicoNodeWindowsDaemonSet{
				Metadata: &operator.Metadata{
					Labels: map[string]string{
						"NoUppercaseOrSpecialCharsLike=Equals":    "b",
						"WowNoUppercaseOrSpecialCharsLike=Equals": "b",
					},
					Annotations: map[string]string{
						"AnnotNoUppercaseOrSpecialCharsLike=Equals": "bar",
					},
				},
			}
			err := validateCustomResource(instance)
			Expect(err).To(HaveOccurred())

			var invalidMinReadySeconds int32 = -1
			instance.Spec.CalicoNodeWindowsDaemonSet = &operator.CalicoNodeWindowsDaemonSet{
				Spec: &operator.CalicoNodeWindowsDaemonSetSpec{
					MinReadySeconds: &invalidMinReadySeconds,
				},
			}
			err = validateCustomResource(instance)
			Expect(err).To(HaveOccurred())
		})
	})

	Describe("validate CalicoKubeControllersDeployment", func() {
		It("should return nil when it is empty", func() {
			instance.Spec.CalicoKubeControllersDeployment = &operator.CalicoKubeControllersDeployment{}
			err := validateCustomResource(instance)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should return an error if it is invalid", func() {
			instance.Spec.CalicoKubeControllersDeployment = &operator.CalicoKubeControllersDeployment{
				Metadata: &operator.Metadata{
					Labels: map[string]string{
						"NoUppercaseOrSpecialCharsLike=Equals":    "b",
						"WowNoUppercaseOrSpecialCharsLike=Equals": "b",
					},
					Annotations: map[string]string{
						"AnnotNoUppercaseOrSpecialCharsLike=Equals": "bar",
					},
				},
			}
			err := validateCustomResource(instance)
			Expect(err).To(HaveOccurred())

			var invalidMinReadySeconds int32 = -1
			instance.Spec.CalicoKubeControllersDeployment = &operator.CalicoKubeControllersDeployment{
				Spec: &operator.CalicoKubeControllersDeploymentSpec{
					MinReadySeconds: &invalidMinReadySeconds,
				},
			}
			err = validateCustomResource(instance)
			Expect(err).To(HaveOccurred())
		})
	})

	Describe("validate TyphaDeployment", func() {
		It("should return nil when it is empty", func() {
			instance.Spec.TyphaDeployment = &operator.TyphaDeployment{}
			err := validateCustomResource(instance)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should return an error if it is invalid", func() {
			instance.Spec.TyphaDeployment = &operator.TyphaDeployment{
				Metadata: &operator.Metadata{
					Labels: map[string]string{
						"NoUppercaseOrSpecialCharsLike=Equals":    "b",
						"WowNoUppercaseOrSpecialCharsLike=Equals": "b",
					},
					Annotations: map[string]string{
						"AnnotNoUppercaseOrSpecialCharsLike=Equals": "bar",
					},
				},
			}
			err := validateCustomResource(instance)
			Expect(err).To(HaveOccurred())

			var invalidMinReadySeconds int32 = -1
			instance.Spec.TyphaDeployment = &operator.TyphaDeployment{
				Spec: &operator.TyphaDeploymentSpec{
					MinReadySeconds: &invalidMinReadySeconds,
				},
			}
			err = validateCustomResource(instance)
			Expect(err).To(HaveOccurred())
		})
	})
	Describe("validate Windows configuration", func() {
		BeforeEach(func() {
			winDpHNS := operator.WindowsDataplaneHNS
			instance.Spec.CalicoNetwork = &operator.CalicoNetworkSpec{
				WindowsDataplane: &winDpHNS,
			}
			instance.Spec.ServiceCIDRs = []string{"10.96.0.0/12"}
			var twentyEight int32 = 28
			instance.Spec.CalicoNetwork.IPPools = []operator.IPPool{
				{
					CIDR:          "192.168.0.0/16",
					BlockSize:     &twentyEight,
					Encapsulation: operator.EncapsulationVXLAN,
					NATOutgoing:   operator.NATOutgoingEnabled,
					NodeSelector:  "all()",
				},
			}
			instance.Spec.CalicoNetwork.BGP = ptr.To(operator.BGPDisabled)
			k8sapi.Endpoint = k8sapi.ServiceEndpoint{
				Host: "1.2.3.4",
				Port: "6443",
			}
		})
		Context("Windows disabled", func() {
			It("should return an error if WindowsNodes is configured but WindowsDataplane is disabled", func() {
				winDpDisabled := operator.WindowsDataplaneDisabled
				instance.Spec.CalicoNetwork.WindowsDataplane = &winDpDisabled
				instance.Spec.WindowsNodes = &operator.WindowsNodeSpec{}

				err := validateCustomResource(instance)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(Equal("installation spec.WindowsNodes is not valid and should not be provided when Calico for Windows is disabled"))
			})
		})
		Context("Calico CNI", func() {
			BeforeEach(func() {
				instance.Spec.CNI = &operator.CNISpec{
					Type: operator.PluginCalico,
					IPAM: &operator.IPAMSpec{Type: operator.IPAMPluginCalico},
				}
			})

			It("should return an error if the k8s service endpoint configmap is not configured correctly", func() {
				k8sapi.Endpoint = k8sapi.ServiceEndpoint{}
				err := validateCustomResource(instance)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(Equal("services endpoint configmap 'kubernetes-services-endpoint' does not have all required information for Calico Windows daemonset configuration"))
			})

			It("should return an error if instance.Spec.ServiceCIDRs is not configured", func() {
				instance.Spec.ServiceCIDRs = []string{}
				err := validateCustomResource(instance)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(Equal("installation spec.ServiceCIDRs must be provided when using Calico CNI on Windows"))
			})

			It("should return an error if IP pool encapsulation is IPIP", func() {
				instance.Spec.CalicoNetwork.IPPools[0].Encapsulation = operator.EncapsulationIPIP
				instance.Spec.CalicoNetwork.BGP = ptr.To(operator.BGPEnabled)
				err := validateCustomResource(instance)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(Equal("IPv4 IPPool encapsulation IPIP is not supported by Calico for Windows"))
			})

			It("should return an error if IP pool encapsulation is VXLANCrossSubnet", func() {
				instance.Spec.CalicoNetwork.IPPools[0].Encapsulation = operator.EncapsulationVXLANCrossSubnet
				err := validateCustomResource(instance)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(Equal("IPv4 IPPool encapsulation VXLANCrossSubnet is not supported by Calico for Windows"))
			})
		})
		Context("AzureVNET CNI (to validate any non-Calico)", func() {
			BeforeEach(func() {
				instance.Spec.CNI = &operator.CNISpec{
					Type: operator.PluginAzureVNET,
					IPAM: &operator.IPAMSpec{Type: operator.IPAMPluginAzureVNET},
				}
				instance.Spec.CalicoNetwork.IPPools[0].Encapsulation = operator.EncapsulationNone
			})

			It("should return an error if the k8s service endpoint configmap is not configured correctly", func() {
				k8sapi.Endpoint = k8sapi.ServiceEndpoint{}
				err := validateCustomResource(instance)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(Equal("services endpoint configmap 'kubernetes-services-endpoint' does not have all required information for Calico Windows daemonset configuration"))
			})

			It("should not return an error if instance.Spec.ServiceCIDRs is not configured", func() {
				instance.Spec.ServiceCIDRs = []string{}
				err := validateCustomResource(instance)
				Expect(err).ToNot(HaveOccurred())
			})
		})
	})
	Describe("validate CSIDaemonset", func() {
		It("should return nil when it is empty", func() {
			instance.Spec.CSINodeDriverDaemonSet = &operator.CSINodeDriverDaemonSet{}
			err := validateCustomResource(instance)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should return an error if it is invalid", func() {
			instance.Spec.CSINodeDriverDaemonSet = &operator.CSINodeDriverDaemonSet{
				Metadata: &operator.Metadata{
					Labels: map[string]string{
						"NoUppercaseOrSpecialCharsLike=Equals":    "b",
						"WowNoUppercaseOrSpecialCharsLike=Equals": "b",
					},
					Annotations: map[string]string{
						"AnnotNoUppercaseOrSpecialCharsLike=Equals": "bar",
					},
				},
			}
			err := validateCustomResource(instance)
			Expect(err).To(HaveOccurred(), "Should error because the labels and annotations are invalid")

			var invalidMinReadySeconds int32 = -1
			instance.Spec.CSINodeDriverDaemonSet = &operator.CSINodeDriverDaemonSet{
				Spec: &operator.CSINodeDriverDaemonSetSpec{
					MinReadySeconds: &invalidMinReadySeconds,
				},
			}
			Expect(err).To(HaveOccurred(), "Should error because the minReadySeconds is invalid")
		})

		It("should validate with container", func() {
			instance.Spec.CSINodeDriverDaemonSet = &operator.CSINodeDriverDaemonSet{
				Spec: &operator.CSINodeDriverDaemonSetSpec{
					Template: &operator.CSINodeDriverDaemonSetPodTemplateSpec{
						Spec: &operator.CSINodeDriverDaemonSetPodSpec{
							Containers: []operator.CSINodeDriverDaemonSetContainer{
								{
									Name: "csi-node-driver",
									Resources: &v1.ResourceRequirements{
										Limits: v1.ResourceList{
											"cpu": resource.MustParse("2"),
										},
									},
								},
							},
						},
					},
				},
			}
			Expect(validateCustomResource(instance)).NotTo(HaveOccurred())
		})
	})

	Describe("validate CSINodeDriverDaemonSet", func() {
		It("should return nil when it is empty", func() {
			instance.Spec.CSINodeDriverDaemonSet = &operator.CSINodeDriverDaemonSet{}
			err := validateCustomResource(instance)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should return an error if it is invalid", func() {
			instance.Spec.CSINodeDriverDaemonSet = &operator.CSINodeDriverDaemonSet{
				Metadata: &operator.Metadata{
					Labels: map[string]string{
						"NoUppercaseOrSpecialCharsLike=Equals":    "b",
						"WowNoUppercaseOrSpecialCharsLike=Equals": "b",
					},
					Annotations: map[string]string{
						"AnnotNoUppercaseOrSpecialCharsLike=Equals": "bar",
					},
				},
			}
			err := validateCustomResource(instance)
			Expect(err).To(HaveOccurred())

			var invalidMinReadySeconds int32 = -1
			instance.Spec.CSINodeDriverDaemonSet = &operator.CSINodeDriverDaemonSet{
				Spec: &operator.CSINodeDriverDaemonSetSpec{
					MinReadySeconds: &invalidMinReadySeconds,
				},
			}
			err = validateCustomResource(instance)
			Expect(err).To(HaveOccurred())
		})

		It("should return nil when resource requirements are set", func() {
			instance.Spec.CSINodeDriverDaemonSet = &operator.CSINodeDriverDaemonSet{
				Spec: &operator.CSINodeDriverDaemonSetSpec{
					Template: &operator.CSINodeDriverDaemonSetPodTemplateSpec{
						Spec: &operator.CSINodeDriverDaemonSetPodSpec{
							Containers: []operator.CSINodeDriverDaemonSetContainer{
								{
									Name:      render.CSIContainerName,
									Resources: &v1.ResourceRequirements{Requests: v1.ResourceList{"cpu": resource.MustParse("1")}},
								},
							},
						},
					},
				},
			}
			err := validateCustomResource(instance)
			Expect(err).NotTo(HaveOccurred())
		})
	})
	Describe("validate FIPSMode", func() {
		DescribeTable("test that FIPSMode=Enabled is rejected since FIPS mode has been removed",
			func(variant operator.ProductVariant, fipsMode operator.FIPSMode, expectErr bool) {
				instance.Spec.Variant = variant
				instance.Spec.FIPSMode = &fipsMode
				err := validateCustomResource(instance)
				if expectErr {
					Expect(err).To(HaveOccurred())
				} else {
					Expect(err).NotTo(HaveOccurred())
				}
			},

			Entry("Product: Calico FipsMode: Disabled", operator.Calico, operator.FIPSModeDisabled, false),
			Entry("Product: Calico FipsMode: Enabled", operator.Calico, operator.FIPSModeEnabled, true),
			Entry("Product: CalicoEnterprise FipsMode: Disabled", operator.CalicoEnterprise, operator.FIPSModeDisabled, false),
			Entry("Product: CalicoEnterprise FipsMode: Enabled", operator.CalicoEnterprise, operator.FIPSModeEnabled, true),
		)
	})
})
