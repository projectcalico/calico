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
	"strings"

	"k8s.io/apimachinery/pkg/api/resource"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operator "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/components"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

var _ = Describe("Defaulting logic tests", func() {
	It("should properly fill defaults on an empty instance", func() {
		// IP pools are defaulted by the IP pool controller, and passed in as input to the defaulting
		// performed in the Installation controller. For the purposes of this test,
		// define them here.
		currentPools := v3.IPPoolList{
			Items: []v3.IPPool{
				{
					Spec: v3.IPPoolSpec{CIDR: "192.168.0.0/16"},
				},
			},
		}

		instance := &operator.Installation{}
		err := fillDefaults(instance, &currentPools)
		Expect(err).NotTo(HaveOccurred())

		// The resulting resource should pass validation.
		Expect(validateCustomResource(instance)).NotTo(HaveOccurred())

		// Assert the correct defaults were set.
		Expect(instance.Spec.Variant).To(Equal(operator.Calico))
		Expect(instance.Spec.Registry).To(BeEmpty())
		Expect(instance.Spec.CNI.Type).To(Equal(operator.PluginCalico))
		Expect(instance.Spec.CalicoNetwork).NotTo(BeNil())
		Expect(instance.Spec.CalicoNetwork.LinuxDataplane).ToNot(BeNil())
		Expect(*instance.Spec.CalicoNetwork.LinuxDataplane).To(Equal(operator.LinuxDataplaneIptables))
		Expect(instance.Spec.CalicoNetwork.WindowsDataplane).ToNot(BeNil())
		Expect(*instance.Spec.CalicoNetwork.WindowsDataplane).To(Equal(operator.WindowsDataplaneDisabled))
		Expect(*instance.Spec.CalicoNetwork.BGP).To(Equal(operator.BGPEnabled))
		Expect(*instance.Spec.CalicoNetwork.LinuxPolicySetupTimeoutSeconds).To(BeZero())
		Expect(*instance.Spec.ControlPlaneReplicas).To(Equal(int32(2)))
		Expect(instance.Spec.KubeletVolumePluginPath).To(Equal(filepath.Clean("/var/lib/kubelet")))
		Expect(*instance.Spec.Logging.CNI.LogSeverity).To(Equal(operator.LogLevelInfo))
		Expect(*instance.Spec.Logging.CNI.LogFileMaxCount).To(Equal(uint32(10)))
		Expect(*instance.Spec.Logging.CNI.LogFileMaxAgeDays).To(Equal(uint32(30)))
		Expect(*instance.Spec.Logging.CNI.LogFileMaxSize).To(Equal(resource.MustParse("100Mi")))
	})

	It("should properly fill defaults on an empty CalicoEnterprise instance", func() {
		// IP pools are defaulted by the IP pool controller, and passed in as input to the defaulting
		// performed in the Installation controller. For the purposes of this test,
		// define them here.
		currentPools := v3.IPPoolList{
			Items: []v3.IPPool{
				{
					Spec: v3.IPPoolSpec{CIDR: "192.168.0.0/16"},
				},
			},
		}

		instance := &operator.Installation{}
		instance.Spec.Variant = operator.CalicoEnterprise
		err := fillDefaults(instance, &currentPools)
		Expect(err).NotTo(HaveOccurred())

		Expect(validateCustomResource(instance)).NotTo(HaveOccurred())
		Expect(instance.Spec.Variant).To(Equal(operator.CalicoEnterprise))
		Expect(instance.Spec.Registry).To(BeEmpty())
		Expect(instance.Spec.CalicoNetwork).NotTo(BeNil())
		Expect(instance.Spec.CalicoNetwork.LinuxDataplane).ToNot(BeNil())
		Expect(*instance.Spec.CalicoNetwork.LinuxDataplane).To(Equal(operator.LinuxDataplaneIptables))
		Expect(instance.Spec.CalicoNetwork.WindowsDataplane).ToNot(BeNil())
		Expect(*instance.Spec.CalicoNetwork.WindowsDataplane).To(Equal(operator.WindowsDataplaneDisabled))
		Expect(*instance.Spec.CalicoNetwork.BGP).To(Equal(operator.BGPEnabled))
		Expect(*instance.Spec.CalicoNetwork.LinuxPolicySetupTimeoutSeconds).To(BeZero())
		Expect(*instance.Spec.ControlPlaneReplicas).To(Equal(int32(2)))
		Expect(instance.Spec.KubeletVolumePluginPath).To(Equal(filepath.Clean("/var/lib/kubelet")))
	})

	It("should not override custom configuration", func() {
		var mtu int32 = 1500
		var nodeMetricsPort int32 = 9081
		false_ := false
		var twentySeven int32 = 27
		var oneTwoThree int32 = 123
		one := intstr.FromInt(1)
		var replicas int32 = 3
		var logFileMaxCount uint32 = 5
		var logFileMaxAgeDays uint32 = 10
		logFileMaxSize := resource.MustParse("50Mi")
		logSeverity := operator.LogLevelError
		var linuxPolicySetupTimeoutSeconds int32 = 1
		cniBinDir := "/opt/custom/cni/bin"
		cniSpecVersion := operator.CNISpecVersion100
		cniConfDir := "/etc/custom/cni/net.d"
		cniInstallMode := operator.CNIInstallModeAll

		hpEnabled := operator.HostPortsEnabled
		disabled := operator.BGPDisabled
		miMode := operator.MultiInterfaceModeNone
		dpIptables := operator.LinuxDataplaneIptables
		winDataplaneDisabled := operator.WindowsDataplaneDisabled
		instance := &operator.Installation{
			Spec: operator.InstallationSpec{
				Variant:  operator.Calico,
				Registry: "test-reg/",
				ImagePullSecrets: []v1.LocalObjectReference{
					{
						Name: "pullSecret1",
					},
					{
						Name: "pullSecret2",
					},
				},
				CNI: &operator.CNISpec{
					Type:        operator.PluginCalico,
					IPAM:        &operator.IPAMSpec{Type: operator.IPAMPluginCalico},
					BinDir:      &cniBinDir,
					ConfDir:     &cniConfDir,
					InstallMode: &cniInstallMode,
					SpecVersion: &cniSpecVersion,
				},
				CalicoNetwork: &operator.CalicoNetworkSpec{
					LinuxDataplane:   &dpIptables, // Actually the default but BPF would make other values invalid.
					WindowsDataplane: &winDataplaneDisabled,
					IPPools: []operator.IPPool{
						{
							CIDR:          "1.2.3.0/24",
							Encapsulation: "VXLANCrossSubnet",
							NATOutgoing:   "Enabled",
							NodeSelector:  "has(thiskey)",
							BlockSize:     &twentySeven,
						},
						{
							CIDR:          "fd00::0/64",
							Encapsulation: "VXLAN",
							NATOutgoing:   "Enabled",
							NodeSelector:  "has(thiskey)",
							BlockSize:     &oneTwoThree,
						},
					},
					MTU: &mtu,
					BGP: &disabled,
					NodeAddressAutodetectionV4: &operator.NodeAddressAutodetection{
						FirstFound: &false_,
					},
					NodeAddressAutodetectionV6: &operator.NodeAddressAutodetection{
						FirstFound: &false_,
					},
					HostPorts:                      &hpEnabled,
					MultiInterfaceMode:             &miMode,
					LinuxPolicySetupTimeoutSeconds: &linuxPolicySetupTimeoutSeconds,
				},
				ControlPlaneReplicas: &replicas,
				NodeMetricsPort:      &nodeMetricsPort,
				FlexVolumePath:       "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/",
				NodeUpdateStrategy: appsv1.DaemonSetUpdateStrategy{
					Type: appsv1.RollingUpdateDaemonSetStrategyType,
					RollingUpdate: &appsv1.RollingUpdateDaemonSet{
						MaxUnavailable: &one,
					},
				},
				KubeletVolumePluginPath: "/my/kubelet/root/dir",
				Logging: &operator.Logging{
					CNI: &operator.CNILogging{
						LogSeverity:       &logSeverity,
						LogFileMaxSize:    &logFileMaxSize,
						LogFileMaxAgeDays: &logFileMaxAgeDays,
						LogFileMaxCount:   &logFileMaxCount,
					},
				},
			},
		}
		instanceCopy := instance.DeepCopyObject().(*operator.Installation)
		err := fillDefaults(instanceCopy, nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(instanceCopy.Spec).To(Equal(instance.Spec))
		Expect(validateCustomResource(instance)).NotTo(HaveOccurred())
	})

	It("should not override custom configuration (BPF)", func() {
		var mtu int32 = 1500
		var nodeMetricsPort int32 = 9081
		false_ := false
		var twentySeven int32 = 27
		one := intstr.FromInt(1)
		var replicas int32 = 3
		var logFileMaxCount uint32 = 5
		var logFileMaxAgeDays uint32 = 10
		logFileMaxSize := resource.MustParse("50Mi")
		logSeverity := operator.LogLevelError
		cniBinDir := "/opt/custom/cni/bin"
		cniSpecVersion := operator.CNISpecVersion100
		cniConfDir := "/etc/custom/cni/net.d"
		cniInstallMode := operator.CNIInstallModeAll

		disabled := operator.BGPDisabled
		miMode := operator.MultiInterfaceModeNone
		dpBPF := operator.LinuxDataplaneBPF
		winDataplaneDisabled := operator.WindowsDataplaneDisabled
		hpEnabled := operator.HostPortsEnabled
		instance := &operator.Installation{
			Spec: operator.InstallationSpec{
				Variant:  operator.CalicoEnterprise,
				Registry: "test-reg/",
				ImagePullSecrets: []v1.LocalObjectReference{
					{
						Name: "pullSecret1",
					},
					{
						Name: "pullSecret2",
					},
				},
				CNI: &operator.CNISpec{
					Type:        operator.PluginCalico,
					IPAM:        &operator.IPAMSpec{Type: operator.IPAMPluginCalico},
					BinDir:      &cniBinDir,
					ConfDir:     &cniConfDir,
					InstallMode: &cniInstallMode,
					SpecVersion: &cniSpecVersion,
				},
				CalicoNetwork: &operator.CalicoNetworkSpec{
					LinuxDataplane:   &dpBPF, // Actually the default but BPF would make other values invalid.
					WindowsDataplane: &winDataplaneDisabled,
					IPPools: []operator.IPPool{
						{
							CIDR:          "1.2.3.0/24",
							Encapsulation: "VXLANCrossSubnet",
							NATOutgoing:   "Enabled",
							NodeSelector:  "has(thiskey)",
							BlockSize:     &twentySeven,
						},
					},
					MTU: &mtu,
					BGP: &disabled,
					NodeAddressAutodetectionV4: &operator.NodeAddressAutodetection{
						FirstFound: &false_,
					},
					MultiInterfaceMode: &miMode,
					HostPorts:          &hpEnabled,
				},
				ControlPlaneReplicas: &replicas,
				NodeMetricsPort:      &nodeMetricsPort,
				FlexVolumePath:       "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/",
				NodeUpdateStrategy: appsv1.DaemonSetUpdateStrategy{
					Type: appsv1.RollingUpdateDaemonSetStrategyType,
					RollingUpdate: &appsv1.RollingUpdateDaemonSet{
						MaxUnavailable: &one,
					},
				},
				KubeletVolumePluginPath: "/my/kubelet/root/dir",
				Logging: &operator.Logging{
					CNI: &operator.CNILogging{
						LogSeverity:       &logSeverity,
						LogFileMaxSize:    &logFileMaxSize,
						LogFileMaxAgeDays: &logFileMaxAgeDays,
						LogFileMaxCount:   &logFileMaxCount,
					},
				},
			},
		}
		instanceCopy := instance.DeepCopyObject().(*operator.Installation)
		err := fillDefaults(instanceCopy, nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(instanceCopy.Spec).To(Equal(instance.Spec))
		Expect(validateCustomResource(instance)).NotTo(HaveOccurred())
	})

	It("should allow for zero IP pools to be specified", func() {
		instance := &operator.Installation{
			Spec: operator.InstallationSpec{
				CNI: &operator.CNISpec{
					Type: operator.PluginCalico,
				},
				CalicoNetwork: &operator.CalicoNetworkSpec{
					IPPools: []operator.IPPool{},
				},
			},
		}
		err := fillDefaults(instance, nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(len(instance.Spec.CalicoNetwork.IPPools)).To(Equal(0))
		Expect(validateCustomResource(instance)).NotTo(HaveOccurred())
	})

	It("should default BGP to enabled for Calico CNI", func() {
		instance := &operator.Installation{
			Spec: operator.InstallationSpec{
				CNI: &operator.CNISpec{
					Type: operator.PluginCalico,
				},
			},
		}
		err := fillDefaults(instance, nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(*instance.Spec.CalicoNetwork.BGP).To(Equal(operator.BGPEnabled))
		Expect(validateCustomResource(instance)).NotTo(HaveOccurred())
	})

	It("should default CNI spec version to Auto for Calico CNI", func() {
		instance := &operator.Installation{
			Spec: operator.InstallationSpec{
				CNI: &operator.CNISpec{
					Type: operator.PluginCalico,
				},
			},
		}
		err := fillDefaults(instance, nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(instance.Spec.CNI.SpecVersion).NotTo(BeNil())
		Expect(*instance.Spec.CNI.SpecVersion).To(Equal(operator.CNISpecVersionAuto))
		Expect(validateCustomResource(instance)).NotTo(HaveOccurred())
	})

	It("should not set CNI spec version for other CNI plugins", func() {
		instance := &operator.Installation{
			Spec: operator.InstallationSpec{
				CNI: &operator.CNISpec{
					Type: operator.PluginAmazonVPC,
				},
				CalicoNetwork: &operator.CalicoNetworkSpec{},
			},
		}
		err := fillDefaults(instance, nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(instance.Spec.CNI.SpecVersion).To(BeNil())
		Expect(validateCustomResource(instance)).NotTo(HaveOccurred())
	})

	It("should default BGP to disabled for other CNI plugins", func() {
		instance := &operator.Installation{
			Spec: operator.InstallationSpec{
				CNI: &operator.CNISpec{
					Type: operator.PluginAmazonVPC,
				},
				CalicoNetwork: &operator.CalicoNetworkSpec{},
			},
		}
		err := fillDefaults(instance, nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(*instance.Spec.CalicoNetwork.BGP).To(Equal(operator.BGPDisabled))

		Expect(validateCustomResource(instance)).NotTo(HaveOccurred())
	})

	It("should not change user provided registry", func() {
		// Older versions of the operator would update the registry such that it would always
		// end with a slash. This test ensures that we do not change the user provided registry.
		instance := &operator.Installation{
			Spec: operator.InstallationSpec{
				Registry: "test-reg",
			},
		}
		err := fillDefaults(instance, nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(instance.Spec.Registry).To(Equal("test-reg"))
		Expect(validateCustomResource(instance)).NotTo(HaveOccurred())

		// "UseDefault" should not be modified.
		instance.Spec.Registry = components.UseDefault
		err = fillDefaults(instance, nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(instance.Spec.Registry).To(Equal(components.UseDefault))
		Expect(validateCustomResource(instance)).NotTo(HaveOccurred())
	})

	It("should properly fill defaults for an IPv6-only instance", func() {
		instance := &operator.Installation{
			Spec: operator.InstallationSpec{
				CalicoNetwork: &operator.CalicoNetworkSpec{
					IPPools: []operator.IPPool{{
						CIDR:          "fd00::0/64",
						Encapsulation: operator.EncapsulationNone,
					}},
				},
			},
		}
		err := fillDefaults(instance, nil)
		Expect(err).NotTo(HaveOccurred())
		Expect(validateCustomResource(instance)).NotTo(HaveOccurred())
	})

	It("should properly fill defaults for an IPv6-only instance with existing IPv6 pool", func() {
		instance := &operator.Installation{
			Spec: operator.InstallationSpec{
				CalicoNetwork: &operator.CalicoNetworkSpec{},
			},
		}
		currentPools := v3.IPPoolList{
			Items: []v3.IPPool{
				{
					Spec: v3.IPPoolSpec{CIDR: "fd00::0/64"},
				},
			},
		}
		err := fillDefaults(instance, &currentPools)
		Expect(err).NotTo(HaveOccurred())
		Expect(validateCustomResource(instance)).NotTo(HaveOccurred())
	})

	DescribeTable("Test different values for FlexVolumePath",
		func(i *operator.Installation, expectedFlexVolumePath string) {
			Expect(fillDefaults(i, nil)).To(BeNil())
			Expect(i.Spec.FlexVolumePath).To(Equal(expectedFlexVolumePath))
		},

		Entry("FlexVolumePath set to None",
			&operator.Installation{
				Spec: operator.InstallationSpec{
					FlexVolumePath: "None",
				},
			}, "None",
		),

		Entry("FlexVolumePath left empty (default)",
			&operator.Installation{
				Spec: operator.InstallationSpec{},
			}, "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/",
		),

		Entry("FlexVolumePath set to a custom path",
			&operator.Installation{
				Spec: operator.InstallationSpec{
					FlexVolumePath: "/foo/bar/",
				},
			}, "/foo/bar/",
		),
	)

	DescribeTable("Test different values for KubeletVolumePluginPath",
		func(i *operator.Installation, expectedKubeletVolumePluginPath string) {
			Expect(fillDefaults(i, nil)).To(BeNil())
			Expect(i.Spec.KubeletVolumePluginPath).To(Equal(expectedKubeletVolumePluginPath))
		},

		Entry("KubeletVolumePluginPath set to None",
			&operator.Installation{
				Spec: operator.InstallationSpec{
					KubeletVolumePluginPath: "None",
				},
			}, "None",
		),

		Entry("KubeletVolumePluginPath left empty (default)",
			&operator.Installation{
				Spec: operator.InstallationSpec{},
			}, filepath.Clean("/var/lib/kubelet"),
		),

		Entry("KubeletVolumePluginPath set to a custom path",
			&operator.Installation{
				Spec: operator.InstallationSpec{
					KubeletVolumePluginPath: "/foo/bar/",
				},
			}, "/foo/bar/",
		),
	)

	It("should default an empty CNI to Calico with no KubernetesProvider", func() {
		instance := &operator.Installation{
			Spec: operator.InstallationSpec{
				CNI: &operator.CNISpec{},
			},
		}
		Expect(fillDefaults(instance, nil)).NotTo(HaveOccurred())
		Expect(instance.Spec.CNI.Type).To(Equal(operator.PluginCalico))
		Expect(validateCustomResource(instance)).NotTo(HaveOccurred())
	})

	It("should set default values for CNILogging if CNI is set to Calico", func() {
		instance := &operator.Installation{
			Spec: operator.InstallationSpec{
				CNI: &operator.CNISpec{},
			},
		}
		Expect(fillDefaults(instance, nil)).NotTo(HaveOccurred())
		Expect(*instance.Spec.Logging.CNI.LogSeverity).To(Equal(operator.LogLevelInfo))
		Expect(*instance.Spec.Logging.CNI.LogFileMaxCount).To(Equal(uint32(10)))
		Expect(*instance.Spec.Logging.CNI.LogFileMaxAgeDays).To(Equal(uint32(30)))
		Expect(*instance.Spec.Logging.CNI.LogFileMaxSize).To(Equal(resource.MustParse("100Mi")))
		Expect(validateCustomResource(instance)).NotTo(HaveOccurred())
	})

	DescribeTable("should default CNI type based on KubernetesProvider for hosted providers",
		func(provider operator.Provider, plugin operator.CNIPluginType) {
			instance := &operator.Installation{
				Spec: operator.InstallationSpec{KubernetesProvider: provider},
			}
			Expect(fillDefaults(instance, nil)).NotTo(HaveOccurred())
			Expect(instance.Spec.CNI.Type).To(Equal(plugin))
			iptables := operator.LinuxDataplaneIptables
			winDataplane := operator.WindowsDataplaneDisabled
			bgpDisabled := operator.BGPDisabled
			Expect(instance.Spec.CalicoNetwork).To(Equal(&operator.CalicoNetworkSpec{
				LinuxDataplane:   &iptables,
				WindowsDataplane: &winDataplane,
				BGP:              &bgpDisabled,
			}))
			Expect(validateCustomResource(instance)).NotTo(HaveOccurred())
		},

		Entry("EKS provider defaults to AmazonVPC plugin", operator.ProviderEKS, operator.PluginAmazonVPC),
		Entry("GKE provider defaults to GKE plugin", operator.ProviderGKE, operator.PluginGKE),
		Entry("AKS provider defaults to AzureVNET plugin", operator.ProviderAKS, operator.PluginAzureVNET),
	)

	DescribeTable("setting non-Calico CNI Plugin should default CalicoNetwork to nil",
		func(plugin operator.CNIPluginType) {
			instance := &operator.Installation{
				Spec: operator.InstallationSpec{
					CNI: &operator.CNISpec{Type: plugin},
				},
			}
			Expect(fillDefaults(instance, nil)).NotTo(HaveOccurred())
			Expect(instance.Spec.CNI.Type).To(Equal(plugin))
			iptables := operator.LinuxDataplaneIptables
			winDataplane := operator.WindowsDataplaneDisabled
			bgpDisabled := operator.BGPDisabled
			Expect(instance.Spec.CalicoNetwork).To(Equal(&operator.CalicoNetworkSpec{
				LinuxDataplane:   &iptables,
				WindowsDataplane: &winDataplane,
				BGP:              &bgpDisabled,
			}))
			Expect(validateCustomResource(instance)).NotTo(HaveOccurred())
		},

		Entry("AmazonVPC plugin", operator.PluginAmazonVPC),
		Entry("GKE plugin", operator.PluginGKE),
		Entry("AzureVNET plugin", operator.PluginAzureVNET),
	)

	// Tests for Calico Networking on EKS should go in this context.
	Context("with Calico Networking on EKS", func() {
		It("should default properly", func() {
			instance := &operator.Installation{
				Spec: operator.InstallationSpec{
					KubernetesProvider: operator.ProviderEKS,
					CNI: &operator.CNISpec{
						Type: operator.PluginCalico,
					},
				},
			}
			err := fillDefaults(instance, nil)
			Expect(err).NotTo(HaveOccurred())
			Expect(*instance.Spec.CalicoNetwork.BGP).To(Equal(operator.BGPDisabled))
			Expect(validateCustomResource(instance)).NotTo(HaveOccurred())
		})
	})

	Context("updateInstallationForAWSNode", func() {
		It("should set the CNI to AmazonVPC", func() {
			instance := &operator.Installation{
				Spec: operator.InstallationSpec{
					CNI: &operator.CNISpec{},
				},
			}
			err := updateInstallationForAWSNode(instance, &appsv1.DaemonSet{})
			Expect(err).NotTo(HaveOccurred())
			Expect(instance.Spec.CNI.Type).To(Equal(operator.PluginAmazonVPC))
		})
	})

	Context("with AmazonVPC CNI", func() {
		It("should default properly with no calicoNetwork specified", func() {
			instance := &operator.Installation{
				Spec: operator.InstallationSpec{
					KubernetesProvider: operator.ProviderEKS,
					CNI: &operator.CNISpec{
						Type: operator.PluginAmazonVPC,
					},
				},
			}
			err := fillDefaults(instance, nil)
			Expect(err).NotTo(HaveOccurred())
			iptables := operator.LinuxDataplaneIptables
			winDataplane := operator.WindowsDataplaneDisabled
			bgpDisabled := operator.BGPDisabled
			Expect(instance.Spec.CalicoNetwork).To(Equal(&operator.CalicoNetworkSpec{
				LinuxDataplane:   &iptables,
				WindowsDataplane: &winDataplane,
				BGP:              &bgpDisabled,
			}))
			Expect(validateCustomResource(instance)).NotTo(HaveOccurred())
		})

		It("should default properly with iptables explicitly enabled", func() {
			dpIpt := operator.LinuxDataplaneIptables
			winDataplane := operator.WindowsDataplaneDisabled
			instance := &operator.Installation{
				Spec: operator.InstallationSpec{
					KubernetesProvider: operator.ProviderEKS,
					CalicoNetwork: &operator.CalicoNetworkSpec{
						LinuxDataplane:   &dpIpt,
						WindowsDataplane: &winDataplane,
					},
					CNI: &operator.CNISpec{
						Type: operator.PluginAmazonVPC,
					},
				},
			}
			err := fillDefaults(instance, nil)
			Expect(err).NotTo(HaveOccurred())
			Expect(*instance.Spec.CalicoNetwork.BGP).To(Equal(operator.BGPDisabled))
			Expect(instance.Spec.CalicoNetwork.IPPools).To(BeEmpty())
			Expect(instance.Spec.CalicoNetwork.NodeAddressAutodetectionV4).To(BeNil())
			Expect(validateCustomResource(instance)).NotTo(HaveOccurred())
		})

		It("should default properly with BPF enabled", func() {
			dpBPF := operator.LinuxDataplaneBPF
			winDataplane := operator.WindowsDataplaneDisabled
			instance := &operator.Installation{
				Spec: operator.InstallationSpec{
					KubernetesProvider: operator.ProviderEKS,
					CalicoNetwork: &operator.CalicoNetworkSpec{
						LinuxDataplane:   &dpBPF,
						WindowsDataplane: &winDataplane,
					},
					CNI: &operator.CNISpec{
						Type: operator.PluginAmazonVPC,
					},
				},
			}
			err := fillDefaults(instance, nil)
			Expect(err).NotTo(HaveOccurred())
			Expect(*instance.Spec.CalicoNetwork.BGP).To(Equal(operator.BGPDisabled))
			Expect(instance.Spec.CalicoNetwork.IPPools).To(BeEmpty())
			Expect(instance.Spec.CalicoNetwork.NodeAddressAutodetectionV4).To(Equal(&operator.NodeAddressAutodetection{
				CanReach: "8.8.8.8",
			}))
			Expect(validateCustomResource(instance)).NotTo(HaveOccurred())
		})
	})

	DescribeTable("should default IPAM type based on CNI type",
		func(cni operator.CNIPluginType, ipam operator.IPAMPluginType) {
			instance := &operator.Installation{
				Spec: operator.InstallationSpec{
					CNI: &operator.CNISpec{Type: cni},
				},
			}
			Expect(fillDefaults(instance, nil)).NotTo(HaveOccurred())
			Expect(instance.Spec.CNI.IPAM.Type).To(Equal(ipam))
		},

		Entry("AmazonVPC CNI defaults to AmazonVPC IPAM", operator.PluginAmazonVPC, operator.IPAMPluginAmazonVPC),
		Entry("GKE CNI defaults to HostLocal IPAM", operator.PluginGKE, operator.IPAMPluginHostLocal),
		Entry("AzureVNET CNI defaults to AzureVNET IPAM", operator.PluginAzureVNET, operator.IPAMPluginAzureVNET),
		Entry("Calico CNI defaults to Calico IPAM", operator.PluginCalico, operator.IPAMPluginCalico),
	)

	// This test verifies that we properly fill out defaults in the Installation based on the discovered IP pools
	// in the cluster. The input - currentPools - represents the IP pools that we have discovered from the cluster's API server,
	// and may have been provisioned either by the user directly, or via the IP pool controller in this operator.
	DescribeTable("should handle various pool configurations",
		func(currentPools []v3.IPPool) {
			instance := &operator.Installation{}
			Expect(fillDefaults(instance, &v3.IPPoolList{Items: currentPools})).NotTo(HaveOccurred())

			// The resulting instance should be valid.
			Expect(validateCustomResource(instance)).NotTo(HaveOccurred())

			// We should properly set fields based on the IP pools we were given.
			// If we were given an IPv4 pool, we expect IPv4 fields to be filled.
			// If we were given an IPv6 pool, we expect IPv6 fields to be filled.
			var v4, v6 bool
			for _, p := range currentPools {
				if strings.Contains(p.Spec.CIDR, ":") {
					v6 = true
				} else {
					v4 = true
				}
			}

			if v4 {
				Expect(*instance.Spec.CalicoNetwork.NodeAddressAutodetectionV4.FirstFound).To(Equal(true))
			} else {
				Expect(instance.Spec.CalicoNetwork.NodeAddressAutodetectionV4).To(BeNil())
			}
			if v6 {
				Expect(*instance.Spec.CalicoNetwork.NodeAddressAutodetectionV6.FirstFound).To(Equal(true))
			} else {
				Expect(instance.Spec.CalicoNetwork.NodeAddressAutodetectionV6).To(BeNil())
			}
		},

		Entry("one IPv4 pool", []v3.IPPool{{Spec: v3.IPPoolSpec{CIDR: "192.168.0.0/16"}}}),
		Entry("one IPv6 pool", []v3.IPPool{{Spec: v3.IPPoolSpec{CIDR: "fd80:24e2:f998:72d6::/64"}}}),
		Entry("two IPv6 pools", []v3.IPPool{
			{Spec: v3.IPPoolSpec{CIDR: "fd80:24e2:f998:72d6::/64"}},
			{Spec: v3.IPPoolSpec{CIDR: "feed:beef:72e5:a94b::/64"}},
		}),
		Entry("two IPv4 pools", []v3.IPPool{
			{Spec: v3.IPPoolSpec{CIDR: "192.168.0.0/16"}},
			{Spec: v3.IPPoolSpec{CIDR: "172.168.0.0/16"}},
		}),
		Entry("dual-spec", []v3.IPPool{
			{Spec: v3.IPPoolSpec{CIDR: "192.168.0.0/16"}},
			{Spec: v3.IPPoolSpec{CIDR: "172.168.0.0/16"}},
			{Spec: v3.IPPoolSpec{CIDR: "fd80:24e2:f998:72d6::/64"}},
			{Spec: v3.IPPoolSpec{CIDR: "feed:beef:72e5:a94b::/64"}},
		}),
	)
})
