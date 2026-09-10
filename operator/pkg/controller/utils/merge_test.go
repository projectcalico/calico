// Copyright (c) 2020-2026 Tigera, Inc. All rights reserved.

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

package utils

import (
	"fmt"
	"reflect"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	diff "github.com/r3labs/diff/v2"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"

	opv1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/test"
)

func intPtr(i int32) *int32 { return &i }

var (
	enabled  = opv1.NetworkPolicyManagementEnabled
	disabled = opv1.NetworkPolicyManagementDisabled
)

func npSpec(m *opv1.NetworkPolicyManagement) *opv1.NetworkPolicySpec {
	return &opv1.NetworkPolicySpec{ManagePolicies: m}
}

var _ = Describe("Installation merge tests", func() {
	DescribeTable("merge Variant", func(main, second, expectVariant *opv1.ProductVariant) {
		m := opv1.InstallationSpec{}
		s := opv1.InstallationSpec{}
		if main != nil {
			m.Variant = *main
		}
		if second != nil {
			s.Variant = *second
		}
		inst := OverrideInstallationSpec(m, s)
		if expectVariant == nil {
			var x opv1.ProductVariant
			Expect(inst.Variant).To(Equal(x))
		} else {
			Expect(inst.Variant).To(Equal(*expectVariant))
		}
	},
		Entry("Both unset", nil, nil, nil),
		Entry("Main only set", &opv1.Calico, nil, &opv1.Calico),
		Entry("Second only set", nil, &opv1.Calico, &opv1.Calico),
		Entry("Both set equal", &opv1.Calico, &opv1.Calico, &opv1.Calico),
		Entry("Both set not matching", &opv1.Calico, &opv1.CalicoEnterprise, &opv1.CalicoEnterprise),
	)

	DescribeTable("merge Registry", func(main, second, expect string) {
		m := opv1.InstallationSpec{}
		s := opv1.InstallationSpec{}
		if main != "" {
			m.Registry = main
		}
		if second != "" {
			s.Registry = second
		}
		inst := OverrideInstallationSpec(m, s)
		Expect(inst.Registry).To(Equal(expect))
	},
		Entry("Both unset", nil, nil, nil),
		Entry("Main only set", "private.registry.com", nil, "private.registry.com"),
		Entry("Second only set", nil, "private.registry.com", "private.registry.com"),
		Entry("Both set equal", "private.registry.com", "private.registry.com", "private.registry.com"),
		Entry("Both set not matching", "private.registry.com", "other.registry.com", "other.registry.com"),
	)

	DescribeTable("merge ImagePath", func(main, second, expect string) {
		m := opv1.InstallationSpec{}
		s := opv1.InstallationSpec{}
		if main != "" {
			m.ImagePath = main
		}
		if second != "" {
			s.ImagePath = second
		}
		inst := OverrideInstallationSpec(m, s)
		Expect(inst.ImagePath).To(Equal(expect))
	},
		Entry("Both unset", nil, nil, nil),
		Entry("Main only set", "pathx", nil, "pathx"),
		Entry("Second only set", nil, "pathx", "pathx"),
		Entry("Both set equal", "pathx", "pathx", "pathx"),
		Entry("Both set not matching", "pathx", "pathy", "pathy"),
	)

	DescribeTable("merge imagePullSecrets", func(main, second, expect []v1.LocalObjectReference) {
		m := opv1.InstallationSpec{}
		s := opv1.InstallationSpec{}
		if main != nil {
			m.ImagePullSecrets = main
		}
		if second != nil {
			s.ImagePullSecrets = second
		}
		inst := OverrideInstallationSpec(m, s)
		Expect(inst.ImagePullSecrets).To(ConsistOf(expect))
	},
		Entry("Both unset", nil, nil, nil),
		Entry("Main only set", []v1.LocalObjectReference{{Name: "pull-secret"}}, nil, []v1.LocalObjectReference{{Name: "pull-secret"}}),
		Entry("Second only set", nil, []v1.LocalObjectReference{{Name: "pull-secret"}}, []v1.LocalObjectReference{{Name: "pull-secret"}}),
		Entry("Both set equal", []v1.LocalObjectReference{{Name: "pull-secret"}}, []v1.LocalObjectReference{{Name: "pull-secret"}}, []v1.LocalObjectReference{{Name: "pull-secret"}}),
		Entry("Both set not matching", []v1.LocalObjectReference{{Name: "pull-secret"}}, []v1.LocalObjectReference{{Name: "other-pull-secret"}}, []v1.LocalObjectReference{{Name: "other-pull-secret"}}),
	)

	DescribeTable("merge ImagePullPolicy", func(main, second, expect *v1.PullPolicy) {
		m := opv1.InstallationSpec{ImagePullPolicy: main}
		s := opv1.InstallationSpec{ImagePullPolicy: second}
		inst := OverrideInstallationSpec(m, s)
		if expect == nil {
			Expect(inst.ImagePullPolicy).To(BeNil())
		} else {
			Expect(inst.ImagePullPolicy).NotTo(BeNil())
			Expect(*inst.ImagePullPolicy).To(Equal(*expect))
		}
	},
		Entry("Both unset", nil, nil, nil),
		Entry("Main only set", ptr.To(v1.PullIfNotPresent), nil, ptr.To(v1.PullIfNotPresent)),
		Entry("Second only set", nil, ptr.To(v1.PullAlways), ptr.To(v1.PullAlways)),
		Entry("Both set equal", ptr.To(v1.PullIfNotPresent), ptr.To(v1.PullIfNotPresent), ptr.To(v1.PullIfNotPresent)),
		Entry("Both set not matching", ptr.To(v1.PullAlways), ptr.To(v1.PullNever), ptr.To(v1.PullNever)),
	)

	DescribeTable("merge KubernetesProvider", func(main, second, expect *opv1.Provider) {
		m := opv1.InstallationSpec{}
		s := opv1.InstallationSpec{}
		if main != nil {
			m.KubernetesProvider = *main
		}
		if second != nil {
			s.KubernetesProvider = *second
		}
		inst := OverrideInstallationSpec(m, s)
		if expect == nil {
			var x opv1.Provider
			Expect(inst.KubernetesProvider).To(Equal(x))
		} else {
			Expect(inst.KubernetesProvider).To(Equal(*expect))
		}
	},
		Entry("Both unset", nil, nil, nil),
		Entry("Main only set", &opv1.ProviderGKE, nil, &opv1.ProviderGKE),
		Entry("Second only set", nil, &opv1.ProviderAKS, &opv1.ProviderAKS),
		Entry("Both set equal", &opv1.ProviderOpenShift, &opv1.ProviderOpenShift, &opv1.ProviderOpenShift),
		Entry("Both set not matching", &opv1.ProviderEKS, &opv1.ProviderGKE, &opv1.ProviderGKE),
	)

	DescribeTable("merge CNISpec", func(main, second, expect *opv1.CNISpec) {
		m := opv1.InstallationSpec{}
		s := opv1.InstallationSpec{}
		if main != nil {
			m.CNI = main
		}
		if second != nil {
			s.CNI = second
		}
		inst := OverrideInstallationSpec(m, s)
		if expect == nil {
			Expect(inst.CNI).To(BeNil())
		} else {
			Expect(*inst.CNI).To(Equal(*expect))
		}
	},
		Entry("Both unset", nil, nil, nil),
		Entry("Main only set", &opv1.CNISpec{Type: opv1.PluginCalico}, nil, &opv1.CNISpec{Type: opv1.PluginCalico}),
		Entry("Second only set", nil, &opv1.CNISpec{Type: opv1.PluginGKE}, &opv1.CNISpec{Type: opv1.PluginGKE}),
		Entry("Both set equal",
			&opv1.CNISpec{Type: opv1.PluginAmazonVPC},
			&opv1.CNISpec{Type: opv1.PluginAmazonVPC},
			&opv1.CNISpec{Type: opv1.PluginAmazonVPC}),
		Entry("Both set not matching",
			&opv1.CNISpec{Type: opv1.PluginAmazonVPC},
			&opv1.CNISpec{Type: opv1.PluginAzureVNET},
			&opv1.CNISpec{Type: opv1.PluginAzureVNET}),
		Entry("Both set differently but mergable",
			&opv1.CNISpec{Type: opv1.PluginAmazonVPC},
			&opv1.CNISpec{IPAM: &opv1.IPAMSpec{Type: opv1.IPAMPluginAmazonVPC}},
			&opv1.CNISpec{Type: opv1.PluginAmazonVPC, IPAM: &opv1.IPAMSpec{Type: opv1.IPAMPluginAmazonVPC}}),
	)

	Context("test CalicoNetwork merge", func() {
		_BGPE := opv1.BGPEnabled
		_BGPD := opv1.BGPDisabled
		DescribeTable("merge BGP", func(main, second, expect *opv1.BGPOption) {
			m := opv1.InstallationSpec{}
			s := opv1.InstallationSpec{}
			if main != nil {
				m.CalicoNetwork = &opv1.CalicoNetworkSpec{BGP: main}
			}
			if second != nil {
				s.CalicoNetwork = &opv1.CalicoNetworkSpec{BGP: second}
			}
			inst := OverrideInstallationSpec(m, s)
			if expect == nil {
				Expect(inst.CalicoNetwork).To(BeNil())
			} else {
				Expect(*inst.CalicoNetwork.BGP).To(Equal(*expect))
			}
		},
			Entry("Both unset", nil, nil, nil),
			Entry("Main only set", &_BGPE, nil, &_BGPE),
			Entry("Second only set", nil, &_BGPD, &_BGPD),
			Entry("Both set equal", &_BGPE, &_BGPE, &_BGPE),
			Entry("Both set not matching", &_BGPE, &_BGPD, &_BGPD),
		)

		DescribeTable("merge IPPools", func(main, second, expect []opv1.IPPool) {
			m := opv1.InstallationSpec{}
			s := opv1.InstallationSpec{}
			if main != nil {
				m.CalicoNetwork = &opv1.CalicoNetworkSpec{IPPools: main}
			}
			if second != nil {
				s.CalicoNetwork = &opv1.CalicoNetworkSpec{IPPools: second}
			}
			inst := OverrideInstallationSpec(m, s)
			if expect == nil {
				Expect(inst.CalicoNetwork).To(BeNil())
			} else {
				Expect(inst.CalicoNetwork.IPPools).To(Equal(expect))
			}
		},
			Entry("Both unset", nil, nil, nil),
			Entry("Main only set", []opv1.IPPool{{CIDR: "192.168.0.0/16"}}, nil, []opv1.IPPool{{CIDR: "192.168.0.0/16"}}),
			Entry("Second only set", nil, []opv1.IPPool{{CIDR: "10.0.0.0/24"}}, []opv1.IPPool{{CIDR: "10.0.0.0/24"}}),
			Entry("Both set equal", []opv1.IPPool{{CIDR: "10.0.0.0/24"}}, []opv1.IPPool{{CIDR: "10.0.0.0/24"}}, []opv1.IPPool{{CIDR: "10.0.0.0/24"}}),
			Entry("Both set not matching", []opv1.IPPool{{CIDR: "10.0.0.0/24"}}, []opv1.IPPool{{CIDR: "172.16.0.0/8"}}, []opv1.IPPool{{CIDR: "172.16.0.0/8"}}),
		)

		DescribeTable("merge MTU", func(main, second, expect *opv1.CalicoNetworkSpec) {
			m := opv1.InstallationSpec{}
			s := opv1.InstallationSpec{}
			if main != nil {
				m.CalicoNetwork = main
			}
			if second != nil {
				s.CalicoNetwork = second
			}
			inst := OverrideInstallationSpec(m, s)
			if expect == nil {
				Expect(inst.CalicoNetwork).To(BeNil())
			} else {
				Expect(*inst.CalicoNetwork).To(Equal(*expect))
			}
		},
			Entry("Both unset", nil, nil, nil),
			Entry("Main only set",
				&opv1.CalicoNetworkSpec{MTU: intPtr(1500)},
				nil,
				&opv1.CalicoNetworkSpec{MTU: intPtr(1500)}),
			Entry("Second only set",
				nil,
				&opv1.CalicoNetworkSpec{MTU: intPtr(8980)},
				&opv1.CalicoNetworkSpec{MTU: intPtr(8980)}),
			Entry("Both set equal",
				&opv1.CalicoNetworkSpec{MTU: intPtr(1440)},
				&opv1.CalicoNetworkSpec{MTU: intPtr(1440)},
				&opv1.CalicoNetworkSpec{MTU: intPtr(1440)}),
			Entry("Both set not matching",
				&opv1.CalicoNetworkSpec{MTU: intPtr(1460)},
				&opv1.CalicoNetworkSpec{MTU: intPtr(8981)},
				&opv1.CalicoNetworkSpec{MTU: intPtr(8981)}),
			Entry("Main only set with cfg override",
				&opv1.CalicoNetworkSpec{MTU: intPtr(1500)},
				&opv1.CalicoNetworkSpec{},
				&opv1.CalicoNetworkSpec{MTU: intPtr(1500)}),
			Entry("Override only set with empty cfg",
				&opv1.CalicoNetworkSpec{},
				&opv1.CalicoNetworkSpec{MTU: intPtr(8980)},
				&opv1.CalicoNetworkSpec{MTU: intPtr(8980)}),
		)

		_true := true
		DescribeTable("merge NodeAddressAutodetectionV4", func(main, second, expect *opv1.NodeAddressAutodetection) {
			m := opv1.InstallationSpec{}
			s := opv1.InstallationSpec{}
			if main != nil {
				m.CalicoNetwork = &opv1.CalicoNetworkSpec{NodeAddressAutodetectionV4: main}
			}
			if second != nil {
				s.CalicoNetwork = &opv1.CalicoNetworkSpec{NodeAddressAutodetectionV4: second}
			}
			inst := OverrideInstallationSpec(m, s)
			if expect == nil {
				Expect(inst.CalicoNetwork).To(BeNil())
			} else {
				Expect(*inst.CalicoNetwork.NodeAddressAutodetectionV4).To(Equal(*expect))
			}
		},
			Entry("Both unset", nil, nil, nil),
			Entry("Main only set",
				&opv1.NodeAddressAutodetection{Interface: "enp0s*"}, nil,
				&opv1.NodeAddressAutodetection{Interface: "enp0s*"}),
			Entry("Second only set", nil,
				&opv1.NodeAddressAutodetection{FirstFound: &_true},
				&opv1.NodeAddressAutodetection{FirstFound: &_true}),
			Entry("Both set equal",
				&opv1.NodeAddressAutodetection{CIDRS: []string{"192.168.5.0/24", "192.168.10.0/24"}},
				&opv1.NodeAddressAutodetection{CIDRS: []string{"192.168.5.0/24", "192.168.10.0/24"}},
				&opv1.NodeAddressAutodetection{CIDRS: []string{"192.168.5.0/24", "192.168.10.0/24"}}),
			Entry("Both set not matching",
				&opv1.NodeAddressAutodetection{CIDRS: []string{"192.168.5.0/24", "192.168.10.0/24"}},
				&opv1.NodeAddressAutodetection{CIDRS: []string{"192.168.6.0/24", "192.168.11.0/24"}},
				&opv1.NodeAddressAutodetection{CIDRS: []string{"192.168.6.0/24", "192.168.11.0/24"}}),
		)

		DescribeTable("merge NodeAddressAutodetectionV6", func(main, second, expect *opv1.NodeAddressAutodetection) {
			m := opv1.InstallationSpec{}
			s := opv1.InstallationSpec{}
			if main != nil {
				m.CalicoNetwork = &opv1.CalicoNetworkSpec{NodeAddressAutodetectionV6: main}
			}
			if second != nil {
				s.CalicoNetwork = &opv1.CalicoNetworkSpec{NodeAddressAutodetectionV6: second}
			}
			inst := OverrideInstallationSpec(m, s)
			if expect == nil {
				Expect(inst.CalicoNetwork).To(BeNil())
			} else {
				Expect(*inst.CalicoNetwork.NodeAddressAutodetectionV6).To(Equal(*expect))
			}
		},
			Entry("Both unset", nil, nil, nil),
			Entry("Main only set",
				&opv1.NodeAddressAutodetection{Interface: "enp0s*"}, nil,
				&opv1.NodeAddressAutodetection{Interface: "enp0s*"}),
			Entry("Second only set", nil,
				&opv1.NodeAddressAutodetection{FirstFound: &_true},
				&opv1.NodeAddressAutodetection{FirstFound: &_true}),
			Entry("Both set equal",
				&opv1.NodeAddressAutodetection{CIDRS: []string{"fd00:0001::/96", "fd00:0002::/96"}},
				&opv1.NodeAddressAutodetection{CIDRS: []string{"fd00:0001::/96", "fd00:0002::/96"}},
				&opv1.NodeAddressAutodetection{CIDRS: []string{"fd00:0001::/96", "fd00:0002::/96"}}),
			Entry("Both set not matching",
				&opv1.NodeAddressAutodetection{CIDRS: []string{"fd00:0001::/96", "fd00:0002::/96"}},
				&opv1.NodeAddressAutodetection{CIDRS: []string{"fd00:000f::/96", "fd00:000d::/96"}},
				&opv1.NodeAddressAutodetection{CIDRS: []string{"fd00:000f::/96", "fd00:000d::/96"}}),
		)

		_hpe := opv1.HostPortsEnabled
		_hpd := opv1.HostPortsDisabled
		DescribeTable("merge HostPorts", func(main, second, expect *opv1.HostPortsType) {
			m := opv1.InstallationSpec{}
			s := opv1.InstallationSpec{}
			if main != nil {
				m.CalicoNetwork = &opv1.CalicoNetworkSpec{HostPorts: main}
			}
			if second != nil {
				s.CalicoNetwork = &opv1.CalicoNetworkSpec{HostPorts: second}
			}
			inst := OverrideInstallationSpec(m, s)
			if expect == nil {
				Expect(inst.CalicoNetwork).To(BeNil())
			} else {
				Expect(*inst.CalicoNetwork.HostPorts).To(Equal(*expect))
			}
		},
			Entry("Both unset", nil, nil, nil),
			Entry("Main only set", &_hpe, nil, &_hpe),
			Entry("Second only set", nil, &_hpd, &_hpd),
			Entry("Both set equal", &_hpe, &_hpe, &_hpe),
			Entry("Both set not matching", &_hpe, &_hpd, &_hpd),
		)

		_miNone := opv1.MultiInterfaceModeNone
		_miMultus := opv1.MultiInterfaceModeMultus
		DescribeTable("merge MultiInterfaceMode", func(main, second, expect *opv1.MultiInterfaceMode) {
			m := opv1.InstallationSpec{}
			s := opv1.InstallationSpec{}
			if main != nil {
				m.CalicoNetwork = &opv1.CalicoNetworkSpec{MultiInterfaceMode: main}
			}
			if second != nil {
				s.CalicoNetwork = &opv1.CalicoNetworkSpec{MultiInterfaceMode: second}
			}
			inst := OverrideInstallationSpec(m, s)
			if expect == nil {
				Expect(inst.CalicoNetwork).To(BeNil())
			} else {
				Expect(*inst.CalicoNetwork.MultiInterfaceMode).To(Equal(*expect))
			}
		},
			Entry("Both unset", nil, nil, nil),
			Entry("Main only set", &_miNone, nil, &_miNone),
			Entry("Second only set", nil, &_miMultus, &_miMultus),
			Entry("Both set equal", &_miNone, &_miNone, &_miNone),
			Entry("Both set not matching", &_miNone, &_miMultus, &_miMultus),
		)

		_cipfE := opv1.ContainerIPForwardingEnabled
		_cipfD := opv1.ContainerIPForwardingDisabled
		DescribeTable("merge ContainerIPForwarding", func(main, second, expect *opv1.ContainerIPForwardingType) {
			m := opv1.InstallationSpec{}
			s := opv1.InstallationSpec{}
			if main != nil {
				m.CalicoNetwork = &opv1.CalicoNetworkSpec{ContainerIPForwarding: main}
			}
			if second != nil {
				s.CalicoNetwork = &opv1.CalicoNetworkSpec{ContainerIPForwarding: second}
			}
			inst := OverrideInstallationSpec(m, s)
			if expect == nil {
				Expect(inst.CalicoNetwork).To(BeNil())
			} else {
				Expect(*inst.CalicoNetwork.ContainerIPForwarding).To(Equal(*expect))
			}
		},
			Entry("Both unset", nil, nil, nil),
			Entry("Main only set", &_cipfE, nil, &_cipfE),
			Entry("Second only set", nil, &_cipfD, &_cipfD),
			Entry("Both set equal", &_cipfE, &_cipfE, &_cipfE),
			Entry("Both set not matching", &_cipfE, &_cipfD, &_cipfD),
		)

		DescribeTable("merge ControlPlaneNodeSelector", func(main, second, expect map[string]string) {
			m := opv1.InstallationSpec{}
			s := opv1.InstallationSpec{}
			if main != nil {
				m.ControlPlaneNodeSelector = main
			}
			if second != nil {
				s.ControlPlaneNodeSelector = second
			}
			inst := OverrideInstallationSpec(m, s)
			if expect == nil {
				Expect(inst.ControlPlaneNodeSelector).To(BeNil())
			} else {
				Expect(inst.ControlPlaneNodeSelector).To(Equal(expect))
			}
		},
			Entry("Both unset", nil, nil, nil),
			Entry("Main only set", map[string]string{"a": "1"}, nil, map[string]string{"a": "1"}),
			Entry("Second only set", nil, map[string]string{"b": "2"}, map[string]string{"b": "2"}),
			Entry("Both set equal", map[string]string{"a": "1"}, map[string]string{"a": "1"}, map[string]string{"a": "1"}),
			Entry("Both set not matching", map[string]string{"a": "1"}, map[string]string{"b": "2"}, map[string]string{"b": "2"}),
		)
		// TODO: Have some test that have different fields set and they merge.

		DescribeTable("merge multiple CalicoNetwork fields", func(main, second, expect *opv1.CalicoNetworkSpec) {
			m := opv1.InstallationSpec{}
			s := opv1.InstallationSpec{}
			if main != nil {
				m.CalicoNetwork = main
			}
			if second != nil {
				s.CalicoNetwork = second
			}
			inst := OverrideInstallationSpec(m, s)
			if expect == nil {
				Expect(inst.CalicoNetwork).To(BeNil())
			} else {
				Expect(inst.CalicoNetwork).To(Equal(expect))
			}
		},
			Entry("Both unset", nil, nil, nil),
			Entry("Different fields in the two are merged",
				&opv1.CalicoNetworkSpec{
					BGP: &_BGPE,
					MTU: intPtr(100),
				},
				&opv1.CalicoNetworkSpec{
					NodeAddressAutodetectionV4: &opv1.NodeAddressAutodetection{Interface: "enp0s*"},
					HostPorts:                  &_hpe,
				},
				&opv1.CalicoNetworkSpec{
					BGP:                        &_BGPE,
					MTU:                        intPtr(100),
					NodeAddressAutodetectionV4: &opv1.NodeAddressAutodetection{Interface: "enp0s*"},
					HostPorts:                  &_hpe,
				}),
			Entry("Different fields in the two are merged but some are overridden",
				&opv1.CalicoNetworkSpec{
					BGP: &_BGPE,
					MTU: intPtr(100),
				},
				&opv1.CalicoNetworkSpec{
					MTU:       intPtr(200),
					HostPorts: &_hpe,
				},
				&opv1.CalicoNetworkSpec{
					BGP:       &_BGPE,
					MTU:       intPtr(200),
					HostPorts: &_hpe,
				}),
		)

		_sysctlTuningA := []opv1.Sysctl{
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
		_sysctlTuningB := []opv1.Sysctl{}
		DescribeTable("merge CNI Tuning", func(main, second, expect []opv1.Sysctl) {
			m := opv1.InstallationSpec{}
			s := opv1.InstallationSpec{}
			if main != nil {
				m.CalicoNetwork = &opv1.CalicoNetworkSpec{Sysctl: main}
			}
			if second != nil {
				s.CalicoNetwork = &opv1.CalicoNetworkSpec{Sysctl: second}
			}
			inst := OverrideInstallationSpec(m, s)
			if expect == nil {
				Expect(inst.CalicoNetwork).To(BeNil())
			} else {
				Expect(inst.CalicoNetwork.Sysctl).To(Equal(expect))
			}
		},
			Entry("Both unset", nil, nil, nil),
			Entry("Main only set", _sysctlTuningA, nil, _sysctlTuningA),
			Entry("Second only set", nil, _sysctlTuningB, _sysctlTuningB),
			Entry("Both set equal", _sysctlTuningA, _sysctlTuningA, _sysctlTuningA),
			Entry("Both set not matching", _sysctlTuningA, _sysctlTuningB, _sysctlTuningB),
		)
	})

	DescribeTable("merge NodeMetricsPort", func(main, second, expect *int32) {
		m := opv1.InstallationSpec{}
		s := opv1.InstallationSpec{}
		if main != nil {
			m.NodeMetricsPort = main
		}
		if second != nil {
			s.NodeMetricsPort = second
		}
		inst := OverrideInstallationSpec(m, s)
		if expect == nil {
			Expect(inst.NodeMetricsPort).To(BeNil())
		} else {
			Expect(*inst.NodeMetricsPort).To(Equal(*expect))
		}
	},
		Entry("Both unset", nil, nil, nil),
		Entry("Main only set", intPtr(1500), nil, intPtr(1500)),
		Entry("Second only set", nil, intPtr(8980), intPtr(8980)),
		Entry("Both set equal", intPtr(1440), intPtr(1440), intPtr(1440)),
		Entry("Both set not matching", intPtr(1460), intPtr(8981), intPtr(8981)),
	)

	DescribeTable("merge FlexVolumePath", func(main, second, expect string) {
		m := opv1.InstallationSpec{}
		s := opv1.InstallationSpec{}
		if main != "" {
			m.FlexVolumePath = main
		}
		if second != "" {
			s.FlexVolumePath = second
		}
		inst := OverrideInstallationSpec(m, s)
		Expect(inst.FlexVolumePath).To(Equal(expect))
	},
		Entry("Both unset", nil, nil, nil),
		Entry("Main only set", "pathx", nil, "pathx"),
		Entry("Second only set", nil, "pathx", "pathx"),
		Entry("Both set equal", "pathx", "pathx", "pathx"),
		Entry("Both set not matching", "pathx", "pathy", "pathy"),
	)

	DescribeTable("merge CalicoRunHostPath", func(main, second, expect string) {
		m := opv1.InstallationSpec{}
		s := opv1.InstallationSpec{}
		if main != "" {
			m.CalicoRunHostPath = main
		}
		if second != "" {
			s.CalicoRunHostPath = second
		}
		inst := OverrideInstallationSpec(m, s)
		Expect(inst.CalicoRunHostPath).To(Equal(expect))
	},
		Entry("Both unset", nil, nil, nil),
		Entry("Main only set", "pathx", nil, "pathx"),
		Entry("Second only set", nil, "pathx", "pathx"),
		Entry("Both set equal", "pathx", "pathx", "pathx"),
		Entry("Both set not matching", "pathx", "pathy", "pathy"),
	)

	DescribeTable("merge CalicoLibHostPath", func(main, second, expect string) {
		m := opv1.InstallationSpec{}
		s := opv1.InstallationSpec{}
		if main != "" {
			m.CalicoLibHostPath = main
		}
		if second != "" {
			s.CalicoLibHostPath = second
		}
		inst := OverrideInstallationSpec(m, s)
		Expect(inst.CalicoLibHostPath).To(Equal(expect))
	},
		Entry("Both unset", nil, nil, nil),
		Entry("Main only set", "pathx", nil, "pathx"),
		Entry("Second only set", nil, "pathx", "pathx"),
		Entry("Both set equal", "pathx", "pathx", "pathx"),
		Entry("Both set not matching", "pathx", "pathy", "pathy"),
	)

	_1 := intstr.FromInt(1)
	_roll1 := appsv1.DaemonSetUpdateStrategy{
		Type:          appsv1.RollingUpdateDaemonSetStrategyType,
		RollingUpdate: &appsv1.RollingUpdateDaemonSet{MaxUnavailable: &_1},
	}
	_2 := intstr.FromInt(2)
	_roll2 := appsv1.DaemonSetUpdateStrategy{
		Type:          appsv1.RollingUpdateDaemonSetStrategyType,
		RollingUpdate: &appsv1.RollingUpdateDaemonSet{MaxUnavailable: &_2},
	}
	DescribeTable("merge NodeUpdateStrategy", func(main, second, expect *appsv1.DaemonSetUpdateStrategy) {
		m := opv1.InstallationSpec{}
		s := opv1.InstallationSpec{}
		if main != nil {
			m.NodeUpdateStrategy = *main
		}
		if second != nil {
			s.NodeUpdateStrategy = *second
		}
		inst := OverrideInstallationSpec(m, s)
		if expect == nil {
			var x appsv1.DaemonSetUpdateStrategy
			Expect(inst.NodeUpdateStrategy).To(Equal(x))
		} else {
			Expect(inst.NodeUpdateStrategy).To(Equal(*expect))
		}
	},
		Entry("Both unset", nil, nil, nil),
		Entry("Main only set", &_roll1, nil, &_roll1),
		Entry("Second only set", nil, &_roll2, &_roll2),
		Entry("Both set equal", &_roll1, &_roll1, &_roll1),
		Entry("Both set not matching", &_roll1, &_roll2, &_roll2),
	)

	_nodeComp := opv1.ComponentResource{
		ComponentName: opv1.ComponentNameNode,
		ResourceRequirements: &v1.ResourceRequirements{
			Requests: v1.ResourceList{v1.ResourceCPU: resource.MustParse("500m")},
		},
	}
	_typhaComp := opv1.ComponentResource{
		ComponentName: opv1.ComponentNameTypha,
		ResourceRequirements: &v1.ResourceRequirements{
			Requests: v1.ResourceList{v1.ResourceMemory: resource.MustParse("500Mi")},
		},
	}
	DescribeTable("merge ComponentResources", func(main, second, expect []opv1.ComponentResource) {
		m := opv1.InstallationSpec{}
		s := opv1.InstallationSpec{}
		if main != nil {
			m.ComponentResources = main
		}
		if second != nil {
			s.ComponentResources = second
		}
		inst := OverrideInstallationSpec(m, s)
		if expect == nil {
			Expect(inst.ComponentResources).To(HaveLen(0))
		} else {
			Expect(inst.ComponentResources).To(ConsistOf(expect))
		}
	},
		Entry("Both unset", nil, nil, nil),
		Entry("Main only set",
			[]opv1.ComponentResource{_nodeComp},
			nil,
			[]opv1.ComponentResource{_nodeComp}),
		Entry("Second only set",
			nil,
			[]opv1.ComponentResource{_typhaComp},
			[]opv1.ComponentResource{_typhaComp}),
		Entry("Both set equal",
			[]opv1.ComponentResource{_nodeComp},
			[]opv1.ComponentResource{_nodeComp},
			[]opv1.ComponentResource{_nodeComp}),
		Entry("Both set not matching",
			[]opv1.ComponentResource{_nodeComp},
			[]opv1.ComponentResource{_typhaComp},
			[]opv1.ComponentResource{_typhaComp}),
	)

	metadataTests := []TableEntry{
		Entry("Both unset", nil, nil, nil),
		Entry("Main only set (labels only)", &opv1.Metadata{Labels: map[string]string{"a": "1"}}, nil, &opv1.Metadata{Labels: map[string]string{"a": "1"}}),
		Entry("Main only set (annots only)", &opv1.Metadata{Annotations: map[string]string{"a": "1"}}, nil, &opv1.Metadata{Annotations: map[string]string{"a": "1"}}),
		Entry("Main only set (both)", &opv1.Metadata{Labels: map[string]string{"a": "1"}, Annotations: map[string]string{"b": "1"}}, nil,
			&opv1.Metadata{Labels: map[string]string{"a": "1"}, Annotations: map[string]string{"b": "1"}}),
		Entry("Second only set (labels only)", nil, &opv1.Metadata{Labels: map[string]string{"a": "1"}}, &opv1.Metadata{Labels: map[string]string{"a": "1"}}),
		Entry("Second only set (annots only)", nil, &opv1.Metadata{Annotations: map[string]string{"a": "1"}}, &opv1.Metadata{Annotations: map[string]string{"a": "1"}}),
		Entry("Second only set (both)", nil, &opv1.Metadata{Labels: map[string]string{"a": "1"}, Annotations: map[string]string{"b": "1"}},
			&opv1.Metadata{Labels: map[string]string{"a": "1"}, Annotations: map[string]string{"b": "1"}}),
		Entry("Both set equal (labels only)", &opv1.Metadata{Labels: map[string]string{"a": "1"}}, &opv1.Metadata{Labels: map[string]string{"a": "1"}},
			&opv1.Metadata{Labels: map[string]string{"a": "1"}}),
		Entry("Both set equal (annots only)", &opv1.Metadata{Annotations: map[string]string{"a": "1"}}, &opv1.Metadata{Annotations: map[string]string{"a": "1"}},
			&opv1.Metadata{Annotations: map[string]string{"a": "1"}}),
		Entry("Both set equal (both)", &opv1.Metadata{Labels: map[string]string{"a": "1"}, Annotations: map[string]string{"b": "1"}}, &opv1.Metadata{Labels: map[string]string{"a": "1"}, Annotations: map[string]string{"b": "1"}},
			&opv1.Metadata{Labels: map[string]string{"a": "1"}, Annotations: map[string]string{"b": "1"}}),
		Entry("Both set not equal (labels only)", &opv1.Metadata{Labels: map[string]string{"a": "1"}}, &opv1.Metadata{Labels: map[string]string{"b": "2"}},
			&opv1.Metadata{Labels: map[string]string{"b": "2"}}),
		Entry("Both set not equal (annots only)", &opv1.Metadata{Annotations: map[string]string{"a": "1"}}, &opv1.Metadata{Annotations: map[string]string{"b": "2"}},
			&opv1.Metadata{Annotations: map[string]string{"b": "2"}}),
		Entry("Both set not equal (both differ)", &opv1.Metadata{Labels: map[string]string{"a": "1"}, Annotations: map[string]string{"b": "1"}}, &opv1.Metadata{Labels: map[string]string{"b": "2"}, Annotations: map[string]string{"c": "2"}},
			&opv1.Metadata{Labels: map[string]string{"b": "2"}, Annotations: map[string]string{"c": "2"}}),
		Entry("Both set not equal (labels differ)", &opv1.Metadata{Labels: map[string]string{"a": "1"}, Annotations: map[string]string{"b": "1"}}, &opv1.Metadata{Labels: map[string]string{"b": "2"}, Annotations: map[string]string{"b": "1"}},
			&opv1.Metadata{Labels: map[string]string{"b": "2"}, Annotations: map[string]string{"b": "1"}}),
		Entry("Both set not equal (annots differ)", &opv1.Metadata{Labels: map[string]string{"a": "1"}, Annotations: map[string]string{"b": "1"}}, &opv1.Metadata{Labels: map[string]string{"a": "1"}, Annotations: map[string]string{"c": "2"}},
			&opv1.Metadata{Labels: map[string]string{"a": "1"}, Annotations: map[string]string{"c": "2"}}),
	}

	Context("test CalicoNodeDaemonSet merge", func() {
		var m opv1.InstallationSpec
		var s opv1.InstallationSpec

		BeforeEach(func() {
			m = opv1.InstallationSpec{
				CalicoNodeDaemonSet: &opv1.CalicoNodeDaemonSet{
					Spec: &opv1.CalicoNodeDaemonSetSpec{
						Template: &opv1.CalicoNodeDaemonSetPodTemplateSpec{
							Spec: &opv1.CalicoNodeDaemonSetPodSpec{},
						},
					},
				},
			}
			s = opv1.InstallationSpec{
				CalicoNodeDaemonSet: &opv1.CalicoNodeDaemonSet{
					Spec: &opv1.CalicoNodeDaemonSetSpec{
						Template: &opv1.CalicoNodeDaemonSetPodTemplateSpec{
							Spec: &opv1.CalicoNodeDaemonSetPodSpec{},
						},
					},
				},
			}
		})

		DescribeTable("merge metadata", func(main, second, expect *opv1.Metadata) {
			// start with empty installation spec
			m = opv1.InstallationSpec{}
			s = opv1.InstallationSpec{}
			if main != nil {
				m.CalicoNodeDaemonSet = &opv1.CalicoNodeDaemonSet{Metadata: main}
			}
			if second != nil {
				s.CalicoNodeDaemonSet = &opv1.CalicoNodeDaemonSet{Metadata: second}
			}
			inst := OverrideInstallationSpec(m, s)
			if expect == nil {
				Expect(inst.CalicoNodeDaemonSet).To(BeNil())
			} else {
				Expect(*inst.CalicoNodeDaemonSet.Metadata).To(Equal(*expect))
			}
		}, metadataTests)

		DescribeTable("merge minReadySeconds", func(main, second, expect *int32) {
			m.CalicoNodeDaemonSet.Spec.MinReadySeconds = main
			s.CalicoNodeDaemonSet.Spec.MinReadySeconds = second
			inst := OverrideInstallationSpec(m, s)
			if expect == nil {
				Expect(inst.CalicoNodeDaemonSet.Spec.MinReadySeconds).To(BeNil())
			} else {
				Expect(*inst.CalicoNodeDaemonSet.Spec.MinReadySeconds).To(Equal(*expect))
			}
		},
			Entry("Both unset", nil, nil, nil),
			Entry("Main only set", intPtr(23), nil, intPtr(23)),
			Entry("Second only set", nil, intPtr(23), intPtr(23)),
			Entry("Both set equal", intPtr(23), intPtr(23), intPtr(23)),
			Entry("Both set not equal", intPtr(23), intPtr(42), intPtr(42)),
		)
		DescribeTable("merge pod template metadata", func(main, second, expect *opv1.Metadata) {
			m.CalicoNodeDaemonSet.Spec.Template.Metadata = main
			s.CalicoNodeDaemonSet.Spec.Template.Metadata = second
			inst := OverrideInstallationSpec(m, s)
			if expect == nil {
				Expect(inst.CalicoNodeDaemonSet.Spec.Template.Metadata).To(BeNil())
			} else {
				Expect(*inst.CalicoNodeDaemonSet.Spec.Template.Metadata).To(Equal(*expect))
			}
		}, metadataTests)

		_resources1 := &v1.ResourceRequirements{
			Requests: v1.ResourceList{v1.ResourceCPU: resource.MustParse("500m")},
			Limits:   v1.ResourceList{v1.ResourceCPU: resource.MustParse("500m")},
		}
		_resources2 := &v1.ResourceRequirements{
			Requests: v1.ResourceList{v1.ResourceCPU: resource.MustParse("1000m"), v1.ResourceMemory: resource.MustParse("500Mi")},
			Limits:   v1.ResourceList{v1.ResourceCPU: resource.MustParse("1000m"), v1.ResourceMemory: resource.MustParse("1000Mi")},
		}
		_calicoNodeInit1a := opv1.CalicoNodeDaemonSetInitContainer{Name: "init1", Resources: _resources1}
		_calicoNodeInit1b := opv1.CalicoNodeDaemonSetInitContainer{Name: "init1", Resources: _resources2}
		_calicoNodeInit2 := opv1.CalicoNodeDaemonSetInitContainer{Name: "init2", Resources: _resources2}

		DescribeTable("merge initContainers", func(main, second, expect []opv1.CalicoNodeDaemonSetInitContainer) {
			m.CalicoNodeDaemonSet.Spec.Template.Spec.InitContainers = main
			s.CalicoNodeDaemonSet.Spec.Template.Spec.InitContainers = second
			inst := OverrideInstallationSpec(m, s)
			if expect == nil {
				Expect(inst.CalicoNodeDaemonSet.Spec.Template.Spec.InitContainers).To(BeNil())
			} else {
				Expect(inst.CalicoNodeDaemonSet.Spec.Template.Spec.InitContainers).To(Equal(expect))
			}
		},
			Entry("Both unset", nil, nil, nil),
			Entry("Main only set", []opv1.CalicoNodeDaemonSetInitContainer{_calicoNodeInit1a, _calicoNodeInit2}, nil, []opv1.CalicoNodeDaemonSetInitContainer{_calicoNodeInit1a, _calicoNodeInit2}),
			Entry("Second only set", nil, []opv1.CalicoNodeDaemonSetInitContainer{_calicoNodeInit1a, _calicoNodeInit2}, []opv1.CalicoNodeDaemonSetInitContainer{_calicoNodeInit1a, _calicoNodeInit2}),
			Entry("Both set equal", []opv1.CalicoNodeDaemonSetInitContainer{_calicoNodeInit1a, _calicoNodeInit2}, []opv1.CalicoNodeDaemonSetInitContainer{_calicoNodeInit1a, _calicoNodeInit2},
				[]opv1.CalicoNodeDaemonSetInitContainer{_calicoNodeInit1a, _calicoNodeInit2}),
			Entry("Both set not equal", []opv1.CalicoNodeDaemonSetInitContainer{_calicoNodeInit1a, _calicoNodeInit2}, []opv1.CalicoNodeDaemonSetInitContainer{_calicoNodeInit1b, _calicoNodeInit2},
				[]opv1.CalicoNodeDaemonSetInitContainer{_calicoNodeInit1b, _calicoNodeInit2}),
		)

		_calicoNode1a := opv1.CalicoNodeDaemonSetContainer{Name: "node1", Resources: _resources1}
		_calicoNode1b := opv1.CalicoNodeDaemonSetContainer{Name: "node1", Resources: _resources2}
		_calicoNode2 := opv1.CalicoNodeDaemonSetContainer{Name: "node2", Resources: _resources2}

		DescribeTable("merge containers", func(main, second, expect []opv1.CalicoNodeDaemonSetContainer) {
			m.CalicoNodeDaemonSet.Spec.Template.Spec.Containers = main
			s.CalicoNodeDaemonSet.Spec.Template.Spec.Containers = second
			inst := OverrideInstallationSpec(m, s)
			if expect == nil {
				Expect(inst.CalicoNodeDaemonSet.Spec.Template.Spec.Containers).To(BeNil())
			} else {
				Expect(inst.CalicoNodeDaemonSet.Spec.Template.Spec.Containers).To(Equal(expect))
			}
		},
			Entry("Both unset", nil, nil, nil),
			Entry("Main only set", []opv1.CalicoNodeDaemonSetContainer{_calicoNode1a, _calicoNode1b}, nil, []opv1.CalicoNodeDaemonSetContainer{_calicoNode1a, _calicoNode1b}),
			Entry("Second only set", nil, []opv1.CalicoNodeDaemonSetContainer{_calicoNode1a, _calicoNode1b}, []opv1.CalicoNodeDaemonSetContainer{_calicoNode1a, _calicoNode1b}),
			Entry("Both set equal", []opv1.CalicoNodeDaemonSetContainer{_calicoNode1a, _calicoNode1b}, []opv1.CalicoNodeDaemonSetContainer{_calicoNode1a, _calicoNode1b},
				[]opv1.CalicoNodeDaemonSetContainer{_calicoNode1a, _calicoNode1b}),
			Entry("Both set not equal", []opv1.CalicoNodeDaemonSetContainer{_calicoNode1a, _calicoNode2}, []opv1.CalicoNodeDaemonSetContainer{_calicoNode1b, _calicoNode2},
				[]opv1.CalicoNodeDaemonSetContainer{_calicoNode1b, _calicoNode2}),
		)

		_aff1 := &v1.Affinity{
			NodeAffinity: &v1.NodeAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution: &v1.NodeSelector{
					NodeSelectorTerms: []v1.NodeSelectorTerm{{
						MatchExpressions: []v1.NodeSelectorRequirement{{
							Key:      "custom-affinity-key",
							Operator: v1.NodeSelectorOpExists,
						}},
					}},
				},
			},
		}
		_aff2 := &v1.Affinity{
			NodeAffinity: &v1.NodeAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution: &v1.NodeSelector{
					NodeSelectorTerms: []v1.NodeSelectorTerm{{
						MatchExpressions: []v1.NodeSelectorRequirement{{
							Key:      "custom-affinity-key2",
							Operator: v1.NodeSelectorOpExists,
						}},
					}},
				},
			},
		}
		_affEmpty := &v1.Affinity{}

		DescribeTable("merge affinity", func(main, second, expect *v1.Affinity) {
			m.CalicoNodeDaemonSet.Spec.Template.Spec.Affinity = main
			s.CalicoNodeDaemonSet.Spec.Template.Spec.Affinity = second
			inst := OverrideInstallationSpec(m, s)
			if expect == nil {
				Expect(inst.CalicoNodeDaemonSet.Spec.Template.Spec.Affinity).To(BeNil())
			} else {
				Expect(*inst.CalicoNodeDaemonSet.Spec.Template.Spec.Affinity).To(Equal(*expect))
			}
		},
			Entry("Both unset", nil, nil, nil),
			Entry("Main only set", _aff1, nil, _aff1),
			Entry("Second only set", nil, _aff1, _aff1),
			Entry("Both set equal", _aff1, _aff1, _aff1),
			Entry("Both set not equal", _aff1, _aff2, _aff2),
			Entry("Both set not equal, override empty", _aff1, _affEmpty, _affEmpty),
		)

		DescribeTable("merge nodeSelector", func(main, second, expect map[string]string) {
			m.CalicoNodeDaemonSet.Spec.Template.Spec.NodeSelector = main
			s.CalicoNodeDaemonSet.Spec.Template.Spec.NodeSelector = second
			inst := OverrideInstallationSpec(m, s)
			if expect == nil {
				Expect(inst.CalicoNodeDaemonSet.Spec.Template.Spec.NodeSelector).To(BeNil())
			} else {
				Expect(inst.CalicoNodeDaemonSet.Spec.Template.Spec.NodeSelector).To(Equal(expect))
			}
		},
			Entry("Both unset", nil, nil, nil),
			Entry("Main only set", map[string]string{"a1": "1"}, nil, map[string]string{"a1": "1"}),
			Entry("Second only set", nil, map[string]string{"a1": "1"}, map[string]string{"a1": "1"}),
			Entry("Both set equal", map[string]string{"a1": "1"}, map[string]string{"a1": "1"}, map[string]string{"a1": "1"}),
			Entry("Both set not equal", map[string]string{"a1": "1"}, map[string]string{"a1": "2", "b1": "3"}, map[string]string{"a1": "2", "b1": "3"}),
			Entry("Both set not equal, override empty", map[string]string{"a1": "1"}, map[string]string{}, map[string]string{}),
		)

		_toleration1 := v1.Toleration{
			Key:      "foo",
			Operator: v1.TolerationOpEqual,
			Value:    "bar",
		}
		_toleration2 := v1.Toleration{
			Key:      "bar",
			Operator: v1.TolerationOpEqual,
			Value:    "baz",
		}

		DescribeTable("merge tolerations", func(main, second, expect []v1.Toleration) {
			m.CalicoNodeDaemonSet.Spec.Template.Spec.Tolerations = main
			s.CalicoNodeDaemonSet.Spec.Template.Spec.Tolerations = second
			inst := OverrideInstallationSpec(m, s)
			if expect == nil {
				Expect(inst.CalicoNodeDaemonSet.Spec.Template.Spec.Tolerations).To(BeNil())
			} else {
				Expect(inst.CalicoNodeDaemonSet.Spec.Template.Spec.Tolerations).To(Equal(expect))
			}
		},
			Entry("Both unset", nil, nil, nil),
			Entry("Main only set", []v1.Toleration{_toleration1}, nil, []v1.Toleration{_toleration1}),
			Entry("Second only set", nil, []v1.Toleration{_toleration1}, []v1.Toleration{_toleration1}),
			Entry("Both set equal", []v1.Toleration{_toleration1}, []v1.Toleration{_toleration1}, []v1.Toleration{_toleration1}),
			Entry("Both set not equal", []v1.Toleration{_toleration1}, []v1.Toleration{_toleration2}, []v1.Toleration{_toleration2}),
			Entry("Both set not equal, override empty", []v1.Toleration{_toleration1}, []v1.Toleration{}, []v1.Toleration{}),
		)

		DescribeTable("merge multiple CalicoDaemonSet fields", func(main, second, expect *opv1.CalicoNodeDaemonSet) {
			// start with empty spec
			m = opv1.InstallationSpec{}
			s = opv1.InstallationSpec{}
			if main != nil {
				m.CalicoNodeDaemonSet = main
			}
			if second != nil {
				s.CalicoNodeDaemonSet = second
			}
			inst := OverrideInstallationSpec(m, s)
			if expect == nil {
				Expect(inst.CalicoNodeDaemonSet).To(BeNil())
			} else {
				Expect(*inst.CalicoNodeDaemonSet).To(Equal(*expect))
			}
		},
			Entry("Both unset", nil, nil, nil),
			Entry("Different fields in the two are merged, some overridden",
				&opv1.CalicoNodeDaemonSet{
					Metadata: &opv1.Metadata{
						Labels: map[string]string{"l": "1"},
					},
					Spec: &opv1.CalicoNodeDaemonSetSpec{
						MinReadySeconds: intPtr(5),
						Template: &opv1.CalicoNodeDaemonSetPodTemplateSpec{
							Spec: &opv1.CalicoNodeDaemonSetPodSpec{
								Containers:   []opv1.CalicoNodeDaemonSetContainer{_calicoNode1a},
								NodeSelector: map[string]string{"selector": "test"},
								Tolerations:  []v1.Toleration{_toleration1},
							},
						},
					},
				},
				&opv1.CalicoNodeDaemonSet{
					Metadata: &opv1.Metadata{
						Labels:      map[string]string{"overridden": "1"},
						Annotations: map[string]string{"a": "1"},
					},
					Spec: &opv1.CalicoNodeDaemonSetSpec{
						Template: &opv1.CalicoNodeDaemonSetPodTemplateSpec{
							Metadata: &opv1.Metadata{
								Labels:      map[string]string{"pod-label": "1"},
								Annotations: map[string]string{"pod-annot": "1"},
							},
							Spec: &opv1.CalicoNodeDaemonSetPodSpec{
								InitContainers: []opv1.CalicoNodeDaemonSetInitContainer{_calicoNodeInit1a},
								Affinity:       _aff1,
								NodeSelector:   map[string]string{"overridden": "selector"},
								Tolerations:    []v1.Toleration{},
							},
						},
					},
				},
				&opv1.CalicoNodeDaemonSet{
					Metadata: &opv1.Metadata{
						Labels:      map[string]string{"overridden": "1"},
						Annotations: map[string]string{"a": "1"},
					},
					Spec: &opv1.CalicoNodeDaemonSetSpec{
						MinReadySeconds: intPtr(5),
						Template: &opv1.CalicoNodeDaemonSetPodTemplateSpec{
							Metadata: &opv1.Metadata{
								Labels:      map[string]string{"pod-label": "1"},
								Annotations: map[string]string{"pod-annot": "1"},
							},
							Spec: &opv1.CalicoNodeDaemonSetPodSpec{
								Containers:     []opv1.CalicoNodeDaemonSetContainer{_calicoNode1a},
								InitContainers: []opv1.CalicoNodeDaemonSetInitContainer{_calicoNodeInit1a},
								Affinity:       _aff1,
								NodeSelector:   map[string]string{"overridden": "selector"},
								Tolerations:    []v1.Toleration{},
							},
						},
					},
				},
			))
	})
	Context("test CalicoNodeWindowsDaemonSet merge", func() {
		var m opv1.InstallationSpec
		var s opv1.InstallationSpec

		BeforeEach(func() {
			m = opv1.InstallationSpec{
				CalicoNodeWindowsDaemonSet: &opv1.CalicoNodeWindowsDaemonSet{
					Spec: &opv1.CalicoNodeWindowsDaemonSetSpec{
						Template: &opv1.CalicoNodeWindowsDaemonSetPodTemplateSpec{
							Spec: &opv1.CalicoNodeWindowsDaemonSetPodSpec{},
						},
					},
				},
			}
			s = opv1.InstallationSpec{
				CalicoNodeWindowsDaemonSet: &opv1.CalicoNodeWindowsDaemonSet{
					Spec: &opv1.CalicoNodeWindowsDaemonSetSpec{
						Template: &opv1.CalicoNodeWindowsDaemonSetPodTemplateSpec{
							Spec: &opv1.CalicoNodeWindowsDaemonSetPodSpec{},
						},
					},
				},
			}
		})

		DescribeTable("merge metadata", func(main, second, expect *opv1.Metadata) {
			// start with empty installation spec
			m = opv1.InstallationSpec{}
			s = opv1.InstallationSpec{}
			if main != nil {
				m.CalicoNodeWindowsDaemonSet = &opv1.CalicoNodeWindowsDaemonSet{Metadata: main}
			}
			if second != nil {
				s.CalicoNodeWindowsDaemonSet = &opv1.CalicoNodeWindowsDaemonSet{Metadata: second}
			}
			inst := OverrideInstallationSpec(m, s)
			if expect == nil {
				Expect(inst.CalicoNodeWindowsDaemonSet).To(BeNil())
			} else {
				Expect(*inst.CalicoNodeWindowsDaemonSet.Metadata).To(Equal(*expect))
			}
		}, metadataTests)

		DescribeTable("merge minReadySeconds", func(main, second, expect *int32) {
			m.CalicoNodeWindowsDaemonSet.Spec.MinReadySeconds = main
			s.CalicoNodeWindowsDaemonSet.Spec.MinReadySeconds = second
			inst := OverrideInstallationSpec(m, s)
			if expect == nil {
				Expect(inst.CalicoNodeWindowsDaemonSet.Spec.MinReadySeconds).To(BeNil())
			} else {
				Expect(*inst.CalicoNodeWindowsDaemonSet.Spec.MinReadySeconds).To(Equal(*expect))
			}
		},
			Entry("Both unset", nil, nil, nil),
			Entry("Main only set", intPtr(23), nil, intPtr(23)),
			Entry("Second only set", nil, intPtr(23), intPtr(23)),
			Entry("Both set equal", intPtr(23), intPtr(23), intPtr(23)),
			Entry("Both set not equal", intPtr(23), intPtr(42), intPtr(42)),
		)
		DescribeTable("merge pod template metadata", func(main, second, expect *opv1.Metadata) {
			m.CalicoNodeWindowsDaemonSet.Spec.Template.Metadata = main
			s.CalicoNodeWindowsDaemonSet.Spec.Template.Metadata = second
			inst := OverrideInstallationSpec(m, s)
			if expect == nil {
				Expect(inst.CalicoNodeWindowsDaemonSet.Spec.Template.Metadata).To(BeNil())
			} else {
				Expect(*inst.CalicoNodeWindowsDaemonSet.Spec.Template.Metadata).To(Equal(*expect))
			}
		}, metadataTests)

		_resources1 := &v1.ResourceRequirements{
			Requests: v1.ResourceList{v1.ResourceCPU: resource.MustParse("500m")},
			Limits:   v1.ResourceList{v1.ResourceCPU: resource.MustParse("500m")},
		}
		_resources2 := &v1.ResourceRequirements{
			Requests: v1.ResourceList{v1.ResourceCPU: resource.MustParse("1000m"), v1.ResourceMemory: resource.MustParse("500Mi")},
			Limits:   v1.ResourceList{v1.ResourceCPU: resource.MustParse("1000m"), v1.ResourceMemory: resource.MustParse("1000Mi")},
		}
		_calicoNodeInit1a := opv1.CalicoNodeWindowsDaemonSetInitContainer{Name: "init1", Resources: _resources1}
		_calicoNodeInit1b := opv1.CalicoNodeWindowsDaemonSetInitContainer{Name: "init1", Resources: _resources2}
		_calicoNodeInit2 := opv1.CalicoNodeWindowsDaemonSetInitContainer{Name: "init2", Resources: _resources2}

		DescribeTable("merge initContainers", func(main, second, expect []opv1.CalicoNodeWindowsDaemonSetInitContainer) {
			m.CalicoNodeWindowsDaemonSet.Spec.Template.Spec.InitContainers = main
			s.CalicoNodeWindowsDaemonSet.Spec.Template.Spec.InitContainers = second
			inst := OverrideInstallationSpec(m, s)
			if expect == nil {
				Expect(inst.CalicoNodeWindowsDaemonSet.Spec.Template.Spec.InitContainers).To(BeNil())
			} else {
				Expect(inst.CalicoNodeWindowsDaemonSet.Spec.Template.Spec.InitContainers).To(Equal(expect))
			}
		},
			Entry("Both unset", nil, nil, nil),
			Entry("Main only set", []opv1.CalicoNodeWindowsDaemonSetInitContainer{_calicoNodeInit1a, _calicoNodeInit2}, nil, []opv1.CalicoNodeWindowsDaemonSetInitContainer{_calicoNodeInit1a, _calicoNodeInit2}),
			Entry("Second only set", nil, []opv1.CalicoNodeWindowsDaemonSetInitContainer{_calicoNodeInit1a, _calicoNodeInit2}, []opv1.CalicoNodeWindowsDaemonSetInitContainer{_calicoNodeInit1a, _calicoNodeInit2}),
			Entry("Both set equal", []opv1.CalicoNodeWindowsDaemonSetInitContainer{_calicoNodeInit1a, _calicoNodeInit2}, []opv1.CalicoNodeWindowsDaemonSetInitContainer{_calicoNodeInit1a, _calicoNodeInit2},
				[]opv1.CalicoNodeWindowsDaemonSetInitContainer{_calicoNodeInit1a, _calicoNodeInit2}),
			Entry("Both set not equal", []opv1.CalicoNodeWindowsDaemonSetInitContainer{_calicoNodeInit1a, _calicoNodeInit2}, []opv1.CalicoNodeWindowsDaemonSetInitContainer{_calicoNodeInit1b, _calicoNodeInit2},
				[]opv1.CalicoNodeWindowsDaemonSetInitContainer{_calicoNodeInit1b, _calicoNodeInit2}),
		)

		_calicoNode1a := opv1.CalicoNodeWindowsDaemonSetContainer{Name: "node1", Resources: _resources1}
		_calicoNode1b := opv1.CalicoNodeWindowsDaemonSetContainer{Name: "node1", Resources: _resources2}
		_calicoNode2 := opv1.CalicoNodeWindowsDaemonSetContainer{Name: "node2", Resources: _resources2}

		DescribeTable("merge containers", func(main, second, expect []opv1.CalicoNodeWindowsDaemonSetContainer) {
			m.CalicoNodeWindowsDaemonSet.Spec.Template.Spec.Containers = main
			s.CalicoNodeWindowsDaemonSet.Spec.Template.Spec.Containers = second
			inst := OverrideInstallationSpec(m, s)
			if expect == nil {
				Expect(inst.CalicoNodeWindowsDaemonSet.Spec.Template.Spec.Containers).To(BeNil())
			} else {
				Expect(inst.CalicoNodeWindowsDaemonSet.Spec.Template.Spec.Containers).To(Equal(expect))
			}
		},
			Entry("Both unset", nil, nil, nil),
			Entry("Main only set", []opv1.CalicoNodeWindowsDaemonSetContainer{_calicoNode1a, _calicoNode1b}, nil, []opv1.CalicoNodeWindowsDaemonSetContainer{_calicoNode1a, _calicoNode1b}),
			Entry("Second only set", nil, []opv1.CalicoNodeWindowsDaemonSetContainer{_calicoNode1a, _calicoNode1b}, []opv1.CalicoNodeWindowsDaemonSetContainer{_calicoNode1a, _calicoNode1b}),
			Entry("Both set equal", []opv1.CalicoNodeWindowsDaemonSetContainer{_calicoNode1a, _calicoNode1b}, []opv1.CalicoNodeWindowsDaemonSetContainer{_calicoNode1a, _calicoNode1b},
				[]opv1.CalicoNodeWindowsDaemonSetContainer{_calicoNode1a, _calicoNode1b}),
			Entry("Both set not equal", []opv1.CalicoNodeWindowsDaemonSetContainer{_calicoNode1a, _calicoNode2}, []opv1.CalicoNodeWindowsDaemonSetContainer{_calicoNode1b, _calicoNode2},
				[]opv1.CalicoNodeWindowsDaemonSetContainer{_calicoNode1b, _calicoNode2}),
		)

		_aff1 := &v1.Affinity{
			NodeAffinity: &v1.NodeAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution: &v1.NodeSelector{
					NodeSelectorTerms: []v1.NodeSelectorTerm{{
						MatchExpressions: []v1.NodeSelectorRequirement{{
							Key:      "custom-affinity-key",
							Operator: v1.NodeSelectorOpExists,
						}},
					}},
				},
			},
		}
		_aff2 := &v1.Affinity{
			NodeAffinity: &v1.NodeAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution: &v1.NodeSelector{
					NodeSelectorTerms: []v1.NodeSelectorTerm{{
						MatchExpressions: []v1.NodeSelectorRequirement{{
							Key:      "custom-affinity-key2",
							Operator: v1.NodeSelectorOpExists,
						}},
					}},
				},
			},
		}
		_affEmpty := &v1.Affinity{}

		DescribeTable("merge affinity", func(main, second, expect *v1.Affinity) {
			m.CalicoNodeWindowsDaemonSet.Spec.Template.Spec.Affinity = main
			s.CalicoNodeWindowsDaemonSet.Spec.Template.Spec.Affinity = second
			inst := OverrideInstallationSpec(m, s)
			if expect == nil {
				Expect(inst.CalicoNodeWindowsDaemonSet.Spec.Template.Spec.Affinity).To(BeNil())
			} else {
				Expect(*inst.CalicoNodeWindowsDaemonSet.Spec.Template.Spec.Affinity).To(Equal(*expect))
			}
		},
			Entry("Both unset", nil, nil, nil),
			Entry("Main only set", _aff1, nil, _aff1),
			Entry("Second only set", nil, _aff1, _aff1),
			Entry("Both set equal", _aff1, _aff1, _aff1),
			Entry("Both set not equal", _aff1, _aff2, _aff2),
			Entry("Both set not equal, override empty", _aff1, _affEmpty, _affEmpty),
		)

		DescribeTable("merge nodeSelector", func(main, second, expect map[string]string) {
			m.CalicoNodeWindowsDaemonSet.Spec.Template.Spec.NodeSelector = main
			s.CalicoNodeWindowsDaemonSet.Spec.Template.Spec.NodeSelector = second
			inst := OverrideInstallationSpec(m, s)
			if expect == nil {
				Expect(inst.CalicoNodeWindowsDaemonSet.Spec.Template.Spec.NodeSelector).To(BeNil())
			} else {
				Expect(inst.CalicoNodeWindowsDaemonSet.Spec.Template.Spec.NodeSelector).To(Equal(expect))
			}
		},
			Entry("Both unset", nil, nil, nil),
			Entry("Main only set", map[string]string{"a1": "1"}, nil, map[string]string{"a1": "1"}),
			Entry("Second only set", nil, map[string]string{"a1": "1"}, map[string]string{"a1": "1"}),
			Entry("Both set equal", map[string]string{"a1": "1"}, map[string]string{"a1": "1"}, map[string]string{"a1": "1"}),
			Entry("Both set not equal", map[string]string{"a1": "1"}, map[string]string{"a1": "2", "b1": "3"}, map[string]string{"a1": "2", "b1": "3"}),
			Entry("Both set not equal, override empty", map[string]string{"a1": "1"}, map[string]string{}, map[string]string{}),
		)

		_toleration1 := v1.Toleration{
			Key:      "foo",
			Operator: v1.TolerationOpEqual,
			Value:    "bar",
		}
		_toleration2 := v1.Toleration{
			Key:      "bar",
			Operator: v1.TolerationOpEqual,
			Value:    "baz",
		}

		DescribeTable("merge tolerations", func(main, second, expect []v1.Toleration) {
			m.CalicoNodeWindowsDaemonSet.Spec.Template.Spec.Tolerations = main
			s.CalicoNodeWindowsDaemonSet.Spec.Template.Spec.Tolerations = second
			inst := OverrideInstallationSpec(m, s)
			if expect == nil {
				Expect(inst.CalicoNodeWindowsDaemonSet.Spec.Template.Spec.Tolerations).To(BeNil())
			} else {
				Expect(inst.CalicoNodeWindowsDaemonSet.Spec.Template.Spec.Tolerations).To(Equal(expect))
			}
		},
			Entry("Both unset", nil, nil, nil),
			Entry("Main only set", []v1.Toleration{_toleration1}, nil, []v1.Toleration{_toleration1}),
			Entry("Second only set", nil, []v1.Toleration{_toleration1}, []v1.Toleration{_toleration1}),
			Entry("Both set equal", []v1.Toleration{_toleration1}, []v1.Toleration{_toleration1}, []v1.Toleration{_toleration1}),
			Entry("Both set not equal", []v1.Toleration{_toleration1}, []v1.Toleration{_toleration2}, []v1.Toleration{_toleration2}),
			Entry("Both set not equal, override empty", []v1.Toleration{_toleration1}, []v1.Toleration{}, []v1.Toleration{}),
		)

		DescribeTable("merge multiple CalicoDaemonSet fields", func(main, second, expect *opv1.CalicoNodeWindowsDaemonSet) {
			// start with empty spec
			m = opv1.InstallationSpec{}
			s = opv1.InstallationSpec{}
			if main != nil {
				m.CalicoNodeWindowsDaemonSet = main
			}
			if second != nil {
				s.CalicoNodeWindowsDaemonSet = second
			}
			inst := OverrideInstallationSpec(m, s)
			if expect == nil {
				Expect(inst.CalicoNodeWindowsDaemonSet).To(BeNil())
			} else {
				Expect(*inst.CalicoNodeWindowsDaemonSet).To(Equal(*expect))
			}
		},
			Entry("Both unset", nil, nil, nil),
			Entry("Different fields in the two are merged, some overridden",
				&opv1.CalicoNodeWindowsDaemonSet{
					Metadata: &opv1.Metadata{
						Labels: map[string]string{"l": "1"},
					},
					Spec: &opv1.CalicoNodeWindowsDaemonSetSpec{
						MinReadySeconds: intPtr(5),
						Template: &opv1.CalicoNodeWindowsDaemonSetPodTemplateSpec{
							Spec: &opv1.CalicoNodeWindowsDaemonSetPodSpec{
								Containers:   []opv1.CalicoNodeWindowsDaemonSetContainer{_calicoNode1a},
								NodeSelector: map[string]string{"selector": "test"},
								Tolerations:  []v1.Toleration{_toleration1},
							},
						},
					},
				},
				&opv1.CalicoNodeWindowsDaemonSet{
					Metadata: &opv1.Metadata{
						Labels:      map[string]string{"overridden": "1"},
						Annotations: map[string]string{"a": "1"},
					},
					Spec: &opv1.CalicoNodeWindowsDaemonSetSpec{
						Template: &opv1.CalicoNodeWindowsDaemonSetPodTemplateSpec{
							Metadata: &opv1.Metadata{
								Labels:      map[string]string{"pod-label": "1"},
								Annotations: map[string]string{"pod-annot": "1"},
							},
							Spec: &opv1.CalicoNodeWindowsDaemonSetPodSpec{
								InitContainers: []opv1.CalicoNodeWindowsDaemonSetInitContainer{_calicoNodeInit1a},
								Affinity:       _aff1,
								NodeSelector:   map[string]string{"overridden": "selector"},
								Tolerations:    []v1.Toleration{},
							},
						},
					},
				},
				&opv1.CalicoNodeWindowsDaemonSet{
					Metadata: &opv1.Metadata{
						Labels:      map[string]string{"overridden": "1"},
						Annotations: map[string]string{"a": "1"},
					},
					Spec: &opv1.CalicoNodeWindowsDaemonSetSpec{
						MinReadySeconds: intPtr(5),
						Template: &opv1.CalicoNodeWindowsDaemonSetPodTemplateSpec{
							Metadata: &opv1.Metadata{
								Labels:      map[string]string{"pod-label": "1"},
								Annotations: map[string]string{"pod-annot": "1"},
							},
							Spec: &opv1.CalicoNodeWindowsDaemonSetPodSpec{
								Containers:     []opv1.CalicoNodeWindowsDaemonSetContainer{_calicoNode1a},
								InitContainers: []opv1.CalicoNodeWindowsDaemonSetInitContainer{_calicoNodeInit1a},
								Affinity:       _aff1,
								NodeSelector:   map[string]string{"overridden": "selector"},
								Tolerations:    []v1.Toleration{},
							},
						},
					},
				},
			))
	})
	Context("test CSINodeDriverDaemonSet merge", func() {
		var m opv1.InstallationSpec
		var s opv1.InstallationSpec

		BeforeEach(func() {
			m = opv1.InstallationSpec{
				CSINodeDriverDaemonSet: &opv1.CSINodeDriverDaemonSet{
					Spec: &opv1.CSINodeDriverDaemonSetSpec{
						Template: &opv1.CSINodeDriverDaemonSetPodTemplateSpec{
							Spec: &opv1.CSINodeDriverDaemonSetPodSpec{},
						},
					},
				},
			}
			s = opv1.InstallationSpec{
				CSINodeDriverDaemonSet: &opv1.CSINodeDriverDaemonSet{
					Spec: &opv1.CSINodeDriverDaemonSetSpec{
						Template: &opv1.CSINodeDriverDaemonSetPodTemplateSpec{
							Spec: &opv1.CSINodeDriverDaemonSetPodSpec{},
						},
					},
				},
			}
		})

		DescribeTable("merge metadata", func(main, second, expect *opv1.Metadata) {
			// start with empty installation spec
			m = opv1.InstallationSpec{}
			s = opv1.InstallationSpec{}
			if main != nil {
				m.CSINodeDriverDaemonSet = &opv1.CSINodeDriverDaemonSet{Metadata: main}
			}
			if second != nil {
				s.CSINodeDriverDaemonSet = &opv1.CSINodeDriverDaemonSet{Metadata: second}
			}
			inst := OverrideInstallationSpec(m, s)
			if expect == nil {
				Expect(inst.CSINodeDriverDaemonSet).To(BeNil())
			} else {
				Expect(*inst.CSINodeDriverDaemonSet.Metadata).To(Equal(*expect))
			}
		}, metadataTests)

		DescribeTable("merge pod template metadata", func(main, second, expect *opv1.Metadata) {
			m.CSINodeDriverDaemonSet.Spec.Template.Metadata = main
			s.CSINodeDriverDaemonSet.Spec.Template.Metadata = second
			inst := OverrideInstallationSpec(m, s)
			if expect == nil {
				Expect(inst.CSINodeDriverDaemonSet.Spec.Template.Metadata).To(BeNil())
			} else {
				Expect(*inst.CSINodeDriverDaemonSet.Spec.Template.Metadata).To(Equal(*expect))
			}
		}, metadataTests)
		_csiNodeDriver1a := opv1.CSINodeDriverDaemonSetContainer{Name: "csi1"}
		_csiNodeDriver1b := opv1.CSINodeDriverDaemonSetContainer{Name: "csi1"}
		_csiNodeDriver2 := opv1.CSINodeDriverDaemonSetContainer{Name: "csi2"}

		DescribeTable("merge containers", func(main, second, expect []opv1.CSINodeDriverDaemonSetContainer) {
			m.CSINodeDriverDaemonSet.Spec.Template.Spec.Containers = main
			s.CSINodeDriverDaemonSet.Spec.Template.Spec.Containers = second
			inst := OverrideInstallationSpec(m, s)
			if expect == nil {
				Expect(inst.CSINodeDriverDaemonSet.Spec.Template.Spec.Containers).To(BeNil())
			} else {
				Expect(inst.CSINodeDriverDaemonSet.Spec.Template.Spec.Containers).To(Equal(expect))
			}
		},
			Entry("Both unset", nil, nil, nil),
			Entry("Main only set", []opv1.CSINodeDriverDaemonSetContainer{_csiNodeDriver1a, _csiNodeDriver1b}, nil, []opv1.CSINodeDriverDaemonSetContainer{_csiNodeDriver1a, _csiNodeDriver1b}),
			Entry("Second only set", nil, []opv1.CSINodeDriverDaemonSetContainer{_csiNodeDriver1a, _csiNodeDriver1b}, []opv1.CSINodeDriverDaemonSetContainer{_csiNodeDriver1a, _csiNodeDriver1b}),
			Entry("Both set equal", []opv1.CSINodeDriverDaemonSetContainer{_csiNodeDriver1a, _csiNodeDriver1b}, []opv1.CSINodeDriverDaemonSetContainer{_csiNodeDriver1a, _csiNodeDriver1b},
				[]opv1.CSINodeDriverDaemonSetContainer{_csiNodeDriver1a, _csiNodeDriver1b}),
			Entry("Both set not equal", []opv1.CSINodeDriverDaemonSetContainer{_csiNodeDriver1a, _csiNodeDriver2}, []opv1.CSINodeDriverDaemonSetContainer{_csiNodeDriver1b, _csiNodeDriver2},
				[]opv1.CSINodeDriverDaemonSetContainer{_csiNodeDriver1b, _csiNodeDriver2}),
		)

		_aff1 := &v1.Affinity{
			NodeAffinity: &v1.NodeAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution: &v1.NodeSelector{
					NodeSelectorTerms: []v1.NodeSelectorTerm{{
						MatchExpressions: []v1.NodeSelectorRequirement{{
							Key:      "custom-affinity-key",
							Operator: v1.NodeSelectorOpExists,
						}},
					}},
				},
			},
		}
		_aff2 := &v1.Affinity{
			NodeAffinity: &v1.NodeAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution: &v1.NodeSelector{
					NodeSelectorTerms: []v1.NodeSelectorTerm{{
						MatchExpressions: []v1.NodeSelectorRequirement{{
							Key:      "custom-affinity-key2",
							Operator: v1.NodeSelectorOpExists,
						}},
					}},
				},
			},
		}
		_affEmpty := &v1.Affinity{}

		DescribeTable("merge affinity", func(main, second, expect *v1.Affinity) {
			m.CSINodeDriverDaemonSet.Spec.Template.Spec.Affinity = main
			s.CSINodeDriverDaemonSet.Spec.Template.Spec.Affinity = second
			inst := OverrideInstallationSpec(m, s)
			if expect == nil {
				Expect(inst.CSINodeDriverDaemonSet.Spec.Template.Spec.Affinity).To(BeNil())
			} else {
				Expect(*inst.CSINodeDriverDaemonSet.Spec.Template.Spec.Affinity).To(Equal(*expect))
			}
		},
			Entry("Both unset", nil, nil, nil),
			Entry("Main only set", _aff1, nil, _aff1),
			Entry("Second only set", nil, _aff1, _aff1),
			Entry("Both set equal", _aff1, _aff1, _aff1),
			Entry("Both set not equal", _aff1, _aff2, _aff2),
			Entry("Both set not equal, override empty", _aff1, _affEmpty, _affEmpty),
		)

		DescribeTable("merge nodeSelector", func(main, second, expect map[string]string) {
			m.CSINodeDriverDaemonSet.Spec.Template.Spec.NodeSelector = main
			s.CSINodeDriverDaemonSet.Spec.Template.Spec.NodeSelector = second
			inst := OverrideInstallationSpec(m, s)
			if expect == nil {
				Expect(inst.CSINodeDriverDaemonSet.Spec.Template.Spec.NodeSelector).To(BeNil())
			} else {
				Expect(inst.CSINodeDriverDaemonSet.Spec.Template.Spec.NodeSelector).To(Equal(expect))
			}
		},
			Entry("Both unset", nil, nil, nil),
			Entry("Main only set", map[string]string{"a1": "1"}, nil, map[string]string{"a1": "1"}),
			Entry("Second only set", nil, map[string]string{"a1": "1"}, map[string]string{"a1": "1"}),
			Entry("Both set equal", map[string]string{"a1": "1"}, map[string]string{"a1": "1"}, map[string]string{"a1": "1"}),
			Entry("Both set not equal", map[string]string{"a1": "1"}, map[string]string{"a1": "2", "b1": "3"}, map[string]string{"a1": "2", "b1": "3"}),
			Entry("Both set not equal, override empty", map[string]string{"a1": "1"}, map[string]string{}, map[string]string{}),
		)

		_toleration1 := v1.Toleration{
			Key:      "foo",
			Operator: v1.TolerationOpEqual,
			Value:    "bar",
		}
		_toleration2 := v1.Toleration{
			Key:      "bar",
			Operator: v1.TolerationOpEqual,
			Value:    "baz",
		}

		DescribeTable("merge tolerations", func(main, second, expect []v1.Toleration) {
			m.CSINodeDriverDaemonSet.Spec.Template.Spec.Tolerations = main
			s.CSINodeDriverDaemonSet.Spec.Template.Spec.Tolerations = second
			inst := OverrideInstallationSpec(m, s)
			if expect == nil {
				Expect(inst.CSINodeDriverDaemonSet.Spec.Template.Spec.Tolerations).To(BeNil())
			} else {
				Expect(inst.CSINodeDriverDaemonSet.Spec.Template.Spec.Tolerations).To(Equal(expect))
			}
		},
			Entry("Both unset", nil, nil, nil),
			Entry("Main only set", []v1.Toleration{_toleration1}, nil, []v1.Toleration{_toleration1}),
			Entry("Second only set", nil, []v1.Toleration{_toleration1}, []v1.Toleration{_toleration1}),
			Entry("Both set equal", []v1.Toleration{_toleration1}, []v1.Toleration{_toleration1}, []v1.Toleration{_toleration1}),
			Entry("Both set not equal", []v1.Toleration{_toleration1}, []v1.Toleration{_toleration2}, []v1.Toleration{_toleration2}),
			Entry("Both set not equal, override empty", []v1.Toleration{_toleration1}, []v1.Toleration{}, []v1.Toleration{}),
		)

		DescribeTable("merge multiple CSINodeDriverDaemonSet fields", func(main, second, expect *opv1.CSINodeDriverDaemonSet) {
			// start with empty spec
			m = opv1.InstallationSpec{}
			s = opv1.InstallationSpec{}
			if main != nil {
				m.CSINodeDriverDaemonSet = main
			}
			if second != nil {
				s.CSINodeDriverDaemonSet = second
			}
			inst := OverrideInstallationSpec(m, s)
			if expect == nil {
				Expect(inst.CSINodeDriverDaemonSet).To(BeNil())
			} else {
				Expect(*inst.CSINodeDriverDaemonSet).To(Equal(*expect))
			}
		},
			Entry("Both unset", nil, nil, nil),
			Entry("Different fields in the two are merged, some overridden",
				&opv1.CSINodeDriverDaemonSet{
					Metadata: &opv1.Metadata{
						Labels: map[string]string{"l": "1"},
					},
					Spec: &opv1.CSINodeDriverDaemonSetSpec{
						MinReadySeconds: intPtr(5),
						Template: &opv1.CSINodeDriverDaemonSetPodTemplateSpec{
							Spec: &opv1.CSINodeDriverDaemonSetPodSpec{
								Containers:   []opv1.CSINodeDriverDaemonSetContainer{_csiNodeDriver1a},
								NodeSelector: map[string]string{"selector": "test"},
								Tolerations:  []v1.Toleration{_toleration1},
							},
						},
					},
				},
				&opv1.CSINodeDriverDaemonSet{
					Metadata: &opv1.Metadata{
						Labels:      map[string]string{"overridden": "1"},
						Annotations: map[string]string{"a": "1"},
					},
					Spec: &opv1.CSINodeDriverDaemonSetSpec{
						Template: &opv1.CSINodeDriverDaemonSetPodTemplateSpec{
							Metadata: &opv1.Metadata{
								Labels:      map[string]string{"pod-label": "1"},
								Annotations: map[string]string{"pod-annot": "1"},
							},
							Spec: &opv1.CSINodeDriverDaemonSetPodSpec{
								Affinity:     _aff1,
								NodeSelector: map[string]string{"overridden": "selector"},
								Tolerations:  []v1.Toleration{},
							},
						},
					},
				},
				&opv1.CSINodeDriverDaemonSet{
					Metadata: &opv1.Metadata{
						Labels:      map[string]string{"overridden": "1"},
						Annotations: map[string]string{"a": "1"},
					},
					Spec: &opv1.CSINodeDriverDaemonSetSpec{
						MinReadySeconds: intPtr(5),
						Template: &opv1.CSINodeDriverDaemonSetPodTemplateSpec{
							Metadata: &opv1.Metadata{
								Labels:      map[string]string{"pod-label": "1"},
								Annotations: map[string]string{"pod-annot": "1"},
							},
							Spec: &opv1.CSINodeDriverDaemonSetPodSpec{
								Containers:   []opv1.CSINodeDriverDaemonSetContainer{_csiNodeDriver1a},
								Affinity:     _aff1,
								NodeSelector: map[string]string{"overridden": "selector"},
								Tolerations:  []v1.Toleration{},
							},
						},
					},
				},
			))
	})

	Context("test CalicoKubeControllersDeployment merge", func() {
		// TODO
	})
	Context("test TyphaDeployment merge", func() {
		// TODO
	})
	Context("test CalicoWindowsUpgradeDaemonSet merge", func() {
		// TODO
	})

	Context("all fields handled", func() {
		var defaulted opv1.InstallationSpec
		BeforeEach(func() {
			defaulter := test.NewNonZeroStructDefaulter()
			Expect(defaulter.SetDefault(&defaulted)).ToNot(HaveOccurred())
		})

		It("when set in cfg", func() {
			inst := OverrideInstallationSpec(
				defaulted,
				opv1.InstallationSpec{},
			)

			changeLog, err := diff.Diff(defaulted, inst)
			Expect(err).NotTo(HaveOccurred())

			Expect(changeLog).To(HaveLen(0))
			Expect(reflect.DeepEqual(inst, defaulted)).To(BeTrue(),
				fmt.Sprintf("Differences: %+v", changeLog))
		})
		It("when set in override", func() {
			inst := OverrideInstallationSpec(
				opv1.InstallationSpec{CalicoNetwork: &opv1.CalicoNetworkSpec{}},
				defaulted,
			)

			changeLog, err := diff.Diff(defaulted, inst)
			Expect(err).NotTo(HaveOccurred())
			Expect(changeLog).To(HaveLen(0))
			Expect(reflect.DeepEqual(inst, defaulted)).To(BeTrue(),
				fmt.Sprintf("Differences: %+v", changeLog))
		})
		DescribeTable("merge defaulted", func(cfg, override, expect *opv1.InstallationSpec) {
			inst := OverrideInstallationSpec(*cfg, *override)

			changeLog, err := diff.Diff(inst, *expect)
			Expect(err).NotTo(HaveOccurred())
			Expect(changeLog).To(HaveLen(0))
			Expect(reflect.DeepEqual(inst, defaulted)).To(BeTrue(),
				fmt.Sprintf("Differences: %+v", changeLog))
		},
			// We must pass defaulted as a pointer here because the BeforeEach is processed
			// after the Entrys are evaluated to It.
			Entry("empty cfg",
				&opv1.InstallationSpec{},
				&defaulted,
				&defaulted),
			Entry("empty override",
				&defaulted,
				&opv1.InstallationSpec{},
				&defaulted),
			Entry("empty cfg with substruct defaults",
				&opv1.InstallationSpec{
					CalicoNetwork: &opv1.CalicoNetworkSpec{},
					CNI:           &opv1.CNISpec{},
				},
				&defaulted,
				&defaulted),
			Entry("empty override with substruct defaults",
				&defaulted,
				&opv1.InstallationSpec{
					CalicoNetwork: &opv1.CalicoNetworkSpec{},
					CNI:           &opv1.CNISpec{},
				},
				&defaulted),
		)

		DescribeTable("merge NetworkPolicy", func(main, second, expect *opv1.NetworkPolicySpec) {
			m := opv1.InstallationSpec{NetworkPolicy: main}
			s := opv1.InstallationSpec{NetworkPolicy: second}
			inst := OverrideInstallationSpec(m, s)
			Expect(inst.NetworkPolicy).To(Equal(expect))
		},
			Entry("Both unset", nil, nil, nil),
			Entry("Main set, second unset", npSpec(&enabled), nil, npSpec(&enabled)),
			Entry("Main unset, second set", nil, npSpec(&enabled), npSpec(&enabled)),
			Entry("Both set, different", npSpec(&enabled), npSpec(&disabled), npSpec(&disabled)),
		)
	})
})
