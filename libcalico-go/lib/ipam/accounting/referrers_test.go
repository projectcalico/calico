// Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

package accounting

import (
	"testing"

	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/libcalico-go/lib/apis/internalapi"
)

func refStrings(refs []AddressRef) []string {
	var out []string
	for _, r := range refs {
		out = append(out, r.IP.String()+" "+string(r.Kind)+" "+r.Referrer.String())
	}
	return out
}

func TestNodeAddressRefs(t *testing.T) {
	RegisterTestingT(t)
	node := &internalapi.Node{
		ObjectMeta: metav1.ObjectMeta{Name: "node-a"},
		Spec: internalapi.NodeSpec{
			IPv4VXLANTunnelAddr: "10.0.0.1",
			BGP:                 &internalapi.NodeBGPSpec{IPv4IPIPTunnelAddr: "10.0.0.2"},
			Wireguard:           &internalapi.NodeWireguardSpec{InterfaceIPv6Address: "fd00::3"},
		},
	}
	refs, err := NodeAddressRefs(node)
	Expect(err).NotTo(HaveOccurred())
	Expect(refStrings(refs)).To(Equal([]string{
		"10.0.0.1 Tunnel Node(node-a)",
		"10.0.0.2 Tunnel Node(node-a)",
		"fd00::3 Tunnel Node(node-a)",
	}))

	node.Spec.IPv6VXLANTunnelAddr = "not-an-ip"
	_, err = NodeAddressRefs(node)
	Expect(err).To(HaveOccurred())
}

func TestWorkloadEndpointAddressRefs(t *testing.T) {
	RegisterTestingT(t)
	wep := &internalapi.WorkloadEndpoint{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "pod"},
		Spec:       internalapi.WorkloadEndpointSpec{IPNetworks: []string{"10.0.0.5/32", "fd00::5/128"}},
	}
	refs, err := WorkloadEndpointAddressRefs(wep)
	Expect(err).NotTo(HaveOccurred())
	Expect(refStrings(refs)).To(Equal([]string{
		"10.0.0.5 Workload Workload(default/pod)",
		"fd00::5 Workload Workload(default/pod)",
	}))
}

func TestServiceAddressRefs(t *testing.T) {
	RegisterTestingT(t)
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "svc"},
		Status: corev1.ServiceStatus{LoadBalancer: corev1.LoadBalancerStatus{Ingress: []corev1.LoadBalancerIngress{
			{IP: "10.0.1.1"},
			{Hostname: "lb.example.com"},
		}}},
	}
	refs, err := ServiceAddressRefs(svc)
	Expect(err).NotTo(HaveOccurred())
	Expect(refStrings(refs)).To(Equal([]string{"10.0.1.1 LoadBalancer Service(default/svc)"}))
	Expect(refs[0].Kind).To(Equal(v3.IPPoolAllowedUseLoadBalancer))
}
