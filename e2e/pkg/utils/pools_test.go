// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package utils

import (
	"testing"

	"github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func testPool(name, cidr string, mutate ...func(*v3.IPPoolSpec)) v3.IPPool {
	p := v3.IPPool{ObjectMeta: metav1.ObjectMeta{Name: name}, Spec: v3.IPPoolSpec{CIDR: cidr}}
	for _, m := range mutate {
		m(&p.Spec)
	}
	return p
}

type poolFamiliesTestCase struct {
	name    string
	pools   []v3.IPPool
	want    []IPFamily
	wantErr string
}

func TestPoolFamilies(t *testing.T) {
	disabled := func(s *v3.IPPoolSpec) { s.Disabled = true }
	tunnelOnly := func(s *v3.IPPoolSpec) { s.AllowedUses = []v3.IPPoolAllowedUse{v3.IPPoolAllowedUseTunnel} }
	workloadAndTunnel := func(s *v3.IPPoolSpec) {
		s.AllowedUses = []v3.IPPoolAllowedUse{v3.IPPoolAllowedUseWorkload, v3.IPPoolAllowedUseTunnel}
	}
	manual := func(s *v3.IPPoolSpec) { m := v3.Manual; s.AssignmentMode = &m }
	automatic := func(s *v3.IPPoolSpec) { a := v3.Automatic; s.AssignmentMode = &a }

	for _, tc := range []poolFamiliesTestCase{
		{
			name:  "IPv4-only",
			pools: []v3.IPPool{testPool("v4", "192.168.0.0/16")},
			want:  []IPFamily{IPv4},
		},
		{
			name:  "IPv6-only",
			pools: []v3.IPPool{testPool("v6", "fd00:10::/64")},
			want:  []IPFamily{IPv6},
		},
		{
			name:  "dual-stack lists IPv4 first whatever the pool order",
			pools: []v3.IPPool{testPool("v6", "fd00:10::/64"), testPool("v4", "192.168.0.0/16"), testPool("v4b", "10.10.0.0/16")},
			want:  []IPFamily{IPv4, IPv6},
		},
		{
			name:  "disabled pool doesn't count",
			pools: []v3.IPPool{testPool("v4", "192.168.0.0/16"), testPool("v6", "fd00:10::/64", disabled)},
			want:  []IPFamily{IPv4},
		},
		{
			name:  "tunnel-only pool doesn't count",
			pools: []v3.IPPool{testPool("v4", "192.168.0.0/16"), testPool("v6", "fd00:10::/64", tunnelOnly)},
			want:  []IPFamily{IPv4},
		},
		{
			name:  "workload and tunnel pool counts",
			pools: []v3.IPPool{testPool("v6", "fd00:10::/64", workloadAndTunnel)},
			want:  []IPFamily{IPv6},
		},
		{
			name:  "manual-assignment pool doesn't count, explicit automatic does",
			pools: []v3.IPPool{testPool("v4", "192.168.0.0/16", automatic), testPool("v6", "fd00:10::/64", manual)},
			want:  []IPFamily{IPv4},
		},
		{
			name:    "unparseable CIDR",
			pools:   []v3.IPPool{testPool("bad", "not-a-cidr")},
			wantErr: `IPPool bad has unparseable CIDR "not-a-cidr"`,
		},
		{
			name:    "no counted pools names each and why",
			pools:   []v3.IPPool{testPool("off", "192.168.0.0/16", disabled), testPool("tun", "fd00:10::/64", tunnelOnly)},
			wantErr: "no IPPool assigns pod addresses automatically: off (disabled), tun (allowedUses [Tunnel])",
		},
		{
			name:    "no pools",
			wantErr: "no IPPools found",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := gomega.NewWithT(t)
			got, err := poolFamilies(tc.pools)
			if tc.wantErr != "" {
				g.Expect(err).To(gomega.MatchError(gomega.ContainSubstring(tc.wantErr)))
				return
			}
			g.Expect(err).NotTo(gomega.HaveOccurred())
			g.Expect(got).To(gomega.Equal(tc.want))
		})
	}
}

type encapTestCase struct {
	name  string
	pools []v3.IPPool
	want  map[IPFamily]string
}

func TestEncapDevices(t *testing.T) {
	ipip := func(s *v3.IPPoolSpec) { s.IPIPMode = v3.IPIPModeAlways }
	vxlan := func(s *v3.IPPoolSpec) { s.VXLANMode = v3.VXLANModeAlways }
	vxlanCrossSubnet := func(s *v3.IPPoolSpec) { s.VXLANMode = v3.VXLANModeCrossSubnet }
	disabled := func(s *v3.IPPoolSpec) { s.Disabled = true }

	for _, tc := range []encapTestCase{
		{
			name:  "dual-stack VXLAN uses a device per family",
			pools: []v3.IPPool{testPool("v4", "192.168.0.0/16", vxlan), testPool("v6", "fd00:10:244::/64", vxlan)},
			want:  map[IPFamily]string{IPv4: "vxlan.calico", IPv6: "vxlan-v6.calico"},
		},
		{
			name:  "IPv6-only VXLAN",
			pools: []v3.IPPool{testPool("v6", "fd00:10:244::/64", vxlanCrossSubnet)},
			want:  map[IPFamily]string{IPv6: "vxlan-v6.calico"},
		},
		{
			name:  "IPIP on IPv4, unencapsulated IPv6",
			pools: []v3.IPPool{testPool("v4", "192.168.0.0/16", ipip), testPool("v6", "fd00:10:244::/64")},
			want:  map[IPFamily]string{IPv4: "tunl0"},
		},
		{
			name:  "no encapsulation",
			pools: []v3.IPPool{testPool("v4", "192.168.0.0/16")},
			want:  map[IPFamily]string{},
		},
		{
			name:  "a disabled pool listed first doesn't pick the device",
			pools: []v3.IPPool{testPool("old", "10.0.0.0/16", ipip, disabled), testPool("v4", "192.168.0.0/16", vxlan)},
			want:  map[IPFamily]string{IPv4: "vxlan.calico"},
		},
		{
			name:  "mixed encapsulation keeps the first pool's device",
			pools: []v3.IPPool{testPool("a", "192.168.0.0/16", ipip), testPool("b", "10.10.0.0/16", vxlan)},
			want:  map[IPFamily]string{IPv4: "tunl0"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := gomega.NewWithT(t)
			g.Expect(encapDevices(tc.pools)).To(gomega.Equal(tc.want))
		})
	}
}
