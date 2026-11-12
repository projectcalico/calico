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

package networking

import (
	"testing"

	"github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/projectcalico/calico/e2e/pkg/utils"
)

func pool(name, cidr string, ipip v3.IPIPMode, vxlan v3.VXLANMode) *v3.IPPool {
	return &v3.IPPool{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       v3.IPPoolSpec{CIDR: cidr, IPIPMode: ipip, VXLANMode: vxlan},
	}
}

func TestDetectEncapInterfaces(t *testing.T) {
	for _, tc := range []struct {
		name  string
		pools []*v3.IPPool
		want  map[utils.IPFamily]string
	}{
		{
			name: "dual-stack VXLAN uses a device per family",
			pools: []*v3.IPPool{
				pool("v4", "192.168.0.0/16", v3.IPIPModeNever, v3.VXLANModeAlways),
				pool("v6", "fd00:10:244::/64", v3.IPIPModeNever, v3.VXLANModeAlways),
			},
			want: map[utils.IPFamily]string{utils.IPv4: "vxlan.calico", utils.IPv6: "vxlan-v6.calico"},
		},
		{
			name:  "IPv6-only VXLAN",
			pools: []*v3.IPPool{pool("v6", "fd00:10:244::/64", v3.IPIPModeNever, v3.VXLANModeCrossSubnet)},
			want:  map[utils.IPFamily]string{utils.IPv6: "vxlan-v6.calico"},
		},
		{
			name: "IPIP on IPv4, unencapsulated IPv6",
			pools: []*v3.IPPool{
				pool("v4", "192.168.0.0/16", v3.IPIPModeAlways, v3.VXLANModeNever),
				pool("v6", "fd00:10:244::/64", v3.IPIPModeNever, v3.VXLANModeNever),
			},
			want: map[utils.IPFamily]string{utils.IPv4: "tunl0"},
		},
		{
			name:  "no encapsulation",
			pools: []*v3.IPPool{pool("v4", "192.168.0.0/16", v3.IPIPModeNever, v3.VXLANModeNever)},
			want:  map[utils.IPFamily]string{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := gomega.NewWithT(t)
			scheme := runtime.NewScheme()
			g.Expect(v3.AddToScheme(scheme)).To(gomega.Succeed())
			b := fake.NewClientBuilder().WithScheme(scheme)
			for _, p := range tc.pools {
				b = b.WithObjects(p)
			}
			g.Expect(detectEncapInterfaces(b.Build())).To(gomega.Equal(tc.want))
		})
	}
}
