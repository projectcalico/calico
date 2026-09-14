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

package validation_test

import (
	"testing"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// libcalico-go validates nets with ParseCIDROrIP, so a bare address is as valid
// as a CIDR and neither has to be strictly masked.
func TestNetworkSets_NetsValidation(t *testing.T) {
	const wantErr = "nets entries must be IP addresses or CIDRs"

	tests := []struct {
		name    string
		nets    []string
		wantErr string
	}{
		{name: "IPv4 CIDR", nets: []string{"10.0.0.0/24"}},
		{name: "IPv6 CIDR", nets: []string{"fd00::/64"}},
		{name: "bare IPv4 address", nets: []string{"10.0.0.1"}},
		{name: "unmasked CIDR", nets: []string{"10.0.0.1/24"}},
		{name: "mixed entries", nets: []string{"10.0.0.0/24", "fd00::/64", "10.0.0.1"}},
		{name: "empty list", nets: nil},
		{name: "prefix length out of range", nets: []string{"10.0.0.0/33"}, wantErr: wantErr},
		{name: "not an address", nets: []string{"garbage"}, wantErr: wantErr},
		{name: "one bad entry among good ones", nets: []string{"10.0.0.0/24", "10.0.0.0/33"}, wantErr: wantErr},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			objs := []client.Object{
				&v3.GlobalNetworkSet{
					ObjectMeta: metav1.ObjectMeta{Name: uniqueName("gns")},
					Spec:       v3.GlobalNetworkSetSpec{Nets: tt.nets},
				},
				&v3.NetworkSet{
					ObjectMeta: metav1.ObjectMeta{Name: uniqueName("ns"), Namespace: "default"},
					Spec:       v3.NetworkSetSpec{Nets: tt.nets},
				},
			}
			for _, obj := range objs {
				if tt.wantErr != "" {
					expectCreateFails(t, obj, tt.wantErr)
				} else {
					expectCreateSucceeds(t, obj)
				}
			}
		})
	}
}
