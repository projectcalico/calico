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

package validation_test

import (
	"testing"

	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestBGPFilterValidation(t *testing.T) {
	tests := []struct {
		name    string
		obj     *v3.BGPFilter
		wantErr string
	}{
		{
			name: "basic valid BGPFilter",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("valid-bgpfilter")},
				Spec: v3.BGPFilterSpec{
					ExportV4: []v3.BGPFilterRuleV4{
						{CIDR: "10.0.0.0/24", Action: v3.Accept},
					},
				},
			},
		},
		{
			name: "invalid BGPFilter with bad action",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("invalid-bgpfilter")},
				Spec: v3.BGPFilterSpec{
					ExportV4: []v3.BGPFilterRuleV4{
						{CIDR: "10.0.0.0/24", Action: "InvalidAction"},
					},
				},
			},
			wantErr: "spec.exportV4[0].action",
		},
		{
			name: "invalid BGPFilter with bad CIDR",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("invalid-bgpfilter")},
				Spec: v3.BGPFilterSpec{
					ImportV4: []v3.BGPFilterRuleV4{
						{CIDR: "invalid-cidr", Action: v3.Accept},
					},
				},
			},
			wantErr: "spec.importV4[0].cidr",
		},
		{
			name: "invalid BGPFilter with bad matchOperator",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("invalid-bgpfilter")},
				Spec: v3.BGPFilterSpec{
					ExportV6: []v3.BGPFilterRuleV6{
						{CIDR: "fd00:1234:abcd::/64", MatchOperator: "InvalidOperator", Action: v3.Reject},
					},
				},
			},
			wantErr: "spec.exportV6[0].matchOperator",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == "" {
				expectCreateSucceeds(t, tt.obj)
			} else {
				expectCreateFails(t, tt.obj, tt.wantErr)
			}
		})
	}
}
