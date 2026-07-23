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
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestBGPFilter_V4_Validation(t *testing.T) {
	tests := []struct {
		name    string
		obj     client.Object
		wantErr string
	}{
		{
			name: "V4 cidr without matchOperator is rejected",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("bgpfilter")},
				Spec: v3.BGPFilterSpec{
					ExportV4: []v3.BGPFilterRuleV4{
						{CIDR: "10.0.0.0/24", Action: v3.Accept},
					},
				},
			},
			wantErr: "cidr and matchOperator must both be set or both be empty",
		},
		{
			name: "V4 matchOperator without cidr is rejected",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("bgpfilter")},
				Spec: v3.BGPFilterSpec{
					ExportV4: []v3.BGPFilterRuleV4{
						{MatchOperator: v3.MatchOperatorEqual, Action: v3.Accept},
					},
				},
			},
			wantErr: "cidr and matchOperator must both be set or both be empty",
		},
		{
			name: "V4 prefixLength without cidr is rejected",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("bgpfilter")},
				Spec: v3.BGPFilterSpec{
					ExportV4: []v3.BGPFilterRuleV4{
						{
							PrefixLength: &v3.BGPFilterPrefixLengthV4{Min: ptr.To[int32](24)},
							Action:       v3.Accept,
						},
					},
				},
			},
			wantErr: "cidr is required when prefixLength is set",
		},
		{
			name: "V4 cidr + matchOperator is accepted",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("bgpfilter")},
				Spec: v3.BGPFilterSpec{
					ExportV4: []v3.BGPFilterRuleV4{
						{CIDR: "10.0.0.0/24", MatchOperator: v3.MatchOperatorEqual, Action: v3.Accept},
					},
				},
			},
		},
		{
			name: "V4 invalid action is rejected",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("bgpfilter")},
				Spec: v3.BGPFilterSpec{
					ExportV4: []v3.BGPFilterRuleV4{
						{CIDR: "10.0.0.0/24", MatchOperator: v3.MatchOperatorEqual, Action: "InvalidAction"},
					},
				},
			},
			wantErr: "spec.exportV4[0].action",
		},
		{
			name: "V4 invalid CIDR format is rejected",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("bgpfilter")},
				Spec: v3.BGPFilterSpec{
					ImportV4: []v3.BGPFilterRuleV4{
						{CIDR: "invalid-cidr", MatchOperator: v3.MatchOperatorEqual, Action: v3.Accept},
					},
				},
			},
			wantErr: "spec.importV4[0].cidr",
		},
		{
			name: "V4 invalid matchOperator is rejected",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("bgpfilter")},
				Spec: v3.BGPFilterSpec{
					ExportV4: []v3.BGPFilterRuleV4{
						{CIDR: "10.0.0.0/24", MatchOperator: "InvalidOperator", Action: v3.Accept},
					},
				},
			},
			wantErr: "spec.exportV4[0].matchOperator",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr != "" {
				expectCreateFails(t, tt.obj, tt.wantErr)
			} else {
				expectCreateSucceeds(t, tt.obj)
			}
		})
	}
}

func TestBGPFilter_V6_Validation(t *testing.T) {
	tests := []struct {
		name    string
		obj     client.Object
		wantErr string
	}{
		{
			name: "V6 cidr without matchOperator is rejected",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("bgpfilter")},
				Spec: v3.BGPFilterSpec{
					ExportV6: []v3.BGPFilterRuleV6{
						{CIDR: "fd00::/64", Action: v3.Accept},
					},
				},
			},
			wantErr: "cidr and matchOperator must both be set or both be empty",
		},
		{
			name: "V6 matchOperator without cidr is rejected",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("bgpfilter")},
				Spec: v3.BGPFilterSpec{
					ExportV6: []v3.BGPFilterRuleV6{
						{MatchOperator: v3.MatchOperatorEqual, Action: v3.Accept},
					},
				},
			},
			wantErr: "cidr and matchOperator must both be set or both be empty",
		},
		{
			name: "V6 prefixLength without cidr is rejected",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("bgpfilter")},
				Spec: v3.BGPFilterSpec{
					ExportV6: []v3.BGPFilterRuleV6{
						{
							PrefixLength: &v3.BGPFilterPrefixLengthV6{Min: ptr.To[int32](64)},
							Action:       v3.Accept,
						},
					},
				},
			},
			wantErr: "cidr is required when prefixLength is set",
		},
		{
			name: "V6 cidr + matchOperator is accepted",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("bgpfilter")},
				Spec: v3.BGPFilterSpec{
					ExportV6: []v3.BGPFilterRuleV6{
						{CIDR: "fd00::/64", MatchOperator: v3.MatchOperatorEqual, Action: v3.Accept},
					},
				},
			},
		},
		{
			name: "V6 invalid matchOperator is rejected",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: uniqueName("bgpfilter")},
				Spec: v3.BGPFilterSpec{
					ExportV6: []v3.BGPFilterRuleV6{
						{CIDR: "fd00::/64", MatchOperator: "InvalidOperator", Action: v3.Reject},
					},
				},
			},
			wantErr: "spec.exportV6[0].matchOperator",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr != "" {
				expectCreateFails(t, tt.obj, tt.wantErr)
			} else {
				expectCreateSucceeds(t, tt.obj)
			}
		})
	}
}
