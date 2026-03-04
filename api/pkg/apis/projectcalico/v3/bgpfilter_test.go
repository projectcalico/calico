// Copyright (c) 2025 Tigera, Inc. All rights reserved.

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

package v3_test

import (
	"context"
	"os"
	"testing"

	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/client/clientset_generated/clientset"
	"github.com/projectcalico/api/pkg/lib/numorstring"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/clientcmd"
)

func setup(t *testing.T) (clientset.Interface, func()) {
	// Register gomega with test.
	RegisterTestingT(t)

	// Create a client.
	cfg, err := clientcmd.BuildConfigFromFlags("", os.Getenv("KUBECONFIG"))
	Expect(err).NotTo(HaveOccurred())
	c, err := clientset.NewForConfig(cfg)
	Expect(err).NotTo(HaveOccurred())

	return c, func() {}
}

func TestBGPFilterValidation(t *testing.T) {
	type bgpFilterTest struct {
		name  string
		obj   *v3.BGPFilter
		valid bool
		err   string
	}
	tests := []bgpFilterTest{
		{
			name: "basic valid BGPFilter",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: "valid-bgpfilter"},
				Spec:       v3.BGPFilterSpec{ExportV4: []v3.BGPFilterRuleV4{{CIDR: "10.0.0.0/24", Action: v3.Accept}}},
			},
			valid: true,
		},
		{
			name: "invalid BGPFilter with bad action",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: "invalid-bgpfilter"},
				Spec: v3.BGPFilterSpec{ExportV4: []v3.BGPFilterRuleV4{
					{CIDR: "10.0.0.0/24", Action: "InvalidAction"},
				}},
			},
			err:   "spec.exportV4[0].action",
			valid: false,
		},
		{
			name: "invalid BGPFilter with bad CIDR",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: "invalid-bgpfilter"},
				Spec: v3.BGPFilterSpec{ImportV4: []v3.BGPFilterRuleV4{
					{CIDR: "invalid-cidr", Action: v3.Accept},
				}},
			},
			err:   "spec.importV4[0].cidr",
			valid: false,
		},
		{
			name: "invalid BGPFilter with matchOperator",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: "invalid-bgpfilter"},
				Spec: v3.BGPFilterSpec{ExportV6: []v3.BGPFilterRuleV6{
					{CIDR: "fd00:1234:abcd::/64", MatchOperator: "InvalidOperator", Action: v3.Reject},
				}},
			},
			err:   "spec.exportV6[0].matchOperator",
			valid: false,
		},

		// --- CEL: operations only with Accept ---
		{
			name: "valid operations with Accept action",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: "cel-ops-accept"},
				Spec: v3.BGPFilterSpec{ExportV4: []v3.BGPFilterRuleV4{
					{
						Action: v3.Accept,
						Operations: []v3.BGPFilterOperation{
							{SetPriority: &v3.BGPFilterSetPriority{Value: 100}},
						},
					},
				}},
			},
			valid: true,
		},
		{
			name: "invalid operations with Reject action (V4)",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: "cel-ops-reject-v4"},
				Spec: v3.BGPFilterSpec{ExportV4: []v3.BGPFilterRuleV4{
					{
						Action: v3.Reject,
						Operations: []v3.BGPFilterOperation{
							{SetPriority: &v3.BGPFilterSetPriority{Value: 100}},
						},
					},
				}},
			},
			err:   "operations may only be used with action Accept",
			valid: false,
		},
		{
			name: "invalid operations with Reject action (V6)",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: "cel-ops-reject-v6"},
				Spec: v3.BGPFilterSpec{ImportV6: []v3.BGPFilterRuleV6{
					{
						Action: v3.Reject,
						Operations: []v3.BGPFilterOperation{
							{AddCommunity: &v3.BGPFilterAddCommunity{Value: "65000:100"}},
						},
					},
				}},
			},
			err:   "operations may only be used with action Accept",
			valid: false,
		},

		// --- CEL: exactly one operation field per entry ---
		{
			name: "valid operation with exactly one field (addCommunity)",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: "cel-op-one-field"},
				Spec: v3.BGPFilterSpec{ExportV4: []v3.BGPFilterRuleV4{
					{
						Action: v3.Accept,
						Operations: []v3.BGPFilterOperation{
							{AddCommunity: &v3.BGPFilterAddCommunity{Value: "65000:100"}},
						},
					},
				}},
			},
			valid: true,
		},
		{
			name: "invalid operation with two fields set",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: "cel-op-two-fields"},
				Spec: v3.BGPFilterSpec{ExportV4: []v3.BGPFilterRuleV4{
					{
						Action: v3.Accept,
						Operations: []v3.BGPFilterOperation{
							{
								AddCommunity: &v3.BGPFilterAddCommunity{Value: "65000:100"},
								SetPriority:  &v3.BGPFilterSetPriority{Value: 100},
							},
						},
					},
				}},
			},
			err:   "exactly one operation must be set",
			valid: false,
		},
		{
			name: "invalid operation with all three fields set",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: "cel-op-three-fields"},
				Spec: v3.BGPFilterSpec{ExportV4: []v3.BGPFilterRuleV4{
					{
						Action: v3.Accept,
						Operations: []v3.BGPFilterOperation{
							{
								AddCommunity:  &v3.BGPFilterAddCommunity{Value: "65000:100"},
								PrependASPath: &v3.BGPFilterPrependASPath{Prefix: []numorstring.ASNumber{65000}},
								SetPriority:   &v3.BGPFilterSetPriority{Value: 100},
							},
						},
					},
				}},
			},
			err:   "exactly one operation must be set",
			valid: false,
		},

		// --- CEL: source not allowed on import rules ---
		{
			name: "valid source on export rule",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: "cel-source-export"},
				Spec: v3.BGPFilterSpec{ExportV4: []v3.BGPFilterRuleV4{
					{Source: v3.BGPFilterSourceRemotePeers, Action: v3.Accept},
				}},
			},
			valid: true,
		},
		{
			name: "invalid source on importV4 rule",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: "cel-source-importv4"},
				Spec: v3.BGPFilterSpec{ImportV4: []v3.BGPFilterRuleV4{
					{Source: v3.BGPFilterSourceRemotePeers, Action: v3.Reject},
				}},
			},
			err:   "source is not applicable to import rules",
			valid: false,
		},
		{
			name: "invalid source on importV6 rule",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: "cel-source-importv6"},
				Spec: v3.BGPFilterSpec{ImportV6: []v3.BGPFilterRuleV6{
					{Source: v3.BGPFilterSourceRemotePeers, Action: v3.Accept},
				}},
			},
			err:   "source is not applicable to import rules",
			valid: false,
		},

		// --- CEL: community value format validation ---
		{
			name: "valid standard community in match",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: "cel-comm-std"},
				Spec: v3.BGPFilterSpec{ImportV4: []v3.BGPFilterRuleV4{
					{
						Action:      v3.Accept,
						Communities: &v3.BGPFilterCommunityMatch{Values: []string{"65000:100"}},
					},
				}},
			},
			valid: true,
		},
		{
			name: "valid large community in match",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: "cel-comm-large"},
				Spec: v3.BGPFilterSpec{ImportV4: []v3.BGPFilterRuleV4{
					{
						Action:      v3.Accept,
						Communities: &v3.BGPFilterCommunityMatch{Values: []string{"65000:100:200"}},
					},
				}},
			},
			valid: true,
		},
		{
			name: "invalid standard community with value > 65535",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: "cel-comm-std-range"},
				Spec: v3.BGPFilterSpec{ImportV4: []v3.BGPFilterRuleV4{
					{
						Action:      v3.Accept,
						Communities: &v3.BGPFilterCommunityMatch{Values: []string{"70000:100"}},
					},
				}},
			},
			err:   "standard communities must have 16-bit values",
			valid: false,
		},
		{
			name: "invalid community with bad format",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: "cel-comm-bad-fmt"},
				Spec: v3.BGPFilterSpec{ImportV4: []v3.BGPFilterRuleV4{
					{
						Action:      v3.Accept,
						Communities: &v3.BGPFilterCommunityMatch{Values: []string{"not-a-community"}},
					},
				}},
			},
			err:   "standard communities must have 16-bit values",
			valid: false,
		},

		// --- CEL: AddCommunity value format validation ---
		{
			name: "valid standard community in AddCommunity operation",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: "cel-addcomm-std"},
				Spec: v3.BGPFilterSpec{ExportV4: []v3.BGPFilterRuleV4{
					{
						Action: v3.Accept,
						Operations: []v3.BGPFilterOperation{
							{AddCommunity: &v3.BGPFilterAddCommunity{Value: "100:200"}},
						},
					},
				}},
			},
			valid: true,
		},
		{
			name: "valid large community in AddCommunity operation",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: "cel-addcomm-large"},
				Spec: v3.BGPFilterSpec{ExportV4: []v3.BGPFilterRuleV4{
					{
						Action: v3.Accept,
						Operations: []v3.BGPFilterOperation{
							{AddCommunity: &v3.BGPFilterAddCommunity{Value: "65000:100:200"}},
						},
					},
				}},
			},
			valid: true,
		},
		{
			name: "invalid AddCommunity with standard community value > 65535",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: "cel-addcomm-range"},
				Spec: v3.BGPFilterSpec{ExportV4: []v3.BGPFilterRuleV4{
					{
						Action: v3.Accept,
						Operations: []v3.BGPFilterOperation{
							{AddCommunity: &v3.BGPFilterAddCommunity{Value: "65536:100"}},
						},
					},
				}},
			},
			err:   "standard communities must have 16-bit values",
			valid: false,
		},
		{
			name: "invalid AddCommunity with bad format",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: "cel-addcomm-bad"},
				Spec: v3.BGPFilterSpec{ExportV4: []v3.BGPFilterRuleV4{
					{
						Action: v3.Accept,
						Operations: []v3.BGPFilterOperation{
							{AddCommunity: &v3.BGPFilterAddCommunity{Value: "garbage"}},
						},
					},
				}},
			},
			err:   "standard communities must have 16-bit values",
			valid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, cleanup := setup(t)
			defer cleanup()

			ctx := context.Background()
			g := NewGomegaWithT(t)

			// Try to create the BGPFilter object.
			created, err := c.ProjectcalicoV3().BGPFilters().Create(ctx, tt.obj, metav1.CreateOptions{})
			if tt.valid {
				defer func() {
					err := c.ProjectcalicoV3().BGPFilters().Delete(ctx, created.Name, metav1.DeleteOptions{})
					g.Expect(err).NotTo(HaveOccurred(), "Expected BGPFilter to be deleted")
				}()
				g.Expect(err).NotTo(HaveOccurred(), "Expected BGPFilter to be valid")
			} else {
				g.Expect(err).To(HaveOccurred(), "Expected BGPFilter to be invalid")
				if tt.err != "" {
					g.Expect(err.Error()).To(ContainSubstring(tt.err))
				}
			}
		})
	}
}
