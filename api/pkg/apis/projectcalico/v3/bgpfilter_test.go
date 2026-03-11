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
						Communities: &v3.BGPFilterCommunityMatch{Values: []v3.BGPCommunityValue{"65000:100"}},
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
						Communities: &v3.BGPFilterCommunityMatch{Values: []v3.BGPCommunityValue{"65000:100:200"}},
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
						Communities: &v3.BGPFilterCommunityMatch{Values: []v3.BGPCommunityValue{"70000:100"}},
					},
				}},
			},
			err:   "Invalid value",
			valid: false,
		},
		{
			name: "invalid community with bad format",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: "cel-comm-bad-fmt"},
				Spec: v3.BGPFilterSpec{ImportV4: []v3.BGPFilterRuleV4{
					{
						Action:      v3.Accept,
						Communities: &v3.BGPFilterCommunityMatch{Values: []v3.BGPCommunityValue{"not-a-community"}},
					},
				}},
			},
			err:   "Invalid value",
			valid: false,
		},

		// --- AddCommunity value format validation ---
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
			err:   "Invalid value",
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
			err:   "Invalid value",
			valid: false,
		},

		// --- Comprehensive community value pattern boundary tests ---

		// Standard community: 16-bit boundary values
		{
			name: "standard community 0:0 (minimum)",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: "comm-std-min"},
				Spec: v3.BGPFilterSpec{ExportV4: []v3.BGPFilterRuleV4{
					{Action: v3.Accept, Communities: &v3.BGPFilterCommunityMatch{Values: []v3.BGPCommunityValue{"0:0"}}},
				}},
			},
			valid: true,
		},
		{
			name: "standard community 65535:65535 (maximum)",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: "comm-std-max"},
				Spec: v3.BGPFilterSpec{ExportV4: []v3.BGPFilterRuleV4{
					{Action: v3.Accept, Communities: &v3.BGPFilterCommunityMatch{Values: []v3.BGPCommunityValue{"65535:65535"}}},
				}},
			},
			valid: true,
		},
		{
			name: "standard community 1:1 (single digit)",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: "comm-std-single"},
				Spec: v3.BGPFilterSpec{ExportV4: []v3.BGPFilterRuleV4{
					{Action: v3.Accept, Communities: &v3.BGPFilterCommunityMatch{Values: []v3.BGPCommunityValue{"1:1"}}},
				}},
			},
			valid: true,
		},
		{
			name: "standard community 9999:9999 (4-digit)",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: "comm-std-4digit"},
				Spec: v3.BGPFilterSpec{ExportV4: []v3.BGPFilterRuleV4{
					{Action: v3.Accept, Communities: &v3.BGPFilterCommunityMatch{Values: []v3.BGPCommunityValue{"9999:9999"}}},
				}},
			},
			valid: true,
		},
		{
			name: "standard community 59999:59999 (upper mid range)",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: "comm-std-59999"},
				Spec: v3.BGPFilterSpec{ExportV4: []v3.BGPFilterRuleV4{
					{Action: v3.Accept, Communities: &v3.BGPFilterCommunityMatch{Values: []v3.BGPCommunityValue{"59999:59999"}}},
				}},
			},
			valid: true,
		},
		{
			name: "standard community 65535:0 (max:min)",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: "comm-std-maxmin"},
				Spec: v3.BGPFilterSpec{ExportV4: []v3.BGPFilterRuleV4{
					{Action: v3.Accept, Communities: &v3.BGPFilterCommunityMatch{Values: []v3.BGPCommunityValue{"65535:0"}}},
				}},
			},
			valid: true,
		},
		{
			name: "invalid standard community 65536:0 (first component over 16-bit)",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: "comm-std-65536a"},
				Spec: v3.BGPFilterSpec{ExportV4: []v3.BGPFilterRuleV4{
					{Action: v3.Accept, Communities: &v3.BGPFilterCommunityMatch{Values: []v3.BGPCommunityValue{"65536:0"}}},
				}},
			},
			err:   "Invalid value",
			valid: false,
		},
		{
			name: "invalid standard community 0:65536 (second component over 16-bit)",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: "comm-std-65536b"},
				Spec: v3.BGPFilterSpec{ExportV4: []v3.BGPFilterRuleV4{
					{Action: v3.Accept, Communities: &v3.BGPFilterCommunityMatch{Values: []v3.BGPCommunityValue{"0:65536"}}},
				}},
			},
			err:   "Invalid value",
			valid: false,
		},
		{
			name: "invalid standard community 99999:0 (5-digit over range)",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: "comm-std-99999"},
				Spec: v3.BGPFilterSpec{ExportV4: []v3.BGPFilterRuleV4{
					{Action: v3.Accept, Communities: &v3.BGPFilterCommunityMatch{Values: []v3.BGPCommunityValue{"99999:0"}}},
				}},
			},
			err:   "Invalid value",
			valid: false,
		},
		{
			name: "invalid standard community 100000:0 (6 digits)",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: "comm-std-6digit"},
				Spec: v3.BGPFilterSpec{ExportV4: []v3.BGPFilterRuleV4{
					{Action: v3.Accept, Communities: &v3.BGPFilterCommunityMatch{Values: []v3.BGPCommunityValue{"100000:0"}}},
				}},
			},
			err:   "Invalid value",
			valid: false,
		},
		{
			name: "invalid standard community with leading zero 01:02",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: "comm-std-leading0"},
				Spec: v3.BGPFilterSpec{ExportV4: []v3.BGPFilterRuleV4{
					{Action: v3.Accept, Communities: &v3.BGPFilterCommunityMatch{Values: []v3.BGPCommunityValue{"01:02"}}},
				}},
			},
			err:   "Invalid value",
			valid: false,
		},

		// Large community: 32-bit boundary values
		{
			name: "large community 0:0:0 (minimum)",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: "comm-lg-min"},
				Spec: v3.BGPFilterSpec{ExportV4: []v3.BGPFilterRuleV4{
					{Action: v3.Accept, Communities: &v3.BGPFilterCommunityMatch{Values: []v3.BGPCommunityValue{"0:0:0"}}},
				}},
			},
			valid: true,
		},
		{
			name: "large community 4294967295:4294967295:4294967295 (maximum)",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: "comm-lg-max"},
				Spec: v3.BGPFilterSpec{ExportV4: []v3.BGPFilterRuleV4{
					{Action: v3.Accept, Communities: &v3.BGPFilterCommunityMatch{Values: []v3.BGPCommunityValue{"4294967295:4294967295:4294967295"}}},
				}},
			},
			valid: true,
		},
		{
			name: "large community 1:1:1 (single digit)",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: "comm-lg-single"},
				Spec: v3.BGPFilterSpec{ExportV4: []v3.BGPFilterRuleV4{
					{Action: v3.Accept, Communities: &v3.BGPFilterCommunityMatch{Values: []v3.BGPCommunityValue{"1:1:1"}}},
				}},
			},
			valid: true,
		},
		{
			name: "large community 999999999:999999999:999999999 (9-digit)",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: "comm-lg-9digit"},
				Spec: v3.BGPFilterSpec{ExportV4: []v3.BGPFilterRuleV4{
					{Action: v3.Accept, Communities: &v3.BGPFilterCommunityMatch{Values: []v3.BGPCommunityValue{"999999999:999999999:999999999"}}},
				}},
			},
			valid: true,
		},
		{
			name: "invalid large community 4294967296:0:0 (first component over 32-bit)",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: "comm-lg-over-a"},
				Spec: v3.BGPFilterSpec{ExportV4: []v3.BGPFilterRuleV4{
					{Action: v3.Accept, Communities: &v3.BGPFilterCommunityMatch{Values: []v3.BGPCommunityValue{"4294967296:0:0"}}},
				}},
			},
			err:   "Invalid value",
			valid: false,
		},
		{
			name: "invalid large community 0:4294967296:0 (second component over 32-bit)",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: "comm-lg-over-b"},
				Spec: v3.BGPFilterSpec{ExportV4: []v3.BGPFilterRuleV4{
					{Action: v3.Accept, Communities: &v3.BGPFilterCommunityMatch{Values: []v3.BGPCommunityValue{"0:4294967296:0"}}},
				}},
			},
			err:   "Invalid value",
			valid: false,
		},
		{
			name: "invalid large community 0:0:4294967296 (third component over 32-bit)",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: "comm-lg-over-c"},
				Spec: v3.BGPFilterSpec{ExportV4: []v3.BGPFilterRuleV4{
					{Action: v3.Accept, Communities: &v3.BGPFilterCommunityMatch{Values: []v3.BGPCommunityValue{"0:0:4294967296"}}},
				}},
			},
			err:   "Invalid value",
			valid: false,
		},
		{
			name: "invalid large community with leading zero 01:02:03",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: "comm-lg-leading0"},
				Spec: v3.BGPFilterSpec{ExportV4: []v3.BGPFilterRuleV4{
					{Action: v3.Accept, Communities: &v3.BGPFilterCommunityMatch{Values: []v3.BGPCommunityValue{"01:02:03"}}},
				}},
			},
			err:   "Invalid value",
			valid: false,
		},

		// Malformed community strings
		{
			name: "invalid community: empty string",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: "comm-empty"},
				Spec: v3.BGPFilterSpec{ExportV4: []v3.BGPFilterRuleV4{
					{Action: v3.Accept, Communities: &v3.BGPFilterCommunityMatch{Values: []v3.BGPCommunityValue{""}}},
				}},
			},
			err:   "Invalid value",
			valid: false,
		},
		{
			name: "invalid community: single number",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: "comm-single-num"},
				Spec: v3.BGPFilterSpec{ExportV4: []v3.BGPFilterRuleV4{
					{Action: v3.Accept, Communities: &v3.BGPFilterCommunityMatch{Values: []v3.BGPCommunityValue{"12345"}}},
				}},
			},
			err:   "Invalid value",
			valid: false,
		},
		{
			name: "invalid community: four colons",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: "comm-four-colon"},
				Spec: v3.BGPFilterSpec{ExportV4: []v3.BGPFilterRuleV4{
					{Action: v3.Accept, Communities: &v3.BGPFilterCommunityMatch{Values: []v3.BGPCommunityValue{"1:2:3:4"}}},
				}},
			},
			err:   "Invalid value",
			valid: false,
		},
		{
			name: "invalid community: non-numeric",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: "comm-alpha"},
				Spec: v3.BGPFilterSpec{ExportV4: []v3.BGPFilterRuleV4{
					{Action: v3.Accept, Communities: &v3.BGPFilterCommunityMatch{Values: []v3.BGPCommunityValue{"abc:def"}}},
				}},
			},
			err:   "Invalid value",
			valid: false,
		},
		{
			name: "invalid community: negative number",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: "comm-negative"},
				Spec: v3.BGPFilterSpec{ExportV4: []v3.BGPFilterRuleV4{
					{Action: v3.Accept, Communities: &v3.BGPFilterCommunityMatch{Values: []v3.BGPCommunityValue{"-1:100"}}},
				}},
			},
			err:   "Invalid value",
			valid: false,
		},
		{
			name: "invalid community: spaces",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: "comm-spaces"},
				Spec: v3.BGPFilterSpec{ExportV4: []v3.BGPFilterRuleV4{
					{Action: v3.Accept, Communities: &v3.BGPFilterCommunityMatch{Values: []v3.BGPCommunityValue{"100 : 200"}}},
				}},
			},
			err:   "Invalid value",
			valid: false,
		},
		{
			name: "invalid community: trailing colon",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: "comm-trailing"},
				Spec: v3.BGPFilterSpec{ExportV4: []v3.BGPFilterRuleV4{
					{Action: v3.Accept, Communities: &v3.BGPFilterCommunityMatch{Values: []v3.BGPCommunityValue{"100:200:"}}},
				}},
			},
			err:   "Invalid value",
			valid: false,
		},

		// AddCommunity also uses BGPCommunityValue — spot-check boundaries
		{
			name: "AddCommunity with max standard community 65535:65535",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: "addcomm-std-max"},
				Spec: v3.BGPFilterSpec{ExportV4: []v3.BGPFilterRuleV4{
					{Action: v3.Accept, Operations: []v3.BGPFilterOperation{
						{AddCommunity: &v3.BGPFilterAddCommunity{Value: "65535:65535"}},
					}},
				}},
			},
			valid: true,
		},
		{
			name: "AddCommunity with max large community",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: "addcomm-lg-max"},
				Spec: v3.BGPFilterSpec{ExportV4: []v3.BGPFilterRuleV4{
					{Action: v3.Accept, Operations: []v3.BGPFilterOperation{
						{AddCommunity: &v3.BGPFilterAddCommunity{Value: "4294967295:4294967295:4294967295"}},
					}},
				}},
			},
			valid: true,
		},
		{
			name: "invalid AddCommunity 65536:65536 (over 16-bit)",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: "addcomm-over16"},
				Spec: v3.BGPFilterSpec{ExportV4: []v3.BGPFilterRuleV4{
					{Action: v3.Accept, Operations: []v3.BGPFilterOperation{
						{AddCommunity: &v3.BGPFilterAddCommunity{Value: "65536:65536"}},
					}},
				}},
			},
			err:   "Invalid value",
			valid: false,
		},
		{
			name: "invalid AddCommunity 4294967296:0:0 (over 32-bit)",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: "addcomm-over32"},
				Spec: v3.BGPFilterSpec{ExportV4: []v3.BGPFilterRuleV4{
					{Action: v3.Accept, Operations: []v3.BGPFilterOperation{
						{AddCommunity: &v3.BGPFilterAddCommunity{Value: "4294967296:0:0"}},
					}},
				}},
			},
			err:   "Invalid value",
			valid: false,
		},
		{
			name: "invalid AddCommunity with leading zero",
			obj: &v3.BGPFilter{
				ObjectMeta: metav1.ObjectMeta{Name: "addcomm-lead0"},
				Spec: v3.BGPFilterSpec{ExportV4: []v3.BGPFilterRuleV4{
					{Action: v3.Accept, Operations: []v3.BGPFilterOperation{
						{AddCommunity: &v3.BGPFilterAddCommunity{Value: "0100:200"}},
					}},
				}},
			},
			err:   "Invalid value",
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
