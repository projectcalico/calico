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
