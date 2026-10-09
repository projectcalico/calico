// Copyright (c) 2017,2020-2021 Tigera, Inc. All rights reserved.

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

package clientv3_test

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/calico/libcalico-go/lib/backend"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
)

var MatchResource = testutils.Resource
var MatchResourceWithStatus = testutils.ResourceWithStatus

var _ = testutils.E2eDatastoreDescribe("Common resource tests", testutils.DatastoreAll, func(config apiconfig.CalicoAPIConfig) {
	Describe("Common resource tests", func() {
		It("Should return the data that was stored in the datastore, even if it was changed", func() {
			ctx := context.Background()
			name1 := "ippool-1"
			spec1 := apiv3.IPPoolSpec{
				CIDR:         "1.2.3.0/24",
				IPIPMode:     apiv3.IPIPModeAlways,
				VXLANMode:    apiv3.VXLANModeNever,
				BlockSize:    26,
				NodeSelector: "all()",
				AllowedUses:  []apiv3.IPPoolAllowedUse{apiv3.IPPoolAllowedUseWorkload},
			}
			c, err := clientv3.New(config)
			Expect(err).NotTo(HaveOccurred())

			be, err := backend.NewClient(config)
			Expect(err).NotTo(HaveOccurred())
			be.Clean()

			By("Creating a new IPPool with name1/spec1 and expecting CreationTimestamp nanoseconds to be stripped off")
			before := time.Now()
			res1, outError := c.IPPools().Create(ctx, &apiv3.IPPool{
				ObjectMeta: metav1.ObjectMeta{Name: name1, CreationTimestamp: metav1.Time{Time: before}},
				Spec:       spec1,
			}, options.SetOptions{})
			after := time.Now()
			Expect(outError).NotTo(HaveOccurred())

			// The assignment mode will be set to Automatic by the API server, we need to update the spec before comparison
			automatic := apiv3.Automatic
			spec1.AssignmentMode = &automatic

			Expect(res1).To(MatchResource(apiv3.KindIPPool, testutils.ExpectNoNamespace, name1, spec1))
			// The API server ignores the timestamp we sent and sets its own, so we can
			// only check that it falls within the Create call.
			timestamp := res1.GetObjectMeta().GetCreationTimestamp()
			Expect(timestamp.Nanosecond()).To(Equal(0))
			Expect(timestamp.Time).To(BeTemporally(">=", before.Truncate(time.Second)))
			Expect(timestamp.Time).To(BeTemporally("<=", after))

			// Track the version of the original data for name1.
			rv1_1 := res1.ResourceVersion

			By("Deleting IPPool (name1) with the new resource version")
			dres, outError := c.IPPools().Delete(ctx, name1, options.DeleteOptions{ResourceVersion: rv1_1})
			Expect(outError).NotTo(HaveOccurred())
			// The pool will first be disabled, so tweak the Disabled field before doing the comparison.
			spec1.Disabled = true
			Expect(dres).To(MatchResource(apiv3.KindIPPool, testutils.ExpectNoNamespace, name1, spec1))
		})
	})
})
