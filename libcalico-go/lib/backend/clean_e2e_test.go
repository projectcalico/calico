// Copyright (c) 2016-2017 Tigera, Inc. All rights reserved.

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

package backend_test

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/calico/libcalico-go/lib/backend"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
)

type isClean interface {
	IsClean() (bool, error)
}

// Perform additional watch tests
var _ = testutils.E2eDatastoreDescribe("Backend API tests", testutils.DatastoreEtcdV3, func(config apiconfig.CalicoAPIConfig) {

	ctx := context.Background()

	Describe("Test Clean() and IsClean() functionality", func() {
		It("should return correct clean status", func() {
			c, err := backend.NewClient(config)
			Expect(err).NotTo(HaveOccurred())

			// Clean the datastore
			By("Cleaning the datastore")
			c.Clean()

			// The backend that we are testing should implement the isClean interface.
			isCleanIf, ok := c.(isClean)
			Expect(ok).To(BeTrue())

			By("Checking the datastore is clean")
			clean, err := isCleanIf.IsClean()
			Expect(err).NotTo(HaveOccurred())
			Expect(clean).To(BeTrue())

			By("Adding an entry to the datastore")
			kvp := &model.KVPair{
				Key: model.ResourceKey{
					Kind: "IPPool",
					Name: "ippool-1",
				},
				Value: apiv3.IPPool{
					ObjectMeta: metav1.ObjectMeta{
						Name: "ippool-1",
					},
					Spec: apiv3.IPPoolSpec{
						CIDR: "1.2.3.0/24",
					},
				},
			}
			kvp, err = c.Create(ctx, kvp)
			Expect(err).NotTo(HaveOccurred())

			By("Checking the datastore is not clean")
			clean, err = isCleanIf.IsClean()
			Expect(err).NotTo(HaveOccurred())
			Expect(clean).To(BeFalse())

			By("Cleaning the datastore")
			c.Clean()

			By("Checking the datastore is clean")
			clean, err = isCleanIf.IsClean()
			Expect(err).NotTo(HaveOccurred())
			Expect(clean).To(BeTrue())
		})
	})

	Describe("Test Apply() with TTL", func() {
		It("should time out", func() {
			c, err := backend.NewClient(config)
			Expect(err).NotTo(HaveOccurred())

			By("Applying a status report with TTL")
			statusReport := model.StatusReport{
				Timestamp:     "5 past 3",
				UptimeSeconds: 10,
				FirstUpdate:   true,
			}
			kv := model.KVPair{
				Key:   model.ActiveStatusReportKey{Hostname: "host1", RegionString: "no-region"},
				Value: &statusReport,
				TTL:   1 * time.Second,
			}
			ctx := context.Background()

			// Apply key/value with a TTL.
			_, err = c.Apply(ctx, &kv)
			Expect(err).NotTo(HaveOccurred())

			// Read it back immediately, and check.
			kvGet, err := c.Get(ctx, kv.Key, "")
			Expect(err).NotTo(HaveOccurred())
			Expect(kvGet.Key).To(Equal(kv.Key))
			Expect(kvGet.Value).To(Equal(kv.Value))

			// Expect new Gets to start failing, within 10s, because the KV has timed
			// out and been removed.
			Eventually(func() error {
				_, err := c.Get(ctx, kv.Key, "")
				return err
			}, "10s", "1s").Should(HaveOccurred())
		})
	})
})
