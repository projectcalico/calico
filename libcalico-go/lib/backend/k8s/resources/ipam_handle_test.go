// Copyright (c) 2020 Tigera, Inc. All rights reserved.

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

package resources_test

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/calico/libcalico-go/lib/backend"
	bapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
)

var _ = testutils.E2eDatastoreDescribe("IPAM handle k8s backend tests", testutils.DatastoreK8s, func(config apiconfig.CalicoAPIConfig) {
	It("should properly handle the deleted flag", func() {
		be, err := backend.NewClient(config)
		Expect(err).NotTo(HaveOccurred())
		be.Clean()

		// Create a new handle.
		kvp := model.KVPair{
			Key: model.IPAMHandleKey{
				HandleID: "handle-id",
			},
			Value: &model.IPAMHandle{
				Deleted: false,
				Block:   map[string]int{"192.168.0.0/26": 1},
			},
		}
		_, err = be.Create(context.Background(), &kvp)
		Expect(err).NotTo(HaveOccurred())

		// Check that it can be seen.
		newKVP, err := be.Get(context.Background(), kvp.Key, "")
		Expect(err).NotTo(HaveOccurred())

		// Update it to be deleted.
		newKVP.Value.(*model.IPAMHandle).Deleted = true
		_, err = be.Update(context.Background(), newKVP)

		// Can no longer see it.
		_, err = be.Get(context.Background(), kvp.Key, "")
		Expect(err).To(HaveOccurred())
		Expect(err).To(BeAssignableToTypeOf(errors.ErrorResourceDoesNotExist{}))
	})

	It("should support Watch and emit handle events", func() {
		be, err := backend.NewClient(config)
		Expect(err).NotTo(HaveOccurred())
		be.Clean()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		w, err := be.Watch(ctx, model.IPAMHandleListOptions{}, bapi.WatchOptions{})
		Expect(err).NotTo(HaveOccurred(), "Watch must no longer be unsupported")
		defer w.Stop()

		// Create a handle and confirm we observe the event.
		kvp := model.KVPair{
			Key: model.IPAMHandleKey{HandleID: "watch-handle"},
			Value: &model.IPAMHandle{
				Deleted: false,
				Block:   map[string]int{"192.168.0.0/26": 1},
			},
		}
		_, err = be.Create(context.Background(), &kvp)
		Expect(err).NotTo(HaveOccurred())

		var got bapi.WatchEvent
		Eventually(w.ResultChan(), 5*time.Second).Should(Receive(&got))
		Expect(got.Type).To(Equal(bapi.WatchAdded))
		Expect(got.New.Key).To(Equal(kvp.Key))
	})
})
