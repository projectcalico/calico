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
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"golang.org/x/net/context"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/calico/libcalico-go/lib/backend"
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
})
