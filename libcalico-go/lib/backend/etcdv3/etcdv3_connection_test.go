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

// This file is in the etcdv3 package (rather than etcdv3_test) so that it can
// shorten clientTimeout: the connection check waits for the full timeout before
// giving up, which is too long for a unit test.

package etcdv3

import (
	"net"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
)

var _ = Describe("NewEtcdV3Client connection check", func() {
	var restoreTimeout func()

	BeforeEach(func() {
		original := clientTimeout
		clientTimeout = 500 * time.Millisecond
		restoreTimeout = func() { clientTimeout = original }
	})

	AfterEach(func() {
		restoreTimeout()
	})

	It("should fail to create a client when the endpoint is unreachable", func() {
		// clientv3.New() no longer dials, so without an explicit connection
		// check an unreachable endpoint would only surface on a later read.
		client, err := NewEtcdV3Client(&apiconfig.EtcdConfig{
			EtcdEndpoints: "http://" + closedAddress(),
		})
		Expect(err).To(HaveOccurred())
		Expect(client).To(BeNil())

		// Callers such as calicoctl distinguish an unreachable datastore from a
		// bad configuration by the error type.
		Expect(err).To(BeAssignableToTypeOf(cerrors.ErrorDatastoreError{}))
	})
})

// closedAddress returns a loopback host:port that nothing is listening on, by
// binding a port and immediately releasing it.
func closedAddress() string {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	Expect(err).NotTo(HaveOccurred())
	address := listener.Addr().String()
	Expect(listener.Close()).To(Succeed())
	return address
}
