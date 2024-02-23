// Copyright (c) 2024 Tigera, Inc. All rights reserved.

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

package statusrep_test

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/proto"
	"github.com/projectcalico/calico/felix/statusrep"
)

type mockBackoff struct {
	C            chan struct{}
	Closed       bool
	StepDuration time.Duration
}

func (b *mockBackoff) Step() time.Duration {
	if !b.Closed {
		close(b.C)
	}
	b.Closed = true
	return b.StepDuration
}

var _ = Describe("Endpoint Policy Status Reports [file-reporting]", func() {
	var endpointUpdatesC chan interface{}
	var ctx context.Context
	var cancel context.CancelFunc
	var doneC chan struct{}
	BeforeEach(func() {
		endpointUpdatesC = make(chan interface{})
		ctx, cancel = context.WithCancel(context.Background())
		doneC = make(chan struct{})
	})

	AfterEach(func() {
		cancel()
		Eventually(doneC).Should(BeClosed(), "Didn't receive signal indicating fileReporter exited")
	})

	It("should create a new directory and retry if it fails", func() {
		var fileReporter *statusrep.EndpointStatusFileReporter

		backoffCalledC := make(chan struct{})
		newMockBackoff := func() statusrep.Backoff {
			return &mockBackoff{
				C:            backoffCalledC,
				StepDuration: 1 * time.Nanosecond,
			}
		}

		// Use a path we think the reporter cannot write to.
		fileReporter = statusrep.NewEndpointStatusFileReporter(endpointUpdatesC, "/root/", statusrep.WithNewBackoffFunc(newMockBackoff))

		By("Starting a fileReporter which cannot create the necessary directory")

		go func() {
			defer func() {
				close(doneC)
			}()
			fileReporter.SyncForever(ctx)
		}()

		Eventually(endpointUpdatesC, "10s").Should(BeSent(&proto.DataplaneInSync{}))
		Eventually(backoffCalledC, "10s").Should(BeClosed(), "Backoff wasn't called by the reporter (is the file-reporting unexpectedly succeeding?).")
	})
})
