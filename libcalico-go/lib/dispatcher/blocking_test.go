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

package dispatcher_test

import (
	"context"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/libcalico-go/lib/dispatcher"
)

var _ = Describe("Dispatching", func() {
	Context("BlockingDispatcher", func() {
		var blockingDispatcher *dispatcher.BlockingDispatcher[interface{}]
		var ctx context.Context
		var cancel context.CancelFunc
		var dispatcherExited chan struct{}
		var input chan interface{}
		runDispatcherInBackgroundWithOutputChans := func(outputs ...chan interface{}) {
			go func() {
				blockingDispatcher.DispatchForever(ctx, outputs...)
				close(dispatcherExited)
			}()
		}

		BeforeEach(func() {
			var err error
			input = make(chan interface{})
			blockingDispatcher, err = dispatcher.NewBlockingDispatcher[interface{}](input)
			Expect(err).NotTo(HaveOccurred())

			ctx, cancel = context.WithCancel(context.Background())
			dispatcherExited = make(chan struct{})
		})

		AfterEach(func() {
			cancel()
			Eventually(dispatcherExited).Should(BeClosed())
		})

		It("should dispatch a message to all outputs", func() {
			output1, output2 := make(chan interface{}, 0), make(chan interface{}, 0)
			dummyInput := 666

			runDispatcherInBackgroundWithOutputChans(output1, output2)

			// Dispatcher itself implicitly acts as a buffer of size 1.
			Eventually(input).Should(BeSent(dummyInput), "Couldn't send input to dispatcher")

			// Should output to each consumer in order.
			for _, o := range []chan interface{}{output1, output2} {
				Eventually(o, "10s").Should(Receive(Equal(dummyInput)), "Output channel didn't receive from dispatcher")
			}
		})
	})
})
