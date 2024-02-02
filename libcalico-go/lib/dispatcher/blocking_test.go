package dispatcher_test

import (
	"context"
	"time"

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
			input <- dummyInput

			for range []chan interface{}{output1, output2} {
				var o interface{}
				var ok bool
				select {
				case o, ok = <-output1:
				case o, ok = <-output2:
				case <-time.After(1 * time.Second):
					Fail("Timed out waiting for dispatcher to send to outputs.")
				}
				Expect(ok).To(BeTrue(), "A channel closed unexpectedly.")
				dummyOutput, ok := o.(int)
				Expect(ok).To(BeTrue(), "Output should be the same datatype as input.")
				Expect(dummyOutput).To(Equal(dummyInput))
			}
		})
	})

	Context("BlockingDispatcherErrorHandling", func() {
		It("should return an error if no input is given", func() {
			blockingDispatcher, err := dispatcher.NewBlockingDispatcher[interface{}](nil)
			Expect(blockingDispatcher).To(BeNil())
			Expect(err).To(HaveOccurred())
		})
	})
})
