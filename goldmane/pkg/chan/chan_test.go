// Copyright (c) 2023 Tigera, Inc. All rights reserved.

package _chan_test

import (
	"context"
	"time"

	_chan "github.com/tigera/image-assurance/pkg/chan"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("ReadBatch", func() {
	It("Reads everything in one batch from the channel when the limit is the size of the number of elements on the channel reached", func() {
		list := []string{"a", "b", "c", "d", "e"}
		ch := make(chan string, 5)
		defer close(ch)

		for _, s := range list {
			ch <- s
		}

		batch := _chan.ReadBatch(ch, 5)
		Expect(batch).Should(Equal(list))
	})

	It("Reads everything in one batch from the channel when the limit is greater than the number of elements on the channel", func() {
		list := []string{"a", "b", "c", "d", "e"}
		ch := make(chan string, 5)
		defer close(ch)

		for _, s := range list {
			ch <- s
		}

		batch := _chan.ReadBatch(ch, 20)
		Expect(batch).Should(Equal(list))
	})

	It("Reads a maximum of the max batch size even if there's more elements on the channel", func() {
		list := []string{"a", "b", "c", "d", "e"}
		ch := make(chan string, 5)
		defer close(ch)

		for _, s := range list {
			ch <- s
		}

		batch := _chan.ReadBatch(ch, 3)
		Expect(batch).Should(Equal(list[0:3]))
	})

	It("Returns an empty batch if the channel has nothing on it", func() {
		ch := make(chan string, 5)
		defer close(ch)

		batch := _chan.ReadBatch(ch, 5)
		Expect(batch).Should(BeEmpty())
	})

	It("Returns an empty batch if the channel is closed", func() {
		ch := make(chan string, 5)
		close(ch)

		batch := _chan.ReadBatch(ch, 5)
		Expect(batch).Should(BeEmpty())
	})
})

var _ = Describe("ReadWithContext", func() {
	var (
		ctx context.Context
	)

	BeforeEach(func() {
		ctx = context.Background()
	})

	It("should return the value from channel when available", func() {
		ch := make(chan int)
		go func() {
			time.Sleep(time.Second * 1)
			ch <- 100
		}()
		result, cancel := _chan.ReadWithContext(ctx, ch)
		Expect(result).To(Equal(100))
		Expect(cancel).To(BeFalse())
	})

	It("should return default int value when context is cancelled", func() {
		ch := make(chan int)
		cancelCtx, cancel := context.WithCancel(ctx)
		go func() {
			time.Sleep(time.Second * 1)
			cancel()
		}()
		result, done := _chan.ReadWithContext(cancelCtx, ch)
		Expect(result).To(Equal(0))
		Expect(done).To(BeTrue())
	})

	It("should return default struct value when context is cancelled", func() {
		ch := make(chan struct{})
		cancelCtx, cancel := context.WithCancel(ctx)
		go func() {
			time.Sleep(time.Second * 1)
			cancel()
		}()
		result, done := _chan.ReadWithContext(cancelCtx, ch)
		Expect(result).To(Equal(struct{}{}))
		Expect(done).To(BeTrue())
	})

})
