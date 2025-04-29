package utils

import (
	"time"

	"github.com/sirupsen/logrus"
)

const (
	// BatchUpdateSize length of the buffered channel for the controllers and the max batch size to handle during ProcessBatch
	BatchUpdateSize = 1000

	// batchWaitDuration maximum time we wait for more updates to be received via channel before starting to process the updates
	batchWaitDuration = 1 * time.Second
)

// ProcessBatch tries to batch multiple updates from a channel before triggering any further processing
// This helps to handle bursts in the channel by quickly reading the items without blocking the channel,
// and processing the updates once the channel is clear
func ProcessBatch[T any](channel <-chan T, update T, fn func(T), log *logrus.Entry) {
	log.Debug("Reading batch of updates from channel")

	var batch []T
	batch = append(batch, update)

	wait := time.After(batchWaitDuration)

consolidationLoop:
	for i := 1; i < BatchUpdateSize; i++ {
		select {
		case nextUpdate := <-channel:
			batch = append(batch, nextUpdate)
			i++
		case <-wait:
			break consolidationLoop
		}
	}

	log.WithField("items", len(batch)).Debug("Received batch of updates")

	if fn == nil {
		// If fn is nil we used ProcessBatch to wait for more updates, but triggering full sync
		log.Debug("Batch processor received a nil fn, skipping update")
		return
	}

	log.WithField("items", len(batch)).Debug("Triggering update for each item in batch")
	for _, update := range batch {
		fn(update)
	}
}
