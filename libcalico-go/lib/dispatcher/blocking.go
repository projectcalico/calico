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

package dispatcher

import (
	"context"
	"errors"

	"github.com/sirupsen/logrus"
)

// BlockingDispatcher blocks on an input channel until stop,
// and broadcasts each input message to all output channels.
// Blocks until all output channels have consumed a message,
// before pulling in the next input message.
type BlockingDispatcher[T any] struct {
	outputs []chan<- T
	input   <-chan T

	log *logrus.Entry
}

// NewBlockingDispatcher returns a BlockingDispatcher which
// will consume messages from the input channel.
// Dispatcher must be started with Start(ctx). Stopped by cancelling ctx.
func NewBlockingDispatcher[T any](input <-chan T) (*BlockingDispatcher[T], error) {
	log := logrus.WithField("component", "BlockingDispatcher")

	if input == nil {
		return nil, errors.New("No input channel provided for dispatcher to consume")
	}

	return &BlockingDispatcher[T]{
		input:   input,
		outputs: make([]chan<- T, 0),
		log:     log,
	}, nil
}

// DispatchForever is stopped by cancelling ctx.
// Loops Forever, pulling from input, and sending to all outputs.
// All output channels must consume messages promptly to keep dispatcher from blocking.
func (d *BlockingDispatcher[T]) DispatchForever(ctx context.Context, outputs ...chan T) {
	log := d.log

	if outputs == nil || len(outputs) == 0 {
		log.Panic("No outputs provided for dispatching input")
	}

	for {
		// Wait for input or ctx cancellation.
		select {
		case <-ctx.Done():
			log.Debug("Stopping...")
			return
		case msg, ok := <-d.input:
			if !ok {
				log.Panic("Input channel closed unexpectedly")
			}
			log.WithField("message", msg).Debug("Pulled message off input chan")
			for _, o := range outputs {
				select {
				case <-ctx.Done():
					log.Debug("Context closed. Exiting...")
					return
				case o <- msg:
				}
			}
			log.WithField("message", msg).Debug("Sent message to all outputs")
		}
	}
}
