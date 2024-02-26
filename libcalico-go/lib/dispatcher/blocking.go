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

	"github.com/sirupsen/logrus"
)

// BlockingDispatcher blocks on an input channel until stop,
// and broadcasts each input message to all output channels.
// Blocks until all output channels have consumed a message,
// before pulling in the next input message.
type BlockingDispatcher[T any] struct {
	outputs []chan<- T
	input   <-chan T
}

// NewBlockingDispatcher returns a BlockingDispatcher which
// will consume messages from the input channel.
// Dispatcher must be started with Start(ctx). Stopped by cancelling ctx.
func NewBlockingDispatcher[T any](input <-chan T) (*BlockingDispatcher[T], error) {
	if input == nil {
		logrus.Panic("No input channels passed to dispatcher")
	}

	return &BlockingDispatcher[T]{
		input:   input,
		outputs: make([]chan<- T, 0),
	}, nil
}

// DispatchForever is stopped by cancelling ctx.
// Loops Forever, pulling from input, and sending to all outputs.
// All output channels must consume messages promptly to keep dispatcher from blocking.
func (d *BlockingDispatcher[T]) DispatchForever(ctx context.Context, outputs ...chan T) {
	if outputs == nil || len(outputs) == 0 {
		logrus.Panic("No output channels provided for dispatching input")
	}

	logrus.WithField("outputs", len(outputs)).Debug("Dispatcher running...")
	for {
		// Wait for input or ctx cancellation.
		select {
		case <-ctx.Done():
			logrus.Debug("Stopping dispatcher...")
			return
		case msg, ok := <-d.input:
			if !ok {
				logrus.Panic("Input channel closed unexpectedly")
			}
			logrus.WithField("message", msg).Debug("Pulled message off input chan")
			for _, o := range outputs {
				select {
				case <-ctx.Done():
					logrus.Debug("Context closed. Exiting...")
					return
				case o <- msg:
				}
			}
			logrus.WithField("message", msg).Debug("Sent message to all outputs")
		}
	}
}
