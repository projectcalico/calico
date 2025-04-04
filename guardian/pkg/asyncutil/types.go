// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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

package asyncutil

import (
	"github.com/projectcalico/calico/lib/std/chanutil"
)

// Command represents a command to run asynchronously. It allows for providing paramters to be passed to whatever is
// executing the command and has a channel to wait for the result on.
type Command[P any, R any] struct {
	params     P
	resultChan chan Result[R]
}

// NewCommand creates a new command of the given type with the given parameter. It also returns the result channel that
// the result will be written to when the command is executed.
func NewCommand[P any, R any](params P) (Command[P, R], chan Result[R]) {
	resultChan := make(chan Result[R], 1)
	return Command[P, R]{params: params, resultChan: resultChan}, resultChan
}

type Result[V any] struct {
	value V
	err   error
}

func (r Result[V]) Result() (V, error) {
	return r.value, r.err
}

func (c Command[C, R]) Get() C {
	return c.params
}

func (c Command[C, R]) Return(result R) {
	defer close(c.resultChan)
	c.resultChan <- Result[R]{value: result}
}

func (c Command[C, R]) ReturnError(err error) {
	defer close(c.resultChan)

	select {
	case c.resultChan <- Result[R]{err: err}:
	default:
		panic("result channel is full, this should never happen since only one result should ever be written")
	}
}

// ErrorBuffer is an error buffer that can be used in multiple routines.
type ErrorBuffer interface {
	Write(err error)
	Receive() <-chan error
	Close()
	Clear()
}

type errorBuffer struct {
	errs chan error
}

func NewErrorBuffer() ErrorBuffer {
	return &errorBuffer{errs: make(chan error, 1)}
}

// Write writes the error to the buffer. If the buffer is full the error is dropped.
func (b *errorBuffer) Write(err error) {
	chanutil.WriteNonBlocking(b.errs, err)
}

func (b *errorBuffer) Receive() <-chan error {
	return b.errs
}

func (b *errorBuffer) Close() {
	close(b.errs)
}

// Clear drains the internal buffer and returns when there's nothing left.
// Not that writing to the error buffer should not be done while clearing, since if writing is happening as quick
// as clearing is then the buffer will never be cleared.
func (b *errorBuffer) Clear() {
	chanutil.Clear(b.errs)
}
