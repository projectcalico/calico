// Copyright (c) 2020 Tigera, Inc. All rights reserved.
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

package idalloc

import (
	"errors"

	"github.com/golang-collections/collections/stack"

	"github.com/projectcalico/libcalico-go/lib/set"
)

type IndexRange struct {
	Min, Max int
}

type IndexAllocator struct {
	indexStack *stack.Stack
}

func NewIndexAllocator(indexRange IndexRange) *IndexAllocator {
	r := &IndexAllocator{
		indexStack: stack.New(),
	}
	// Push in reverse order so that the lowest index will come out first.
	for i := indexRange.Max; i >= indexRange.Min; i-- {
		r.indexStack.Push(i)
	}
	return r
}

func (r *IndexAllocator) GrabIndex() (int, error) {
	if r.indexStack.Len() == 0 {
		return 0, errors.New("No more indices available")
	}
	return r.indexStack.Pop().(int), nil
}

func (r *IndexAllocator) ReleaseIndex(index int) {
	r.indexStack.Push(index)
}

func (r *IndexAllocator) GrabAllRemainingIndices() set.Set {
	remainingIndices := set.New()
	idx, err := r.GrabIndex()
	for err == nil {
		remainingIndices.Add(idx)
		idx, err = r.GrabIndex()
	}
	return remainingIndices
}
