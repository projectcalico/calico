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

// Package topk keeps the first k values of a stream in sort order, without sorting the rest.
package topk

import (
	"container/heap"
	"fmt"
	"slices"
)

// Keeper keeps the first limit values offered, in cmp order, without sorting the rest. The third
// page of 20 flows, for example, needs only the first 60, so a Keeper with a limit of 60 holds
// those while every other flow streams past. Once full, it holds the values in a heap whose root
// is the kept value that sorts last, so a value sorting before the root replaces it in
// O(log limit) and any other is dropped.
type Keeper[T any] struct {
	h byLast[T]
}

// New returns a Keeper for the first limit values in cmp order. A limit of zero keeps nothing.
// sizeHint, when known, saves regrowing the backing slice while it fills.
func New[T any](limit int, cmp func(a, b T) int, sizeHint int) *Keeper[T] {
	return &Keeper[T]{h: byLast[T]{
		limit:  limit,
		cmp:    cmp,
		values: make([]T, 0, max(0, min(limit, sizeHint))),
	}}
}

// Offer keeps v if it is among the first limit values offered so far.
func (k *Keeper[T]) Offer(v T) {
	h := &k.h
	switch {
	case len(h.values) < h.limit:
		h.values = append(h.values, v)
		if len(h.values) == h.limit {
			heap.Init(h)
		}
	case h.limit > 0 && h.cmp(v, h.values[0]) < 0:
		h.values[0] = v
		heap.Fix(h, 0)
	}
}

// Sorted returns the kept values in cmp order. The Keeper reuses the slice, so stop offering
// values once it has been called.
func (k *Keeper[T]) Sorted() []T {
	slices.SortFunc(k.h.values, k.h.cmp)
	return k.h.values
}

// byLast is a heap.Interface whose root is the value that sorts last under cmp.
type byLast[T any] struct {
	limit  int
	cmp    func(a, b T) int
	values []T
}

// Len returns the number of values held.
func (h *byLast[T]) Len() int {
	return len(h.values)
}

// Less puts the value that sorts later under cmp nearer the root.
func (h *byLast[T]) Less(i, j int) bool {
	return h.cmp(h.values[i], h.values[j]) > 0
}

// Swap exchanges two held values.
func (h *byLast[T]) Swap(i, j int) {
	h.values[i], h.values[j] = h.values[j], h.values[i]
}

// Push appends v, which heap.Push hands over as an any.
func (h *byLast[T]) Push(v any) {
	t, ok := v.(T)
	if !ok {
		panic(fmt.Sprintf("topk: pushed a %T onto a heap of %T", v, t))
	}
	h.values = append(h.values, t)
}

// Pop removes and returns the last value, which heap.Pop has just moved there from the root.
func (h *byLast[T]) Pop() any {
	v := h.values[len(h.values)-1]
	h.values = h.values[:len(h.values)-1]
	return v
}
