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

package ipsets

import (
	"container/list"
	"iter"
	"slices"
)

// resyncPri is the priority of a queued resync.  Higher-valued priorities are
// drained first; the ordering matters for promotion (see resyncQueue.Add).
type resyncPri int

const (
	// resyncPriBackground sets are re-checked opportunistically, a time-boxed
	// batch per apply loop.
	resyncPriBackground resyncPri = iota
	// resyncPriMust sets are re-checked before we trust the dataplane: the
	// start-of-day resync and error-forced single-set resyncs.
	resyncPriMust
)

// resyncQueue is a FIFO of IP set names awaiting a dataplane resync, split into
// a "must" tier and a "background" tier.  A name appears in at most one tier at
// a time.  Re-adding a name that is already queued keeps its original position
// so that, even if we never fully drain between refreshes, every set still
// reaches the front eventually; the exception is promotion, which moves a
// background entry to the back of the must tier.
type resyncQueue struct {
	must       *list.List
	background *list.List
	entries    map[string]resyncEntry
}

type resyncEntry struct {
	pri     resyncPri
	element *list.Element
}

func newResyncQueue() *resyncQueue {
	return &resyncQueue{
		must:       list.New(),
		background: list.New(),
		entries:    map[string]resyncEntry{},
	}
}

// Add queues name at the given priority.  If name is already queued at the same
// or a higher priority its position is left unchanged.  A background entry that
// is re-added at "must" is promoted to the back of the must tier; there is no
// demotion.
func (q *resyncQueue) Add(name string, pri resyncPri) {
	existing, ok := q.entries[name]
	if !ok {
		q.push(name, pri)
		return
	}
	if pri <= existing.pri {
		return
	}
	q.listFor(existing.pri).Remove(existing.element)
	q.push(name, pri)
}

func (q *resyncQueue) push(name string, pri resyncPri) {
	q.entries[name] = resyncEntry{
		pri:     pri,
		element: q.listFor(pri).PushBack(name),
	}
}

func (q *resyncQueue) Remove(name string) {
	e, ok := q.entries[name]
	if !ok {
		return
	}
	q.listFor(e.pri).Remove(e.element)
	delete(q.entries, name)
}

func (q *resyncQueue) PopMust() (string, bool) {
	return q.pop(q.must)
}

func (q *resyncQueue) PopBackground() (string, bool) {
	return q.pop(q.background)
}

// PopAllMust pops all the "must" items and returns an iterator over them.
func (q *resyncQueue) PopAllMust() iter.Seq[string] {
	var names []string
	for {
		name, ok := q.PopMust()
		if !ok {
			break
		}
		names = append(names, name)
	}
	return slices.Values(names)
}

func (q *resyncQueue) pop(l *list.List) (string, bool) {
	front := l.Front()
	if front == nil {
		return "", false
	}
	name := front.Value.(string)
	l.Remove(front)
	delete(q.entries, name)
	return name, true
}

func (q *resyncQueue) Len() int {
	return len(q.entries)
}

func (q *resyncQueue) MustLen() int {
	return q.must.Len()
}

func (q *resyncQueue) Clear() {
	q.must.Init()
	q.background.Init()
	clear(q.entries)
}

func (q *resyncQueue) listFor(pri resyncPri) *list.List {
	if pri == resyncPriMust {
		return q.must
	}
	return q.background
}
