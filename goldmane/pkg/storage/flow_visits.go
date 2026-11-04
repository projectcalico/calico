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

package storage

import "iter"

// flowVisits reads the flows in a set of buckets, yielding each flow once even though it sits in
// every bucket it has a window in. A set of the flows seen would hold most of the ring on a long
// range, so instead each read gets a new number, and a flow records the number of the last read
// that yielded it. Only the main loop may read, and reads can't nest.
type flowVisits struct {
	// lastRead numbers the most recent read.
	lastRead uint64

	// reading is set during a read. A read inside it would take a new number, so the outer read
	// would see its flows as unvisited and yield them again.
	reading bool
}

// read yields each flow in the buckets once. It panics if another read is in progress.
func (v *flowVisits) read(buckets []*AggregationBucket) iter.Seq[*DiachronicFlow] {
	return func(yield func(*DiachronicFlow) bool) {
		if v.reading {
			panic("BucketRing: a read of the buckets' flows started inside another")
		}
		v.reading = true
		defer func() { v.reading = false }()

		v.lastRead++
		thisRead := v.lastRead
		for _, b := range buckets {
			for d := range b.Flows.All() {
				// An earlier bucket in this read already yielded the flow.
				if d.lastVisited == thisRead {
					continue
				}
				d.lastVisited = thisRead
				if !yield(d) {
					return
				}
			}
		}
	}
}
