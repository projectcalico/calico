// Copyright (c) 2025 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package storage

import (
	"context"
	"sync"
	"testing"

	"github.com/projectcalico/calico/goldmane/pkg/testutils"
	"github.com/projectcalico/calico/goldmane/pkg/types"
	"github.com/projectcalico/calico/lib/std/time"
)

var now = time.Now()

func addFlows(b *AggregationBucket, cache *diachronicCache, n int) {
	for range n {
		f := testutils.NewRandomFlow(now.Unix())
		tf := types.ProtoToFlow(f)
		cache.add(tf)
		b.AddFlow(tf)
	}
	b.markReady()
}

type diachronicCache struct {
	sync.Mutex
	d map[types.FlowKey]*DiachronicFlow
}

func (c *diachronicCache) add(f *types.Flow) {
	c.Lock()
	defer c.Unlock()
	if _, ok := c.d[*f.Key]; !ok {
		c.d[*f.Key] = NewDiachronicFlow(f.Key, 0)
	}
}

func (c *diachronicCache) get(key types.FlowKey) *DiachronicFlow {
	c.Lock()
	defer c.Unlock()
	return c.d[key]
}

// setup configures a test. Each call to setup() creates a unique environment for the test to execute within,
// allowing for concurrent testing. Namely, each test gets:
// - Its own context.
// - Its own cache of diachronic flows.
// - Its own bucket to operate on.
// - Its own cancel function.
func setup(t *testing.T) (context.Context, *diachronicCache, *AggregationBucket, func()) {
	diachronics := &diachronicCache{d: make(map[types.FlowKey]*DiachronicFlow)}

	var cancel context.CancelFunc
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)

	// Create a new Bucket for the test.
	b := NewAggregationBucket(now, now.Add(15*time.Second))
	b.lookupFlow = diachronics.get

	return ctx, diachronics, b, func() { cancel() }
}

func TestConcurrentAccess(t *testing.T) {
	t.Run("multiple reads", func(t *testing.T) {
		ctx, cache, b, cancel := setup(t)
		defer cancel()

		// Write some flows to the bucket.
		addFlows(b, cache, 10)

		// We should be able to start many readers at once.
		num := 100
		iterStarted := make(chan bool, num)
		for range num {
			go func(ctx context.Context) {
				// Iterate the bucket, sending an indicator when we have started the first iteration.
				// We'll then just wait for the context to expire and exit. If concurrent access does not function,
				// we will block other readers.
				b.Iter(func(b FlowBuilder) bool {
					iterStarted <- true
					<-ctx.Done()
					return true // Indicates stop iteration.
				})
			}(ctx)
		}

		// Wait for indications that all goroutines successfully started iteration.
		for range num {
			select {
			case <-ctx.Done():
				t.Errorf("Test timed out")
				return
			case <-iterStarted:
			}
		}
	})

	t.Run("concurrent read/write", func(t *testing.T) {
		ctx, cache, b, cancel := setup(t)
		defer cancel()

		// Write some initial flows to the bucket.
		addFlows(b, cache, 100)

		// Start a goroutine that adds flows continuously.
		go func(ctx context.Context) {
			for {
				select {
				case <-ctx.Done():
					return
				default:
					addFlows(b, cache, 100)
				}
			}
		}(ctx)

		// We should be able to iterate the bucket without a problem.
		for range 100 {
			select {
			case <-ctx.Done():
				t.Errorf("Test timed out")
				return
			default:
				b.Iter(func(FlowBuilder) bool {
					return false
				})
			}
		}

		// We should be able to reset the bucket.
		b.Reset(time.Now().Unix(), time.Now().Add(15*time.Second).Unix())
	})
}

func TestReady(t *testing.T) {
	// Bucket should not iterate if it is not marked ready.
	_, cache, b, cancel := setup(t)
	defer cancel()

	addFlows(b, cache, 100)
	b.ready = false
	b.Iter(func(_ FlowBuilder) bool {
		t.Errorf("Should not iterate!")
		return true
	})
}
