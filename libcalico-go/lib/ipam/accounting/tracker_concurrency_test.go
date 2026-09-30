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

package accounting

import (
	"math/rand/v2"
	"net"
	"sync"
	"sync/atomic"
	"testing"

	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

// One writer and several readers at once, for the race detector (make -C libcalico-go ut GINKGO_ARGS=-race). The
// final state must still match a rebuild.
func TestConcurrentReadsAndWrites(t *testing.T) {
	RegisterTestingT(t)
	tr := NewTracker()
	in := &trackerInputs{
		pools:        map[string]*v3.IPPool{},
		blocks:       map[string]*model.AllocationBlock{},
		reservations: map[string]*v3.IPReservation{},
		nodes:        map[string]bool{},
		refs:         map[string]AddressRef{},
	}

	var done atomic.Bool
	var readers sync.WaitGroup
	for range 4 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for !done.Load() {
				for name := range tr.SummarizeAll() {
					tr.Summarize(name)
					tr.Allocations(name)
					tr.Unreferenced(name)
				}
				tr.NoPoolBlocks()
				tr.NoPoolUnreferenced()
				tr.AllRefs()
				tr.Refs(net.ParseIP("10.0.0.1"))
			}
		}()
	}

	rng := rand.New(rand.NewPCG(7, 1))
	for range 2000 {
		randomOp(rng, tr, in)
	}
	done.Store(true)
	readers.Wait()
	expectSameReads(tr, in.rebuild(), "after concurrent writes")
}
