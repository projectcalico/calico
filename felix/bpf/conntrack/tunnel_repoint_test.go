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

package conntrack_test

import (
	"errors"
	"testing"

	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/felix/bpf/conntrack"
)

type fakeRepointer struct {
	calls []conntrack.IfindexReplacement
	err   error
}

func (f *fakeRepointer) RepointIfindex(oldIfindex, newIfindex int) (int, error) {
	f.calls = append(f.calls, conntrack.IfindexReplacement{OldIfindex: oldIfindex, NewIfindex: newIfindex})
	return 1, f.err
}

func TestTunnelIfaceRepointerReplaysToLateFamilies(t *testing.T) {
	RegisterTestingT(t)
	r := conntrack.NewTunnelIfaceRepointer()

	r.OnTunnelReplaced(10, 20)
	r.OnTunnelReplaced(20, 30)

	v4 := &fakeRepointer{}
	r.RegisterFamily(4, v4)
	Expect(v4.calls).To(Equal([]conntrack.IfindexReplacement{{OldIfindex: 10, NewIfindex: 20}, {OldIfindex: 20, NewIfindex: 30}}))

	v6 := &fakeRepointer{}
	r.RegisterFamily(6, v6)
	Expect(v6.calls).To(Equal([]conntrack.IfindexReplacement{{OldIfindex: 10, NewIfindex: 20}, {OldIfindex: 20, NewIfindex: 30}}))
}

func TestTunnelIfaceRepointerRepointsAllFamilies(t *testing.T) {
	RegisterTestingT(t)
	r := conntrack.NewTunnelIfaceRepointer()
	v4 := &fakeRepointer{}
	v6 := &fakeRepointer{err: errors.New("boom")}
	r.RegisterFamily(4, v4)
	r.RegisterFamily(6, v6)

	r.OnTunnelReplaced(10, 20)
	Expect(v4.calls).To(Equal([]conntrack.IfindexReplacement{{OldIfindex: 10, NewIfindex: 20}}))
	Expect(v6.calls).To(Equal([]conntrack.IfindexReplacement{{OldIfindex: 10, NewIfindex: 20}}))
}
