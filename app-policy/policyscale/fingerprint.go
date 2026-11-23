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

package policyscale

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"

	googleproto "google.golang.org/protobuf/proto"
)

const (
	// FixtureLabel is the label on every rendered object that holds the Fingerprint of the
	// fixture it came from. Objects with another value are left over from another policy set.
	FixtureLabel = "policyscale.projectcalico.org/fixture"
	// ObjectsAnnotation on each rendered tier holds how many objects the fixture renders, so a
	// set that was only partly applied shows as fewer objects carrying its FixtureLabel.
	ObjectsAnnotation = "policyscale.projectcalico.org/objects"
)

// Fingerprint identifies the policy set the fixture holds: fixtures with equal fingerprints have
// the same sets, policies, rules, tiers and profile. It is computed from what was built, not from
// the Spec, so a change to the generator that changes its output changes the fingerprint too.
//
// A tool that sends traffic at a cluster compares its fixture's fingerprint with the FixtureLabel
// on the applied objects: flows drawn from a different fixture aim at destinations no applied
// rule carries, and every one of them misses.
func (fx *Fixture) Fingerprint() string {
	h := sha256.New()
	marshal := googleproto.MarshalOptions{Deterministic: true}
	write := func(m googleproto.Message) {
		b, err := marshal.Marshal(m)
		if err != nil {
			panic(err)
		}
		writeField(h, b)
	}
	// Every set, including those left out of the store on purpose: a cluster holds them all.
	for _, id := range fx.setOrder {
		s := fx.sets[id]
		writeField(h, fmt.Appendf(nil, "set %s missing=%t ipport=%t %d", id, s.missing, s.isIPPort(), len(s.members)))
		for _, m := range s.members {
			writeField(h, []byte(m))
		}
	}
	for _, u := range fx.Updates() {
		if u.GetIpsetUpdate() == nil {
			write(u)
		}
	}
	// Tier order, default actions and the policies of each direction.
	write(fx.Endpoint())
	return hex.EncodeToString(h.Sum(nil)[:6])
}

// writeField writes b with its length, so that no two sequences of fields hash alike.
func writeField(h hash.Hash, b []byte) {
	_, _ = fmt.Fprintf(h, "%d:", len(b))
	_, _ = h.Write(b)
}
