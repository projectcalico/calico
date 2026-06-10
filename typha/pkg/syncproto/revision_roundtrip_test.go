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

package syncproto

import (
	"bytes"
	"encoding/gob"
	"testing"

	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

// TestRevisionSurvivesChainedHop asserts that a KV's revision survives the
// round-trip a chained ("hierarchical") Typha performs: an upstream Typha
// serializes the update, sends it over the wire (gob), the follower
// deserializes it with ToUpdate(), and then re-serializes it into its own
// snapshot cache.  The revision must come out unchanged so that downstream
// dedupe/skip logic keeps working across the extra hop.
func TestRevisionSurvivesChainedHop(t *testing.T) {
	RegisterTestingT(t)

	orig := api.Update{
		KVPair: model.KVPair{
			Key:      model.GlobalConfigKey{Name: "some-config"},
			Value:    "some-value",
			Revision: "12345",
		},
		UpdateType: api.UpdateTypeKVNew,
	}

	// Upstream serializes.
	su1, err := SerializeUpdate(orig)
	Expect(err).NotTo(HaveOccurred())
	Expect(su1.Revision).To(Equal("12345"))

	// Over the wire: gob encode/decode the SerializedUpdate (as MsgKVs would).
	var buf bytes.Buffer
	Expect(gob.NewEncoder(&buf).Encode(su1)).To(Succeed())
	var su1Decoded SerializedUpdate
	Expect(gob.NewDecoder(&buf).Decode(&su1Decoded)).To(Succeed())

	// Follower deserializes into an api.Update (this is what the syncclient
	// hands the dedupe buffer).
	upd, err := su1Decoded.ToUpdate()
	Expect(err).NotTo(HaveOccurred())
	Expect(upd.Revision).To(Equal("12345"))

	// Follower re-serializes into its own snapshot cache.
	su2, err := SerializeUpdate(upd)
	Expect(err).NotTo(HaveOccurred())
	Expect(su2.Revision).To(Equal("12345"))

	// And the value is intact after the double hop.
	upd2, err := su2.ToUpdate()
	Expect(err).NotTo(HaveOccurred())
	Expect(upd2.Value).To(Equal("some-value"))
	Expect(upd2.Revision).To(Equal("12345"))
}
