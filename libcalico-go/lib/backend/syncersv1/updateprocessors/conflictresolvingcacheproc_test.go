// Copyright (c) 2017 Tigera, Inc. All rights reserved.

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

package updateprocessors_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/syncersv1/updateprocessors"
	"github.com/projectcalico/calico/libcalico-go/lib/net"
)

// fakeconverter allows us to tune what is returned from the converter to test different
// error paths.
type fakeconverter struct {
	res *model.KVPair
	err error
}

func (fc *fakeconverter) Convert(in *model.KVPair) (*model.KVPair, error) {
	return fc.res, fc.err
}

// Most of the tests for the ConflictResolvingCacheUpdateProcessor are handled through the
// testing of the concrete implementations (BGPPeerProcessor and IPPoolProcessor).  The
// tests in this file mop up some of the error branches that need more controlled error
// handling.
var _ = Describe("Test the conflict resolving cache", func() {

	// Define a common set of keys and values for our tests.  Note the actual value
	// types are not important - but make sure we have something non-nil to indicate
	// a value is present.
	v3PeerKVP := &model.KVPair{
		Key: model.ResourceKey{
			Kind: apiv3.KindBGPPeer,
			Name: "name1",
		},
		Value:    "foobar",
		Revision: "12345",
	}
	v1Key1 := model.GlobalBGPPeerKey{
		PeerIP: net.MustParseIP("1.2.3.4"),
	}

	converter := &fakeconverter{}

	It("should handle converting the resource, but failing to create the v1 key", func() {
		c := updateprocessors.NewConflictResolvingCacheUpdateProcessor(apiv3.KindBGPPeer, converter.Convert)
		converter.res = &model.KVPair{
			Key:      v1Key1,
			Value:    "foobarfizz",
			Revision: "12345",
		}
		converter.err = nil

		By("successfully converting a Peer to populate the cache")
		// Note that we don't need proper values here since this test doesn't touch the conversion
		// code and instead uses our "fake" converter.
		kvp, err := c.Process(v3PeerKVP)
		Expect(err).NotTo(HaveOccurred())
		Expect(kvp).To(HaveLen(1))
		Expect(kvp[0]).To(Equal(
			&model.KVPair{
				Key:      v1Key1,
				Value:    "foobarfizz",
				Revision: "12345",
			},
		))

		By("Converter successfully converts the KVPair, but returns an invalid Key that cannot be converted - get delete and error")
		converter.res = &model.KVPair{
			Key:      model.GlobalBGPPeerKey{},
			Value:    "foobarfoo",
			Revision: "12346",
		}
		kvp, err = c.Process(v3PeerKVP)
		Expect(kvp).To(HaveLen(1))
		Expect(kvp[0]).To(Equal(
			&model.KVPair{
				Key: v1Key1,
			},
		))
		Expect(err).To(HaveOccurred())

		By("Converter successfully converts the KVPair, but returns an invalid Key that cannot be converted - get no actions, just error")
		converter.res = &model.KVPair{
			Key:      model.GlobalBGPPeerKey{},
			Value:    "foobarfoo",
			Revision: "12346",
		}
		kvp, err = c.Process(v3PeerKVP)
		Expect(kvp).To(HaveLen(0))
		Expect(err).To(HaveOccurred())
	})
})
