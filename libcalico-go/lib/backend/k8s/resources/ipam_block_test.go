// Copyright (c) 2025 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package resources

import (
	"context"
	"encoding/json"
	"net/netip"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/projectcalico/api/pkg/client/clientset_generated/clientset/scheme"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/rest/fake"

	"github.com/projectcalico/calico/libcalico-go/lib/apis/internalapi"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
)

var _ = Describe("ipamBlockClient tests with fake REST client", func() {
	var client K8sResourceClient
	var fakeREST *fake.RESTClient

	BeforeEach(func() {
		fakeREST = &fake.RESTClient{
			NegotiatedSerializer: serializer.WithoutConversionCodecFactory{CodecFactory: scheme.Codecs},
			GroupVersion: schema.GroupVersion{
				Group:   "crd.projectcalico.org",
				Version: "v1",
			},
			VersionedAPIPath: "/apis",
		}
		client = NewIPAMBlockClient(fakeREST, BackingAPIGroupV1)
	})

	It("should list all (v3)", func() {
		l, err := client.List(context.TODO(), model.ResourceListOptions{
			Kind: internalapi.KindIPAMBlock,
		}, "")

		// Expect an error since the client is not implemented.
		Expect(err).To(HaveOccurred())
		Expect(l).To(BeNil())

		// But we should be able to check the request...
		url := fakeREST.Req.URL
		logrus.Debug("URL: ", url)
		Expect(url.Path).To(Equal("/apis/ipamblocks"))
		Expect(url.Query()).NotTo(HaveKey("metadata.name"))
	})

	It("should list all (v1)", func() {
		l, err := client.List(context.TODO(), model.BlockListOptions{}, "")

		// Expect an error since the client is not implemented.
		Expect(err).To(HaveOccurred())
		Expect(l).To(BeNil())

		// But we should be able to check the request...
		url := fakeREST.Req.URL
		logrus.Debug("URL: ", url)
		Expect(url.Path).To(Equal("/apis/ipamblocks"))
		Expect(url.Query()).NotTo(HaveKey("metadata.name"))
	})
})

var _ = Describe("ipamBlockClient cooldown release round-trip", func() {
	// This exercises the crd.projectcalico.org/v1 ("KDD v1") backend, which is the
	// default datastore. An IP that has been released but is still in its cooldown
	// window is represented by an AllocationAttribute with ReleasedAt set; this must
	// survive a store/load round-trip or garbage collection will never deallocate it.
	//
	// With the default IPCooldownSeconds of 0, ReleasedAt is consumed immediately and
	// never needs to survive a round-trip, so a regression here would otherwise be
	// invisible to CI. This test pins the behaviour with a non-zero cooldown release.
	c := &ipamBlockClient{v3: false}

	It("preserves a non-nil ReleasedAt through V1->internalapi->JSON->V1", func() {
		releasedAt := metav1.NewTime(time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC))
		handle := "handle-0"
		idx := 0

		v1kvp := &model.KVPair{
			Key: model.BlockKey{
				CIDR: netip.MustParsePrefix("10.0.0.0/26"),
			},
			Value: &model.AllocationBlock{
				CIDR:        netToIPNet("10.0.0.0/26"),
				Allocations: []*int{&idx},
				Unallocated: []int{},
				Attributes: []model.AllocationAttribute{
					{
						HandleID:   &handle,
						ReleasedAt: &releasedAt,
					},
				},
			},
		}

		// V1 (model) -> internalapi.IPAMBlock, the type actually stored in the
		// crd.projectcalico.org/v1 datastore.
		v3kvp := c.IPAMBlockV1toV3(v1kvp)
		block := v3kvp.Value.(*internalapi.IPAMBlock)
		Expect(block.Spec.Attributes).To(HaveLen(1))
		Expect(block.Spec.Attributes[0].ReleasedAt).NotTo(BeNil())

		// Simulate the datastore persisting and returning the object as JSON. This
		// catches a missing JSON tag or a field pruned by the CRD structural schema,
		// in addition to a conversion that drops the field.
		data, err := json.Marshal(block)
		Expect(err).NotTo(HaveOccurred())
		var reloaded internalapi.IPAMBlock
		Expect(json.Unmarshal(data, &reloaded)).To(Succeed())

		// internalapi.IPAMBlock -> V1 (model), as read back by the IPAM code.
		back, err := c.IPAMBlockV3toV1(&model.KVPair{
			Key:   v3kvp.Key,
			Value: &reloaded,
		})
		Expect(err).NotTo(HaveOccurred())

		ab := back.Value.(*model.AllocationBlock)
		Expect(ab.Attributes).To(HaveLen(1))
		Expect(ab.Attributes[0].ReleasedAt).NotTo(BeNil(), "cooldown release was lost on the KDD v1 round-trip")
		Expect(ab.Attributes[0].ReleasedAt.Time).To(BeTemporally("==", releasedAt.Time))
	})
})

func netToIPNet(cidr string) cnet.IPNet {
	_, n, err := cnet.ParseCIDR(cidr)
	Expect(err).NotTo(HaveOccurred())
	return *n
}
