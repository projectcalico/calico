// Copyright (c) 2017,2019,2021 Tigera, Inc. All rights reserved.

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

package clientv3_test

import (
	"context"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/calico/libcalico-go/lib/backend"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/encap"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
	"github.com/projectcalico/calico/libcalico-go/lib/watch"
)

var _ = testutils.E2eDatastoreDescribe("IPPool KDD v1 to v3 migration tests", testutils.DatastoreK8s, func(config apiconfig.CalicoAPIConfig) {

	ctx := context.Background()
	name1 := "ippool-1"
	name2 := "ippool-2"

	spec1_v3 := apiv3.IPPoolSpec{
		CIDR:         "1.2.3.0/24",
		NATOutgoing:  true,
		IPIPMode:     apiv3.IPIPModeCrossSubnet,
		VXLANMode:    apiv3.VXLANModeNever,
		BlockSize:    26,
		NodeSelector: "all()",
		AllowedUses:  []apiv3.IPPoolAllowedUse{apiv3.IPPoolAllowedUseWorkload, apiv3.IPPoolAllowedUseTunnel},
	}
	kvp1 := &model.KVPair{
		Key: model.ResourceKey{
			Name: name1,
			Kind: apiv3.KindIPPool,
		},
		Value: &apiv3.IPPool{
			TypeMeta: metav1.TypeMeta{
				Kind:       apiv3.KindIPPool,
				APIVersion: apiv3.GroupVersionCurrent,
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: name1,
			},
			Spec: apiv3.IPPoolSpec{
				CIDR:         "1.2.3.0/24",
				Disabled:     false,
				NATOutgoing:  true,
				NodeSelector: "all()",
				VXLANMode:    apiv3.VXLANModeNever,
				IPIP: &apiv3.IPIPConfiguration{
					Enabled: true,
					Mode:    encap.CrossSubnet,
				},
				BlockSize: 26,
			},
		},
	}

	spec2_v3 := apiv3.IPPoolSpec{
		CIDR:         "2001::/120",
		NATOutgoing:  true,
		IPIPMode:     apiv3.IPIPModeNever,
		VXLANMode:    apiv3.VXLANModeNever,
		BlockSize:    122,
		NodeSelector: "all()",
		AllowedUses:  []apiv3.IPPoolAllowedUse{apiv3.IPPoolAllowedUseWorkload, apiv3.IPPoolAllowedUseTunnel},
	}
	kvp2 := &model.KVPair{
		Key: model.ResourceKey{
			Name: name1,
			Kind: apiv3.KindIPPool,
		},
		Value: &apiv3.IPPool{
			TypeMeta: metav1.TypeMeta{
				Kind:       apiv3.KindIPPool,
				APIVersion: apiv3.GroupVersionCurrent,
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: name1,
			},
			Spec: apiv3.IPPoolSpec{
				CIDR:         "2001::/120",
				Disabled:     false,
				NATOutgoing:  true,
				BlockSize:    122,
				NodeSelector: "all()",
				VXLANMode:    apiv3.VXLANModeNever,
				IPIP: &apiv3.IPIPConfiguration{
					Enabled: false,
				},
			},
		},
	}

	spec3_v3 := apiv3.IPPoolSpec{
		CIDR:         "1.1.1.0/24",
		NATOutgoing:  false,
		IPIPMode:     apiv3.IPIPModeAlways,
		VXLANMode:    apiv3.VXLANModeNever,
		BlockSize:    26,
		NodeSelector: "all()",
		AllowedUses:  []apiv3.IPPoolAllowedUse{apiv3.IPPoolAllowedUseWorkload, apiv3.IPPoolAllowedUseTunnel},
	}
	kvp3 := &model.KVPair{
		Key: model.ResourceKey{
			Name: name1,
			Kind: apiv3.KindIPPool,
		},
		Value: &apiv3.IPPool{
			TypeMeta: metav1.TypeMeta{
				Kind:       apiv3.KindIPPool,
				APIVersion: apiv3.GroupVersionCurrent,
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: name1,
			},
			Spec: apiv3.IPPoolSpec{
				CIDR:      "1.1.1.0/24",
				Disabled:  false,
				VXLANMode: apiv3.VXLANModeNever,
				IPIP: &apiv3.IPIPConfiguration{
					Enabled: true,
				},
				BlockSize:    26,
				NodeSelector: "all()",
			},
		},
	}

	spec5_v3 := apiv3.IPPoolSpec{
		CIDR:         "1.2.3.0/24",
		NATOutgoing:  true,
		IPIPMode:     apiv3.IPIPModeAlways,
		VXLANMode:    apiv3.VXLANModeNever,
		BlockSize:    26,
		NodeSelector: "all()",
		AllowedUses:  []apiv3.IPPoolAllowedUse{apiv3.IPPoolAllowedUseWorkload, apiv3.IPPoolAllowedUseTunnel},
	}
	kvp5 := &model.KVPair{
		Key: model.ResourceKey{
			Name: name1,
			Kind: apiv3.KindIPPool,
		},
		Value: &apiv3.IPPool{
			TypeMeta: metav1.TypeMeta{
				Kind:       apiv3.KindIPPool,
				APIVersion: apiv3.GroupVersionCurrent,
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: name1,
			},
			Spec: apiv3.IPPoolSpec{
				CIDR:      "1.2.3.0/24",
				Disabled:  false,
				VXLANMode: apiv3.VXLANModeNever,
				IPIP: &apiv3.IPIPConfiguration{
					Enabled: true,
					Mode:    encap.Always,
				},
				NATOutgoing:   true,
				NATOutgoingV1: false,
				BlockSize:     26,
				NodeSelector:  "all()",
			},
		},
	}

	spec6_v3 := apiv3.IPPoolSpec{
		CIDR:         "1.2.3.0/24",
		NATOutgoing:  true,
		IPIPMode:     apiv3.IPIPModeCrossSubnet,
		VXLANMode:    apiv3.VXLANModeNever,
		BlockSize:    26,
		NodeSelector: "has(x)",
		AllowedUses:  []apiv3.IPPoolAllowedUse{apiv3.IPPoolAllowedUseWorkload, apiv3.IPPoolAllowedUseTunnel},
	}
	kvp6 := &model.KVPair{
		Key: model.ResourceKey{
			Name: name1,
			Kind: apiv3.KindIPPool,
		},
		Value: &apiv3.IPPool{
			TypeMeta: metav1.TypeMeta{
				Kind:       apiv3.KindIPPool,
				APIVersion: apiv3.GroupVersionCurrent,
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: name1,
			},
			Spec: apiv3.IPPoolSpec{
				CIDR:          "1.2.3.0/24",
				Disabled:      false,
				VXLANMode:     apiv3.VXLANModeNever,
				IPIPMode:      apiv3.IPIPModeCrossSubnet,
				IPIP:          nil,
				NATOutgoing:   false,
				NATOutgoingV1: true,
				BlockSize:     26,
				NodeSelector:  "has(x)",
			},
		},
	}

	DescribeTable("IPPool CRD with v1 IPIP field tests",
		func(name1, name2 string, spec_v3 apiv3.IPPoolSpec, kvp *model.KVPair) {
			c, err := clientv3.New(config)
			Expect(err).NotTo(HaveOccurred())

			be, err := backend.NewClient(config)
			Expect(err).NotTo(HaveOccurred())
			be.Clean()

			By("Attempting to creating a new IPPool with the non-writable v1 IPIP field")
			_, outError := c.IPPools().Create(ctx, &apiv3.IPPool{
				ObjectMeta: metav1.ObjectMeta{Name: name1},
				Spec:       kvp.Value.(*apiv3.IPPool).Spec,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())

			By("Creating IPPool with v1 IPIP field directly in the backend")
			outKVP1, err := be.Create(ctx, kvp)
			Expect(err).NotTo(HaveOccurred())

			outPool, err := be.Get(ctx, kvp.Key, outKVP1.Revision)
			Expect(err).NotTo(HaveOccurred())
			Expect(outPool.Value.(*apiv3.IPPool).Spec.IPIP).To(BeNil())

			// We don't expect the AllowedUses field to be filled in by the backend client.  That is defaulted
			// in the frontend.
			spec_v3_copy := spec_v3
			spec_v3_copy.AllowedUses = nil
			Expect(outPool.Value.(*apiv3.IPPool).Spec).To(Equal(spec_v3_copy))

			By("Updating the IPPool from the API client with the non-writable v1 IPIP field")
			_, outError = c.IPPools().Update(ctx, &apiv3.IPPool{
				ObjectMeta: metav1.ObjectMeta{Name: name1, ResourceVersion: "555", CreationTimestamp: metav1.Now(), UID: "a-rabbit-ate-my-carrot"},
				Spec:       kvp.Value.(*apiv3.IPPool).Spec,
			}, options.SetOptions{})
			Expect(outError).To(HaveOccurred())

			By("Listing all the IPPools, expecting a single result with name1/spec_v1")
			outList, outError := c.IPPools().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(ConsistOf(
				testutils.Resource(apiv3.KindIPPool, testutils.ExpectNoNamespace, name1, spec_v3),
			))

			By("Creating a new IPPool with name2/spec_v3")

			By("Creating another IPPool with v1 IPIP field directly in the backend name2/kvp_v3")
			kvpName2 := *kvp
			kvpName2.Key = model.ResourceKey{
				Name: name2,
				Kind: apiv3.KindIPPool,
			}

			// Also need to change the Value Metadata Name because that will be the CRD key and needs to be unique.
			kvpName2.Value.(*apiv3.IPPool).Name = name2

			_, err = be.Create(ctx, &kvpName2)
			Expect(err).NotTo(HaveOccurred())

			By("Listing all the IPPools, expecting a two results with name1/spec_v1 and name2/spec_v3")
			outList, outError = c.IPPools().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(ConsistOf(
				testutils.Resource(apiv3.KindIPPool, testutils.ExpectNoNamespace, name1, spec_v3),
				testutils.Resource(apiv3.KindIPPool, testutils.ExpectNoNamespace, name2, spec_v3),
			))
		},

		Entry("IPv4 IPPool CRD with v1 IPIP field and IPIP Enabled set to true and Mode CrossSubnet", name1, name2, spec1_v3, kvp1),
		Entry("IPv6 IPPool CRD with v1 IPIP field and IPIP Enabled set to false and Mode Never", name1, name2, spec2_v3, kvp2),
		Entry("IPv4 IPPool CRD with v1 IPIP field and IPIP Enabled set to true and Mode Always", name1, name2, spec3_v3, kvp3),
		Entry("IPv4 IPPool CRD with v1 NATOutgoingV1 field set to false and v3 NATOutgoing set to true", name1, name2, spec5_v3, kvp5),
		Entry("IPv4 IPPool CRD with v1 NATOutgoingV1 field set to true (v1 IPIP set to nil) and v3 NATOutgoing set to false", name1, name2, spec6_v3, kvp6),
	)

	Describe("IPPool watch functionality", func() {
		It("should handle watch events for backend IPPool with v1 IPIP field", func() {
			c, err := clientv3.New(config)
			Expect(err).NotTo(HaveOccurred())

			be, err := backend.NewClient(config)
			Expect(err).NotTo(HaveOccurred())
			be.Clean()

			By("Listing IPPools with no resource version and checking for no results")
			outList, outError := c.IPPools().List(ctx, options.ListOptions{})
			Expect(outError).NotTo(HaveOccurred())
			Expect(outList.Items).To(HaveLen(0))
			rev0 := outList.ResourceVersion

			By("Creating IPPool with v1 IPIP field directly in the backend")
			kvp1Name1 := *kvp1
			kvp1Name1.Key = model.ResourceKey{
				Name: name1,
				Kind: apiv3.KindIPPool,
			}

			// Also need to change the Value Metadata Name because that will be the CRD key and needs to be unique.
			kvp1Name1.Value.(*apiv3.IPPool).Name = name1

			outKVP1, err := be.Create(ctx, &kvp1Name1)
			Expect(err).NotTo(HaveOccurred())
			outRes1 := outKVP1.Value.(*apiv3.IPPool)

			By("Creating another IPPool with v1 IPIP field directly in the backend")
			kvp2Name2 := *kvp2
			kvp2Name2.Key = model.ResourceKey{
				Name: name2,
				Kind: apiv3.KindIPPool,
			}

			// Also need to change the Value Metadata Name because that will be the CRD key and needs to be unique.
			kvp2Name2.Value.(*apiv3.IPPool).Name = name2

			outKVP2, err := be.Create(ctx, &kvp2Name2)
			Expect(err).NotTo(HaveOccurred())
			outRes2 := outKVP2.Value.(*apiv3.IPPool)

			By("Deleting IPPool with v1 IPIP field directly in the backend")
			outKVP3, err := be.Delete(ctx, kvp1.Key, "")
			Expect(err).NotTo(HaveOccurred())
			outRes3 := outKVP3.Value.(*apiv3.IPPool)

			By("Starting a watcher from rev0 - this should get all events")
			w, err := c.IPPools().Watch(ctx, options.ListOptions{ResourceVersion: rev0})
			Expect(err).NotTo(HaveOccurred())
			testWatcher2 := testutils.NewTestResourceWatch(config.Spec.DatastoreType, w)
			defer testWatcher2.Stop()

			By("Modifying res2")
			outRes4, err := c.IPPools().Update(
				ctx,
				&apiv3.IPPool{
					ObjectMeta: metav1.ObjectMeta{Name: name2, ResourceVersion: outRes2.ResourceVersion, CreationTimestamp: metav1.Now(), UID: outKVP2.Value.(*apiv3.IPPool).ObjectMeta.UID},
					Spec:       spec2_v3,
				},
				options.SetOptions{},
			)
			Expect(err).NotTo(HaveOccurred())
			testWatcher2.ExpectEvents(apiv3.KindIPPool, []watch.Event{
				{
					Type:   watch.Added,
					Object: outRes1,
				},
				{
					Type:   watch.Added,
					Object: outRes2,
				},
				{
					Type:     watch.Deleted,
					Previous: outRes3,
				},
				{
					Type:     watch.Modified,
					Previous: outRes2,
					Object:   outRes4,
				},
			})
			testWatcher2.Stop()

		})
	})

})
