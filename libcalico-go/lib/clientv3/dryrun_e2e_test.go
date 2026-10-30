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

package clientv3_test

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/projectcalico/api/pkg/lib/numorstring"
	etcdclient "go.etcd.io/etcd/client/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	"github.com/projectcalico/calico/libcalico-go/lib/backend"
	"github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
)

var _ = testutils.E2eDatastoreDescribe("Dry-run writes", testutils.DatastoreAll, func(config apiconfig.CalicoAPIConfig) {
	ctx := context.Background()
	dryRun := options.SetOptions{DryRun: true}
	var calicoClient clientv3.Interface

	BeforeEach(func() {
		var err error
		calicoClient, err = clientv3.New(config)
		Expect(err).NotTo(HaveOccurred())
		be, err := backend.NewClient(config)
		Expect(err).NotTo(HaveOccurred())
		Expect(be.Clean()).To(Succeed())
	})

	newSet := func(nets ...string) *apiv3.GlobalNetworkSet {
		return &apiv3.GlobalNetworkSet{
			ObjectMeta: metav1.ObjectMeta{Name: "dryrun-set"},
			Spec:       apiv3.GlobalNetworkSetSpec{Nets: nets},
		}
	}

	It("should not persist a dry-run create", func() {
		_, err := calicoClient.GlobalNetworkSets().Create(ctx, newSet("10.0.0.0/24"), dryRun)
		Expect(err).NotTo(HaveOccurred())

		_, err = calicoClient.GlobalNetworkSets().Get(ctx, "dryrun-set", options.GetOptions{})
		Expect(err).To(BeAssignableToTypeOf(cerrors.ErrorResourceDoesNotExist{}))
	})

	It("should reject a dry-run create of an existing resource", func() {
		_, err := calicoClient.GlobalNetworkSets().Create(ctx, newSet("10.0.0.0/24"), options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())

		_, err = calicoClient.GlobalNetworkSets().Create(ctx, newSet("10.1.0.0/24"), dryRun)
		Expect(err).To(BeAssignableToTypeOf(cerrors.ErrorResourceAlreadyExists{}))
	})

	It("should not persist a dry-run update", func() {
		orig, err := calicoClient.GlobalNetworkSets().Create(ctx, newSet("10.0.0.0/24"), options.SetOptions{})
		Expect(err).NotTo(HaveOccurred())

		upd := orig.DeepCopy()
		upd.Spec.Nets = []string{"10.1.0.0/24"}
		_, err = calicoClient.GlobalNetworkSets().Update(ctx, upd, dryRun)
		Expect(err).NotTo(HaveOccurred())

		stored, err := calicoClient.GlobalNetworkSets().Get(ctx, "dryrun-set", options.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		Expect(stored.Spec.Nets).To(Equal([]string{"10.0.0.0/24"}))
	})
})

var _ = testutils.E2eDatastoreDescribe("Dry-run writes against CRD validation", testutils.DatastoreK8s, func(config apiconfig.CalicoAPIConfig) {
	ctx := context.Background()

	It("should reject a dry run that only the CRD's CEL rules reject", func() {
		c, err := clientv3.New(config)
		Expect(err).NotTo(HaveOccurred())

		// The Calico validator accepts this peer; only a CEL rule on the CRD rejects it.
		_, err = c.BGPPeers().Create(ctx, &apiv3.BGPPeer{
			ObjectMeta: metav1.ObjectMeta{Name: "dryrun-peer"},
			Spec: apiv3.BGPPeerSpec{
				PeerSelector: "all()",
				ASNumber:     numorstring.ASNumber(64512),
			},
		}, options.SetOptions{DryRun: true})
		Expect(err).To(MatchError(ContainSubstring("asNumber must be empty when peerSelector is set")))
	})
})

var _ = testutils.E2eDatastoreDescribe("Dry-run writes with a TTL", testutils.DatastoreEtcdV3, func(config apiconfig.CalicoAPIConfig) {
	ctx := context.Background()

	It("should not grant an etcd lease", func() {
		c, err := clientv3.New(config)
		Expect(err).NotTo(HaveOccurred())
		etcd, err := etcdclient.New(etcdclient.Config{Endpoints: []string{config.Spec.EtcdEndpoints}})
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(etcd.Close)

		// Other specs leave short-lived leases behind, so look for this TTL rather than for no leases.
		ttl := 97 * time.Minute
		_, err = c.GlobalNetworkSets().Create(ctx, &apiv3.GlobalNetworkSet{
			ObjectMeta: metav1.ObjectMeta{Name: "dryrun-ttl-set"},
			Spec:       apiv3.GlobalNetworkSetSpec{Nets: []string{"10.0.0.0/24"}},
		}, options.SetOptions{DryRun: true, TTL: ttl})
		Expect(err).NotTo(HaveOccurred())

		leases, err := etcd.Leases(ctx)
		Expect(err).NotTo(HaveOccurred())
		for _, l := range leases.Leases {
			resp, err := etcd.TimeToLive(ctx, l.ID)
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.GrantedTTL).NotTo(Equal(int64(ttl.Seconds())))
		}
	})
})
