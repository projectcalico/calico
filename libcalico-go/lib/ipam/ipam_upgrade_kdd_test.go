// Copyright (c) 2025 Tigera, Inc. All rights reserved.
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

package ipam

import (
	"context"
	"os"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	libapiv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/backend"
	bapi "github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/rawcrdclient"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam/ipamtestutils"
	"github.com/projectcalico/calico/libcalico-go/lib/testutils"
)

var _ = testutils.E2eDatastoreDescribe("IPAM UpgradeHost (Kubernetes datastore only)", testutils.DatastoreK8s, func(config apiconfig.CalicoAPIConfig) {
	var (
		bc        bapi.Client
		ic        Interface
		crdClient crclient.Client
		useV3     = os.Getenv("CALICO_API_GROUP") == "projectcalico.org"
	)

	BeforeEach(func() {
		// Fresh backend client and IPAM client.
		var err error
		bc, err = backend.NewClient(config)
		Expect(err).NotTo(HaveOccurred())
		Expect(bc.Clean()).NotTo(HaveOccurred())
		ic = NewIPAMClient(bc, ipPools, &fakeReservations{})

		// Build a raw CRD REST client using the same kubeconfig as the backend client.
		cfg, _, err := k8s.CreateKubernetesClientset(&config.Spec)
		Expect(err).NotTo(HaveOccurred())
		crdClient, err = rawcrdclient.New(cfg, useV3)
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		// Best-effort cleanup.
		_ = bc.Clean()
	})

	It("should add labels to this host's block affinities only", func() {
		if !useV3 {
			Skip("Block affinity upgrade not needed for v1 API group")
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		hostA := "host-a"
		hostB := "host-b"
		// Create unlabeled block affinities for two different hosts.
		Expect(ipamtestutils.CreateUnlabeledBlockAffinity(ctx, crdClient, hostA, "10.10.0.0/26")).To(Succeed())
		Expect(ipamtestutils.CreateUnlabeledBlockAffinity(ctx, crdClient, hostA, "10.10.0.64/26")).To(Succeed())
		Expect(ipamtestutils.CreateUnlabeledBlockAffinity(ctx, crdClient, hostB, "10.10.1.0/26")).To(Succeed())

		// Sanity check: List and assert they currently have no labels.
		var list libapiv3.BlockAffinityList
		Expect(crdClient.List(ctx, &list)).To(Succeed())
		Expect(list.Items).To(HaveLen(3))
		for _, item := range list.Items {
			Expect(item.Labels).To(HaveLen(0))
		}

		// Run the upgrade for hostA.
		Expect(ic.UpgradeHost(ctx, hostA)).To(Succeed())

		// Re-list and verify labels applied to hostA's affinities, but not hostB.
		list = libapiv3.BlockAffinityList{}
		Expect(crdClient.List(ctx, &list)).To(Succeed())
		By("verifying labels exist for host-a and not for host-b")
		for _, item := range list.Items {
			if item.Spec.Node == hostA {
				// Expect the 3 key labels to be present.
				Expect(item.Labels).To(HaveKey(v3.LabelHostnameHash))
				Expect(item.Labels).To(HaveKey(v3.LabelAffinityType))
				Expect(item.Labels).To(HaveKey(v3.LabelIPVersion))
				// Sanity check: values are as expected for host/type/ipversion
				Expect(item.Labels[v3.LabelAffinityType]).To(Equal("host"))
				Expect(item.Labels[v3.LabelIPVersion]).To(Equal("4"))
			} else if item.Spec.Node == hostB {
				// Other host should remain unlabeled.
				Expect(item.Labels).To(HaveLen(0), "unexpected labels on host-b")
			}
		}
	})
})
