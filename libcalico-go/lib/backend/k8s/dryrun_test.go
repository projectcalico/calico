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

package k8s

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/k8s/resources"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
)

const fakeKind = "FakeKind"

// writeCountingClient counts the writes that reach it. It has no dry-run support,
// so any write it receives would be persisted.
type writeCountingClient struct {
	resources.K8sResourceClient
	writes int
}

func (c *writeCountingClient) Create(_ context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	c.writes++
	return kvp, nil
}

func (c *writeCountingClient) Update(_ context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	c.writes++
	return kvp, nil
}

// dryRunCountingClient is a writeCountingClient that honors dry runs.
type dryRunCountingClient struct {
	writeCountingClient
}

func (c *dryRunCountingClient) SupportsDryRun() bool {
	return true
}

var _ = Describe("KubeClient dry-run writes", func() {
	var kvp *model.KVPair

	BeforeEach(func() {
		kvp = &model.KVPair{Key: model.ResourceKey{Kind: fakeKind, Name: "res"}}
	})

	kubeClientFor := func(rc resources.K8sResourceClient) *KubeClient {
		return &KubeClient{clientsByResourceKind: map[string]resources.K8sResourceClient{fakeKind: rc}}
	}

	It("should refuse a dry run to a client that can't honor one", func() {
		rc := &writeCountingClient{}
		c := kubeClientFor(rc)

		_, err := c.Create(api.WithDryRun(context.Background()), kvp)
		Expect(err).To(BeAssignableToTypeOf(cerrors.ErrorOperationNotSupported{}))
		_, err = c.Update(api.WithDryRun(context.Background()), kvp)
		Expect(err).To(BeAssignableToTypeOf(cerrors.ErrorOperationNotSupported{}))
		Expect(rc.writes).To(BeZero())
	})

	It("should pass a dry run to a client that honors one", func() {
		rc := &dryRunCountingClient{}
		c := kubeClientFor(rc)

		_, err := c.Create(api.WithDryRun(context.Background()), kvp)
		Expect(err).NotTo(HaveOccurred())
		_, err = c.Update(api.WithDryRun(context.Background()), kvp)
		Expect(err).NotTo(HaveOccurred())
		Expect(rc.writes).To(Equal(2))
	})

	It("should pass a normal write to a client without dry-run support", func() {
		rc := &writeCountingClient{}
		c := kubeClientFor(rc)

		_, err := c.Create(context.Background(), kvp)
		Expect(err).NotTo(HaveOccurred())
		_, err = c.Update(context.Background(), kvp)
		Expect(err).NotTo(HaveOccurred())
		Expect(rc.writes).To(Equal(2))
	})
})
