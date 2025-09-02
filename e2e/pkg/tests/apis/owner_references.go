// Copyright (c) 2024-2025 Tigera, Inc. All rights reserved.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package apis

import (
	"context"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/e2e/pkg/describe"
	"github.com/projectcalico/calico/e2e/pkg/utils"
	"github.com/projectcalico/calico/e2e/pkg/utils/client"
)

var _ = describe.CalicoDescribe(
	describe.WithTeam(describe.Core),
	describe.WithFeature("OwnerReferences"),
	describe.WithCategory(describe.Configuration),
	"OwnerReference tests",
	func() {
		f := utils.NewDefaultFramework("owner-reference")

		var (
			cli ctrlclient.Client
			ctx context.Context
		)

		BeforeEach(func() {
			// Ensure a clean starting environment before each test.
			var err error
			cli, err = client.New(f.ClientConfig())
			Expect(err).NotTo(HaveOccurred())

			// Ensure a clean starting environment before each test.
			Expect(utils.CleanDatastore(cli)).ShouldNot(HaveOccurred())

			ctx = context.Background()
		})

		// This test verifies that the Kubernetes Garbage Collector correctly deletes Calico objects
		// with OwnerReferences if the referenced owner is deleted.
		It("should delete a NetworkSet if its owner has been deleted", func() {
			// Create a NetworkSet that will act as the owner.
			ns := v3.NewNetworkSet()
			ns.Name = "parent"
			ns.Namespace = f.Namespace.Name
			Expect(cli.Create(ctx, ns)).ShouldNot(HaveOccurred())

			// Query the network set so we can get the UID.
			var owner v3.NetworkSet
			Expect(cli.Get(ctx, ctrlclient.ObjectKeyFromObject(ns), &owner)).ShouldNot(HaveOccurred())

			// Create a new NetworkSet that is owned by the first NetworkSet.
			child := v3.NewNetworkSet()
			child.Name = "child"
			child.Namespace = f.Namespace.Name
			child.OwnerReferences = []metav1.OwnerReference{
				{
					APIVersion: "projectcalico.org/v3",
					Kind:       "NetworkSet",
					Name:       "parent",
					UID:        owner.UID,
				},
			}
			Expect(cli.Create(ctx, child)).ShouldNot(HaveOccurred())

			// Delete the parent NetworkSet.
			Expect(cli.Delete(ctx, &owner)).ShouldNot(HaveOccurred())

			// Eventually, the child NetworkSet should be deleted by the Kubernetes garbage collector.
			Eventually(func() error {
				err := cli.Get(ctx, ctrlclient.ObjectKeyFromObject(child), &v3.NetworkSet{})
				if errors.IsNotFound(err) {
					return nil
				} else if err != nil {
					return err
				}
				return fmt.Errorf("NetworkSet still exists")
			}, 5*time.Second).ShouldNot(HaveOccurred())
		})
	})
