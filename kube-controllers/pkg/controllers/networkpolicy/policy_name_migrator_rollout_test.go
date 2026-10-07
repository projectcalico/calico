// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package networkpolicy

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

var _ = Describe("policy name migrator rollout wait", func() {
	var (
		ctx    context.Context
		cancel context.CancelFunc
		m      *policyMigrator
	)

	BeforeEach(func() {
		// One poll interval is 5s, so leave room for a single successful check.
		ctx, cancel = context.WithTimeout(context.Background(), 8*time.Second)
		DeferCleanup(func() { cancel() })

		canal := &appsv1.DaemonSet{
			ObjectMeta: metav1.ObjectMeta{Name: "canal", Namespace: "kube-system", Generation: 1},
			Status: appsv1.DaemonSetStatus{
				ObservedGeneration:     1,
				DesiredNumberScheduled: 1,
				CurrentNumberScheduled: 1,
				UpdatedNumberScheduled: 1,
			},
		}
		m = &policyMigrator{
			ctx:       ctx,
			cs:        fake.NewClientset(canal),
			namespace: "kube-system",
		}
	})

	It("should finish once the configured DaemonSet has rolled out", func() {
		m.nodeDaemonSet = "canal"
		Expect(m.waitForCalicoNodeRollout()).To(Succeed())
	})

	It("should keep waiting when the configured DaemonSet does not exist", func() {
		m.nodeDaemonSet = "calico-node"
		Expect(m.waitForCalicoNodeRollout()).To(MatchError(context.DeadlineExceeded))
	})
})
