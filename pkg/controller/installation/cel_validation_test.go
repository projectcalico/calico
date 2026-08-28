// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package installation

import (
	"context"
	"encoding/json"
	"path/filepath"
	"runtime"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	operator "github.com/tigera/operator/api/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

var _ = Describe("Installation CRD CEL validation", Serial, func() {
	var (
		testEnv *envtest.Environment
		c       client.Client
		ctx     context.Context
	)

	BeforeEach(func() {
		ctx = context.Background()

		_, thisFile, _, ok := runtime.Caller(0)
		Expect(ok).To(BeTrue())
		crdDir := filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "config", "crd", "bases")

		testEnv = &envtest.Environment{
			CRDDirectoryPaths:     []string{crdDir},
			ErrorIfCRDPathMissing: true,
		}
		cfg, err := testEnv.Start()
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { _ = testEnv.Stop() })

		Expect(operator.AddToScheme(scheme.Scheme)).To(Succeed())
		c, err = client.New(cfg, client.Options{Scheme: scheme.Scheme})
		Expect(err).NotTo(HaveOccurred())
	})

	newInstallation := func(v4 *operator.NodeAddressAutodetection) *operator.Installation {
		return &operator.Installation{
			ObjectMeta: metav1.ObjectMeta{Name: "default"},
			Spec: operator.InstallationSpec{
				CalicoNetwork: &operator.CalicoNetworkSpec{
					NodeAddressAutodetectionV4: v4,
				},
			},
		}
	}

	Describe("NodeAddressAutodetection", func() {
		AfterEach(func() {
			inst := &operator.Installation{ObjectMeta: metav1.ObjectMeta{Name: "default"}}
			err := c.Delete(ctx, inst)
			if err != nil {
				GinkgoLogr.Error(err, "Failed to delete Installation in AfterEach")
			}
		})

		DescribeTable("should allow single or no methods",
			func(v4 *operator.NodeAddressAutodetection) {
				Expect(c.Create(ctx, newInstallation(v4))).To(Succeed())
			},
			Entry("empty", &operator.NodeAddressAutodetection{}),
			Entry("nil", nil),
			Entry("firstFound", &operator.NodeAddressAutodetection{FirstFound: ptr.To(true)}),
			Entry("interface", &operator.NodeAddressAutodetection{Interface: "eth0"}),
			Entry("skipInterface", &operator.NodeAddressAutodetection{SkipInterface: "docker.*"}),
			Entry("canReach", &operator.NodeAddressAutodetection{CanReach: "8.8.8.8"}),
			Entry("cidrs", &operator.NodeAddressAutodetection{CIDRS: []string{"10.0.0.0/8"}}),
			Entry("kubernetes", &operator.NodeAddressAutodetection{Kubernetes: ptr.To(operator.NodeInternalIP)}),
		)

		DescribeTable("should reject multiple methods",
			func(v4 *operator.NodeAddressAutodetection) {
				err := c.Create(ctx, newInstallation(v4))
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("no more than one autodetection method"))
			},
			Entry("firstFound + interface", &operator.NodeAddressAutodetection{
				FirstFound: ptr.To(true),
				Interface:  "eth0",
			}),
			Entry("interface + canReach", &operator.NodeAddressAutodetection{
				Interface: "eth0",
				CanReach:  "8.8.8.8",
			}),
			Entry("kubernetes + cidrs", &operator.NodeAddressAutodetection{
				Kubernetes: ptr.To(operator.NodeInternalIP),
				CIDRS:      []string{"10.0.0.0/8"},
			}),
			Entry("three methods", &operator.NodeAddressAutodetection{
				FirstFound: ptr.To(true),
				Interface:  "eth0",
				CanReach:   "8.8.8.8",
			}),
			Entry("skipInterface + canReach", &operator.NodeAddressAutodetection{
				SkipInterface: "docker.*",
				CanReach:      "8.8.8.8",
			}),
		)

		It("should reject a merge patch that adds a second method", func() {
			inst := newInstallation(&operator.NodeAddressAutodetection{FirstFound: ptr.To(true)})
			Expect(c.Create(ctx, inst)).To(Succeed())

			// Merge patch adds interface alongside firstFound — the exact
			// scenario that motivated this CEL rule.
			patch, err := json.Marshal(map[string]any{
				"spec": map[string]any{
					"calicoNetwork": map[string]any{
						"nodeAddressAutodetectionV4": map[string]any{
							"interface": "eth0",
						},
					},
				},
			})
			Expect(err).NotTo(HaveOccurred())
			err = c.Patch(ctx, inst, client.RawPatch(types.MergePatchType, patch))
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("no more than one autodetection method"))
		})
	})
})
