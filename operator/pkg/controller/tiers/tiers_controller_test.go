// Copyright (c) 2022-2026 Tigera, Inc. All rights reserved.

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

package tiers

import (
	"context"
	"errors"

	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/stretchr/testify/mock"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	operatorv1 "github.com/projectcalico/calico/operator/api/v1"
	"github.com/projectcalico/calico/operator/pkg/apis"
	"github.com/projectcalico/calico/operator/pkg/common"
	"github.com/projectcalico/calico/operator/pkg/controller/options"
	"github.com/projectcalico/calico/operator/pkg/controller/status"
	"github.com/projectcalico/calico/operator/pkg/controller/utils"
	"github.com/projectcalico/calico/operator/pkg/ctrlruntime"
	ctrlrfake "github.com/projectcalico/calico/operator/pkg/ctrlruntime/client/fake"
	"github.com/projectcalico/calico/operator/pkg/extensions"
)

var _ = Describe("tier controller tests", func() {
	var r ReconcileTiers
	var c client.Client
	var ctx context.Context
	var scheme *runtime.Scheme
	var mockStatus *status.MockStatus
	var readyFlag *utils.ReadyFlag

	BeforeEach(func() {
		// The schema contains all objects that should be known to the fake client when the test runs.
		scheme = runtime.NewScheme()
		Expect(apis.AddToScheme(scheme, false)).NotTo(HaveOccurred())
		Expect(operatorv1.SchemeBuilder.AddToScheme(scheme)).NotTo(HaveOccurred())
		Expect(appsv1.AddToScheme(scheme))

		// Create a client that will have a crud interface of k8s objects.
		c = ctrlrfake.DefaultFakeClientBuilder(scheme).Build()
		ctx = context.Background()

		mockStatus = &status.MockStatus{}
		mockStatus.On("OnCRFound").Return()

		// Mark that the watches were successful.
		readyFlag = &utils.ReadyFlag{}
		readyFlag.MarkAsReady()

		// Create an object we can use throughout the test to perform the reconcile loops.
		r = ReconcileTiers{
			client:             c,
			scheme:             scheme,
			status:             mockStatus,
			tierWatchReady:     readyFlag,
			policyWatchesReady: readyFlag,
			opts: options.ControllerOptions{
				DetectedProvider: operatorv1.ProviderNone,
			},
		}

		// Create objects that are prerequisites of the reconcile loop.
		Expect(c.Create(
			ctx,
			&operatorv1.Installation{
				ObjectMeta: metav1.ObjectMeta{Name: "default"},
				Spec: operatorv1.InstallationSpec{
					Variant:  operatorv1.CalicoEnterprise,
					Registry: "some.registry.org/",
				},
				Status: operatorv1.InstallationStatus{
					Variant: operatorv1.CalicoEnterprise,
					Computed: &operatorv1.InstallationSpec{
						Variant:  operatorv1.CalicoEnterprise,
						Registry: "some.registry.org/",
						// The test is provider agnostic.
						KubernetesProvider: operatorv1.ProviderNone,
					},
				},
			})).NotTo(HaveOccurred())

		Expect(c.Create(ctx, &operatorv1.APIServer{
			ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"},
			Status:     operatorv1.APIServerStatus{State: operatorv1.TigeraStatusReady},
		})).NotTo(HaveOccurred())

		Expect(c.Create(ctx, &appsv1.DaemonSet{
			ObjectMeta: metav1.ObjectMeta{Name: "node-local-dns", Namespace: "kube-dns"},
			TypeMeta:   metav1.TypeMeta{Kind: (&appsv1.DaemonSet{}).String()},
		})).NotTo(HaveOccurred())
	})

	// Validate that the tier is created. Policy coverage is handled in the render tests.
	It("reconciles the calico-system tier", func() {
		mockStatus.On("ReadyToMonitor")
		mockStatus.On("ClearDegraded")

		_, err := r.Reconcile(ctx, reconcile.Request{})
		Expect(err).ShouldNot(HaveOccurred())

		tier := v3.Tier{}
		Expect(c.Get(ctx, client.ObjectKey{Name: "calico-system"}, &tier)).To(BeNil())
	})

	It("waits for API server to be available before reconciling", func() {
		err := c.Delete(ctx, &operatorv1.APIServer{ObjectMeta: metav1.ObjectMeta{Name: "tigera-secure"}})
		Expect(err).ShouldNot(HaveOccurred())
		mockStatus = &status.MockStatus{}
		mockStatus.On("OnCRFound").Return()
		mockStatus.On("SetDegraded", operatorv1.ResourceNotReady, "Waiting for Tigera API server to be ready", mock.Anything, mock.Anything).Return()
		r = ReconcileTiers{
			client:             c,
			scheme:             scheme,
			status:             mockStatus,
			tierWatchReady:     readyFlag,
			policyWatchesReady: readyFlag,
			opts: options.ControllerOptions{
				DetectedProvider: operatorv1.ProviderNone,
			},
		}

		_, err = r.Reconcile(ctx, reconcile.Request{})

		Expect(err).ShouldNot(HaveOccurred())
		mockStatus.AssertExpectations(GinkgoT())
	})

	It("allows DNS access to the namespaces the variant contributes", func() {
		r.opts.Extensions = extensions.New(extensions.Set{Tiers: dnsClientNamespaces{"tigera-manager", "tigera-prometheus"}})

		cfg, res := r.prepareTiersConfig(ctx, logr.Discard())
		Expect(res).To(BeNil())
		Expect(cfg.CalicoNamespaces).To(Equal([]string{common.CalicoNamespace, "tigera-manager", "tigera-prometheus"}))
	})

	It("runs the extension's own tier work before rendering", func() {
		ext := &recordingTiers{}
		r.opts.Extensions = extensions.New(extensions.Set{Tiers: ext})
		mockStatus.On("ReadyToMonitor")
		mockStatus.On("ClearDegraded")

		_, err := r.Reconcile(ctx, reconcile.Request{})
		Expect(err).ShouldNot(HaveOccurred())
		Expect(ext.called).To(BeTrue())
	})

	It("degrades when the extension's tier work fails", func() {
		r.opts.Extensions = extensions.New(extensions.Set{Tiers: &recordingTiers{err: errors.New("patch failed")}})
		mockStatus.On("SetDegraded", operatorv1.ResourcePatchError, "Error patching tier", mock.Anything, mock.Anything).Return()

		_, err := r.Reconcile(ctx, reconcile.Request{})
		Expect(err).ShouldNot(HaveOccurred())
		mockStatus.AssertExpectations(GinkgoT())
	})

	It("allows DNS access to the core namespace alone when the variant contributes none", func() {
		cfg, res := r.prepareTiersConfig(ctx, logr.Discard())
		Expect(res).To(BeNil())
		Expect(cfg.CalicoNamespaces).To(Equal([]string{common.CalicoNamespace}))
	})
})

// dnsClientNamespaces is a variant that contributes namespaces and nothing else.
type dnsClientNamespaces []string

func (dnsClientNamespaces) Watches(ctrlruntime.Controller) error { return nil }

func (n dnsClientNamespaces) DNSClientNamespaces(context.Context, client.Client) ([]string, error) {
	return n, nil
}

func (dnsClientNamespaces) Reconcile(context.Context, client.Client) error { return nil }

// recordingTiers is a variant that only reports whether its tier work ran.
type recordingTiers struct {
	called bool
	err    error
}

func (recordingTiers) Watches(ctrlruntime.Controller) error { return nil }

func (recordingTiers) DNSClientNamespaces(context.Context, client.Client) ([]string, error) {
	return nil, nil
}

func (t *recordingTiers) Reconcile(context.Context, client.Client) error {
	t.called = true
	return t.err
}
