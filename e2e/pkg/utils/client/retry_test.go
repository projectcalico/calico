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

package client

import (
	"context"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

// shrinkRetry keeps the retry paths from sleeping on the real two-minute budget.
func shrinkRetry(t *testing.T) {
	orig := apiRetry
	apiRetry = wait.Backoff{Steps: 5, Duration: time.Millisecond}
	t.Cleanup(func() { apiRetry = orig })
}

func newFakeClient(t *testing.T, objs ...ctrlclient.Object) ctrlclient.WithWatch {
	scheme, err := newScheme()
	NewWithT(t).Expect(err).NotTo(HaveOccurred())
	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
}

func registeredAPIService() *apiregistrationv1.APIService {
	return &apiregistrationv1.APIService{
		ObjectMeta: metav1.ObjectMeta{Name: calicoV3APIServiceName},
	}
}

// stubDiscovery answers ServerGroups from fn, which sees the 1-indexed call count.
type stubDiscovery struct {
	calls int
	fn    func(call int) (*metav1.APIGroupList, error)
}

func (s *stubDiscovery) ServerGroups() (*metav1.APIGroupList, error) {
	s.calls++
	return s.fn(s.calls)
}

func servingV3() *metav1.APIGroupList {
	return &metav1.APIGroupList{
		Groups: []metav1.APIGroup{{
			Name:     v3.SchemeGroupVersion.Group,
			Versions: []metav1.GroupVersionForDiscovery{{Version: v3.SchemeGroupVersion.Version}},
		}},
	}
}

func servingNothing() *metav1.APIGroupList {
	return &metav1.APIGroupList{}
}

func TestRetriableAPIError(t *testing.T) {
	g := NewWithT(t)

	g.Expect(RetriableAPIError(apierrors.NewServiceUnavailable("unexpected EOF"))).To(BeTrue())
	g.Expect(RetriableAPIError(apierrors.NewInternalError(context.DeadlineExceeded))).To(BeTrue())
	g.Expect(RetriableAPIError(&meta.NoKindMatchError{GroupKind: schema.GroupKind{Group: "projectcalico.org"}})).To(BeTrue())

	// Conflict belongs to the callers that re-read the object, not to the wrapper.
	g.Expect(RetriableAPIError(apierrors.NewConflict(schema.GroupResource{}, "default", nil))).To(BeFalse())
	g.Expect(RetriableAPIError(apierrors.NewNotFound(schema.GroupResource{}, "default"))).To(BeFalse())
	g.Expect(RetriableAPIError(apierrors.NewForbidden(schema.GroupResource{}, "default", nil))).To(BeFalse())
}

func TestWithRetryRetriesServiceUnavailable(t *testing.T) {
	g := NewWithT(t)
	shrinkRetry(t)

	gets := 0
	base := newFakeClient(t, registeredAPIService())
	c := WithRetry(interceptor.NewClient(base, interceptor.Funcs{
		Get: func(ctx context.Context, cli ctrlclient.WithWatch, key ctrlclient.ObjectKey, obj ctrlclient.Object, opts ...ctrlclient.GetOption) error {
			gets++
			if gets < 3 {
				return apierrors.NewServiceUnavailable("error trying to reach service: unexpected EOF")
			}
			return cli.Get(ctx, key, obj, opts...)
		},
	}))

	got := &apiregistrationv1.APIService{}
	g.Expect(c.Get(context.Background(), ctrlclient.ObjectKey{Name: calicoV3APIServiceName}, got)).To(Succeed())
	g.Expect(gets).To(Equal(3))
}

// Discovery drops projectcalico.org/v3 while calico-apiserver rolls, which surfaces
// as a no-match rather than a status error.
func TestWithRetryRetriesNoMatch(t *testing.T) {
	g := NewWithT(t)
	shrinkRetry(t)

	lists := 0
	base := newFakeClient(t)
	c := WithRetry(interceptor.NewClient(base, interceptor.Funcs{
		List: func(ctx context.Context, cli ctrlclient.WithWatch, list ctrlclient.ObjectList, opts ...ctrlclient.ListOption) error {
			lists++
			if lists < 2 {
				return &meta.NoKindMatchError{GroupKind: schema.GroupKind{Group: "projectcalico.org", Kind: "GlobalNetworkPolicy"}}
			}
			return cli.List(ctx, list, opts...)
		},
	}))

	g.Expect(c.List(context.Background(), &v3.GlobalNetworkPolicyList{})).To(Succeed())
	g.Expect(lists).To(Equal(2))
}

func TestWithRetryDoesNotRetryNotFound(t *testing.T) {
	g := NewWithT(t)
	shrinkRetry(t)

	gets := 0
	base := newFakeClient(t)
	c := WithRetry(interceptor.NewClient(base, interceptor.Funcs{
		Get: func(ctx context.Context, cli ctrlclient.WithWatch, key ctrlclient.ObjectKey, obj ctrlclient.Object, opts ...ctrlclient.GetOption) error {
			gets++
			return cli.Get(ctx, key, obj, opts...)
		},
	}))

	err := c.Get(context.Background(), ctrlclient.ObjectKey{Name: "missing"}, &apiregistrationv1.APIService{})
	g.Expect(apierrors.IsNotFound(err)).To(BeTrue())
	g.Expect(gets).To(Equal(1))
}

// A CRD-served v3 shows up in discovery with no aggregated apiserver behind it.
func TestCalicoV3APIAvailableFromDiscovery(t *testing.T) {
	g := NewWithT(t)
	shrinkRetry(t)

	d := &stubDiscovery{fn: func(int) (*metav1.APIGroupList, error) { return servingV3(), nil }}
	available, err := calicoV3APIAvailable(context.Background(), d, newFakeClient(t))
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(available).To(BeTrue())
	g.Expect(d.calls).To(Equal(1))
}

// Nothing serves v3, so the calicoctl fallback should be taken without waiting out
// the backoff.
func TestCalicoV3APIAvailableNoV3(t *testing.T) {
	g := NewWithT(t)
	shrinkRetry(t)

	start := time.Now()
	d := &stubDiscovery{fn: func(int) (*metav1.APIGroupList, error) { return servingNothing(), nil }}
	available, err := calicoV3APIAvailable(context.Background(), d, newFakeClient(t))
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(available).To(BeFalse())
	g.Expect(time.Since(start)).To(BeNumerically("<", time.Second))
}

// A rolling apiserver drops out of discovery but keeps its APIService. Wait for it
// rather than falling back to calicoctl.
func TestCalicoV3APIAvailableWaitsForDiscovery(t *testing.T) {
	g := NewWithT(t)
	shrinkRetry(t)

	d := &stubDiscovery{fn: func(call int) (*metav1.APIGroupList, error) {
		if call < 3 {
			return servingNothing(), nil
		}
		return servingV3(), nil
	}}

	available, err := calicoV3APIAvailable(context.Background(), d, newFakeClient(t, registeredAPIService()))
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(available).To(BeTrue())
	g.Expect(d.calls).To(Equal(3))
}

// An apiserver that never comes back is an error, not a silent switch to calicoctl.
func TestCalicoV3APIAvailableNeverServed(t *testing.T) {
	g := NewWithT(t)
	shrinkRetry(t)

	d := &stubDiscovery{fn: func(int) (*metav1.APIGroupList, error) { return servingNothing(), nil }}
	available, err := calicoV3APIAvailable(context.Background(), d, newFakeClient(t, registeredAPIService()))
	g.Expect(err).To(HaveOccurred())
	g.Expect(available).To(BeFalse())
}

// Discovery itself fails while the apiserver rolls, which must not read as "no v3".
func TestCalicoV3APIAvailableRetriesDiscoveryError(t *testing.T) {
	g := NewWithT(t)
	shrinkRetry(t)

	d := &stubDiscovery{fn: func(call int) (*metav1.APIGroupList, error) {
		if call < 3 {
			return nil, apierrors.NewServiceUnavailable("unexpected EOF")
		}
		return servingV3(), nil
	}}

	available, err := calicoV3APIAvailable(context.Background(), d, newFakeClient(t))
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(available).To(BeTrue())
	g.Expect(d.calls).To(Equal(3))
}

// RBAC-restricted clients can't read APIServices, so discovery has the only say.
func TestCalicoV3APIAvailableForbidden(t *testing.T) {
	g := NewWithT(t)
	shrinkRetry(t)

	base := newFakeClient(t)
	c := WithRetry(interceptor.NewClient(base, interceptor.Funcs{
		Get: func(ctx context.Context, cli ctrlclient.WithWatch, key ctrlclient.ObjectKey, obj ctrlclient.Object, opts ...ctrlclient.GetOption) error {
			return apierrors.NewForbidden(schema.GroupResource{Resource: "apiservices"}, key.Name, nil)
		},
	}))

	d := &stubDiscovery{fn: func(int) (*metav1.APIGroupList, error) { return servingNothing(), nil }}
	available, err := calicoV3APIAvailable(context.Background(), d, c)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(available).To(BeFalse())
}

// The budget has to outlast a calico-apiserver restart, which takes tens of seconds.
func TestAPIRetryBudget(t *testing.T) {
	g := NewWithT(t)

	b := apiRetry
	var total time.Duration
	for b.Steps > 0 {
		total += b.Step()
	}
	g.Expect(total).To(BeNumerically(">=", 90*time.Second))
}
