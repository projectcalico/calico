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

func availableAPIService() *apiregistrationv1.APIService {
	return &apiregistrationv1.APIService{
		ObjectMeta: metav1.ObjectMeta{Name: calicoV3APIServiceName},
		Status: apiregistrationv1.APIServiceStatus{
			Conditions: []apiregistrationv1.APIServiceCondition{
				{
					Type:   apiregistrationv1.Available,
					Status: apiregistrationv1.ConditionTrue,
				},
			},
		},
	}
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
	base := newFakeClient(t, availableAPIService())
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

func TestCalicoV3APIAvailable(t *testing.T) {
	g := NewWithT(t)
	shrinkRetry(t)

	available, err := calicoV3APIAvailable(context.Background(), newFakeClient(t, availableAPIService()))
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(available).To(BeTrue())
}

// No APIService means nothing serves v3, so the calicoctl fallback should be taken
// without waiting out the backoff.
func TestCalicoV3APIAvailableNoAPIService(t *testing.T) {
	g := NewWithT(t)
	shrinkRetry(t)

	start := time.Now()
	available, err := calicoV3APIAvailable(context.Background(), newFakeClient(t))
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(available).To(BeFalse())
	g.Expect(time.Since(start)).To(BeNumerically("<", time.Second))
}

// A rolling apiserver leaves the APIService in place with Available=False. Wait for
// it rather than falling back to calicoctl.
func TestCalicoV3APIAvailableWaitsForAvailable(t *testing.T) {
	g := NewWithT(t)
	shrinkRetry(t)

	rolling := availableAPIService()
	rolling.Status.Conditions[0].Status = apiregistrationv1.ConditionFalse

	gets := 0
	base := newFakeClient(t, rolling)
	c := WithRetry(interceptor.NewClient(base, interceptor.Funcs{
		Get: func(ctx context.Context, cli ctrlclient.WithWatch, key ctrlclient.ObjectKey, obj ctrlclient.Object, opts ...ctrlclient.GetOption) error {
			gets++
			if err := cli.Get(ctx, key, obj, opts...); err != nil {
				return err
			}
			if gets >= 3 {
				apiService, ok := obj.(*apiregistrationv1.APIService)
				if !ok {
					return nil
				}
				apiService.Status.Conditions[0].Status = apiregistrationv1.ConditionTrue
			}
			return nil
		},
	}))

	available, err := calicoV3APIAvailable(context.Background(), c)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(available).To(BeTrue())
	g.Expect(gets).To(Equal(3))
}

// An apiserver that never comes back is an error, not a silent switch to calicoctl.
func TestCalicoV3APIAvailableNeverAvailable(t *testing.T) {
	g := NewWithT(t)
	shrinkRetry(t)

	rolling := availableAPIService()
	rolling.Status.Conditions[0].Status = apiregistrationv1.ConditionFalse

	available, err := calicoV3APIAvailable(context.Background(), newFakeClient(t, rolling))
	g.Expect(err).To(HaveOccurred())
	g.Expect(available).To(BeFalse())
}

// RBAC-restricted clients can't read APIServices, and calicoctl would exec past the
// RBAC those tests assert on.
func TestCalicoV3APIAvailableForbidden(t *testing.T) {
	g := NewWithT(t)
	shrinkRetry(t)

	base := newFakeClient(t)
	c := WithRetry(interceptor.NewClient(base, interceptor.Funcs{
		Get: func(ctx context.Context, cli ctrlclient.WithWatch, key ctrlclient.ObjectKey, obj ctrlclient.Object, opts ...ctrlclient.GetOption) error {
			return apierrors.NewForbidden(schema.GroupResource{Resource: "apiservices"}, key.Name, nil)
		},
	}))

	available, err := calicoV3APIAvailable(context.Background(), c)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(available).To(BeTrue())
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
