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

package controller

import (
	"context"
	"testing"
	"time"

	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	fakeapiext "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/fake"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const testCRDName = "widgets.example.com"

// mockContextController records calls to RunWithContext. Each call sends the
// context on the started channel, then blocks until the context is cancelled.
type mockContextController struct {
	started chan context.Context
}

func newMockContextController() *mockContextController {
	return &mockContextController{started: make(chan context.Context, 10)}
}

func (m *mockContextController) RunWithContext(ctx context.Context) {
	m.started <- ctx
	<-ctx.Done()
}

// waitForStart blocks until RunWithContext is called, returning the context.
func (m *mockContextController) waitForStart(t *testing.T) context.Context {
	t.Helper()
	select {
	case ctx := <-m.started:
		return ctx
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for inner controller to start")
		return nil
	}
}

// expectNoStart verifies that RunWithContext is NOT called within a short window.
func (m *mockContextController) expectNoStart(t *testing.T) {
	t.Helper()
	select {
	case <-m.started:
		t.Fatal("inner controller started unexpectedly")
	case <-time.After(500 * time.Millisecond):
	}
}

// newEstablishedCRD returns a CRD object with the Established condition set.
func newEstablishedCRD(name string) *apiextv1.CustomResourceDefinition {
	return &apiextv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Status: apiextv1.CustomResourceDefinitionStatus{
			Conditions: []apiextv1.CustomResourceDefinitionCondition{
				{
					Type:   apiextv1.Established,
					Status: apiextv1.ConditionTrue,
				},
			},
		},
	}
}

// TestDeferredCRDController_StartsWhenCRDEstablished verifies that the inner
// controller starts when the watched CRD becomes Established.
func TestDeferredCRDController_StartsWhenCRDEstablished(t *testing.T) {
	inner := newMockContextController()
	// NewClientset() in k8s 1.35 has a broken SMD schema for CRD types, so Create() fails with
	// "no type found matching". Use the deprecated NewSimpleClientset() until upstream is fixed.
	fakeClient := fakeapiext.NewSimpleClientset() //nolint:staticcheck

	ctrl := NewDeferredCRDController(testCRDName, fakeClient, inner)
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	go ctrl.Run(stop)

	inner.expectNoStart(t)

	// Create the Established CRD — inner should start.
	ctx := context.Background()
	crd := newEstablishedCRD(testCRDName)
	if _, err := fakeClient.ApiextensionsV1().CustomResourceDefinitions().Create(ctx, crd, metav1.CreateOptions{}); err != nil {
		t.Fatalf("creating CRD: %v", err)
	}

	inner.waitForStart(t)
}

// TestDeferredCRDController_StopsWhenCRDDeleted verifies that deleting the CRD
// cancels the inner controller's context.
func TestDeferredCRDController_StopsWhenCRDDeleted(t *testing.T) {
	inner := newMockContextController()
	crd := newEstablishedCRD(testCRDName)
	fakeClient := fakeapiext.NewSimpleClientset(crd) //nolint:staticcheck

	ctrl := NewDeferredCRDController(testCRDName, fakeClient, inner)
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	go ctrl.Run(stop)

	innerCtx := inner.waitForStart(t)

	// Delete the CRD — inner context should be cancelled.
	ctx := context.Background()
	if err := fakeClient.ApiextensionsV1().CustomResourceDefinitions().Delete(ctx, testCRDName, metav1.DeleteOptions{}); err != nil {
		t.Fatalf("deleting CRD: %v", err)
	}

	select {
	case <-innerCtx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for inner context to be cancelled")
	}
}

// TestDeferredCRDController_RestartsWhenCRDRecreated verifies that the inner
// controller is restarted if the CRD is deleted and recreated.
func TestDeferredCRDController_RestartsWhenCRDRecreated(t *testing.T) {
	inner := newMockContextController()
	crd := newEstablishedCRD(testCRDName)
	fakeClient := fakeapiext.NewSimpleClientset(crd) //nolint:staticcheck

	ctrl := NewDeferredCRDController(testCRDName, fakeClient, inner)
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	go ctrl.Run(stop)

	// First start.
	firstCtx := inner.waitForStart(t)

	// Delete the CRD and wait for cancellation.
	ctx := context.Background()
	if err := fakeClient.ApiextensionsV1().CustomResourceDefinitions().Delete(ctx, testCRDName, metav1.DeleteOptions{}); err != nil {
		t.Fatalf("deleting CRD: %v", err)
	}
	select {
	case <-firstCtx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for first context cancellation")
	}

	// Recreate — should trigger a second start.
	crd = newEstablishedCRD(testCRDName)
	if _, err := fakeClient.ApiextensionsV1().CustomResourceDefinitions().Create(ctx, crd, metav1.CreateOptions{}); err != nil {
		t.Fatalf("recreating CRD: %v", err)
	}

	inner.waitForStart(t)
}

// TestDeferredCRDController_IgnoresOtherCRDs verifies that CRDs with different
// names don't trigger the inner controller.
func TestDeferredCRDController_IgnoresOtherCRDs(t *testing.T) {
	inner := newMockContextController()
	fakeClient := fakeapiext.NewSimpleClientset() //nolint:staticcheck

	ctrl := NewDeferredCRDController(testCRDName, fakeClient, inner)
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	go ctrl.Run(stop)

	// Create a CRD with a different name.
	ctx := context.Background()
	other := newEstablishedCRD("gadgets.example.com")
	if _, err := fakeClient.ApiextensionsV1().CustomResourceDefinitions().Create(ctx, other, metav1.CreateOptions{}); err != nil {
		t.Fatalf("creating other CRD: %v", err)
	}

	inner.expectNoStart(t)
}
