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

package utils

import (
	"context"
	"testing"

	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

// A ServiceUnavailable from the aggregation layer (the "unexpected EOF" flake
// when calico-apiserver is rolling) should be retried until it clears.
func TestConfigureWithCleanupRetriesTransientUpdate(t *testing.T) {
	g := NewWithT(t)

	existing := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Data:       map[string]string{"key": "original"},
	}

	updateCalls := 0
	base := fake.NewClientBuilder().WithObjects(existing).Build()
	cli := interceptor.NewClient(base, interceptor.Funcs{
		Update: func(ctx context.Context, c ctrlclient.WithWatch, obj ctrlclient.Object, opts ...ctrlclient.UpdateOption) error {
			updateCalls++
			if updateCalls < 3 {
				return apierrors.NewServiceUnavailable("error trying to reach service: unexpected EOF")
			}
			return c.Update(ctx, obj, opts...)
		},
	})

	restore, err := ConfigureWithCleanup(cli, ctrlclient.ObjectKey{Name: "default"}, &corev1.ConfigMap{}, func(cm *corev1.ConfigMap) {
		cm.Data["key"] = "mutated"
	})
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(updateCalls).To(Equal(3), "transient ServiceUnavailable responses should be retried")

	got := &corev1.ConfigMap{}
	g.Expect(cli.Get(context.Background(), ctrlclient.ObjectKey{Name: "default"}, got)).To(Succeed())
	g.Expect(got.Data["key"]).To(Equal("mutated"))
	g.Expect(restore).NotTo(BeNil())
}

// A permanent error (e.g. Forbidden) is not retriable and should fail fast
// rather than burning the whole backoff.
func TestConfigureWithCleanupDoesNotRetryPermanentError(t *testing.T) {
	g := NewWithT(t)

	existing := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "default"},
		Data:       map[string]string{"key": "original"},
	}

	updateCalls := 0
	base := fake.NewClientBuilder().WithObjects(existing).Build()
	cli := interceptor.NewClient(base, interceptor.Funcs{
		Update: func(ctx context.Context, c ctrlclient.WithWatch, obj ctrlclient.Object, opts ...ctrlclient.UpdateOption) error {
			updateCalls++
			return apierrors.NewForbidden(corev1.Resource("configmaps"), "default", nil)
		},
	})

	_, err := ConfigureWithCleanup(cli, ctrlclient.ObjectKey{Name: "default"}, &corev1.ConfigMap{}, func(cm *corev1.ConfigMap) {
		cm.Data["key"] = "mutated"
	})
	g.Expect(err).To(HaveOccurred())
	g.Expect(updateCalls).To(Equal(1), "a non-retriable error should not be retried")
}
