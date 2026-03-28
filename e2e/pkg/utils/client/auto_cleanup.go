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

	. "github.com/onsi/ginkgo/v2"
	"github.com/sirupsen/logrus"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// autoCleanupClient wraps a controller-runtime client.Client and registers a
// Ginkgo DeferCleanup for every successful Create call. This ensures that
// test-created resources are always cleaned up, even if the test author forgets
// to add explicit cleanup logic.
type autoCleanupClient struct {
	client.Client
}

// NewWithAutoCleanup wraps an existing client so that every successful Create
// automatically registers a Ginkgo DeferCleanup to delete the object.
func NewWithAutoCleanup(c client.Client) client.Client {
	return &autoCleanupClient{Client: c}
}

func (c *autoCleanupClient) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	if err := c.Client.Create(ctx, obj, opts...); err != nil {
		return err
	}

	// Capture the GVK and object key at creation time so the deferred delete
	// doesn't depend on the original object pointer, which the test may mutate.
	gvk, err := c.GroupVersionKindFor(obj)
	if err != nil {
		logrus.WithError(err).Warn("Auto-cleanup: unable to determine GVK, skipping cleanup registration")
		return nil
	}
	key := client.ObjectKeyFromObject(obj)

	DeferCleanup(func() {
		stub := &unstructured.Unstructured{}
		stub.SetGroupVersionKind(gvk)
		stub.SetName(key.Name)
		stub.SetNamespace(key.Namespace)
		if err := c.Client.Delete(context.Background(), stub); err != nil {
			if !apierrors.IsNotFound(err) {
				logrus.WithError(err).WithFields(logrus.Fields{
					"gvk":  gvk,
					"name": key,
				}).Warn("Auto-cleanup: failed to delete object")
			}
		}
	})
	return nil
}
