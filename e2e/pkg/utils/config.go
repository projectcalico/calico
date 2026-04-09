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
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/kubernetes/test/e2e/framework"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// ConfigureWithCleanup fetches a cluster-scoped object by key, applies a
// mutation, and returns a cleanup function that restores the original state.
// If the object doesn't exist, it is created with the mutation applied and the
// cleanup function deletes it.
//
// Typical usage with Ginkgo:
//
//	restore, err := utils.ConfigureWithCleanup(cli, ctrlclient.ObjectKey{Name: "default"}, &v3.IPAMConfiguration{}, func(cfg *v3.IPAMConfiguration) {
//	    cfg.Spec.StrictAffinity = false
//	})
//	Expect(err).NotTo(HaveOccurred())
//	DeferCleanup(restore)
func ConfigureWithCleanup[T ctrlclient.Object](cli ctrlclient.Client, key ctrlclient.ObjectKey, obj T, mutate func(T)) (func(), error) {
	ctx := context.Background()

	err := cli.Get(ctx, key, obj)
	if apierrors.IsNotFound(err) {
		obj.SetName(key.Name)
		obj.SetNamespace(key.Namespace)
		mutate(obj)
		if err := cli.Create(ctx, obj); err != nil {
			return nil, fmt.Errorf("failed to create %T: %w", obj, err)
		}
		return func() {
			if err := cli.Delete(context.Background(), obj); err != nil && !apierrors.IsNotFound(err) {
				framework.Logf("WARNING: failed to delete %T %s: %v", obj, key, err)
			}
		}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get %T: %w", obj, err)
	}

	original := obj.DeepCopyObject().(T)
	mutate(obj)
	if err := cli.Update(ctx, obj); err != nil {
		return nil, fmt.Errorf("failed to update %T: %w", obj, err)
	}

	return func() {
		// Re-fetch to get the current resourceVersion before restoring.
		if err := cli.Get(context.Background(), key, obj); err != nil {
			framework.Logf("WARNING: failed to get %T for restoration: %v", obj, err)
			return
		}
		original.SetResourceVersion(obj.GetResourceVersion())
		if err := cli.Update(context.Background(), original); err != nil {
			framework.Logf("WARNING: failed to restore %T: %v", obj, err)
		}
	}, nil
}
