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
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/retry"
	"k8s.io/kubernetes/test/e2e/framework"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// configRetry backs off long enough to ride out a calico-apiserver pod that's
// briefly rolling or unreachable, which is where the transient errors that
// retriableAPIError covers come from.
var configRetry = wait.Backoff{
	Steps:    8,
	Duration: 100 * time.Millisecond,
	Factor:   2.0,
	Jitter:   0.1,
	Cap:      10 * time.Second,
}

// ConfigureWithCleanup fetches an object by key, applies a mutation, and
// returns a cleanup function that restores the original state. If the object
// doesn't exist, it is created with the mutation applied and the cleanup
// function deletes it.
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

	err := retry.OnError(configRetry, retriableAPIError, func() error {
		return cli.Get(ctx, key, obj)
	})
	if apierrors.IsNotFound(err) {
		obj.SetName(key.Name)
		obj.SetNamespace(key.Namespace)
		mutate(obj)
		if err := retry.OnError(configRetry, retriableAPIError, func() error {
			return cli.Create(ctx, obj)
		}); err != nil {
			return nil, fmt.Errorf("failed to create %T: %w", obj, err)
		}
		return func() {
			if err := cli.Delete(context.Background(), obj); err != nil && !apierrors.IsNotFound(err) {
				framework.Logf("WARNING: failed to delete %T %s: %v", obj, key, err)
			}
		}, nil
	} else if err != nil {
		return nil, fmt.Errorf("failed to get %T: %w", obj, err)
	}

	// Operator-reconciled resources (e.g. Installation) can be updated by a
	// controller between our Get and Update, returning 409 Conflict. Re-read
	// the latest resourceVersion and re-apply our mutation on conflict, and on
	// the transient apiserver errors retriableAPIError covers.
	var original T
	if err := retry.OnError(configRetry, retriableAPIError, func() error {
		if err := cli.Get(ctx, key, obj); err != nil {
			return err
		}
		original = obj.DeepCopyObject().(T)
		mutate(obj)
		return cli.Update(ctx, obj)
	}); err != nil {
		return nil, fmt.Errorf("failed to update %T: %w", obj, err)
	}

	return func() {
		if err := retry.OnError(configRetry, retriableAPIError, func() error {
			if err := cli.Get(context.Background(), key, obj); err != nil {
				return err
			}
			original.SetResourceVersion(obj.GetResourceVersion())
			return cli.Update(context.Background(), original)
		}); err != nil {
			framework.Logf("WARNING: failed to restore %T: %v", obj, err)
		}
	}, nil
}

// retriableAPIError reports whether err is worth retrying against the
// aggregated projectcalico.org/v3 API server. Besides 409 Conflict, the
// aggregation layer intermittently drops a request mid-flight when the backing
// calico-apiserver pod is rolling. That surfaces as ServiceUnavailable
// ("unexpected EOF") or a 500 InternalError, and clears on retry.
func retriableAPIError(err error) bool {
	return apierrors.IsConflict(err) ||
		apierrors.IsServiceUnavailable(err) ||
		apierrors.IsInternalError(err) ||
		apierrors.IsTimeout(err) ||
		apierrors.IsTooManyRequests(err)
}
