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
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Two minutes of fixed interval outlasts a calico-apiserver restart. No Cap:
// wait.Backoff zeroes Steps once Duration*Factor exceeds it.
var apiRetry = wait.Backoff{
	Steps:    30,
	Duration: 4 * time.Second,
	Factor:   1.0,
}

// RetriableAPIError reports whether err is a transient projectcalico.org/v3 failure.
// A rolling calico-apiserver drops requests and briefly leaves discovery.
func RetriableAPIError(err error) bool {
	if meta.IsNoMatchError(err) || discovery.IsGroupDiscoveryFailedError(err) {
		return true
	}
	return apierrors.IsServiceUnavailable(err) ||
		apierrors.IsInternalError(err) ||
		apierrors.IsTimeout(err) ||
		apierrors.IsTooManyRequests(err)
}

// WithRetry wraps c so requests survive a calico-apiserver restart. Conflicts
// are not retried; the caller has to re-read first.
func WithRetry(c client.Client) client.Client {
	return &retryClient{Client: c}
}

var _ client.Client = &retryClient{}

type retryClient struct {
	client.Client
}

func (c *retryClient) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	return c.do(func() error {
		return c.Client.Get(ctx, key, obj, opts...)
	})
}

func (c *retryClient) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	return c.do(func() error {
		return c.Client.List(ctx, list, opts...)
	})
}

func (c *retryClient) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	return c.do(func() error {
		return c.Client.Create(ctx, obj, opts...)
	})
}

func (c *retryClient) Delete(ctx context.Context, obj client.Object, opts ...client.DeleteOption) error {
	return c.do(func() error {
		return c.Client.Delete(ctx, obj, opts...)
	})
}

func (c *retryClient) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	return c.do(func() error {
		return c.Client.Update(ctx, obj, opts...)
	})
}

func (c *retryClient) Patch(ctx context.Context, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
	return c.do(func() error {
		return c.Client.Patch(ctx, obj, patch, opts...)
	})
}

func (c *retryClient) DeleteAllOf(ctx context.Context, obj client.Object, opts ...client.DeleteAllOfOption) error {
	return c.do(func() error {
		return c.Client.DeleteAllOf(ctx, obj, opts...)
	})
}

func (c *retryClient) Apply(ctx context.Context, obj runtime.ApplyConfiguration, opts ...client.ApplyOption) error {
	return c.do(func() error {
		return c.Client.Apply(ctx, obj, opts...)
	})
}

func (c *retryClient) do(fn func() error) error {
	return retry.OnError(apiRetry, RetriableAPIError, fn)
}
