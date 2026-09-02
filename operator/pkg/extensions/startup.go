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

package extensions

import (
	"context"

	"k8s.io/client-go/kubernetes"
)

// StartupExtension is the variant's hook into the operator's startup, before any
// controller registers.
type StartupExtension interface {
	// VerifyAPIsExist reports whether the APIs the variant's controllers watch are
	// served. The operator exits when they are not, so the kubelet retries it once
	// the CRDs are installed.
	VerifyAPIsExist(cs kubernetes.Interface) error

	// VerifyClusterState rejects a cluster whose existing state contradicts the
	// configuration the operator was given.
	VerifyClusterState(ctx context.Context, cs kubernetes.Interface, migrating, external bool) error

	// ProtectedNamespaces are the namespaces the variant manages. The operator must
	// not run in one of them.
	ProtectedNamespaces() []string

	// MultiTenant reports whether the cluster runs the variant in multi-tenant mode.
	MultiTenant() bool

	// Cloud reports whether this binary was built for the variant's hosted product.
	Cloud() bool
}

// noopStartup runs the core operator's behavior unchanged.
type noopStartup struct{}

func (noopStartup) VerifyAPIsExist(kubernetes.Interface) error {
	return nil
}

func (noopStartup) VerifyClusterState(context.Context, kubernetes.Interface, bool, bool) error {
	return nil
}

func (noopStartup) ProtectedNamespaces() []string {
	return nil
}

func (noopStartup) MultiTenant() bool {
	return false
}

func (noopStartup) Cloud() bool {
	return false
}
