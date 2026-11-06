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

package utils

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"

	client "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
)

// SandboxLookups holds the clients and API objects the calico plugin has already built or
// fetched for the sandbox it is networking. It rides on the context into calico-ipam when that
// runs in the same process, so IPAM uses them instead of building and fetching its own. Any field
// may be nil, in which case IPAM does that work itself, as it always does when exec'd.
type SandboxLookups struct {
	CalicoClient client.Interface
	K8sClient    kubernetes.Interface
	Pod          *corev1.Pod
	Namespace    *corev1.Namespace
}

type sandboxLookupsKey struct{}

// WithSandboxLookups returns a copy of ctx that carries lookups.
func WithSandboxLookups(ctx context.Context, lookups SandboxLookups) context.Context {
	return context.WithValue(ctx, sandboxLookupsKey{}, lookups)
}

// SandboxLookupsFrom returns the lookups ctx carries, or an empty set if it carries none.
func SandboxLookupsFrom(ctx context.Context) SandboxLookups {
	lookups, ok := ctx.Value(sandboxLookupsKey{}).(SandboxLookups)
	if !ok {
		return SandboxLookups{}
	}
	return lookups
}
